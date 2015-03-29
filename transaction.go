package pam

//#include <security/pam_appl.h>
//#include <stdlib.h>
//#cgo CFLAGS: -Wall -std=c99
//#cgo LDFLAGS: -lpam
//struct pam_conv *make_pam_conv(void *);
import "C"

import (
	"runtime"
	"strings"
	"unsafe"
)

type Style int

const (
	PromptEchoOff Style = C.PAM_PROMPT_ECHO_OFF
	PromptEchoOn        = C.PAM_PROMPT_ECHO_ON
	ErrorMsg            = C.PAM_ERROR_MSG
	TextInfo            = C.PAM_TEXT_INFO
)

// Objects implementing the ConversationHandler interface can
// be registered as conversation callbacks to be used during
// PAM authentication.  RespondPAM receives a message style
// (one of PROMPT_ECHO_OFF, PROMPT_ECHO_ON, ERROR_MSG, or
// TEXT_INFO) and a message string.  It is expected to return
// a response string and a bool indicating success or failure.
type ConversationHandler interface {
	RespondPAM(Style, string) (string, error)
}

// ConversationFunc is an adapter to allow the use of ordinary
// functions as conversation callbacks. ConversationFunc(f) is
// a ConversationHandler that calls f, where f must have
// the signature func(int,string)(string,bool).
type ConversationFunc func(Style, string) (string, error)

func (f ConversationFunc) RespondPAM(s Style, msg string) (string, error) {
	return f(s, msg)
}

// Internal conversation structure
type Conversation struct {
	handler ConversationHandler
	conv    *C.struct_pam_conv
}

// Constructs a new conversation object with a given handler and a newly
// allocated pam_conv struct that uses this object as its appdata_ptr
func NewConversation(handler ConversationHandler) (*Conversation, C.int) {
	c := &Conversation{}
	c.handler = handler
	c.conv = C.make_pam_conv(unsafe.Pointer(c))
	if c.conv == nil {
		return nil, C.PAM_BUF_ERR
	}
	return c, C.PAM_SUCCESS
}

// Go-side function for processing a single conversational message. Ultimately
// this calls the associated ConversationHandler's ResponsePAM callback with data
// coming in from a C-side call.
//export cbPAMConv
func cbPAMConv(s C.int, msg *C.char, appdata unsafe.Pointer) (*C.char, C.int) {
	c := (*Conversation)(appdata)
	r, err := c.handler.RespondPAM(Style(s), C.GoString(msg))
	if err != nil {
		return nil, C.PAM_CONV_ERR
	}
	return C.CString(r), C.PAM_SUCCESS
}

// Transaction is the application's handle for a single PAM transaction.
type Transaction struct {
	handle *C.pam_handle_t
	conv   *Conversation
	status C.int
}

// Ends a PAM transaction.  From Linux-PAM documentation: "The [status] argument
// should be set to the value returned by the last PAM library call."
func TransactionFinalizer(t *Transaction) {
	C.pam_end(t.handle, t.status)
	C.free(unsafe.Pointer(t.conv.conv))
}

// Start initiates a new PAM transaction. service is treated identically
// to how pam_start treats it internally.
//
// All application calls to PAM begin with Start(). The returned *Transaction
// provides an interface to the remainder of the API.
//
// The returned status int may be ABORT, BUF_ERR, SUCCESS, or SYSTEM_ERR, as per
// the official PAM documentation.
func Start(service, user string, handler ConversationHandler) (*Transaction, error) {
	t := &Transaction{}
	t.conv, t.status = NewConversation(handler)
	if t.status != C.PAM_SUCCESS {
		return nil, t
	}
	s := C.CString(service)
	defer C.free(unsafe.Pointer(s))
	var u *C.char
	if len(user) != 0 {
		u = C.CString(user)
		defer C.free(unsafe.Pointer(u))
	}
	t.status = C.pam_start(s, u, t.conv.conv, &t.handle)
	if t.status != C.PAM_SUCCESS {
		C.free(unsafe.Pointer(t.conv.conv))
		return nil, t
	}
	runtime.SetFinalizer(t, TransactionFinalizer)
	return t, nil
}

func StartFunc(service, user string, handler func(Style, string) (string, error)) (*Transaction, error) {
	return Start(service, user, ConversationFunc(handler))
}

func (t *Transaction) Error() string {
	return C.GoString(C.pam_strerror(t.handle, C.int(t.status)))
}

type Item int

const (
	Service    Item = C.PAM_SERVICE
	User            = C.PAM_USER
	Tty             = C.PAM_TTY
	Rhost           = C.PAM_RHOST
	Authtok         = C.PAM_AUTHTOK
	Oldauthtok      = C.PAM_OLDAUTHTOK
	Ruser           = C.PAM_RUSER
	UserPrompt      = C.PAM_USER_PROMPT
)

// Sets a PAM informational item. Legal values of i are listed here
// (excluding Linux extensions):
//
// http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-by-app-expected.html#adg-pam_set_item
//
// PAM_CONV is not supported in order to simplify the Go API
// (and due to the fact that it is completely unnecessary).
func (t *Transaction) SetItem(i Item, item string) error {
	cs := unsafe.Pointer(C.CString(item))
	defer C.free(cs)
	t.status = C.pam_set_item(t.handle, C.int(i), cs)
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// Gets a PAM item. Legal values of itemType are as specified by the
// documentation of SetItem.
func (t *Transaction) GetItem(i Item) (string, error) {
	var s unsafe.Pointer
	t.status = C.pam_get_item(t.handle, C.int(i), &s)
	if t.status != C.PAM_SUCCESS {
		return "", t
	}
	return C.GoString((*C.char)(s)), nil
}

type Flags int

const (
	Silent               Flags = C.PAM_SILENT
	DisallowNullAuthtok        = C.PAM_DISALLOW_NULL_AUTHTOK
	EstablishCred              = C.PAM_ESTABLISH_CRED
	DeleteCred                 = C.PAM_DELETE_CRED
	ReinitializeCred           = C.PAM_REINITIALIZE_CRED
	RefreshCred                = C.PAM_REFRESH_CRED
	ChangeExpiredAuthtok       = C.PAM_CHANGE_EXPIRED_AUTHTOK
)

// pam_authenticate
func (t *Transaction) Authenticate(f Flags) error {
	t.status = C.pam_authenticate(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_setcred
func (t *Transaction) SetCred(f Flags) error {
	t.status = C.pam_setcred(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_acctmgmt
func (t *Transaction) AcctMgmt(f Flags) error {
	t.status = C.pam_acct_mgmt(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_chauthtok
func (t *Transaction) ChangeAuthTok(f Flags) error {
	t.status = C.pam_chauthtok(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_open_session
func (t *Transaction) OpenSession(f Flags) error {
	t.status = C.pam_open_session(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_close_session
func (t *Transaction) CloseSession(f Flags) error {
	t.status = C.pam_close_session(t.handle, C.int(f))
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_putenv
func (t *Transaction) PutEnv(nameval string) error {
	cs := C.CString(nameval)
	defer C.free(unsafe.Pointer(cs))
	t.status = C.pam_putenv(t.handle, cs)
	if t.status != C.PAM_SUCCESS {
		return t
	}
	return nil
}

// pam_getenv
func (t *Transaction) GetEnv(name string) string {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	value := C.pam_getenv(t.handle, cs)
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

// GetEnvList internally calls pam_getenvlist and then uses some very
// dangerous code to pull out the returned environment data and mash
// it into a map[string]string. This call may be safe, but it hasn't
// been tested on enough platforms/architectures/PAM-implementations to
// be sure.
func (t *Transaction) GetEnvList() (map[string]string, error) {
	env := make(map[string]string)
	p := C.pam_getenvlist(t.handle)
	if p == nil {
		t.status = C.PAM_BUF_ERR
		return nil, t
	}
	list := (uintptr)(unsafe.Pointer(p))
	for *(*uintptr)(unsafe.Pointer(list)) != 0 {
		entry := *(*uintptr)(unsafe.Pointer(list))
		nameval := C.GoString((*C.char)(unsafe.Pointer(entry)))
		chunks := strings.SplitN(nameval, "=", 2)
		if len(chunks) == 2 {
			env[chunks[0]] = chunks[1]
			list += (uintptr)(unsafe.Sizeof(list))
		}
	}
	return env, nil
}
