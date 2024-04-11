// Package utils contains the internal test utils
package utils

//#include <stdint.h>
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/msteinert/pam/v2"
)

// Action represents a PAM action to perform.
type Action int

const (
	// Account is the account.
	Account Action = iota + 1
	// Auth is the auth.
	Auth
	// Password is the password.
	Password
	// Session is the session.
	Session
)

func (a Action) String() string {
	switch a {
	case Account:
		return "account"
	case Auth:
		return "auth"
	case Password:
		return "password"
	case Session:
		return "session"
	default:
		return ""
	}
}

// Actions is a map with all the available Actions by their name.
var Actions = map[string]Action{
	Account.String():  Account,
	Auth.String():     Auth,
	Password.String(): Password,
	Session.String():  Session,
}

// Control represents how a PAM module should controlled in PAM service file.
type Control int

const (
	// Required implies that the module is required.
	Required Control = iota + 1
	// Requisite implies that the module is requisite.
	Requisite
	// Sufficient implies that the module is sufficient.
	Sufficient
	// Optional implies that the module is optional.
	Optional
)

func (c Control) String() string {
	switch c {
	case Required:
		return "required"
	case Requisite:
		return "requisite"
	case Sufficient:
		return "sufficient"
	case Optional:
		return "optional"
	default:
		return ""
	}
}

// ServiceLine is the representation of a PAM module service file line.
type ServiceLine struct {
	Action  Action
	Control Control
	Module  string
	Args    []string
}

// FallBackModule is a type to represent the module that should be used as fallback.
type FallBackModule int

const (
	// NoFallback add no fallback module.
	NoFallback FallBackModule = iota + 1
	// Permit uses a module that always permits.
	Permit
	// Deny uses a module that always denys.
	Deny
)

func (a FallBackModule) String() string {
	switch a {
	case Permit:
		return "pam_permit.so"
	case Deny:
		return "pam_deny.so"
	default:
		return ""
	}
}

// SerializableError is a representation of an error in a way can be serialized.
type SerializableError struct {
	Msg string
}

func (e *SerializableError) Error() string {
	return e.Msg
}

// Credentials is a test [pam.ConversationHandler] implementation.
type Credentials struct {
	User              string
	Password          string
	EchoOn            string
	EchoOff           string
	TextInfo          string
	ErrorMsg          string
	ExpectedMessage   string
	CheckEmptyMessage bool
	ExpectedStyle     pam.Style
	CheckZeroStyle    bool
	Context           interface{}
}

// RespondPAM handles PAM string conversations.
func (c Credentials) RespondPAM(s pam.Style, msg string) (string, error) {
	if (c.ExpectedMessage != "" || c.CheckEmptyMessage) &&
		msg != c.ExpectedMessage {
		return "", errors.Join(pam.ErrConv,
			&SerializableError{
				fmt.Sprintf("unexpected prompt: %s vs %s", msg, c.ExpectedMessage),
			})
	}

	if (c.ExpectedStyle != 0 || c.CheckZeroStyle) &&
		s != c.ExpectedStyle {
		return "", errors.Join(pam.ErrConv,
			&SerializableError{
				fmt.Sprintf("unexpected style: %#v vs %#v", s, c.ExpectedStyle),
			})
	}

	switch s {
	case pam.PromptEchoOn:
		if c.User != "" {
			return c.User, nil
		}
		return c.EchoOn, nil
	case pam.PromptEchoOff:
		if c.Password != "" {
			return c.Password, nil
		}
		return c.EchoOff, nil
	case pam.TextInfo:
		return c.TextInfo, nil
	case pam.ErrorMsg:
		return c.ErrorMsg, nil
	}

	return "", errors.Join(pam.ErrConv,
		&SerializableError{fmt.Sprintf("unhandled style: %v", s)})
}

// BinaryTransaction represents a binary PAM transaction handler struct.
type BinaryTransaction struct {
	data         []byte
	ExpectedNull bool
	ReturnedData []byte
}

// TestBinaryDataEncoder encodes a test binary data.
func TestBinaryDataEncoder(bytes []byte) []byte {
	if len(bytes) > 0xff {
		panic("Binary transaction size not supported")
	}

	if bytes == nil {
		return bytes
	}

	data := make([]byte, 0, len(bytes)+1)
	data = append(data, byte(len(bytes)))
	data = append(data, bytes...)
	return data
}

// TestBinaryDataDecoder decodes a test binary data.
func TestBinaryDataDecoder(ptr pam.BinaryPointer) ([]byte, error) {
	if ptr == nil {
		return nil, nil
	}

	length := uint8(*((*C.uint8_t)(ptr)))
	if length == 0 {
		return []byte{}, nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length+1))[1:], nil
}

// NewBinaryTransactionWithData creates a new [pam.BinaryTransaction] from bytes.
func NewBinaryTransactionWithData(data []byte, retData []byte) BinaryTransaction {
	t := BinaryTransaction{ReturnedData: retData}
	t.data = TestBinaryDataEncoder(data)
	t.ExpectedNull = data == nil
	return t
}

// NewBinaryTransactionWithRandomData creates a new [pam.BinaryTransaction] with random data.
func NewBinaryTransactionWithRandomData(size uint8, retData []byte) BinaryTransaction {
	t := BinaryTransaction{ReturnedData: retData}
	randomData := make([]byte, size)
	if err := binary.Read(rand.Reader, binary.LittleEndian, &randomData); err != nil {
		panic(err)
	}

	t.data = TestBinaryDataEncoder(randomData)
	return t
}

// Data returns the bytes of the transaction.
func (b BinaryTransaction) Data() []byte {
	return b.data
}

// RespondPAM (not) handles the PAM string conversations.
func (b BinaryTransaction) RespondPAM(s pam.Style, msg string) (string, error) {
	return "", errors.Join(pam.ErrConv,
		&SerializableError{"unexpected non-binary request"})
}

// RespondPAMBinary handles the PAM binary conversations.
func (b BinaryTransaction) RespondPAMBinary(ptr pam.BinaryPointer) ([]byte, error) {
	if ptr == nil && !b.ExpectedNull {
		return nil, errors.Join(pam.ErrConv,
			&SerializableError{"unexpected null binary data"})
	} else if ptr == nil {
		return TestBinaryDataEncoder(b.ReturnedData), nil
	}

	bytes, _ := TestBinaryDataDecoder(ptr)
	if !reflect.DeepEqual(bytes, b.data[1:]) {
		return nil, errors.Join(pam.ErrConv,
			&SerializableError{
				fmt.Sprintf("data mismatch %#v vs %#v", bytes, b.data[1:]),
			})
	}

	return TestBinaryDataEncoder(b.ReturnedData), nil
}
