// Package pam provides a wrapper for the PAM application API.
package pam

/*
#cgo CFLAGS: -Wall -std=c99
#cgo LDFLAGS: -lpam

#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// ModuleTransaction is an interface that a pam module transaction
// should implement.
type ModuleTransaction interface {
	SetItem(Item, string) error
	GetItem(Item) (string, error)
	PutEnv(nameVal string) error
	GetEnv(name string) string
	GetEnvList() (map[string]string, error)
	GetUser(prompt string) (string, error)
}

// ModuleHandlerFunc is a function type used by the ModuleHandler.
type ModuleHandlerFunc func(ModuleTransaction, Flags, []string) error

// ModuleTransaction is the module-side handle for a PAM transaction.
type moduleTransaction struct {
	transactionBase
}

// ModuleHandler is an interface for objects that can be used to create
// PAM modules from go.
type ModuleHandler interface {
	AcctMgmt(ModuleTransaction, Flags, []string) error
	Authenticate(ModuleTransaction, Flags, []string) error
	ChangeAuthTok(ModuleTransaction, Flags, []string) error
	CloseSession(ModuleTransaction, Flags, []string) error
	OpenSession(ModuleTransaction, Flags, []string) error
	SetCred(ModuleTransaction, Flags, []string) error
}

// ModuleTransactionInvoker is an interface that a pam module transaction
// should implement to redirect requests from C handlers to go,
type ModuleTransactionInvoker interface {
	ModuleTransaction
	InvokeHandler(handler ModuleHandlerFunc, flags Flags, args []string) error
}

// NewModuleTransactionInvoker allows initializing a transaction invoker from
// the module side.
func NewModuleTransactionInvoker(handle NativeHandle) ModuleTransactionInvoker {
	return &moduleTransaction{transactionBase{handle: handle}}
}

func (m *moduleTransaction) InvokeHandler(handler ModuleHandlerFunc,
	flags Flags, args []string) error {
	invoker := func() error {
		if handler == nil {
			return ErrIgnore
		}
		err := handler(m, flags, args)
		if err != nil {
			service, _ := m.GetItem(Service)

			var pamErr Error
			if !errors.As(err, &pamErr) {
				err = ErrSystem
			}

			if pamErr == ErrIgnore || service == "" {
				return err
			}

			return fmt.Errorf("%s failed: %w", service, err)
		}
		return nil
	}
	err := invoker()
	if errors.Is(err, Error(0)) {
		err = nil
	}
	var status int32
	if err != nil {
		status = int32(ErrSystem)

		var pamErr Error
		if errors.As(err, &pamErr) {
			status = int32(pamErr)
		}
	}
	m.lastStatus.Store(status)
	return err
}

type moduleTransactionIface interface {
	getUser(outUser **C.char, prompt *C.char) C.int
}

func (m *moduleTransaction) getUser(outUser **C.char, prompt *C.char) C.int {
	return C.pam_get_user(m.handle, outUser, prompt)
}

// getUserImpl is the default implementation for GetUser, but kept as private so
// that can be used to test the pam package
func (m *moduleTransaction) getUserImpl(iface moduleTransactionIface,
	prompt string) (string, error) {
	var user *C.char
	var cPrompt = C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))
	err := m.handlePamStatus(iface.getUser(&user, cPrompt))
	if err != nil {
		return "", err
	}
	return C.GoString(user), nil
}

// GetUser is similar to GetItem(User), but it would start a conversation if
// no user is currently set in PAM.
func (m *moduleTransaction) GetUser(prompt string) (string, error) {
	return m.getUserImpl(m, prompt)
}
