//go:build !go_pam_module

package pam

/*
#cgo CFLAGS: -Wall -std=c99
#include <stdint.h>
#include <stdlib.h>
#include <security/pam_modules.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

type mockModuleTransactionExpectations struct {
	UserPrompt string
	DataKey    string
}

type mockModuleTransactionReturnedData struct {
	User            string
	InteractiveUser bool
	Status          Error
}

type mockModuleTransaction struct {
	moduleTransaction
	T                   *testing.T
	Expectations        mockModuleTransactionExpectations
	RetData             mockModuleTransactionReturnedData
	ConversationHandler ConversationHandler
	moduleData          map[string]uintptr
	allocatedData       []unsafe.Pointer
}

func newMockModuleTransaction(m *mockModuleTransaction) *mockModuleTransaction {
	m.moduleData = make(map[string]uintptr)
	runtime.SetFinalizer(m, func(m *mockModuleTransaction) {
		for _, ptr := range m.allocatedData {
			C.free(ptr)
		}
		for _, handle := range m.moduleData {
			_go_pam_data_cleanup(nil, C.uintptr_t(handle), C.PAM_DATA_SILENT)
		}
	})
	return m
}

func (m *mockModuleTransaction) getUser(outUser **C.char, prompt *C.char) C.int {
	goPrompt := C.GoString(prompt)
	if goPrompt != m.Expectations.UserPrompt {
		m.T.Fatalf("unexpected prompt: %s vs %s", goPrompt, m.Expectations.UserPrompt)
		return C.int(ErrAbort)
	}

	user := m.RetData.User
	if m.RetData.InteractiveUser || (m.RetData.User == "" && m.ConversationHandler != nil) {
		if m.ConversationHandler == nil {
			m.T.Fatalf("no conversation handler provided")
		}
		u, err := m.ConversationHandler.RespondPAM(PromptEchoOn, goPrompt)
		user = u

		if err != nil {
			var pamErr Error
			if errors.As(err, &pamErr) {
				return C.int(pamErr)
			}
			return C.int(ErrAbort)
		}
	}

	cUser := C.CString(user)
	m.allocatedData = append(m.allocatedData, unsafe.Pointer(cUser))

	*outUser = cUser
	return C.int(m.RetData.Status)
}

func (m *mockModuleTransaction) getData(key *C.char, outHandle *C.uintptr_t) C.int {
	goKey := C.GoString(key)
	if m.Expectations.DataKey != "" && goKey != m.Expectations.DataKey {
		m.T.Fatalf("data key mismatch: %#v vs %#v", goKey, m.Expectations.DataKey)
	}
	if handle, ok := m.moduleData[goKey]; ok {
		*outHandle = C.uintptr_t(handle)
	} else {
		*outHandle = 0
	}
	return C.int(m.RetData.Status)
}

func (m *mockModuleTransaction) setData(key *C.char, handle C.uintptr_t) C.int {
	goKey := C.GoString(key)
	if m.Expectations.DataKey != "" && goKey != m.Expectations.DataKey {
		m.T.Fatalf("data key mismatch: %#v vs %#v", goKey, m.Expectations.DataKey)
	}
	if oldHandle, ok := m.moduleData[goKey]; ok {
		_go_pam_data_cleanup(nil, C.uintptr_t(oldHandle), C.PAM_DATA_REPLACE)
	}
	if handle != 0 {
		m.moduleData[goKey] = uintptr(handle)
	}
	return C.int(m.RetData.Status)
}

type mockConversationHandler struct {
	User              string
	ExpectedMessage   string
	CheckEmptyMessage bool
	ExpectedStyle     Style
	CheckZeroStyle    bool
}

func (c mockConversationHandler) RespondPAM(s Style, msg string) (string, error) {
	if (c.ExpectedMessage != "" || c.CheckEmptyMessage) &&
		msg != c.ExpectedMessage {
		return "", fmt.Errorf("%w: unexpected prompt: %s vs %s",
			ErrConv, msg, c.ExpectedMessage)
	}

	if (c.ExpectedStyle != 0 || c.CheckZeroStyle) &&
		s != c.ExpectedStyle {
		return "", fmt.Errorf("%w: unexpected style: %#v vs %#v",
			ErrConv, s, c.ExpectedStyle)
	}

	switch s {
	case PromptEchoOn:
		return c.User, nil
	}

	return "", fmt.Errorf("%w: unhandled style: %v", ErrConv, s)
}
