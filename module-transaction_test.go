// Package pam provides a wrapper for the PAM application API.
package pam

import (
	"errors"
	"reflect"
	"testing"
)

func Test_NewNullModuleTransaction(t *testing.T) {
	t.Parallel()
	mt := moduleTransaction{}

	if mt.handle != nil {
		t.Fatalf("unexpected handle value: %v", mt.handle)
	}

	if s := Error(mt.lastStatus.Load()); s != success {
		t.Fatalf("unexpected status: %v", s)
	}

	tests := map[string]struct {
		testFunc      func(t *testing.T) (any, error)
		expectedError error
		ignoreError   bool
	}{
		"GetItem": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.GetItem(Service)
			},
		},
		"SetItem": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return nil, mt.SetItem(Service, "foo")
			},
		},
		"GetEnv": {
			ignoreError: true,
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.GetEnv("foo"), nil
			},
		},
		"PutEnv": {
			expectedError: ErrAbort,
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return nil, mt.PutEnv("foo=bar")
			},
		},
		"GetEnvList": {
			expectedError: ErrBuf,
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				list, err := mt.GetEnvList()
				if len(list) > 0 {
					t.Fatalf("unexpected list: %v", list)
				}
				return nil, err
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name+"-error-check", func(t *testing.T) {
			t.Parallel()
			data, err := tc.testFunc(t)

			switch d := data.(type) {
			case string:
				if d != "" {
					t.Fatalf("empty value was expected, got %s", d)
				}
			case interface{}:
				if !reflect.ValueOf(d).IsNil() {
					t.Fatalf("nil value was expected, got %v", d)
				}
			default:
				if d != nil {
					t.Fatalf("nil value was expected, got %v", d)
				}
			}

			if tc.ignoreError {
				return
			}
			if err == nil {
				t.Fatal("error was expected, but got none")
			}

			var expectedError error = ErrSystem
			if tc.expectedError != nil {
				expectedError = tc.expectedError
			}

			if !errors.Is(err, expectedError) {
				t.Fatalf("status %v was expected, but got %v",
					expectedError, err)
			}
		})
	}

	for name, tc := range tests {
		// These can't be parallel - we test a private value that is not thread safe
		t.Run(name+"-lastStatus-check", func(t *testing.T) {
			mt.lastStatus.Store(99999)
			_, err := tc.testFunc(t)
			status := Error(mt.lastStatus.Load())

			if tc.ignoreError {
				return
			}
			if err == nil {
				t.Fatal("error was expected, but got none")
			}

			expectedStatus := ErrSystem
			if tc.expectedError != nil {
				errors.As(err, &expectedStatus)
			}

			if status != expectedStatus {
				t.Fatalf("status %v was expected, but got %d",
					expectedStatus, status)
			}
		})
	}
}
