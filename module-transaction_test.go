// Package pam provides a wrapper for the PAM application API.
package pam

import (
	"errors"
	"reflect"
	"strings"
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

func Test_ModuleTransaction_InvokeHandler(t *testing.T) {
	t.Parallel()
	mt := &moduleTransaction{}

	err := mt.InvokeHandler(nil, 0, nil)
	if !errors.Is(err, ErrIgnore) {
		t.Fatalf("unexpected err: %v", err)
	}

	tests := map[string]struct {
		flags            Flags
		args             []string
		returnedError    error
		expectedError    error
		expectedErrorMsg string
	}{
		"success": {
			expectedError: nil,
		},
		"success-with-flags": {
			expectedError: nil,
			flags:         Silent | RefreshCred,
		},
		"success-with-args": {
			expectedError: nil,
			args:          []string{"foo", "bar"},
		},
		"success-with-args-and-flags": {
			expectedError: nil,
			flags:         Silent | RefreshCred,
			args:          []string{"foo", "bar"},
		},
		"ignore": {
			expectedError: ErrIgnore,
			returnedError: ErrIgnore,
		},
		"ignore-with-args-and-flags": {
			expectedError: ErrIgnore,
			returnedError: ErrIgnore,
			args:          []string{"foo", "bar"},
		},
		"generic-error": {
			expectedError:    ErrSystem,
			returnedError:    errors.New("this is a generic go error"),
			expectedErrorMsg: "this is a generic go error",
		},
		"transaction-error-service-error": {
			expectedError:    ErrService,
			returnedError:    errors.Join(ErrService, errors.New("ErrService")),
			expectedErrorMsg: ErrService.Error(),
		},
		"return-type-as-error-success": {
			expectedError: nil,
			returnedError: Error(0),
		},
		"return-type-as-error": {
			expectedError:    ErrNoModuleData,
			returnedError:    ErrNoModuleData,
			expectedErrorMsg: ErrNoModuleData.Error(),
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := mt.InvokeHandler(func(handlerMt ModuleTransaction,
				handlerFlags Flags, handlerArgs []string) error {
				if handlerMt != mt {
					t.Fatalf("unexpected mt: %#v vs %#v", mt, handlerMt)
				}
				if handlerFlags != tc.flags {
					t.Fatalf("unexpected mt: %#v vs %#v", tc.flags, handlerFlags)
				}
				if strings.Join(handlerArgs, "") != strings.Join(tc.args, "") {
					t.Fatalf("unexpected mt: %#v vs %#v", tc.args, handlerArgs)
				}

				return tc.returnedError
			}, tc.flags, tc.args)

			status := Error(mt.lastStatus.Load())

			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("unexpected err: %#v vs %#v", err, tc.expectedError)
			}

			var expectedStatus Error
			if err != nil {
				var pamErr Error
				if errors.As(err, &pamErr) {
					expectedStatus = pamErr
				} else {
					expectedStatus = ErrSystem
				}
			}

			if status != expectedStatus {
				t.Fatalf("unexpected status: %#v vs %#v", status, expectedStatus)
			}
		})
	}
}
