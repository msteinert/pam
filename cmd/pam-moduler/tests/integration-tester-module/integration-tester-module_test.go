package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/msteinert/pam/v2"
	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

func (r *Request) check(res *Result, expectedResults []interface{}) error {
	switch res.Action {
	case "return":
	case "error":
		return fmt.Errorf("module error: %v", res.ActionArgs...)
	default:
		return fmt.Errorf("unexpected action %v", res.Action)
	}

	if !reflect.DeepEqual(res.ActionArgs, expectedResults) {
		return fmt.Errorf("unexpected return values %#v vs %#v",
			res.ActionArgs, expectedResults)
	}

	return nil
}

func (r *Request) checkRemote(listener *Listener, expectedResults []interface{}) error {
	res, err := listener.DoRequest(r)
	if err != nil {
		return err
	}

	return res.check(res, expectedResults)
}

type checkedRequest struct {
	r                    Request
	exp                  []interface{}
	compareWithTestState bool
}

func (cr *checkedRequest) checkRemote(listener *Listener) error {
	return cr.r.checkRemote(listener, cr.exp)
}

func (cr *checkedRequest) check(res *Result) error {
	return cr.r.check(res, cr.exp)
}

func ensureItem(tx *pam.Transaction, item pam.Item, expected string) error {
	if value, err := tx.GetItem(item); err != nil {
		return err
	} else if value != expected {
		return fmt.Errorf("invalid item %v value: %s vs %v", item, value, expected)
	}
	return nil
}

func ensureEnv(tx *pam.Transaction, variable string, expected string) error {
	if env := tx.GetEnv(variable); env != expected {
		return fmt.Errorf("unexpected env %s value: %s vs %s", variable, env, expected)
	}
	return nil
}

func Test_Moduler_IntegrationTesterModule(t *testing.T) {
	t.Parallel()
	if !pam.CheckPamHasStartConfdir() {
		t.Skip("this requires PAM with Conf dir support")
	}

	ts := utils.NewTestSetup(t, utils.WithWorkDir())
	modulePath := ts.GenerateModuleDefault(ts.GetCurrentFileDir())

	type testState = map[string]interface{}

	tests := map[string]struct {
		expectedError   error
		user            string
		credentials     pam.ConversationHandler
		checkedRequests []checkedRequest
		setup           func(*pam.Transaction, *Listener, testState) error
		finish          func(*pam.Transaction, *Listener, testState) error
	}{
		"success": {
			expectedError: nil,
		},
		"get-item-Service": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.Service),
				exp: []interface{}{"get-item-service", nil},
			}},
		},
		"get-item-User-empty": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.User),
				exp: []interface{}{"", nil},
			}},
		},
		"get-item-User-preset": {
			user: "test-user",
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.User),
				exp: []interface{}{"test-user", nil},
			}},
		},
		"get-item-Authtok-empty": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.Authtok),
				exp: []interface{}{"", nil},
			}},
		},
		"get-item-Oldauthtok-empty": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.Oldauthtok),
				exp: []interface{}{"", nil},
			}},
		},
		"get-item-UserPrompt-empty": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.UserPrompt),
				exp: []interface{}{"", nil},
			}},
		},
		"set-item-Service": {
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("SetItem", pam.Service, "foo-service"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetItem", pam.Service),
					exp: []interface{}{"foo-service", nil},
				},
			},
		},
		"set-item-User-empty": {
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("SetItem", pam.User, "an-user"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetItem", pam.User),
					exp: []interface{}{"an-user", nil},
				}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureItem(tx, pam.User, "an-user")
			},
		},
		"set-item-User-preset": {
			user: "test-user",
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("SetItem", pam.User, "an-user"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetItem", pam.User),
					exp: []interface{}{"an-user", nil},
				}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureItem(tx, pam.User, "an-user")
			},
		},
		"set-get-item-User-empty": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return tx.SetItem(pam.User, "setup-user")
			},
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.User),
				exp: []interface{}{"setup-user", nil},
			}},
		},
		"set-get-item-User-preset": {
			user: "test-user",
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return tx.SetItem(pam.User, "setup-user")
			},
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetItem", pam.User),
				exp: []interface{}{"setup-user", nil},
			}},
		},
		"get-env-unset": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetEnv", "_PAM_GO_HOPEFULLY_NOT_SET"),
				exp: []interface{}{""},
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_HOPEFULLY_NOT_SET", "")
			},
		},
		"get-env-preset": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return tx.PutEnv("_PAM_GO_ENV_SET_VAR=foobar")
			},
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
				exp: []interface{}{"foobar"},
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "foobar")
			},
		},
		"get-env-preset-empty": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				if err := tx.PutEnv("_PAM_GO_ENV_SET_VAR=value"); err != nil {
					return err
				}
				return tx.PutEnv("_PAM_GO_ENV_SET_VAR=")
			},
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
				exp: []interface{}{""},
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "")
			},
		},
		"get-env-preset-unset": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				if err := tx.PutEnv("_PAM_GO_ENV_SET_VAR=value"); err != nil {
					return err
				}
				return tx.PutEnv("_PAM_GO_ENV_SET_VAR")
			},
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
				exp: []interface{}{""},
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "")
			},
		},
		"put-env-not-preset": {
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR=a value"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{"a value"},
				},
			},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "a value")
			},
		},
		"put-env-preset": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return tx.PutEnv("_PAM_GO_ENV_SET_VAR=foobar")
			},
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR=another value"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{"another value"},
				},
			},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "another value")
			},
		},
		"put-env-resets-not-preset": {
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR=a value"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{"a value"},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR="),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{""},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{""},
				},
			},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "")
			},
		},
		"put-env-resets-preset": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return tx.PutEnv("_PAM_GO_ENV_SET_VAR=foobar")
			},
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR=a value"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{"a value"},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR="),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{""},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{""},
				},
			},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return ensureEnv(tx, "_PAM_GO_ENV_SET_VAR", "")
			},
		},
		"put-env-unsets-not-set": {
			expectedError: pam.ErrBadItem,
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR_NEVER_SET"),
					exp: []interface{}{pam.ErrBadItem},
				},
			},
		},
		"put-env-unsets-empty-value": {
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR="),
					exp: []interface{}{nil},
				},
				{
					r: NewRequest("GetEnvList"),
					exp: []interface{}{
						map[string]string{"_PAM_GO_ENV_SET_VAR": ""}, nil,
					},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("GetEnvList"),
					exp: []interface{}{map[string]string{}, nil},
				},
			},
		},
		"put-env-invalid-syntax": {
			expectedError: pam.ErrBadItem,
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "="),
					exp: []interface{}{pam.ErrBadItem},
				},
				{
					r:   NewRequest("PutEnv", "=bar"),
					exp: []interface{}{pam.ErrBadItem},
				},
				{
					r:   NewRequest("PutEnv", "with spaces"),
					exp: []interface{}{pam.ErrBadItem},
				},
			},
		},
		"get-env-list-empty": {
			checkedRequests: []checkedRequest{{
				r:   NewRequest("GetEnvList"),
				exp: []interface{}{map[string]string{}, nil},
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				return nil
			},
		},
		"get-env-list-preset": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				expected := map[string]string{
					"_PAM_GO_ENV_SET_VAR1":      "value1",
					"_PAM_GO_ENV_SET_VAR2":      "value due",
					"_PAM_GO_ENV_SET_VAR3":      "3",
					"_PAM_GO_ENV_SET_VAR_EMPTY": "",
					"_PAM_GO_ENV WITH SPACES":   "yes works",
				}

				for env, value := range expected {
					if err := tx.PutEnv(fmt.Sprintf("%s=%s", env, value)); err != nil {
						return err
					}
				}
				ts["expected"] = expected
				ts["expectedResults"] = [][]interface{}{{expected, nil}}
				return nil
			},
			checkedRequests: []checkedRequest{{
				r:                    NewRequest("GetEnvList"),
				compareWithTestState: true,
			}},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				if list, err := tx.GetEnvList(); err != nil {
					return err
				} else if !reflect.DeepEqual(list, ts["expected"]) {
					return fmt.Errorf("Unexpected return values %#v vs %#v",
						list, ts["expected"])
				}
				return nil
			},
		},
		"get-env-list-module-set": {
			setup: func(tx *pam.Transaction, l *Listener, ts testState) error {
				expected := map[string]string{
					"_PAM_GO_ENV_SET_VAR1":      "value1",
					"_PAM_GO_ENV_SET_VAR2":      "value due",
					"_PAM_GO_ENV_SET_VAR3":      "3",
					"_PAM_GO_ENV_SET_VAR_EMPTY": "",
					"_PAM_GO_ENV WITH SPACES":   "yes works",
				}

				ts["expected"] = expected
				ts["expectedResults"] = [][]interface{}{
					nil, nil, nil, nil, nil, nil, nil, {expected, nil},
				}
				return nil
			},
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR1=value1"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR2=value due"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR3=3"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR_EMPTY="),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR_TO_UNSET=unset"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV_SET_VAR_TO_UNSET"),
					exp: []interface{}{nil},
				},
				{
					r:   NewRequest("PutEnv", "_PAM_GO_ENV WITH SPACES=yes works"),
					exp: []interface{}{nil},
				},
				{
					r:                    NewRequest("GetEnvList"),
					compareWithTestState: true,
				},
			},
			finish: func(tx *pam.Transaction, l *Listener, ts testState) error {
				if list, err := tx.GetEnvList(); err != nil {
					return err
				} else if !reflect.DeepEqual(list, ts["expected"]) {
					return fmt.Errorf("unexpected return values %#v vs %#v",
						list, ts["expected"])
				}
				return nil
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			socketPath := filepath.Join(ts.WorkDir(), name+".socket")
			ts.CreateService(name, []utils.ServiceLine{
				{Action: utils.Auth, Control: utils.Requisite, Module: modulePath,
					Args: []string{socketPath}},
			})

			tx, err := pam.StartConfDir(name, tc.user, tc.credentials, ts.WorkDir())
			if err != nil {
				t.Fatalf("start #error: %v", err)
			}
			defer func() {
				err := tx.End()
				if err != nil {
					t.Fatalf("end #error: %v", err)
				}
			}()

			listener := NewListener(socketPath)
			if err := listener.StartListening(); err != nil {
				t.Fatalf("listening #error: %v", err)
			}

			listenerHandler := func() error {
				res, err := listener.WaitForData()
				if err != nil {
					return err
				}

				if res == nil || res.Action != "hello" {
					return errors.New("missing hello packet")
				}

				req := NewRequest("GetItem", pam.Service)
				if err := req.checkRemote(listener,
					[]interface{}{strings.ToLower(name), nil}); err != nil {
					return err
				}

				testState := testState{}
				if tc.setup != nil {
					if err := tc.setup(tx, listener, testState); err != nil {
						return err
					}
				}

				for i, req := range tc.checkedRequests {
					if req.compareWithTestState {
						expectedResults, _ := testState["expectedResults"].([][]interface{})
						if err := req.r.checkRemote(listener, expectedResults[i]); err != nil {
							return err
						}
					} else if err := req.checkRemote(listener); err != nil {
						return err
					}
				}

				if tc.finish != nil {
					if err := tc.finish(tx, listener, testState); err != nil {
						return err
					}
				}

				if err := listener.SendRequest(&Request{Action: "bye"}); err != nil {
					return err
				}

				return nil
			}

			serverError := make(chan error)
			go func() {
				serverError <- listenerHandler()
			}()

			authResult := make(chan error)
			go func() {
				authResult <- tx.Authenticate(pam.Silent)
			}()

			if err = <-serverError; err != nil {
				t.Fatalf("communication #error: %v", err)
			}

			err = <-authResult
			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("authenticate #unexpected: %#v vs %#v",
					err, tc.expectedError)
			}
		})
	}

	t.Cleanup(func() {
		// Ensure GC will happen, so that transaction's pam_end will be called
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
	})
}

func Test_Moduler_IntegrationTesterModule_handleRequest(t *testing.T) {
	t.Parallel()

	module := integrationTesterModule{}
	mt := pam.NewModuleTransactionInvoker(nil)

	tests := []struct {
		checkedRequest
		name     string
		parallel bool
	}{
		{
			name: "putEnv",
			checkedRequest: checkedRequest{
				r:   NewRequest("PutEnv", "FOO_ENV=Bar"),
				exp: []interface{}{pam.ErrAbort},
			},
		},
		{
			parallel: true,
			name:     "get-item-Service",
			checkedRequest: checkedRequest{
				r:   NewRequest("GetItem", pam.Service),
				exp: []interface{}{"", pam.ErrSystem},
			},
		},
		{
			parallel: true,
			name:     "set-item-Service",
			checkedRequest: checkedRequest{
				r:   NewRequest("SetItem", pam.Service, "foo"),
				exp: []interface{}{pam.ErrSystem},
			},
		},
	}

	for _, cr := range tests {
		cr := cr
		t.Run(cr.name, func(t *testing.T) {
			if cr.parallel {
				t.Parallel()
			}

			authRequest := authRequest{mt, nil}
			res, err := module.handleRequest(&authRequest, &cr.r)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			if res.Action != "return" {
				t.Fatalf("unexpected result action %v", res.Action)
			}

			if err := cr.check(res); err != nil {
				t.Fatalf("unexpected result %v", err)
			}
		})
	}

	t.Run("missing-method", func(t *testing.T) {
		t.Parallel()
		req := NewRequest("Hopefully a missing method")
		res, err := module.handleRequest(&authRequest{mt, nil}, &req)

		if err == nil {
			t.Fatalf("error was expected, got %v", res)
		}
		if res != nil {
			t.Fatalf("unexpected result %v", res)
		}
	})

	t.Run("wrong-signature", func(t *testing.T) {
		t.Parallel()
		req := NewRequest("GetItem", "this", "and", 3, "of that")
		res, err := module.handleRequest(&authRequest{mt, nil}, &req)

		if err == nil {
			t.Fatalf("error was expected, got %v", res)
		}
		if res != nil {
			t.Fatalf("unexpected result %v", res)
		}
	})
}

func Test_Moduler_IntegrationTesterModule_Authenticate(t *testing.T) {
	t.Parallel()

	ts := utils.NewTestSetup(t, utils.WithWorkDir())
	module := integrationTesterModule{}

	tests := map[string]struct {
		expectedError   error
		credentials     pam.ConversationHandler
		checkedRequests []checkedRequest
	}{
		"success": {
			expectedError: nil,
		},
		"get-item-Service": {
			expectedError: pam.ErrSystem,
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("GetItem", pam.Service),
					exp: []interface{}{"", pam.ErrSystem},
				},
			},
		},
		"get-item-User": {
			expectedError: pam.ErrSystem,
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("GetItem", pam.User),
					exp: []interface{}{"", pam.ErrSystem},
				},
			},
		},
		"putEnv": {
			expectedError: pam.ErrAbort,
			checkedRequests: []checkedRequest{
				{
					r:   NewRequest("PutEnv", "FooBar=Baz"),
					exp: []interface{}{pam.ErrAbort},
				},
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			socketPath := filepath.Join(ts.WorkDir(), name+".socket")
			listener := NewListener(socketPath)
			if err := listener.StartListening(); err != nil {
				t.Fatalf("listening #error: %v", err)
			}

			listenerHandler := func() error {
				res, err := listener.WaitForData()
				if err != nil {
					return err
				}

				if res == nil || res.Action != "hello" {
					return errors.New("missing hello packet")
				}

				for _, req := range tc.checkedRequests {
					if err := req.checkRemote(listener); err != nil {
						return err
					}
				}

				if err := listener.SendRequest(&Request{Action: "bye"}); err != nil {
					return err
				}

				return nil
			}

			serverError := make(chan error)
			go func() {
				serverError <- listenerHandler()
			}()

			authResult := make(chan error)
			go func() {
				authResult <- module.Authenticate(
					pam.NewModuleTransactionInvoker(nil),
					pam.Silent, []string{socketPath})
			}()

			if err := <-serverError; err != nil {
				t.Fatalf("communication #error: %v", err)
			}

			err := <-authResult
			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("authenticate #unexpected: %#v vs %#v",
					err, tc.expectedError)
			}
		})
	}
}
