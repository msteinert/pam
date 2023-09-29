package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

func ensureNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func ensureError(t *testing.T, err error, expected error) {
	t.Helper()
	if err == nil {
		t.Fatalf("error was expected, got none")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("error %v was expected, got %v", err, expected)
	}
}

func ensureEqual(t *testing.T, a any, b any) {
	t.Helper()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("values mismatch %v vs %v", a, b)
	}
}

func Test_Communication(t *testing.T) {
	t.Parallel()

	ts := utils.NewTestSetup(t, utils.WithWorkDir())

	for _, name := range []string{"test-1", "test-2"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			socketPath := filepath.Join(ts.WorkDir(), name+".socket")

			listener := NewListener(socketPath)
			connector := NewConnector(socketPath)

			ensureNoError(t, listener.StartListening())
			ensureNoError(t, connector.Connect())

			ensureError(t, listener.StartListening(), ErrAlreadyListening)
			ensureError(t, connector.Connect(), ErrAlreadyConnected)

			resChan, errChan := make(chan *Result), make(chan error)
			go func() {
				res, err := listener.WaitForData()
				resChan <- res
				errChan <- err
			}()

			req := NewRequest("A Request")
			ensureNoError(t, connector.SendRequest(&req))

			res, err := <-resChan, <-errChan
			ensureNoError(t, err)
			ensureEqual(t, *res, req)

			go func() {
				res := NewRequest("Listener result")
				ensureNoError(t, listener.SendResult(&res))
			}()

			res, err = connector.WaitForData()
			ensureNoError(t, err)
			ensureEqual(t, *res, NewRequest("Listener result"))

			go func() {
				req, err := listener.WaitForData()
				res := NewRequest("Response", *req)

				defer func() {
					resChan <- &res
					errChan <- err
				}()
				ensureNoError(t, listener.SendResult(&res))
			}()

			done := make(chan bool)
			req = NewRequest("Requesting...")
			go func() {
				defer func() {
					done <- true
				}()
				res, err := connector.DoRequest(&req)
				ensureNoError(t, err)
				ensureEqual(t, *res, NewRequest("Response", req))
			}()

			res, err = <-resChan, <-errChan
			ensureNoError(t, err)
			ensureEqual(t, *res, NewRequest("Response", req))
			<-done
		})
	}
}
