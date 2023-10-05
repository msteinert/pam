//go:generate go run github.com/msteinert/pam/v2/cmd/pam-moduler -type integrationTesterModule
//go:generate go generate --skip="pam_module.go"

// Package main is the package for the integration tester module PAM shared library.
package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/msteinert/pam/v2"
	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

type integrationTesterModule struct {
	utils.BaseModule
}

type authRequest struct {
	mt        pam.ModuleTransaction
	lastError error
}

func (m *integrationTesterModule) handleRequest(authReq *authRequest, r *Request) (res *Result, err error) {
	switch r.Action {
	case "bye":
		return nil, authReq.lastError
	}

	defer func() {
		if p := recover(); p != nil {
			if s, ok := p.(string); ok {
				if strings.HasPrefix(s, "reflect:") {
					res = nil
					err = &utils.SerializableError{Msg: fmt.Sprintf(
						"error on request %v: %v", *r, p)}
					authReq.lastError = err
					return
				}
			}
			panic(p)
		}

		if err != nil {
			authReq.lastError = err
		}
	}()

	method := reflect.ValueOf(authReq.mt).MethodByName(r.Action)
	if method == (reflect.Value{}) {
		return nil, &utils.SerializableError{Msg: fmt.Sprintf(
			"no method %s found", r.Action)}
	}

	var args []reflect.Value
	for i, arg := range r.ActionArgs {
		switch v := arg.(type) {
		case SerializableStringConvRequest:
			args = append(args, reflect.ValueOf(
				pam.NewStringConvRequest(v.Style, v.Request)))
		case SerializableBinaryConvRequest:
			args = append(args, reflect.ValueOf(
				pam.NewBinaryConvRequestFromBytes(v.Request)))
		default:
			if arg == nil {
				args = append(args, reflect.Zero(method.Type().In(i)))
			} else {
				args = append(args, reflect.ValueOf(arg))
			}
		}
	}

	res = &Result{Action: "return"}
	for _, ret := range method.Call(args) {
		iface := ret.Interface()
		switch value := iface.(type) {
		case pam.StringConvResponse:
			res.ActionArgs = append(res.ActionArgs,
				SerializableStringConvResponse{value.Style(), value.Response()})
		case pam.BinaryConvResponse:
			data, err := value.Decode(utils.TestBinaryDataDecoder)
			if err != nil {
				return nil, err
			}
			res.ActionArgs = append(res.ActionArgs, SerializableBinaryConvResponse{data})
		case pam.Error:
			authReq.lastError = value
			res.ActionArgs = append(res.ActionArgs, value)
		case error:
			var pamError pam.Error
			if errors.As(value, &pamError) {
				retErr := &SerializablePamError{Msg: value.Error(),
					RetStatus: pamError}
				authReq.lastError = retErr
				res.ActionArgs = append(res.ActionArgs, retErr)
				return res, err
			}
			authReq.lastError = value
			res.ActionArgs = append(res.ActionArgs,
				&utils.SerializableError{Msg: value.Error()})
		default:
			res.ActionArgs = append(res.ActionArgs, iface)
		}
	}
	return res, err
}

func (m *integrationTesterModule) handleError(err error) *Result {
	return &Result{
		Action:     "error",
		ActionArgs: []interface{}{&utils.SerializableError{Msg: err.Error()}},
	}
}

func (m *integrationTesterModule) Authenticate(mt pam.ModuleTransaction, _ pam.Flags, args []string) error {
	if len(args) != 1 {
		return errors.New("Invalid arguments")
	}

	authRequest := authRequest{mt, nil}
	connection := NewConnector(args[0])
	if err := connection.Connect(); err != nil {
		return err
	}

	connectionHandler := func() error {
		if err := connection.SendRequest(&Request{Action: "hello"}); err != nil {
			return err
		}

		for {
			req, err := connection.WaitForData()
			if err != nil {
				return err
			}

			res, err := m.handleRequest(&authRequest, req)
			if err != nil {
				_ = connection.SendResult(m.handleError(err))
				return err
			}
			if res == nil {
				return nil
			}
			if err := connection.SendResult(res); err != nil {
				_ = connection.SendResult(m.handleError(err))
				return err
			}
		}
	}

	if err := connectionHandler(); err != nil {
		return err
	}

	return nil
}
