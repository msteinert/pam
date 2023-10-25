// Package pam provides a wrapper for the PAM application API.
package pam

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type customConvRequest int

func (r customConvRequest) Style() Style {
	return Style(r)
}

func ensureNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func Test_NewNullModuleTransaction(t *testing.T) {
	t.Parallel()
	t.Cleanup(maybeDoLeakCheck)
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
		"GetUser": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.GetUser("prompt")
			},
		},
		"GetData": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.GetData("some-data")
			},
		},
		"SetData": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return nil, mt.SetData("foo", []interface{}{})
			},
		},
		"SetData-nil": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return nil, mt.SetData("foo", nil)
			},
		},
		"StartConv-StringConv": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.StartConv(NewStringConvRequest(TextInfo, "a prompt"))
			},
		},
		"StartStringConv": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.StartStringConv(TextInfo, "a prompt")
			},
		},
		"StartStringConvf": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.StartStringConvf(TextInfo, "a prompt %s", "with info")
			},
		},
		"StartConvMulti": {
			testFunc: func(t *testing.T) (any, error) {
				t.Helper()
				return mt.StartConvMulti([]ConvRequest{
					NewStringConvRequest(TextInfo, "a prompt"),
					NewStringConvRequest(ErrorMsg, "another prompt"),
					NewBinaryConvRequest(BinaryPointer(&mt), nil),
					NewBinaryConvRequestFromBytes([]byte("These are bytes!")),
					NewBinaryConvRequestFromBytes([]byte{}),
					NewBinaryConvRequestFromBytes(nil),
					NewBinaryConvRequest(nil, nil),
				})
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name+"-error-check", func(t *testing.T) {
			t.Parallel()
			t.Cleanup(maybeDoLeakCheck)
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
	t.Cleanup(maybeDoLeakCheck)
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

func testMockModuleTransaction(t *testing.T, mt *moduleTransaction) {
	t.Helper()
	t.Parallel()
	t.Cleanup(maybeDoLeakCheck)

	tests := map[string]struct {
		testFunc            func(mock *mockModuleTransaction) (any, error)
		mockExpectations    mockModuleTransactionExpectations
		mockRetData         mockModuleTransactionReturnedData
		conversationHandler ConversationHandler

		expectedError error
		expectedValue any
		ignoreError   bool
	}{
		"GetUser-empty": {
			mockExpectations: mockModuleTransactionExpectations{
				UserPrompt: "who are you?"},
			expectedValue: "",
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getUserImpl(mock, "who are you?")
			},
		},
		"GetUser-preset-value": {
			mockExpectations: mockModuleTransactionExpectations{
				UserPrompt: "who are you?"},
			mockRetData:   mockModuleTransactionReturnedData{User: "dummy-user"},
			expectedValue: "dummy-user",
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getUserImpl(mock, "who are you?")
			},
		},
		"GetUser-conversation-value": {
			mockExpectations: mockModuleTransactionExpectations{
				UserPrompt: "who are you?"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOn,
				ExpectedMessage: "who are you?",
				User:            "returned-dummy-user",
			},
			expectedValue: "returned-dummy-user",
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getUserImpl(mock, "who are you?")
			},
		},
		"GetUser-conversation-error-prompt": {
			expectedError: ErrConv,
			mockExpectations: mockModuleTransactionExpectations{
				UserPrompt: "who are you?"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOn,
				ExpectedMessage: "who are you???",
			},
			expectedValue: "",
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getUserImpl(mock, "who are you?")
			},
		},
		"GetUser-conversation-error-style": {
			expectedError: ErrConv,
			mockExpectations: mockModuleTransactionExpectations{
				UserPrompt: "who are you?"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOff,
				ExpectedMessage: "who are you?",
			},
			expectedValue: "",
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getUserImpl(mock, "who are you?")
			},
		},
		"GetData-not-available": {
			expectedError: ErrNoModuleData,
			mockExpectations: mockModuleTransactionExpectations{
				DataKey: "not-available-data"},
			expectedValue: nil,
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getDataImpl(mock, "not-available-data")
			},
		},
		"GetData-not-available-other-failure": {
			expectedError: ErrBuf,
			mockExpectations: mockModuleTransactionExpectations{
				DataKey: "not-available-data"},
			mockRetData:   mockModuleTransactionReturnedData{Status: ErrBuf},
			expectedValue: nil,
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.getDataImpl(mock, "not-available-data")
			},
		},
		"SetData-empty-nil": {
			expectedError: ErrNoModuleData,
			expectedValue: nil,
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				ensureNoError(mock.T, mt.setDataImpl(mock, "", nil))
				return mt.getDataImpl(mock, "")
			},
		},
		"SetData-empty-to-value": {
			expectedValue: []string{"hello", "world"},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				ensureNoError(mock.T, mt.setDataImpl(mock, "",
					[]string{"hello", "world"}))
				return mt.getDataImpl(mock, "")
			},
		},
		"SetData-to-value": {
			expectedValue: []interface{}{"a string", true, 0.55, errors.New("oh no")},
			mockExpectations: mockModuleTransactionExpectations{
				DataKey: "some-data"},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				ensureNoError(mock.T, mt.setDataImpl(mock, "some-data",
					[]interface{}{"a string", true, 0.55, errors.New("oh no")}))
				return mt.getDataImpl(mock, "some-data")
			},
		},
		"SetData-to-value-replacing": {
			expectedValue: "just a value",
			mockExpectations: mockModuleTransactionExpectations{
				DataKey: "replaced-data"},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				ensureNoError(mock.T, mt.setDataImpl(mock, "replaced-data",
					[]interface{}{"a string", true, 0.55, errors.New("oh no")}))
				ensureNoError(mock.T, mt.setDataImpl(mock, "replaced-data",
					"just a value"))
				return mt.getDataImpl(mock, "replaced-data")
			},
		},
		"StartConv-no-conv-set": {
			expectedError: ErrConv,
			expectedValue: nil,
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					TextInfo,
					"hello PAM!",
				})
			},
		},
		"StartConv-text-info": {
			expectedValue: stringConvResponse{TextInfo, "nice to see you, Go!"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   TextInfo,
				ExpectedMessage: "hello PAM!",
				TextInfo:        "nice to see you, Go!",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					TextInfo,
					"hello PAM!",
				})
			},
		},
		"StartConv-error-msg": {
			expectedValue: stringConvResponse{ErrorMsg, "ops, sorry..."},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   ErrorMsg,
				ExpectedMessage: "This is wrong, PAM!",
				ErrorMsg:        "ops, sorry...",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					ErrorMsg,
					"This is wrong, PAM!",
				})
			},
		},
		"StartConv-prompt-echo-on": {
			expectedValue: stringConvResponse{PromptEchoOn, "here's my public data"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOn,
				ExpectedMessage: "Give me your non-private infos",
				PromptEchoOn:    "here's my public data",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					PromptEchoOn,
					"Give me your non-private infos",
				})
			},
		},
		"StartConv-prompt-echo-off": {
			expectedValue: stringConvResponse{PromptEchoOff, "here's my private data"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOff,
				ExpectedMessage: "Give me your private secrets",
				PromptEchoOff:   "here's my private data",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					PromptEchoOff,
					"Give me your private secrets",
				})
			},
		},
		"StartConv-unknown-style": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   Style(9999),
				ExpectedMessage: "hello PAM!",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					Style(9999),
					"hello PAM!",
				})
			},
		},
		"StartConv-unknown-style-response": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:      Style(9999),
				ExpectedMessage:    "hello PAM!",
				IgnoreUnknownStyle: true,
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, StringConvRequest{
					Style(9999),
					"hello PAM!",
				})
			},
		},
		"StartStringConv-text-info": {
			expectedValue: stringConvResponse{TextInfo, "nice to see you, Go!"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   TextInfo,
				ExpectedMessage: "hello PAM!",
				TextInfo:        "nice to see you, Go!",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startStringConvImpl(mock, TextInfo,
					"hello PAM!")
			},
		},
		"StartStringConv-error-msg": {
			expectedValue: stringConvResponse{ErrorMsg, "ops, sorry..."},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   ErrorMsg,
				ExpectedMessage: "This is wrong, PAM!",
				ErrorMsg:        "ops, sorry...",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startStringConvImpl(mock, ErrorMsg,
					"This is wrong, PAM!")
			},
		},
		"StartStringConv-prompt-echo-on": {
			expectedValue: stringConvResponse{PromptEchoOn, "here's my public data"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOn,
				ExpectedMessage: "Give me your non-private infos",
				PromptEchoOn:    "here's my public data",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startStringConvImpl(mock, PromptEchoOn,
					"Give me your non-private infos")
			},
		},
		"StartStringConv-prompt-echo-off": {
			expectedValue: stringConvResponse{PromptEchoOff, "here's my private data"},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   PromptEchoOff,
				ExpectedMessage: "Give me your private secrets",
				PromptEchoOff:   "here's my private data",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startStringConvImpl(mock, PromptEchoOff,
					"Give me your private secrets")
			},
		},
		"StartStringConv-binary": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:   BinaryPrompt,
				ExpectedMessage: "require binary data",
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startStringConvImpl(mock, PromptEchoOff,
					"require binary data")
			},
		},
		"StartConvMulti-missing": {
			expectedError:       ErrConv,
			expectedValue:       ([]ConvResponse)(nil),
			conversationHandler: mockConversationHandler{},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvMultiImpl(mock, nil)
			},
		},
		"StartConvMulti-too-many": {
			expectedError:       ErrConv,
			expectedValue:       ([]ConvResponse)(nil),
			conversationHandler: mockConversationHandler{},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				reqs := [maxNumMsg + 1]ConvRequest{}
				return mt.startConvMultiImpl(mock, reqs[:])
			},
		},
		"StartConvMulti-unexpected-style": {
			expectedError:       ErrConv,
			expectedValue:       ([]ConvResponse)(nil),
			conversationHandler: mockConversationHandler{},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				var req ConvRequest = customConvRequest(0xdeadbeef)
				return mt.startConvMultiImpl(mock, []ConvRequest{req})
			},
		},
		"StartConvMulti-string-as-binary": {
			expectedError:       ErrConv,
			expectedValue:       ([]ConvResponse)(nil),
			conversationHandler: mockConversationHandler{},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvMultiImpl(mock, []ConvRequest{
					NewStringConvRequest(BinaryPrompt, "no binary!"),
				})
			},
		},
		"StartConvMulti-all-types": {
			expectedValue: []any{
				[]ConvResponse{
					stringConvResponse{TextInfo, "nice to see you, Go!"},
					stringConvResponse{ErrorMsg, "ops, sorry..."},
					stringConvResponse{PromptEchoOn, "here's my public data"},
					stringConvResponse{PromptEchoOff, "here's my private data"},
				},
				[][]byte{
					{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
				},
			},
			conversationHandler: mockConversationHandler{
				TextInfo:      "nice to see you, Go!",
				ErrorMsg:      "ops, sorry...",
				PromptEchoOn:  "here's my public data",
				PromptEchoOff: "here's my private data",
				Binary:        []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
				ExpectedMessagesByStyle: map[Style]string{
					TextInfo:      "hello PAM!",
					ErrorMsg:      "This is wrong, PAM!",
					PromptEchoOn:  "Give me your non-private infos",
					PromptEchoOff: "Give me your private secrets",
				},
				ExpectedBinary: []byte("\x00This is a binary data request\xC5\x00\xffYes it is!"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				requests := []ConvRequest{
					NewStringConvRequest(TextInfo, "hello PAM!"),
					NewStringConvRequest(ErrorMsg, "This is wrong, PAM!"),
					NewStringConvRequest(PromptEchoOn, "Give me your non-private infos"),
					NewStringConvRequest(PromptEchoOff, "Give me your private secrets"),
					NewBinaryConvRequestFromBytes(
						testBinaryDataEncoder([]byte("\x00This is a binary data request\xC5\x00\xffYes it is!"))),
				}

				data, err := mt.startConvMultiImpl(mock, requests)
				if err != nil {
					return data, err
				}

				stringResponses := []ConvResponse{}
				binaryResponses := [][]byte{}
				for i, r := range data {
					if r.Style() != requests[i].Style() {
						mock.T.Fatalf("unexpected style %#v vs %#v",
							r.Style(), requests[i].Style())
					}

					switch rt := r.(type) {
					case BinaryConvResponse:
						decoded, err := rt.Decode(testBinaryDataDecoder)
						if err != nil {
							return data, err
						}
						binaryResponses = append(binaryResponses, decoded)
					case StringConvResponse:
						stringResponses = append(stringResponses, r)
					default:
						mock.T.Fatalf("unexpected value %v", rt)
					}
				}
				return []any{
					stringResponses,
					binaryResponses,
				}, err
			},
		},
		"StartConvMulti-all-types-some-failing": {
			expectedError: ErrConv,
			expectedValue: []ConvResponse(nil),
			conversationHandler: mockConversationHandler{
				TextInfo:      "nice to see you, Go!",
				ErrorMsg:      "ops, sorry...",
				PromptEchoOn:  "here's my public data",
				PromptEchoOff: "here's my private data",
				Binary:        []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
				ExpectedMessagesByStyle: map[Style]string{
					TextInfo:      "hello PAM!",
					ErrorMsg:      "This is wrong, PAM!",
					PromptEchoOn:  "Give me your non-private infos",
					PromptEchoOff: "Give me your private secrets",
					Style(0xfaaf): "This will fail",
				},
				ExpectedBinary:     []byte("\x00This is a binary data request\xC5\x00\xffYes it is!"),
				IgnoreUnknownStyle: true,
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				requests := []ConvRequest{
					NewStringConvRequest(TextInfo, "hello PAM!"),
					NewStringConvRequest(ErrorMsg, "This is wrong, PAM!"),
					NewStringConvRequest(PromptEchoOn, "Give me your non-private infos"),
					NewStringConvRequest(PromptEchoOff, "Give me your private secrets"),
					NewStringConvRequest(Style(0xfaaf), "This will fail"),
					NewBinaryConvRequestFromBytes(
						testBinaryDataEncoder([]byte("\x00This is a binary data request\xC5\x00\xffYes it is!"))),
				}

				return mt.startConvMultiImpl(mock, requests)
			},
		},
		"StartConv-Binary-unsupported": {
			expectedValue: nil,
			expectedError: ErrConv,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This is a binary data request\xC5\x00\xffYes it is!"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				mock.binaryProtocol = false
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				return mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
			},
		},
		"StartConv-Binary": {
			expectedValue: []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This is a binary data request\xC5\x00\xffYes it is!"),
				Binary:         []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				data, err := mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
				if err != nil {
					return data, err
				}
				bcr, _ := data.(BinaryConvResponse)
				return bcr.Decode(testBinaryDataDecoder)
			},
		},
		"StartConv-Binary-expected-data-mismatch": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This is not the expected data!"),
				Binary:         []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				return mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
			},
		},
		"StartConv-Binary-unexpected-nil": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This should not be nil"),
				Binary:         []byte("\x1ASome binary Dat\xaa"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(nil))
			},
		},
		"StartConv-Binary-expected-nil": {
			expectedValue: []byte("\x1ASome binary Dat\xaa"),
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedNil:    true,
				ExpectedBinary: []byte("\x00This should not be nil"),
				Binary:         []byte("\x1ASome binary Dat\xaa"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				data, err := mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(nil))
				if err != nil {
					return data, err
				}
				bcr, _ := data.(BinaryConvResponse)
				return bcr.Decode(testBinaryDataDecoder)
			},
		},
		"StartConv-Binary-returns-nil": {
			expectedValue: BinaryPointer(nil),
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x1ASome binary Dat\xaa"),
				Binary:         nil,
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte("\x1ASome binary Dat\xaa"))
				data, err := mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
				if err != nil {
					return data, err
				}
				bcr, _ := data.(BinaryConvResponse)
				return bcr.Data(), err
			},
		},
		"StartBinaryConv": {
			expectedValue: []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This is a binary data request\xC5\x00\xffYes it is!"),
				Binary:         []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				data, err := mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
				if err != nil {
					return data, err
				}
				bcr, _ := data.(BinaryConvResponse)
				return bcr.Decode(testBinaryDataDecoder)
			},
		},
		"StartBinaryConv-expected-data-mismatch": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This is not the expected data!"),
				Binary:         []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				return mt.startBinaryConvImpl(mock, bytes)
			},
		},
		"StartBinaryConv-unexpected-nil": {
			expectedError: ErrConv,
			expectedValue: nil,
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x00This should not be nil"),
				Binary:         []byte("\x1ASome binary Dat\xaa"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startBinaryConvImpl(mock, nil)
			},
		},
		"StartBinaryConv-expected-nil": {
			expectedValue: []byte("\x1ASome binary Dat\xaa"),
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedNil:    true,
				ExpectedBinary: []byte("\x00This should not be nil"),
				Binary:         []byte("\x1ASome binary Dat\xaa"),
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				data, err := mt.startBinaryConvImpl(mock, nil)
				if err != nil {
					return data, err
				}
				return data.Decode(testBinaryDataDecoder)
			},
		},
		"StartBinaryConv-returns-nil": {
			expectedValue: BinaryPointer(nil),
			conversationHandler: mockConversationHandler{
				ExpectedStyle:  BinaryPrompt,
				ExpectedBinary: []byte("\x1ASome binary Dat\xaa"),
				Binary:         nil,
			},
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte("\x1ASome binary Dat\xaa"))
				data, err := mt.startBinaryConvImpl(mock, bytes)
				if err != nil {
					return data, err
				}
				return data.Data(), err
			},
		},
		"StartConv-Binary-with-ConvFunc": {
			expectedValue: []byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99},
			conversationHandler: BinaryConversationFunc(func(ptr BinaryPointer) ([]byte, error) {
				bytes, _ := testBinaryDataDecoder(ptr)
				expectedBinary := []byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!")
				if !reflect.DeepEqual(bytes, expectedBinary) {
					return nil, fmt.Errorf("%w, data mismatch %#v vs %#v",
						ErrConv, bytes, expectedBinary)
				}
				return testBinaryDataEncoder([]byte{0x01, 0x02, 0x03, 0x05, 0x00, 0x99}), nil
			}),
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				bytes := testBinaryDataEncoder([]byte(
					"\x00This is a binary data request\xC5\x00\xffYes it is!"))
				data, err := mt.startConvImpl(mock, NewBinaryConvRequestFromBytes(bytes))
				if err != nil {
					return data, err
				}
				resp, _ := data.(BinaryConvResponse)
				return resp.Decode(testBinaryDataDecoder)
			},
		},
		"StartConv-Binary-with-ConvFunc-error": {
			expectedError: ErrConv,
			conversationHandler: BinaryConversationFunc(func(ptr BinaryPointer) ([]byte, error) {
				return nil, errors.New("got an error")
			}),
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, NewBinaryConvRequestFromBytes([]byte{}))
			},
		},
		"StartConv-String-with-ConvBinaryFunc": {
			expectedError: ErrConv,
			conversationHandler: BinaryConversationFunc(func(ptr BinaryPointer) ([]byte, error) {
				return nil, nil
			}),
			testFunc: func(mock *mockModuleTransaction) (any, error) {
				return mt.startConvImpl(mock, NewStringConvRequest(TextInfo, "prompt"))
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Cleanup(maybeDoLeakCheck)
			mock := newMockModuleTransaction(&mockModuleTransaction{T: t,
				Expectations: tc.mockExpectations, RetData: tc.mockRetData,
				ConversationHandler: tc.conversationHandler})
			data, err := tc.testFunc(mock)

			if !tc.ignoreError && !errors.Is(err, tc.expectedError) {
				t.Fatalf("unexpected err: %#v vs %#v", err, tc.expectedError)
			}

			if !reflect.DeepEqual(data, tc.expectedValue) {
				t.Fatalf("data mismatch, %#v vs %#v", data, tc.expectedValue)
			}
		})
	}
}

func Test_MockModuleTransaction(t *testing.T) {
	mt, _ := NewModuleTransactionInvoker(nil).(*moduleTransaction)
	testMockModuleTransaction(t, mt)
}

func Test_MockModuleTransactionParallelConv(t *testing.T) {
	mt, _ := NewModuleTransactionInvokerParallelConv(nil).(*moduleTransaction)
	testMockModuleTransaction(t, mt)
}
