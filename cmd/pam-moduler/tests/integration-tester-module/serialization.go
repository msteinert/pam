package main

import (
	"encoding/gob"

	"github.com/msteinert/pam/v2"
	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

// SerializablePamError represents a [pam.Error] in a
// serializable way that splits message and return code.
type SerializablePamError struct {
	Msg       string
	RetStatus pam.Error
}

// NewSerializablePamError initializes a SerializablePamError from
// the default status error message.
func NewSerializablePamError(status pam.Error) SerializablePamError {
	return SerializablePamError{Msg: status.Error(), RetStatus: status}
}

func (e *SerializablePamError) Error() string {
	return e.RetStatus.Error()
}

// SerializableStringConvRequest is a serializable string request.
type SerializableStringConvRequest struct {
	Style   pam.Style
	Request string
}

// SerializableStringConvResponse is a serializable string response.
type SerializableStringConvResponse struct {
	Style    pam.Style
	Response string
}

// SerializableBinaryConvRequest is a serializable binary request.
type SerializableBinaryConvRequest struct {
	Request []byte
}

// SerializableBinaryConvResponse is a serializable binary response.
type SerializableBinaryConvResponse struct {
	Response []byte
}

func init() {
	gob.Register(map[string]string{})
	gob.Register(Request{})
	gob.Register(pam.Item(0))
	gob.Register(pam.Error(0))
	gob.Register(pam.Style(0))
	gob.Register([]pam.ConvResponse{})
	gob.RegisterName("main.SerializablePamError",
		SerializablePamError{})
	gob.RegisterName("main.SerializableStringConvRequest",
		SerializableStringConvRequest{})
	gob.RegisterName("main.SerializableStringConvResponse",
		SerializableStringConvResponse{})
	gob.RegisterName("main.SerializableBinaryConvRequest",
		SerializableBinaryConvRequest{})
	gob.RegisterName("main.SerializableBinaryConvResponse",
		SerializableBinaryConvResponse{})
	gob.Register(utils.SerializableError{})
}
