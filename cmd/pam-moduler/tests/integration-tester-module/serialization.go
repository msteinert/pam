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

func init() {
	gob.Register(map[string]string{})
	gob.Register(Request{})
	gob.Register(pam.Item(0))
	gob.Register(pam.Error(0))
	gob.RegisterName("main.SerializablePamError",
		SerializablePamError{})
	gob.Register(utils.SerializableError{})
}
