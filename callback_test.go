package pam

import (
	"reflect"
	"testing"
)

func TestCallback_001(t *testing.T) {
	c := cbAdd(TestCallback_001)
	v := cbGet(c)
	if reflect.TypeOf(v) != reflect.TypeOf(TestCallback_001) {
		t.Error("Received unexpected value")
	}
}

func TestCallback_002(t *testing.T) {
	defer func() {
		recover()
	}()
	c := cbAdd(TestCallback_002)
	cbGet(c + 1)
	t.Error("Expected a panic")
}
