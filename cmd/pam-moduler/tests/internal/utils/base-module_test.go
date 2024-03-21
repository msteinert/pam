package utils

import (
	"testing"

	"github.com/msteinert/pam/v2"
)

func TestMain(t *testing.T) {
	bm := BaseModule{}

	if bm.AcctMgmt(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}

	if bm.Authenticate(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}

	if bm.ChangeAuthTok(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}

	if bm.OpenSession(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}

	if bm.CloseSession(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}

	if bm.SetCred(nil, pam.Flags(0), nil) != nil {
		t.Fatalf("Unexpected non-nil value")
	}
}
