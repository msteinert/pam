//go:build linux

package pam

import (
	"testing"
)

func Test_LinuxError(t *testing.T) {
	t.Parallel()
	if !CheckPamHasStartConfdir() {
		t.Skip("this requires PAM with Conf dir support")
	}

	statuses := map[string]error{
		"bad_item":   ErrBadItem,
		"conv_again": ErrConvAgain,
		"incomplete": ErrIncomplete,
	}

	testError(t, statuses)
}

func TestFailure_001(t *testing.T) {
	tx := Transaction{}
	_, err := tx.GetEnvList()
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_002(t *testing.T) {
	tx := Transaction{}
	err := tx.PutEnv("")
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_003(t *testing.T) {
	tx := Transaction{}
	err := tx.CloseSession(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_004(t *testing.T) {
	tx := Transaction{}
	err := tx.OpenSession(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_005(t *testing.T) {
	tx := Transaction{}
	err := tx.ChangeAuthTok(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_006(t *testing.T) {
	tx := Transaction{}
	err := tx.AcctMgmt(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_007(t *testing.T) {
	tx := Transaction{}
	err := tx.SetCred(0)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_008(t *testing.T) {
	tx := Transaction{}
	err := tx.SetItem(User, "test")
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_009(t *testing.T) {
	tx := Transaction{}
	_, err := tx.GetItem(User)
	if err == nil {
		t.Fatalf("getenvlist #expected an error")
	}
}

func TestFailure_010(t *testing.T) {
	tx := Transaction{}
	err := tx.End()
	if err != nil {
		t.Fatalf("end #unexpected error %v", err)
	}
}
