package pam

import (
	"errors"
	"os/user"
	"testing"
)

func TestPAM_001(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("", "test", func(s Style, msg string) (string, error) {
		return "secret", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

func TestPAM_002(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("", "", func(s Style, msg string) (string, error) {
		switch s {
		case PromptEchoOn:
			return "test", nil
		case PromptEchoOff:
			return "secret", nil
		}
		return "", errors.New("unexpected")
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

type Credentials struct {
	User     string
	Password string
}

func (c Credentials) RespondPAM(s Style, msg string) (string, error) {
	switch s {
	case PromptEchoOn:
		return c.User, nil
	case PromptEchoOff:
		return c.Password, nil
	}
	return "", errors.New("unexpected")
}

func TestPAM_003(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	c := Credentials{
		User:     "test",
		Password: "secret",
	}
	tx, err := Start("", "", c)
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

func TestPAM_004(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	c := Credentials{
		Password: "secret",
	}
	tx, err := Start("", "test", c)
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

func TestGetEnvList(t *testing.T) {
	tx, err := StartFunc("", "", func(s Style, msg string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}

	m, err := tx.GetEnvList()
	if err != nil {
		t.Fatalf("getenvlist #error: %v", err)
	}
	n := len(m)
	if n != 0 {
		t.Fatalf("putenv #error: expected 0 items, got %v", n)
	}

	vals := []string{
		"VAL1=1",
		"VAL2=2",
		"VAL3=3",
	}
	for _, s := range vals {
		err = tx.PutEnv(s)
		if err != nil {
			t.Fatalf("putenv #error: %v", err)
		}
	}

	s := tx.GetEnv("VAL1")
	if s != "1" {
		t.Fatalf("getenv #error: expected 1, got %v", s)
	}
	s = tx.GetEnv("VAL2")
	if s != "2" {
		t.Fatalf("getenv #error: expected 2, got %v", s)
	}
	s = tx.GetEnv("VAL3")
	if s != "3" {
		t.Fatalf("getenv #error: expected 3, got %v", s)
	}

	m, err = tx.GetEnvList()
	if err != nil {
		t.Fatalf("getenvlist #error: %v", err)
	}
	n = len(m)
	if n != 3 {
		t.Fatalf("getenvlist #error: expected 3 items, got %v", n)
	}
	if m["VAL1"] != "1" {
		t.Fatalf("getenvlist #error: expected 1, got %v", m["VAL1"])
	}
	if m["VAL2"] != "2" {
		t.Fatalf("getenvlist #error: expected 2, got %v", m["VAL1"])
	}
	if m["VAL3"] != "3" {
		t.Fatalf("getenvlist #error: expected 3, got %v", m["VAL1"])
	}
}
