package pam

import (
	"errors"
	"testing"
)

func TestPAM_001(t *testing.T) {
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
