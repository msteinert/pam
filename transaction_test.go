package pam

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestPAM_001(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	p := "secret"
	tx, err := StartFunc("", "test", func(s Style, msg string) (string, error) {
		return p, nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	err = tx.AcctMgmt(Silent)
	if err != nil {
		t.Fatalf("acct_mgmt #error: %v", err)
	}
	err = tx.SetCred(Silent | EstablishCred)
	if err != nil {
		t.Fatalf("setcred #error: %v", err)
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

func TestPAM_005(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("passwd", "test", func(s Style, msg string) (string, error) {
		return "secret", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	service, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("GetItem #error: %v", err)
	}
	if service != "passwd" {
		t.Fatalf("Unexpected service: %v", service)
	}
	err = tx.ChangeAuthTok(Silent)
	if err != nil {
		t.Fatalf("chauthtok #error: %v", err)
	}
}

func TestPAM_006(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("passwd", u.Username, func(s Style, msg string) (string, error) {
		return "secret", nil
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.OpenSession(Silent)
	if err != nil {
		t.Fatalf("open_session #error: %v", err)
	}
	err = tx.CloseSession(Silent)
	if err != nil {
		t.Fatalf("close_session #error: %v", err)
	}
}

func TestPAM_007(t *testing.T) {
	u, _ := user.Current()
	if u.Uid != "0" {
		t.Skip("run this test as root")
	}
	tx, err := StartFunc("", "test", func(s Style, msg string) (string, error) {
		return "", errors.New("Sorry, it didn't work")
	})
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
	if tx.Status() != AuthErr {
		t.Fatalf("error #unexpected status %v", tx.Status())
	}
}

func TestPAM_ConfDir(t *testing.T) {
	u, _ := user.Current()
	c := Credentials{
		// the custom service always permits even with wrong password.
		Password: "wrongsecret",
	}
	tx, err := StartConfDir("permit-service", u.Username, c, "test-services")
	if !CheckPamHasStartConfdir() {
		if err == nil {
			t.Fatalf("start should have errored out as pam_start_confdir is not available: %v", err)
		}
		// nothing else we do, we don't support it.
		return
	}
	service, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("GetItem #error: %v", err)
	}
	if service != "permit-service" {
		t.Fatalf("Unexpected service: %v", service)
	}
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

func TestPAM_ConfDir_FailNoServiceOrUnsupported(t *testing.T) {
	u, _ := user.Current()
	c := Credentials{
		Password: "secret",
	}
	_, err := StartConfDir("does-not-exists", u.Username, c, ".")
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
}

func TestPAM_ConfDir_InfoMessage(t *testing.T) {
	u, _ := user.Current()
	var infoText string
	tx, err := StartConfDir("echo-service", u.Username,
		ConversationFunc(func(s Style, msg string) (string, error) {
			switch s {
			case TextInfo:
				infoText = msg
				return "", nil
			}
			return "", errors.New("unexpected")
		}), "test-services")
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	service, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("GetItem #error: %v", err)
	}
	if service != "echo-service" {
		t.Fatalf("Unexpected service: %v", service)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
	if infoText != "This is an info message for user "+u.Username+" on echo-service" {
		t.Fatalf("Unexpected info message: %v", infoText)
	}
}

func TestPAM_ConfDir_Deny(t *testing.T) {
	u, _ := user.Current()
	tx, err := StartConfDir("deny-service", u.Username, Credentials{}, "test-services")
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	service, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("GetItem #error: %v", err)
	}
	if service != "deny-service" {
		t.Fatalf("Unexpected service: %v", service)
	}
	err = tx.Authenticate(0)
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
	if tx.Status() != AuthErr {
		t.Fatalf("error #unexpected status %v", tx.Status())
	}
}

func TestPAM_ConfDir_PromptForUserName(t *testing.T) {
	c := Credentials{
		User: "testuser",
		// the custom service only cares about correct user name.
		Password: "wrongsecret",
	}
	tx, err := StartConfDir("succeed-if-user-test", "", c, "test-services")
	if !CheckPamHasStartConfdir() {
		if err == nil {
			t.Fatalf("start should have errored out as pam_start_confdir is not available: %v", err)
		}
		// nothing else we do, we don't support it.
		return
	}
	if err != nil {
		t.Fatalf("start #error: %v", err)
	}
	err = tx.Authenticate(0)
	if err != nil {
		t.Fatalf("authenticate #error: %v", err)
	}
}

func TestPAM_ConfDir_WrongUserName(t *testing.T) {
	c := Credentials{
		User:     "wronguser",
		Password: "wrongsecret",
	}
	tx, err := StartConfDir("succeed-if-user-test", "", c, "test-services")
	if !CheckPamHasStartConfdir() {
		if err == nil {
			t.Fatalf("start should have errored out as pam_start_confdir is not available: %v", err)
		}
		// nothing else we do, we don't support it.
		return
	}
	err = tx.Authenticate(0)
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
	if tx.Status() != AuthErr {
		t.Fatalf("error #unexpected status %v", tx.Status())
	}
}

func TestItem(t *testing.T) {
	tx, _ := StartFunc("passwd", "test", func(s Style, msg string) (string, error) {
		return "", nil
	})

	s, err := tx.GetItem(Service)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "passwd" {
		t.Fatalf("getitem #error: expected passwd, got %v", s)
	}

	s, err = tx.GetItem(User)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "test" {
		t.Fatalf("getitem #error: expected test, got %v", s)
	}

	err = tx.SetItem(User, "root")
	if err != nil {
		t.Fatalf("setitem #error: %v", err)
	}
	s, err = tx.GetItem(User)
	if err != nil {
		t.Fatalf("getitem #error: %v", err)
	}
	if s != "root" {
		t.Fatalf("getitem #error: expected root, got %v", s)
	}
}

func TestEnv(t *testing.T) {
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

	s := tx.GetEnv("VAL0")
	if s != "" {
		t.Fatalf("getenv #error: expected \"\", got %v", s)
	}

	s = tx.GetEnv("VAL1")
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

func Test_Status(t *testing.T) {
	if !CheckPamHasStartConfdir() {
		t.Skip("this requires PAM with Conf dir support")
	}

	t.Parallel()

	retTypes := map[string]ReturnType{
		"success":               Success,
		"open_err":              OpenErr,
		"symbol_err":            SymbolErr,
		"service_err":           ServiceErr,
		"system_err":            SystemErr,
		"buf_err":               BufErr,
		"perm_denied":           PermDenied,
		"auth_err":              AuthErr,
		"cred_insufficient":     CredInsufficient,
		"authinfo_unavail":      AuthinfoUnavail,
		"user_unknown":          UserUnknown,
		"maxtries":              Maxtries,
		"new_authtok_reqd":      NewAuthtokReqd,
		"acct_expired":          AcctExpired,
		"session_err":           SessionErr,
		"cred_unavail":          CredUnavail,
		"cred_expired":          CredExpired,
		"cred_err":              CredErr,
		"no_module_data":        NoModuleData,
		"conv_err":              ConvErr,
		"authtok_err":           AuthtokErr,
		"authtok_recover_err":   AuthtokRecoveryErr,
		"authtok_lock_busy":     AuthtokLockBusy,
		"authtok_disable_aging": AuthtokDisableAging,
		"try_again":             TryAgain,
		"ignore":                Success, /* Ignore can't be returned */
		"abort":                 Abort,
		"authtok_expired":       AuthtokExpired,
		"module_unknown":        ModuleUnknown,
		"bad_item":              BadItem,
		"conv_again":            ConvAgain,
		"incomplete":            Incomplete,
	}

	type Action int
	const (
		account Action = iota + 1
		auth
		password
		session
	)
	actions := map[string]Action{
		"account":  account,
		"auth":     auth,
		"password": password,
		"session":  session,
	}

	c := Credentials{}

	servicePath := t.TempDir()

	for ret, expected := range retTypes {
		ret := ret
		expected := expected
		for actionName, action := range actions {
			actionName := actionName
			action := action
			t.Run(fmt.Sprintf("%s %s", ret, actionName), func(t *testing.T) {
				t.Parallel()
				serviceName := ret + "-" + actionName
				serviceFile := filepath.Join(servicePath, serviceName)
				contents := fmt.Sprintf("%[1]s requisite pam_debug.so "+
					"auth=%[2]s cred=%[2]s acct=%[2]s prechauthtok=%[2]s "+
					"chauthtok=%[2]s open_session=%[2]s close_session=%[2]s\n"+
					"%[1]s requisite pam_permit.so\n", actionName, ret)

				if err := os.WriteFile(serviceFile,
					[]byte(contents), 0600); err != nil {
					t.Fatalf("can't create service file %v: %v", serviceFile, err)
				}

				tx, err := StartConfDir(serviceName, "user", c, servicePath)
				if err != nil {
					t.Fatalf("start #error: %v", err)
				}

				switch action {
				case account:
					err = tx.AcctMgmt(0)
				case auth:
					err = tx.Authenticate(0)
				case password:
					err = tx.ChangeAuthTok(0)
				case session:
					err = tx.OpenSession(0)
				}

				if tx.Status() != expected {
					t.Fatalf("error #unexpected status %v", tx.Status())
				}
				if tx.Status() == Success && err != nil {
					t.Fatalf("error #unexpected: %v", err)
				} else if tx.Status() != Success && err == nil {
					t.Fatalf("error #expected an error message")
				}
			})
		}
	}
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
