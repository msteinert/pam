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
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error #unexpected error %v", err)
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
	var pamErr Error
	if !errors.As(err, &pamErr) {
		t.Fatalf("error #unexpected type: %#v", err)
	}
	if pamErr != ErrAbort {
		t.Fatalf("error #unexpected status: %v", pamErr)
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
	err = tx.Authenticate(0)
	if err == nil {
		t.Fatalf("authenticate #expected an error")
	}
	s := err.Error()
	if len(s) == 0 {
		t.Fatalf("error #expected an error message")
	}
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error #unexpected error %v", err)
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
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error #unexpected error %v", err)
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

func Test_Error(t *testing.T) {
	t.Parallel()
	if !CheckPamHasStartConfdir() {
		t.Skip("this requires PAM with Conf dir support")
	}

	statuses := map[string]error{
		"success":               nil,
		"open_err":              ErrOpen,
		"symbol_err":            ErrSymbol,
		"service_err":           ErrService,
		"system_err":            ErrSystem,
		"buf_err":               ErrBuf,
		"perm_denied":           ErrPermDenied,
		"auth_err":              ErrAuth,
		"cred_insufficient":     ErrCredInsufficient,
		"authinfo_unavail":      ErrAuthinfoUnavail,
		"user_unknown":          ErrUserUnknown,
		"maxtries":              ErrMaxtries,
		"new_authtok_reqd":      ErrNewAuthtokReqd,
		"acct_expired":          ErrAcctExpired,
		"session_err":           ErrSession,
		"cred_unavail":          ErrCredUnavail,
		"cred_expired":          ErrCredExpired,
		"cred_err":              ErrCred,
		"no_module_data":        ErrNoModuleData,
		"conv_err":              ErrConv,
		"authtok_err":           ErrAuthtok,
		"authtok_recover_err":   ErrAuthtokRecovery,
		"authtok_lock_busy":     ErrAuthtokLockBusy,
		"authtok_disable_aging": ErrAuthtokDisableAging,
		"try_again":             ErrTryAgain,
		"ignore":                nil, /* Ignore can't be returned */
		"abort":                 ErrAbort,
		"authtok_expired":       ErrAuthtokExpired,
		"module_unknown":        ErrModuleUnknown,
		"bad_item":              ErrBadItem,
		"conv_again":            ErrConvAgain,
		"incomplete":            ErrIncomplete,
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

	for ret, expected := range statuses {
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

				if !errors.Is(err, expected) {
					t.Fatalf("error #unexpected status %#v vs %#v", err,
						expected)
				}

				if err != nil {
					var status Error
					if !errors.As(err, &status) || err.Error() != status.Error() {
						t.Fatalf("error #unexpected status %v vs %v", err.Error(),
							status.Error())
					}
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
