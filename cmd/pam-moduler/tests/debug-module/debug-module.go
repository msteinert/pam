//go:generate go run github.com/msteinert/pam/v2/cmd/pam-moduler -libname "pam_godebug.so"
//go:generate go generate --skip="pam_module.go"

// This is a similar implementation of pam_debug.so

// Package main is the package for the debug PAM module library
package main

import (
	"fmt"
	"strings"

	"github.com/msteinert/pam/v2"
	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

var pamModuleHandler pam.ModuleHandler = &DebugModule{}
var _ = pamModuleHandler

var moduleArgsRetTypes = map[string]error{
	"success":               nil,
	"open_err":              pam.ErrOpen,
	"symbol_err":            pam.ErrSymbol,
	"service_err":           pam.ErrService,
	"system_err":            pam.ErrSystem,
	"buf_err":               pam.ErrBuf,
	"perm_denied":           pam.ErrPermDenied,
	"auth_err":              pam.ErrAuth,
	"cred_insufficient":     pam.ErrCredInsufficient,
	"authinfo_unavail":      pam.ErrAuthinfoUnavail,
	"user_unknown":          pam.ErrUserUnknown,
	"maxtries":              pam.ErrMaxtries,
	"new_authtok_reqd":      pam.ErrNewAuthtokReqd,
	"acct_expired":          pam.ErrAcctExpired,
	"session_err":           pam.ErrSession,
	"cred_unavail":          pam.ErrCredUnavail,
	"cred_expired":          pam.ErrCredExpired,
	"cred_err":              pam.ErrCred,
	"no_module_data":        pam.ErrNoModuleData,
	"conv_err":              pam.ErrConv,
	"authtok_err":           pam.ErrAuthtok,
	"authtok_recover_err":   pam.ErrAuthtokRecovery,
	"authtok_lock_busy":     pam.ErrAuthtokLockBusy,
	"authtok_disable_aging": pam.ErrAuthtokDisableAging,
	"try_again":             pam.ErrTryAgain,
	"ignore":                pam.ErrIgnore,
	"abort":                 pam.ErrAbort,
	"authtok_expired":       pam.ErrAuthtokExpired,
	"module_unknown":        pam.ErrModuleUnknown,
	"bad_item":              pam.ErrBadItem,
	"conv_again":            pam.ErrConvAgain,
	"incomplete":            pam.ErrIncomplete,
}

var debugModuleArgs = []string{"auth", "cred", "acct", "prechauthtok",
	"chauthtok", "open_session", "close_session"}

// DebugModule is the PAM module structure.
type DebugModule struct {
	utils.BaseModule
}

func (dm *DebugModule) getReturnType(args []string, key string) error {
	var value string
	for _, a := range args {
		v, found := strings.CutPrefix(a, key+"=")
		if found {
			value = v
		}
	}

	if value == "" {
		return fmt.Errorf("Value not found")
	}

	if ret, found := moduleArgsRetTypes[value]; found {
		return ret
	}
	return fmt.Errorf("Parameter %s not known", value)
}

func (dm *DebugModule) handleCall(args []string, action string) error {
	err := dm.getReturnType(args, action)
	if err == nil {
		return nil
	}

	return fmt.Errorf("error %w", err)
}

// AcctMgmt is a PAM handler.
func (dm *DebugModule) AcctMgmt(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "acct")
}

// Authenticate is a PAM handler.
func (dm *DebugModule) Authenticate(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "auth")
}

// ChangeAuthTok is a PAM handler.
func (dm *DebugModule) ChangeAuthTok(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "chauthtok")
}

// OpenSession is a PAM handler.
func (dm *DebugModule) OpenSession(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "open_session")
}

// CloseSession is a PAM handler.
func (dm *DebugModule) CloseSession(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "close_session")
}

// SetCred is a PAM handler.
func (dm *DebugModule) SetCred(mt pam.ModuleTransaction, flags pam.Flags, args []string) error {
	return dm.handleCall(args, "cred")
}
