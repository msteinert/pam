package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/msteinert/pam/v2"
	"github.com/msteinert/pam/v2/cmd/pam-moduler/tests/internal/utils"
)

func Test_DebugModule_ActionStatus(t *testing.T) {
	t.Parallel()

	module := DebugModule{}

	for ret, expected := range moduleArgsRetTypes {
		ret := ret
		expected := expected
		for actionName, action := range utils.Actions {
			actionName := actionName
			action := action
			t.Run(fmt.Sprintf("%s %s", ret, actionName), func(t *testing.T) {
				t.Parallel()
				moduleArgs := make([]string, 0)
				for _, a := range debugModuleArgs {
					moduleArgs = append(moduleArgs, fmt.Sprintf("%s=%s", a, ret))
				}

				mt := pam.ModuleTransactionInvoker(nil)
				var err error

				switch action {
				case utils.Account:
					err = module.AcctMgmt(mt, 0, moduleArgs)
				case utils.Auth:
					err = module.Authenticate(mt, 0, moduleArgs)
				case utils.Password:
					err = module.ChangeAuthTok(mt, 0, moduleArgs)
				case utils.Session:
					err = module.OpenSession(mt, 0, moduleArgs)
				}

				if !errors.Is(err, expected) {
					t.Fatalf("error #unexpected %#v vs %#v", expected, err)
				}
			})
		}
	}
}

func Test_DebugModuleTransaction_ActionStatus(t *testing.T) {
	t.Parallel()
	if !pam.CheckPamHasStartConfdir() {
		t.Skip("this requires PAM with Conf dir support")
	}

	ts := utils.NewTestSetup(t, utils.WithWorkDir())
	modulePath := ts.GenerateModule(".", "pam_godebug.so")

	for ret, expected := range moduleArgsRetTypes {
		ret := ret
		expected := expected
		for actionName, action := range utils.Actions {
			ret := ret
			expected := expected
			actionName := actionName
			action := action
			t.Run(fmt.Sprintf("%s %s", ret, actionName), func(t *testing.T) {
				t.Parallel()
				serviceName := ret + "-" + actionName
				moduleArgs := make([]string, 0)
				for _, a := range debugModuleArgs {
					moduleArgs = append(moduleArgs, fmt.Sprintf("%s=%s", a, ret))
				}
				control := utils.Requisite
				fallbackModule := utils.Permit
				if ret == "success" {
					fallbackModule = utils.Deny
					control = utils.Sufficient
				}
				ts.CreateService(serviceName, []utils.ServiceLine{
					{Action: action, Control: control, Module: modulePath, Args: moduleArgs},
					{Action: action, Control: control, Module: fallbackModule.String(), Args: []string{}},
				})

				tx, err := pam.StartConfDir(serviceName, "user", nil, ts.WorkDir())
				if err != nil {
					t.Fatalf("start #error: %v", err)
				}
				defer func() {
					err := tx.End()
					if err != nil {
						t.Fatalf("end #error: %v", err)
					}
				}()

				switch action {
				case utils.Account:
					err = tx.AcctMgmt(pam.Silent)
				case utils.Auth:
					err = tx.Authenticate(pam.Silent)
				case utils.Password:
					err = tx.ChangeAuthTok(pam.Silent)
				case utils.Session:
					err = tx.OpenSession(pam.Silent)
				}

				if errors.Is(expected, pam.ErrIgnore) {
					// Ignore can't be returned
					expected = nil
				}

				if !errors.Is(err, expected) {
					t.Fatalf("error #unexpected %#v vs %#v", expected, err)
				}
			})
		}
	}
}
