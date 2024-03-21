package utils

import "github.com/msteinert/pam/v2"

// BaseModule is the type for a base PAM module.
type BaseModule struct{}

// AcctMgmt is the handler function for PAM AcctMgmt.
func (h *BaseModule) AcctMgmt(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

// Authenticate is the handler function for PAM Authenticate.
func (h *BaseModule) Authenticate(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

// ChangeAuthTok is the handler function for PAM ChangeAuthTok.
func (h *BaseModule) ChangeAuthTok(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

// OpenSession is the handler function for PAM OpenSession.
func (h *BaseModule) OpenSession(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

// CloseSession is the handler function for PAM CloseSession.
func (h *BaseModule) CloseSession(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

// SetCred is the handler function for PAM SetCred.
func (h *BaseModule) SetCred(pam.ModuleTransaction, pam.Flags, []string) error {
	return nil
}

var _ pam.ModuleHandler = &BaseModule{}
