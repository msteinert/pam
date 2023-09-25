// Package utils contains the internal test utils
package utils

// Action represents a PAM action to perform.
type Action int

const (
	// Account is the account.
	Account Action = iota + 1
	// Auth is the auth.
	Auth
	// Password is the password.
	Password
	// Session is the session.
	Session
)

func (a Action) String() string {
	switch a {
	case Account:
		return "account"
	case Auth:
		return "auth"
	case Password:
		return "password"
	case Session:
		return "session"
	default:
		return ""
	}
}

// Actions is a map with all the available Actions by their name.
var Actions = map[string]Action{
	Account.String():  Account,
	Auth.String():     Auth,
	Password.String(): Password,
	Session.String():  Session,
}

// Control represents how a PAM module should controlled in PAM service file.
type Control int

const (
	// Required implies that the module is required.
	Required Control = iota + 1
	// Requisite implies that the module is requisite.
	Requisite
	// Sufficient implies that the module is sufficient.
	Sufficient
	// Optional implies that the module is optional.
	Optional
)

func (c Control) String() string {
	switch c {
	case Required:
		return "required"
	case Requisite:
		return "requisite"
	case Sufficient:
		return "sufficient"
	case Optional:
		return "optional"
	default:
		return ""
	}
}

// ServiceLine is the representation of a PAM module service file line.
type ServiceLine struct {
	Action  Action
	Control Control
	Module  string
	Args    []string
}

// FallBackModule is a type to represent the module that should be used as fallback.
type FallBackModule int

const (
	// NoFallback add no fallback module.
	NoFallback FallBackModule = iota + 1
	// Permit uses a module that always permits.
	Permit
	// Deny uses a module that always denys.
	Deny
)

func (a FallBackModule) String() string {
	switch a {
	case Permit:
		return "pam_permit.so"
	case Deny:
		return "pam_deny.so"
	default:
		return ""
	}
}
