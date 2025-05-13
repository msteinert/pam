//go:build linux

package pam

/*
#include <security/pam_appl.h>
*/
import "C"

// PAM Item types.
const (
	// FailDelay is the app supplied function to override failure delays.
	FailDelay Item = C.PAM_FAIL_DELAY
	// Xdisplay is the X display name.
	Xdisplay Item = C.PAM_XDISPLAY
	// Xauthdata is the X server authentication data.
	Xauthdata Item = C.PAM_XAUTHDATA
	// AuthtokType is the type for pam_get_authtok.
	AuthtokType Item = C.PAM_AUTHTOK_TYPE
)
