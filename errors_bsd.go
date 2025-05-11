//go:build freebsd

package pam

/*
#include <security/pam_appl.h>
*/
import "C"

// Pam Return types
const (
	// ErrBadItem indicates a bad item passed to pam_*_item().
	ErrBadItem Error = C.PAM_BAD_ITEM
)
