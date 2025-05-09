//go:build linux

package pam

/*
#include <security/pam_appl.h>
*/
import "C"

// Pam Return types
const (
	// ErrBadItem indicates a bad item passed to pam_*_item().
	ErrBadItem Error = C.PAM_BAD_ITEM
	// ErrConvAgain indicates a conversation function is event driven and data
	// is not available yet.
	ErrConvAgain Error = C.PAM_CONV_AGAIN
	// ErrIncomplete indicates to please call this function again to complete
	// authentication stack. Before calling again, verify that conversation
	// is completed.
	ErrIncomplete Error = C.PAM_INCOMPLETE
)
