// Package pam provides a wrapper for the PAM application API.
package pam

/*
#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/lsan_interface.h>
#endif

static inline void
maybe_do_leak_check (void)
{
#ifdef __SANITIZE_ADDRESS__
	__lsan_do_leak_check();
#endif
}
*/
import "C"

import (
	"os"
	"runtime"
	"time"
)

func maybeDoLeakCheck() {
	runtime.GC()
	time.Sleep(time.Millisecond * 20)
	if os.Getenv("GO_PAM_SKIP_LEAK_CHECK") == "" {
		C.maybe_do_leak_check()
	}
}
