//go:build !go_pam_module

package pam

/*
#include <security/pam_appl.h>
#include <stdint.h>
*/
import "C"

import "runtime/cgo"

// _go_pam_conv_handler is a C wrapper for the conversation callback function.
//
//export _go_pam_conv_handler
func _go_pam_conv_handler(msg *C.struct_pam_message, c C.uintptr_t, outMsg **C.char) C.int {
	convHandler, ok := cgo.Handle(c).Value().(ConversationHandler)
	if !ok || convHandler == nil {
		return C.int(ErrConv)
	}
	replyMsg, r := pamConvHandler(Style(msg.msg_style), msg.msg, convHandler)
	*outMsg = replyMsg
	return r
}
