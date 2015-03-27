#include "_cgo_export.h"
#include <security/pam_appl.h>

int cb_pam_conv(
	int num_msg,
	const struct pam_message **msg,
	struct pam_response **resp,
	void *appdata_ptr)
{
	*resp = calloc(num_msg, sizeof **resp);
	if (!*resp) {
		return PAM_BUF_ERR;
	}
	for (size_t i = 0; i < num_msg; ++i) {
		const struct pam_message *m = msg[i];
		struct cbPAMConv_return result =
			cbPAMConv(m->msg_style, (char *)m->msg, appdata_ptr);
		if (result.r1 != PAM_SUCCESS) {
			goto error;
		}
		(*resp)[i].resp = result.r0;
	}
	return PAM_SUCCESS;
error:
	for (size_t i = 0; i < num_msg; ++i) {
		free((*resp)[i].resp);
	}
	free(*resp);
	*resp = NULL;
	return PAM_CONV_ERR;
}

struct pam_conv *make_pam_conv(void *appdata_ptr)
{
	struct pam_conv* conv = malloc(sizeof *conv);
	if (!conv) {
		return NULL;
	}
	conv->conv = cb_pam_conv;
	conv->appdata_ptr = appdata_ptr;
	return conv;
}
