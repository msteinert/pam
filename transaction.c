#include "_cgo_export.h"
#include <security/pam_appl.h>
#include <stdint.h>
#include <string.h>

#ifdef __sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

int cb_pam_conv(
	int num_msg,
	PAM_CONST struct pam_message **msg,
	struct pam_response **resp,
	void *appdata_ptr)
{
	*resp = calloc(num_msg, sizeof **resp);
	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
		return PAM_CONV_ERR;
	}
	if (!*resp) {
		return PAM_BUF_ERR;
	}
	for (size_t i = 0; i < num_msg; ++i) {
		struct cbPAMConv_return result = cbPAMConv(
				msg[i]->msg_style,
				(char *)msg[i]->msg,
				(uintptr_t)appdata_ptr);
		if (result.r1 != PAM_SUCCESS) {
			goto error;
		}
		(*resp)[i].resp = result.r0;
	}
	return PAM_SUCCESS;
error:
	for (size_t i = 0; i < num_msg; ++i) {
		if ((*resp)[i].resp) {
			memset((*resp)[i].resp, 0, strlen((*resp)[i].resp));
			free((*resp)[i].resp);
		}
	}
	memset(*resp, 0, num_msg * sizeof *resp);
	free(*resp);
	*resp = NULL;
	return PAM_CONV_ERR;
}

void init_pam_conv(struct pam_conv *conv, uintptr_t appdata)
{
	conv->conv = cb_pam_conv;
	conv->appdata_ptr = (void *)appdata;
}

// pam_start_confdir is a recent PAM api to declare a confdir (mostly for tests)
// weaken the linking dependency to detect if it’s present.
int pam_start_confdir(const char *service_name, const char *user, const struct pam_conv *pam_conversation, const char *confdir, pam_handle_t **pamh) __attribute__ ((weak));
int check_pam_start_confdir(void) {
	if (pam_start_confdir == NULL)
		return 1;
	return 0;
}
