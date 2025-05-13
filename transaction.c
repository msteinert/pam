#include "_cgo_export.h"
#include <security/pam_appl.h>
#include <stdint.h>
#include <string.h>

#if defined(__sun) && !defined(__illumos__)
#define PAM_CONST
#else
#define PAM_CONST const
#endif

int cb_pam_conv(int num_msg, PAM_CONST struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	*resp = calloc(num_msg, sizeof **resp);
	if (!*resp)
		return PAM_BUF_ERR;

	for (size_t i = 0; i < num_msg; ++i) {
		struct cbPAMConv_return result = cbPAMConv(msg[i]->msg_style, (char *)msg[i]->msg, (uintptr_t)appdata_ptr);
		if (result.r1 != PAM_SUCCESS)
			goto error;

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

int pam_start_confdir_wrapper(pam_start_confdir_fn fn, const char *service_name, const char *user,
			      const struct pam_conv *pam_conversation, const char *confdir, pam_handle_t **pamh)
{
	return (fn)(service_name, user, pam_conversation, confdir, pamh);
}
