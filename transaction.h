#include <security/pam_appl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef PAM_BINARY_PROMPT
#define BINARY_PROMPT_IS_SUPPORTED 1
#else
#include <limits.h>
#define PAM_BINARY_PROMPT INT_MAX
#define BINARY_PROMPT_IS_SUPPORTED 0
#endif

#ifdef __sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

extern int _go_pam_conv_handler(struct pam_message *, uintptr_t, char **reply);

static inline int cb_pam_conv(int num_msg, PAM_CONST struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	*resp = calloc(num_msg, sizeof **resp);
	if (!*resp)
		return PAM_BUF_ERR;

	for (size_t i = 0; i < num_msg; ++i) {
		int result = _go_pam_conv_handler((struct pam_message *)msg[i], (uintptr_t)appdata_ptr, &(*resp)[i].resp);
		if (result != PAM_SUCCESS)
			goto error;
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

static inline void init_pam_conv(struct pam_conv *conv, uintptr_t appdata)
{
	conv->conv = cb_pam_conv;
	conv->appdata_ptr = (void *)appdata;
}

// pam_start_confdir is a recent PAM api to declare a confdir (mostly for
// tests) weaken the linking dependency to detect if it’s present.
int pam_start_confdir(const char *service_name, const char *user, const struct pam_conv *pam_conversation,
		      const char *confdir, pam_handle_t **pamh) __attribute__((weak));

static inline int check_pam_start_confdir(void)
{
	if (pam_start_confdir == NULL)
		return 1;

	return 0;
}
