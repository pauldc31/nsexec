#include <stdbool.h>
#include <stdio.h>

#include "helper.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>

#define DEFAULT_CONTEXT "unconfined_u:unconfined_r:unconfined_t:s0"
#endif

bool set_context(char *context)
{
	(void)context;
#ifdef HAVE_SELINUX
	if (!context)
		context = DEFAULT_CONTEXT;

	verbose("Using SELinux context: %s\n", context);

	if (setexeccon_raw(context) < 0) {
		perror("setexeccon");
		return false;
	}
#else
	verbose("LSM not defined\n");
#endif
	return true;
}
