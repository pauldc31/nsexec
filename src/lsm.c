#include <stdbool.h>
#include <stdio.h>

#include "helper.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

bool set_context(char *context)
{
	(void)context;
#ifdef HAVE_SELINUX
	if (!context)
		return true;

	verbose("Setting SELinux context: %s\n", context);
	if (setexeccon_raw(context) < 0) {
		perror("setexeccon");
		return false;
	}
#else
	verbose("LSM not defined\n");
#endif
	return true;
}
