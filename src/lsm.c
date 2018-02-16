#include <stdbool.h>
#include <stdio.h>

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

	printf("USING SELINUX: %s\n", context);

	if (setexeccon_raw(context) < 0) {
		perror("setexeccon");
		return false;
	}
#else
	printf("LSM NOT DEFINED\n");
#endif
	return true;
}
