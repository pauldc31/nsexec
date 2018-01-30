#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static bool resolve_add_rule(scmp_filter_ctx ctx, const char *sys_name)
{
	int sysc;

	sysc = seccomp_syscall_resolve_name(sys_name);
	if (sysc == __NR_SCMP_ERROR) {
		fprintf(stderr, "Invalid syscall: %s\n", sys_name);
		return false;
	}

	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sysc, 0) < 0) {
		fprintf(stderr, "Couldn't add rule for syscall %s\n", sys_name);
		return false;
	}

	return true;
}

bool install_seccomp_filter(char *filter)
{
	scmp_filter_ctx ctx = NULL;
	char *token, *saveptr;

	/* default behavior is to kill the process */
	ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx) {
		fprintf(stderr, "Could not init the seccomp ctx\n");
		return false;
	}

	token = strtok_r(filter, ",", &saveptr);
	/* only one syscall */
	if (!token) {
		if (!resolve_add_rule(ctx, filter))
			return false;
	} else {
		while (token) {
			if (!resolve_add_rule(ctx, token))
				return false;

			token = strtok_r(NULL, ",", &saveptr);
		}
	}

	if (seccomp_load(ctx)) {
		fprintf(stderr, "Could not load the ctx\n");
		return false;
	}

	return true;
}
