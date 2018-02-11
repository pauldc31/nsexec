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

bool default_whitelist(void)
{
	int *i;
	int syscall_whitelist[] = {
		SCMP_SYS(access),
		SCMP_SYS(arch_prctl),
		SCMP_SYS(bind),
		SCMP_SYS(bpf),
		SCMP_SYS(brk),
		SCMP_SYS(clone),
		SCMP_SYS(close),
		SCMP_SYS(connect),
		SCMP_SYS(epoll_create1),
		SCMP_SYS(epoll_ctl),
		SCMP_SYS(execve),
		SCMP_SYS(ioctl),
		SCMP_SYS(fstat),
		SCMP_SYS(futex),
		SCMP_SYS(listen),
		SCMP_SYS(mmap),
		SCMP_SYS(mprotect),
		SCMP_SYS(munmap),
		SCMP_SYS(nanosleep),
		SCMP_SYS(openat),
		SCMP_SYS(poll),
		SCMP_SYS(prlimit64),
		SCMP_SYS(read),
		SCMP_SYS(rt_sigaction),
		SCMP_SYS(rt_sigprocmask),
		SCMP_SYS(set_robust_list),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(setsockopt),
		SCMP_SYS(stat),
		SCMP_SYS(socket),
		SCMP_SYS(write),
		-1
	};

	scmp_filter_ctx ctx = NULL;
	/* default behavior is to kill the process */
	ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx) {
		fprintf(stderr, "Could not init the seccomp ctx\n");
		return false;
	}

	for (i = syscall_whitelist; *i != -1; i++) {
		printf("%d\n", *i);
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, *i, 0) < 0) {
			fprintf(stderr, "Couldn't add rule for syscall %d\n", *i);
			return false;
		}
	}

	if (seccomp_load(ctx)) {
		fprintf(stderr, "Could not load the ctx\n");
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

	/* if no filter is passed, install default whitelist */
	if (!filter)
		return default_whitelist();

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
