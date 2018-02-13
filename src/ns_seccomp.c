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
		SCMP_SYS(capget),
		SCMP_SYS(capset),
		SCMP_SYS(chdir),
		SCMP_SYS(chmod),
		SCMP_SYS(chown),
		SCMP_SYS(clone),
		SCMP_SYS(close),
		SCMP_SYS(connect),
		SCMP_SYS(dup),
		SCMP_SYS(dup2),
		SCMP_SYS(dup3),
		SCMP_SYS(epoll_create1),
		SCMP_SYS(epoll_ctl),
		SCMP_SYS(execve),
		SCMP_SYS(exit_group),
		SCMP_SYS(ioctl),
		SCMP_SYS(faccessat),
		SCMP_SYS(fchdir),
		SCMP_SYS(fcntl),
		SCMP_SYS(fstat),
		SCMP_SYS(fsync),
		SCMP_SYS(futex),
		SCMP_SYS(ftruncate),
		SCMP_SYS(ftruncate64),
		SCMP_SYS(getcwd),
		SCMP_SYS(getdents),
		SCMP_SYS(getegid),
		SCMP_SYS(geteuid),
		SCMP_SYS(getgid),
		SCMP_SYS(getpgrp),
		SCMP_SYS(getpid),
		SCMP_SYS(getppid),
		SCMP_SYS(getrandom),
		SCMP_SYS(getsockname),
		SCMP_SYS(getsockopt),
		SCMP_SYS(getuid),
		SCMP_SYS(listen),
		SCMP_SYS(lseek),
		SCMP_SYS(lstat),
		SCMP_SYS(kill),
		SCMP_SYS(mmap),
		SCMP_SYS(mprotect),
		SCMP_SYS(mremap),
		SCMP_SYS(munmap),
		SCMP_SYS(nanosleep),
		SCMP_SYS(open),
		SCMP_SYS(openat),
		SCMP_SYS(pipe),
		SCMP_SYS(pipe2),
		SCMP_SYS(poll),
		SCMP_SYS(prctl),
		SCMP_SYS(prlimit64),
		SCMP_SYS(pselect6),
		SCMP_SYS(read),
		SCMP_SYS(readlink),
		SCMP_SYS(recvfrom),
		SCMP_SYS(recvmsg),
		SCMP_SYS(rt_sigaction),
		SCMP_SYS(rt_sigprocmask),
		SCMP_SYS(rt_sigreturn),
		SCMP_SYS(select),
		SCMP_SYS(sendmsg),
		SCMP_SYS(sendmmsg),
		SCMP_SYS(sendto),
		SCMP_SYS(set_robust_list),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(setpgid),
		SCMP_SYS(setsockopt),
		SCMP_SYS(setuid),
		SCMP_SYS(sigaltstack),
		SCMP_SYS(socket),
		SCMP_SYS(stat),
		SCMP_SYS(statfs),
		SCMP_SYS(syscall),
		SCMP_SYS(sysinfo),
		SCMP_SYS(umask),
		SCMP_SYS(uname),
		SCMP_SYS(unlink),
		SCMP_SYS(wait4),
		SCMP_SYS(waitid),
		SCMP_SYS(write),
		SCMP_SYS(writev),
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
