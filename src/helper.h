#include <stdarg.h>

struct NS_ARGS {
	bool graphics_enabled;
	int ns_user;
	int ns_group;
	int child_args;
	int pod_pid;
	/* vethXXXX */
	char veth_h[9];
	char veth_ns[9];
	char *rootfs;
	const char *exec_file;
	const char *hostname;
	char *seccomp_filter;
	char *lsm_context;
	char **global_argv;
};

/* declared by nsexec */
extern int enable_verbose;

__attribute__((format (printf, 1, 2)))
static inline void verbose(char *fmt, ...)
{
	va_list ap;

	if (enable_verbose) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}
