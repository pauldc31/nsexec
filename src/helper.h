#include <stdarg.h>

typedef enum {
	MOUNT_RO,
	MOUNT_RW,
	SYMLINK
} MOUNT_FLAG;

struct MOUNT_LIST {
	char *src;
	char *dst;
	MOUNT_FLAG mount_type;
	struct MOUNT_LIST *next;
};

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
	char *seccomp_filter;
	char *lsm_context;
	char *exec_file;
	char *hostname;
	char *term;
	char *session;
	char *display;
	char *chdir;
	char **global_argv;
	struct MOUNT_LIST *mount_list;
	struct MOUNT_LIST *link_list;
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
