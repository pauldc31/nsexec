#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <net/if.h> /* IFF_UP */
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static int child_args;
static char base_path[PATH_MAX];
static int enable_verbose = 0;
static int wait_fd = -1;
static char val = 1;
const char *exec_file = NULL;
char **global_argv;

static struct nl_sock *sk;

__attribute__((unused))
static int ret;

static void fatalErrMsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void fatalErr(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static inline void verbose(char *fmt, ...)
{
	va_list ap;

	if (enable_verbose) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

static void setup_network(void)
{
	struct rtnl_link *link, *eth, *change;
	struct nl_cache *cache;
	int err;

	sk = nl_socket_alloc();
	err = nl_connect(sk, NETLINK_ROUTE);
	if (err < 0)
		fatalErrMsg("Error: Unable to connect netlink route: %s\n",
				nl_geterror(err));

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err < 0)
		fatalErrMsg("Error: Unable to build link cache: %s\n",
				nl_geterror(err));

	link = rtnl_link_get_by_name(cache, "lo");
	if (!link)
		fatalErrMsg("Error: Could not find loopback interface\n");

	change = rtnl_link_alloc();
	rtnl_link_set_flags(change, IFF_UP);

	err = rtnl_link_change(sk, link, change, 0);
	if (err < 0)
		fatalErrMsg("Error: Unable to activate loopback: \n",
				nl_geterror(err));

	eth = rtnl_link_get_by_name(cache, "eth0");
	if (!eth)
		fatalErrMsg("Error: Unable to find eth0\n");

	err = rtnl_link_change(sk, eth, change, 0);
	if (err < 0)
		fatalErrMsg("Error: Unable to activate eth0: %s\n",
				nl_geterror(err));

	nl_close(sk);
}

static void setup_bridge(int child_pid)
{
	pid_t pid;
	char *binpath = "/usr/bin/nsexec_nic";
	char strpid[15];
	int wstatus;

	pid = fork();
	switch (pid) {
	case -1:
		fatalErr("fork bridge");
		/* fall-thru */
	case 0:
		if (snprintf(strpid, sizeof(strpid), "%d", child_pid) < 0)
			fatalErr("strnpid child_pid");
		execlp(binpath, binpath, "create", strpid, NULL);
		fatalErr("execlp bridge failed\n");
		/* fall-thru */
	default:
		if (waitpid(pid, &wstatus, 0) == -1)
			fatalErr("waitpid bridge\n");
		if (!WIFEXITED(wstatus))
			fatalErrMsg("bridge process terminated anormally\n");
	}
}

static void setup_mountns(void)
{
	/* set / as slave, so changes from here won't be propagated to parent
	 * namespace */
	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
		fatalErr("mount recursive slave");

	if (mount("", base_path, "tmpfs", MS_NOSUID | MS_NODEV, NULL) < 0)
		fatalErr("mount tmpfs");

	if (chdir(base_path) == -1)
		fatalErr("chdir");

	/* prepare pivot_root environment */
	if (mkdir("newroot", 0755) == -1)
		fatalErr("newroot");

	if (mkdir("oldroot", 0755) == -1)
		fatalErr("oldroot");

	/* there is not a wrapper in glibc for pivot_root */
	if (syscall(__NR_pivot_root, base_path, "oldroot") == -1)
		fatalErr("pivot_root");

	if (chdir("/") == -1)
		fatalErr("chdir to new root");

	/* mount bind the oldroot into the new tmpfs */
	if (mount("/oldroot/", "/newroot/", NULL, MS_BIND | MS_REC, NULL) < 0)
		fatalErr("mount bind old rootfs");

	/* remount oldroot no not propagate to parent namespace */
	if (mount("oldroot", "oldroot", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		fatalErr("remount oldroot");

	/* apply lazy umount on oldroot */
	if (umount2("oldroot", MNT_DETACH) < 0)
		fatalErr("umount2 oldroot");

	if (chdir("/newroot") == -1)
		fatalErr("chdir newroot");

	if (chroot("/newroot") == -1)
		fatalErr("chroot newroot");

	if (chdir("/") == -1)
		fatalErr("chdir /");

	/* if newpid was specified, mount a new proc, or let the /proc mounted
	 * by rootfs */
	if (child_args & CLONE_NEWPID)
		if (mount("proc", "/proc", "proc", 0, NULL) < 0)
			fatalErr("mount proc");
}

/* map user 1000 to user 0 (root) inside namespace */
static void set_maps(pid_t pid, const char *map) {
	int fd, data_len;
	char path[PATH_MAX];
	char data[] = "0 1000 1";

	if (!strncmp(map, "gid_map", 7)) {
		if (snprintf(path, PATH_MAX, "/proc/%d/setgroups", pid) < 0)
			fatalErr("snprintf");

		/* check if setgroups exists, in order to set the group map */
		fd = open(path, O_RDWR);
		if (fd == -1 && errno != ENOENT)
			fatalErr("setgroups");

		if (write(fd, "deny", 5) == -1)
			fatalErr("write setgroups");

		if (close(fd) == -1)
			fatalErr("close setgroups");
	}

	if (snprintf(path, PATH_MAX, "/proc/%d/%s", pid, map) < 0)
		fatalErr("snprintf");

	fd = open(path, O_RDWR);
	if (fd == -1)
		fatalErr(path);

	data_len = strlen(data);

	if (write(fd, data, data_len) != data_len)
		fatalErr("write");
}

static int child_func(void *arg)
{
	const char *argv0;
	int child_args = *(int *)arg;
	cap_t cap = cap_get_proc();

	/* blocked by parent process */
	if (child_args & CLONE_NEWUSER || child_args & CLONE_NEWNET)
		ret = read(wait_fd, &val, sizeof(char));

	setup_mountns();

	/* only active loopack is a new network namespace is created */
	if (child_args & CLONE_NEWNET)
		setup_network();

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0) == -1)
		fatalErr("prctl PR_SET_PRDEATHSIG");

	argv0 = (exec_file) ? exec_file : global_argv[0];
	if (!argv0)
		argv0 = "/bin/bash";

	verbose("PID: %d, PPID: %d\n", getpid(), getppid());
	verbose("eUID: %d, eGID: %d\n", geteuid(), getegid());
	verbose("capabilities: %s\n", cap_to_text(cap, NULL));

	/* avoid acquiring capabilities form the executable file on execlp */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == -1)
		fatalErr("PR_SET_NO_NEW_PRIVS");

	if (execvp(argv0, global_argv) == -1)
		fatalErr("execvp");

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n\n", argv0);
	fprintf(stderr,
		"--help                 Print this message\n"
		"--exec-file            Execute the specified file inside the sandbox\n"
		"--unshare-all          Create all supported namespaces\n"
		"--unshare-ipc          Create new IPC namespace\n"
		"--unshare-net          Create new network namespace\n"
		"--unshare-pid          Create new PID namespace\n"
		"--unshare-uts          Create new uts namespace\n"
		"--unshare-user         Create new user namespace\n"
		"--verbose              Enable verbose mode\n"
	);
}

int main(int argc, char **argv)
{
	pid_t pid;
	child_args = SIGCHLD | CLONE_NEWNS;
	int opt;

	static struct option long_opt[] = {
		{"exec-file", required_argument, 0, 'e'},
		{"help", no_argument, 0, 'h'},
		{"unshare-all", no_argument, 0, 'a'},
		{"unshare-ipc", no_argument, 0, 'i'},
		{"unshare-net", no_argument, 0, 'n'},
		{"unshare-pid", no_argument, 0, 'p'},
		{"unshare-uts", no_argument, 0, 'u'},
		{"unshare-user", no_argument, 0, 'U'},
		{"verbose", no_argument, 0, 'v'},
		{0, 0, 0, 0},
	};

	while (1) {
		opt = getopt_long(argc, argv, "hinmpuUve:", long_opt, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'a':
			child_args |= CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWPID
				| CLONE_NEWUTS | CLONE_NEWUSER;
			break;
		case 'i':
			child_args |= CLONE_NEWIPC;
			break;
		case 'n':
			child_args |= CLONE_NEWNET;
			break;
		case 'p':
			child_args |= CLONE_NEWPID;
			break;
		case 'u':
			child_args |= CLONE_NEWUTS;
			break;
		case 'U':
			child_args |= CLONE_NEWUSER;
			break;
		case 'e':
			exec_file = optarg;
			break;
		case 'v':
			enable_verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_FAILURE);
		default:
			/* don't bother with invalid options here */
			break;
		}
	}

	/* use the unparsed options in execvp later */
	global_argv = argv + optind;

	/* prepare sandbox base dir */
	if (snprintf(base_path, PATH_MAX, "/tmp/.ns_exec-%d", getuid()) < 0)
		fatalErr("prepare_tmpfs sprintf");

	if (mkdir(base_path, 0755) == -1 && errno != EEXIST)
		fatalErr("mkdir base_path err");

	if (child_args & CLONE_NEWUSER || child_args & CLONE_NEWNET) {
		wait_fd = eventfd(0, EFD_CLOEXEC);
		if (wait_fd == -1)
			fatalErr("eventfd");
	}

	/* stack grows downward */
	pid = clone(child_func, child_stack + STACK_SIZE, child_args
			, (void *)&child_args);
	if (pid == -1)
		fatalErr("clone");

	if (child_args & CLONE_NEWUSER) {
		set_maps(pid, "uid_map");
		set_maps(pid, "gid_map");
	}

	if (child_args & CLONE_NEWNET)
		setup_bridge(pid);

	if (child_args & CLONE_NEWUSER || child_args & CLONE_NEWNET)
		ret = write(wait_fd, &val, 8);

	if (waitpid(pid, NULL, 0) == -1)
		fatalErr("waitpid");

	return 0;
}
