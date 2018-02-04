#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h> /* true, false, bool */
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
#include <uuid/uuid.h>

#include "ns_network.h"
#include "ns_seccomp.h"

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static int child_args;
static char base_path[PATH_MAX];
static int enable_verbose = 0;
static int wait_fd = -1;
static uint64_t val = 1;
/* vethXXXX */
static char veth_h[9] = {}, veth_ns[9] = {};
const char *exec_file = NULL;
const char *hostname = NULL;
static bool graphics_enabled = false;
static char *seccomp_filter = NULL;
char **global_argv;

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

static void setup_veth_names(void)
{
	static uuid_t gen_uuid;
	char uuid_parsed[37];

	uuid_generate_random(gen_uuid);
	uuid_unparse_upper(gen_uuid, uuid_parsed);

	/* copy just the first foud characters from uuid for veth_h */
	if (snprintf(veth_h, 9, "veth%s", uuid_parsed) < 0)
		err(EXIT_FAILURE, "building veth_h");

	/* copy the next four characters from the start of the uuid */
	if (snprintf(veth_ns, 9, "veth%s", uuid_parsed + 4) < 0)
		err(EXIT_FAILURE, "building veth_ns");
}

static void setup_mountns(void)
{
	struct {
		char *dirn;
		char *mntd;
	} *mp, mount_list[] = {
		{"newroot", NULL},
		{"newroot/dev", NULL},
		{"newroot/dev/shm", NULL},
		{"newroot/dev/pts", NULL},
		{"newroot/tmp", NULL},
		{"newroot/usr", "oldroot/usr"},
		{"newroot/bin", "oldroot/bin"},
		{"newroot/lib", "oldroot/lib"},
		{"newroot/lib64", "oldroot/lib64"},
		{NULL, NULL}
	};

	/* 9         + 4    + 7 (bigger dev string) + 21 (with null) */
	/* /oldroot/ + dev/ + urandom*/
	/* /newroot/ + dev/ + urandom*/
	char dev_opath[21], dev_npath[21];
	const char **devp, *sym_devs[] = {"full", "null", "random", "tty",
		"urandom", NULL};

	/* set / as slave, so changes from here won't be propagated to parent
	 * namespace */
	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
		err(EXIT_FAILURE, "mount recursive slave");

	if (mount("", base_path, "tmpfs", MS_NOSUID | MS_NODEV, NULL) < 0)
		err(EXIT_FAILURE, "mount tmpfs");

	if (chdir(base_path) == -1)
		err(EXIT_FAILURE, "chdir");

	/* prepare pivot_root environment */
	if (mkdir("oldroot", 0755) == -1)
		err(EXIT_FAILURE, "oldroot");

	/* there is not a wrapper in glibc for pivot_root */
	if (syscall(__NR_pivot_root, base_path, "oldroot") == -1)
		err(EXIT_FAILURE, "pivot_root");

	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir to new root");

	for (mp = mount_list; mp->dirn; mp++) {
		if (mkdir(mp->dirn, 0755) == -1)
			err(EXIT_FAILURE, "mkdir %s\n", mp->dirn);

		if (mp->mntd)
			if (mount(mp->mntd, mp->dirn, NULL, MS_BIND | MS_RDONLY,
						NULL) < 0)
				err(EXIT_FAILURE, "mount bind %s\n", mp->mntd);
	}

	if (mount("devpts", "newroot/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=620") != 0)
		err(EXIT_FAILURE, "mount devpts failed");

	/* bind-mount /dev devices from hosts, following what bubblewrap does
	 * when using user-namespaces
	 * */
	/* FIXME: This can be umounted by container, how to fix it?? */
	for (devp = sym_devs; *devp; devp++) {
		sprintf(dev_opath, "oldroot/dev/%s", *devp);
		sprintf(dev_npath, "newroot/dev/%s", *devp);

		if (creat(dev_npath, 0666) == -1)
			err(EXIT_FAILURE, "creat failed for %s", dev_npath);

		if (mount(dev_opath, dev_npath, NULL, MS_BIND, NULL) < 0)
			err(EXIT_FAILURE, "failed to mount %s into %s",
					dev_opath, dev_npath);
	}

	/* check for both Xorg or Wayland */
	if (graphics_enabled) {
		const char *session = getenv("XDG_SESSION_TYPE");
		if (!session)
			errx(EXIT_FAILURE, "XDG_SESSION_TYPE not defined");

		if (!strncmp(session, "x11", 3)) {
			if (mkdir("newroot/tmp/.X11-unix", 0755) == -1)
				err(EXIT_FAILURE, "mkdir X11 failed");

			if (mount("oldroot/tmp/.X11-unix", "newroot/tmp/.X11-unix"
				, NULL, MS_BIND | MS_REC, NULL) < 0)
				err(EXIT_FAILURE, "bind mount X11");
		}
	}

	/* if newpid was specified, mount a new proc */
	if (child_args & CLONE_NEWPID) {
		if (mkdir("newroot/proc", 0755) == -1)
			err(EXIT_FAILURE, "mkdir etc");

		if (mount("proc", "newroot/proc", "proc", 0, NULL) < 0)
			err(EXIT_FAILURE, "mount proc");
	}

	/* remount oldroot no not propagate to parent namespace */
	if (mount("oldroot", "oldroot", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		err(EXIT_FAILURE, "remount oldroot");

	/* apply lazy umount on oldroot */
	if (umount2("oldroot", MNT_DETACH) < 0)
		err(EXIT_FAILURE, "umount2 oldroot");

	if (chdir("/newroot") == -1)
		err(EXIT_FAILURE, "chdir newroot");

	if (chroot("/newroot") == -1)
		err(EXIT_FAILURE, "chroot newroot");

	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir /");

	/* bind mount new resolv.conf pointing to the bridge connection */
	if (child_args & CLONE_NEWNET) {
		if (mkdir("/etc/", 0755) == -1)
			err(EXIT_FAILURE, "mkdir etc");

		int fd = open("/etc/resolv.conf", O_WRONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
		if ( fd == -1)
			err(EXIT_FAILURE, "open resolv.conf wronly");

		const char *nameserver = "nameserver 192.168.122.1\n";
		if (write(fd, nameserver, strlen(nameserver)) == -1)
			err(EXIT_FAILURE, "write resolve.conf");
	}

	if (symlink("/dev/pts/ptmx", "/dev/ptmx") == -1)
		err(EXIT_FAILURE, "symlnk ptmx failed");
}

/* map user 1000 to user 0 (root) inside namespace */
static void set_maps(pid_t pid, const char *map) {
	int fd, data_len;
	char path[PATH_MAX];
	char data[] = "0 1000 1";

	if (!strncmp(map, "gid_map", 7)) {
		if (snprintf(path, PATH_MAX, "/proc/%d/setgroups", pid) < 0)
			err(EXIT_FAILURE, "snprintf");

		/* check if setgroups exists, in order to set the group map */
		fd = open(path, O_RDWR);
		if (fd == -1 && errno != ENOENT)
			err(EXIT_FAILURE, "setgroups");

		if (write(fd, "deny", 5) == -1)
			err(EXIT_FAILURE, "write setgroups");

		if (close(fd) == -1)
			err(EXIT_FAILURE, "close setgroups");
	}

	if (snprintf(path, PATH_MAX, "/proc/%d/%s", pid, map) < 0)
		err(EXIT_FAILURE, "snprintf");

	fd = open(path, O_RDWR);
	if (fd == -1)
		err(EXIT_FAILURE, "set maps %s", path);

	data_len = strlen(data);

	if (write(fd, data, data_len) != data_len)
		err(EXIT_FAILURE, "write");
}

static int child_func(void *arg)
{
	const char *argv0;
	int c_args = *(int *)arg;
	cap_t cap = cap_get_proc();

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "prctl PR_SET_PRDEATHSIG");

	/* blocked by parent process */
	if (c_args & CLONE_NEWUSER || c_args & CLONE_NEWNET)
		if (read(wait_fd, &val, sizeof(val)) < 0)
			err(EXIT_FAILURE, "read error before setting mountns");

	setup_mountns();

	/* only configure network is a new netns is created */
	if (c_args & CLONE_NEWNET)
		setup_container_network(veth_ns);

	argv0 = (exec_file) ? exec_file : global_argv[0];
	if (!argv0)
		argv0 = "bash";

	verbose("PID: %d, PPID: %d\n", getpid(), getppid());
	verbose("eUID: %d, eGID: %d\n", geteuid(), getegid());
	verbose("capabilities: %s\n", cap_to_text(cap, NULL));

	if (c_args & CLONE_NEWUTS && hostname) {
		verbose("hostname: %s\n", hostname);

		if (sethostname(hostname, strlen(hostname)) == -1)
			err(EXIT_FAILURE, "Unable to set desired hostname");
	}

	/* avoid acquiring capabilities form the executable file on execlp */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "PR_SET_NO_NEW_PRIVS");

	/* setup filter here, as a normal user, since we have NO_NEW_PRIVS */
	if (seccomp_filter && !install_seccomp_filter(seccomp_filter))
		errx(EXIT_FAILURE, "Could not install seccomp filter");

	if (execvp(argv0, global_argv) == -1)
		err(EXIT_FAILURE, "execvp");

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [OPTIONS] [ARGUMENTS]\n\n", argv0);
	fprintf(stderr,
		"OPTIONS:\n"
		"--help                 Print this message\n"
		"--exec-file            Execute the specified file inside the sandbox\n"
		"--unshare-all          Create all supported namespaces\n"
		"--unshare-ipc          Create new IPC namespace\n"
		"--unshare-net          Create new network namespace\n"
		"--unshare-pid          Create new PID namespace\n"
		"--unshare-uts          Create new uts namespace\n"
		"--unshare-user         Create new user namespace\n"
		"--graphics             Bind xorg/wayland files into the container\n"
		"--seccomp-keep         Enable seccomp by adding only the specified syscalls to whitelist\n"
		"--verbose              Enable verbose mode\n\n"
		"ARGUMENTS:\n"
		"--hostname             To start with desired hostname (only valid with --unshare-uts option)\n"
	);
}

int main(int argc, char **argv)
{
	pid_t pid;
	child_args = SIGCHLD | CLONE_NEWNS;
	int opt, pstatus;

	static struct option long_opt[] = {
		{"exec-file", required_argument, 0, 'e'},
		{"hostname", required_argument, 0, 's'},
		{"seccomp-keep", required_argument, 0, 'k'},
		{"help", no_argument, 0, 'h'},
		{"unshare-all", no_argument, 0, 'a'},
		{"unshare-ipc", no_argument, 0, 'i'},
		{"unshare-net", no_argument, 0, 'n'},
		{"unshare-pid", no_argument, 0, 'p'},
		{"unshare-uts", no_argument, 0, 'u'},
		{"unshare-user", no_argument, 0, 'U'},
		{"graphics", no_argument, 0, 'g'},
		{"verbose", no_argument, 0, 'v'},
		{0, 0, 0, 0},
	};

	while (1) {
		opt = getopt_long(argc, argv, "eshainpuUv:k:", long_opt, NULL);
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
		case 's':
			hostname = optarg;
			break;
		case 'g':
			graphics_enabled = true;
			break;
		case 'v':
			enable_verbose = 1;
			break;
		case 'k':
			seccomp_filter = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_FAILURE);
		default:
			/* don't bother with invalid options here */
			break;
		}
	}

	if (hostname && !(child_args & CLONE_NEWUTS))
		errx(EXIT_FAILURE, "--hostname is valid only with --unshare-uts"
			       "option");

	/* use the unparsed options in execvp later */
	global_argv = argv + optind;

	/* prepare sandbox base dir */
	if (snprintf(base_path, PATH_MAX, "/tmp/.ns_exec-%d", getuid()) < 0)
		err(EXIT_FAILURE, "prepare_tmpfs sprintf");

	if (mkdir(base_path, 0755) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkdir base_path err");

	if (child_args & CLONE_NEWUSER || child_args & CLONE_NEWNET) {
		wait_fd = eventfd(0, EFD_CLOEXEC);
		if (wait_fd == -1)
			err(EXIT_FAILURE, "eventfd");
	}

	if (child_args & CLONE_NEWNET)
		setup_veth_names();

	/* stack grows downward */
	pid = clone(child_func, child_stack + STACK_SIZE, child_args
			, (void *)&child_args);
	if (pid == -1)
		err(EXIT_FAILURE, "clone");

	if (child_args & CLONE_NEWUSER) {
		set_maps(pid, "uid_map");
		set_maps(pid, "gid_map");
	}

	if (child_args & CLONE_NEWNET)
		create_bridge(pid, veth_h, veth_ns);

	if (child_args & CLONE_NEWUSER || child_args & CLONE_NEWNET)
		if (write(wait_fd, &val, sizeof(val)) < 0)
			err(EXIT_FAILURE, "write error on signaling child process");

	if (waitpid(pid, &pstatus, 0) == -1)
		err(EXIT_FAILURE, "waitpid");

	// FIXME: is this necessary? Does the veth interface in host dies when
	// the container finishes??
	//if (child_args & CLONE_NEWNET)
	//	delete_bridge(pid, veth_h);

	/* return the exit code from the container's process */
	return WEXITSTATUS(pstatus);
}
