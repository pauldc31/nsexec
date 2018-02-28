#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h> /* true, false, bool */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "helper.h"
#include "ns_mount.h"
#include "ns_network.h"
#include "ns_seccomp.h"
#include "lsm.h"

int enable_verbose = 0;

static int wait_fd = -1;
static uint64_t val = 1;
/* vethXXXX */
static char veth_h[9] = {0}, veth_ns[9] = {0};
const char *exec_file = NULL;
const char *hostname = NULL;
static bool graphics_enabled = false;
static char *seccomp_filter = NULL;
static char *lsm_context = NULL;
static int ns_user = 0;
static int ns_group = 0;
static struct passwd *ns_pwd;
static int child_args = SIGCHLD | CLONE_NEWNS | CLONE_NEWUSER;
static int pod_pid = -1;
char **global_argv;

static int child_func(void)
{
	const char *argv0;
	cap_t cap = cap_get_proc();

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "prctl PR_SET_PRDEATHSIG");

	/* blocked by parent process */
	if (read(wait_fd, &val, sizeof(val)) < 0)
		err(EXIT_FAILURE, "read error before setting mountns");

	setup_mountns(child_args, graphics_enabled, ns_pwd
							? ns_pwd->pw_name
							: NULL);

	/* only configure network is a new netns is created */
	if (child_args & CLONE_NEWNET)
		setup_container_network(veth_ns);

	argv0 = (exec_file) ? exec_file : global_argv[0];
	if (!argv0)
		argv0 = "bash";

	verbose("PID: %d, PPID: %d\n", getpid(), getppid());
	verbose("eUID: %d, eGID: %d\n", geteuid(), getegid());
	verbose("capabilities: %s\n", cap_to_text(cap, NULL));

	if (child_args & CLONE_NEWUTS && hostname) {
		verbose("hostname: %s\n", hostname);

		if (sethostname(hostname, strlen(hostname)) == -1)
			err(EXIT_FAILURE, "Unable to set desired hostname");
		if (setenv("HOSTNAME", hostname, 1) == -1)
			err(EXIT_FAILURE, "Unable to set HOSTNAME");
	}

	/* avoid acquiring capabilities form the executable file on execlp */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "PR_SET_NO_NEW_PRIVS");

	if (!set_context(lsm_context))
		errx(EXIT_FAILURE, "Could not set the LSM context");

	/* setup filter here, as a normal user, since we have NO_NEW_PRIVS */
	if (!install_seccomp_filter(seccomp_filter))
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
		"--exec                 Execute the specified file inside the sandbox\n"
		"--graphics             Bind xorg/wayland files into the container\n"
		"--help                 Print this message\n"
		"--uid                  Specify an UID to be executed inside the container\n"
		"--gid                  Specify an GID to be executed inside the container\n"
		"--same-pod-of          Specify a pid to share the same namespaces (can't be used with unshare flags\n"
		"--seccomp-keep         Enable seccomp by adding only the specified syscalls to whitelist\n"
		"--lsm-context          Specify a cotext to be used in SELinux\n"
		"--unshare-all          Create all supported namespaces\n"
		"--unshare-ipc          Create new IPC namespace\n"
		"--unshare-net          Create new network namespace\n"
		"--unshare-pid          Create new PID namespace\n"
		"--unshare-uts          Create new uts namespace\n"
		"--unshare-user         Create new user namespace\n"
		"--verbose              Enable verbose mode\n\n"
		"ARGUMENTS:\n"
		"--hostname             To start with desired hostname (only valid with --unshare-uts option)\n"
	);
}

static void handle_arguments(int argc, char **argv)
{
	int opt;
	static struct option long_opt[] = {
		{"exec-file", required_argument, 0, 'e'},
		{"graphics", no_argument, 0, 'g'},
		{"gid", required_argument, 0, 'X'},
		{"help", no_argument, 0, 'h'},
		{"hostname", required_argument, 0, 's'},
		{"lsm-context", required_argument, 0, 'l'},
		{"same-pod-of", required_argument, 0, 'P'},
		{"seccomp-keep", required_argument, 0, 'k'},
		{"unshare-all", no_argument, 0, 'a'},
		{"unshare-ipc", no_argument, 0, 'i'},
		{"unshare-net", no_argument, 0, 'n'},
		{"unshare-pid", no_argument, 0, 'p'},
		{"unshare-uts", no_argument, 0, 'u'},
		{"uid", required_argument, 0, 'x'},
		{"verbose", no_argument, 0, 'v'},
		{0, 0, 0, 0},
	};

	while (1) {
		opt = getopt_long(argc, argv, "eshainpuUvk:l:", long_opt, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'a':
			child_args |= CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWPID
				| CLONE_NEWUTS;
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
		case 'x':
		{
			char* endptr;
			ns_user = strtol(optarg, &endptr, 10);
			if (ns_user < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid uid: %s", optarg);
			break;
		}
		case 'X':
		{
			char *endptr;
			ns_group = strtol(optarg, &endptr, 10);
			if (ns_group < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid gid: %s", optarg);
			break;
		}
		case 'P':
		{
			char *endptr;
			pod_pid = strtol(optarg, &endptr, 10);
			if (ns_group < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid pid: %s", optarg);
			break;
		}
		case 'l':
			lsm_context = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			/* don't bother with invalid options here */
			break;
		}
	}
}

int main(int argc, char **argv)
{
	pid_t pid;
	int pstatus;

	handle_arguments(argc, argv);

	if (hostname && !(child_args & CLONE_NEWUTS))
		errx(EXIT_FAILURE, "--hostname is valid only with --unshare-uts"
			       "option");

	if (pod_pid != -1 && child_args ^ (SIGCHLD | CLONE_NEWNS |
				CLONE_NEWUSER))
		errx(EXIT_FAILURE, "--same-pod-of can't be used with unshare "
					"flags\n");

	/* use the unparsed options in execvp later */
	global_argv = argv + optind;

	/* this will make the child process to wait for the parent setup */
	wait_fd = eventfd(0, EFD_CLOEXEC);
	if (wait_fd == -1)
		err(EXIT_FAILURE, "eventfd");

	if (child_args & CLONE_NEWNET)
		setup_veth_names(veth_h, veth_ns);

	/* get the username of the user insde the namespace */
	ns_pwd = getpwuid(ns_user);

	/* stack grows downward */
	pid = syscall(__NR_clone, child_args, NULL);
	if (pid == -1)
		err(EXIT_FAILURE, "clone");

	/* child, setup the new tmpfs, and call the proper exec routine */
	else if (pid == 0)
		child_func();

	/* parent, set user mapping and the necessary network */
	set_maps(pid, "uid_map", ns_user, ns_group);
	set_maps(pid, "gid_map", ns_user, ns_group);

	if (child_args & CLONE_NEWNET)
		create_bridge(pid, veth_h, veth_ns);

	/* write to eventfd after setting uid maps and network if needed */
	if (write(wait_fd, &val, sizeof(val)) < 0)
		err(EXIT_FAILURE, "write error on signaling child process");

	if (waitpid(pid, &pstatus, 0) == -1)
		err(EXIT_FAILURE, "waitpid");

	/* return the exit code from the container's process */
	return WEXITSTATUS(pstatus);
}
