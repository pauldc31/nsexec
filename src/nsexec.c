#define _GNU_SOURCE

#include <err.h>
#include <getopt.h>
#include <grp.h>
#include <sched.h>
#include <stdbool.h> /* true, false, bool */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
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

struct NS_ARGS ns_args;

static int child_func(void)
{
	const char *argv0;
	cap_t cap = cap_get_proc();

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "prctl PR_SET_PRDEATHSIG");

	/* blocked by parent process */
	if (read(wait_fd, &val, sizeof(val)) < 0)
		err(EXIT_FAILURE, "read error before setting mountns");

	setup_mountns(&ns_args);

	/* only configure network is a new netns is created */
	if (ns_args.child_args & CLONE_NEWNET)
		setup_container_network(ns_args.veth_ns);

	if (ns_args.child_args & CLONE_NEWUTS && ns_args.hostname) {
		verbose("hostname: %s\n", ns_args.hostname);

		if (sethostname(ns_args.hostname, strlen(ns_args.hostname)))
			err(EXIT_FAILURE, "Unable to set desired hostname");
		if (setenv("HOSTNAME", ns_args.hostname, 1) == -1)
			err(EXIT_FAILURE, "Unable to set HOSTNAME");
	}

	/* avoid acquiring capabilities form the executable file on execlp */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == -1)
		err(EXIT_FAILURE, "PR_SET_NO_NEW_PRIVS");

	if (!set_context(ns_args.lsm_context))
		errx(EXIT_FAILURE, "Could not set the LSM context");

	/* setup filter here, as a normal user, since we have NO_NEW_PRIVS */
	if (!install_seccomp_filter(ns_args.seccomp_filter))
		errx(EXIT_FAILURE, "Could not install seccomp filter");

	argv0 = (ns_args.exec_file) ? ns_args.exec_file
				: ns_args.global_argv[0];
	if (!argv0)
		argv0 = "bash";

	/* remove supplementay groups */
	setgroups(0, 0);

	verbose("PID: %d, PPID: %d\n", getpid(), getppid());
	verbose("eUID: %d, eGID: %d\n", geteuid(), getegid());
	verbose("capabilities: %s\n", cap_to_text(cap, NULL));

	if (execvp(argv0, ns_args.global_argv) == -1)
		err(EXIT_FAILURE, "execvp");

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [OPTIONS] [ARGUMENTS]\n\n", argv0);
	fprintf(stderr,
		"OPTIONS:\n"
		"--chdir                Change directory inside the container\n"
		"--bind                 Execute a bind mount\n"
		"--bind-ro              Execute a bind mount read-only\n"
		"--exec-file            Execute the specified file inside the sandbox\n"
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

	memset(&ns_args, 0, sizeof(ns_args));
	ns_args.child_args = SIGCHLD | CLONE_NEWNS | CLONE_NEWUSER;

	static struct option long_opt[] = {
		{"chdir", required_argument, 0, 'c'},
		{"bind", required_argument, 0, 'b'},
		{"bind-ro", required_argument, 0, 'B'},
		{"exec-file", required_argument, 0, 'e'},
		{"graphics", no_argument, 0, 'g'},
		{"gid", required_argument, 0, 'X'},
		{"help", no_argument, 0, 'h'},
		{"hostname", required_argument, 0, 's'},
		{"lsm-context", required_argument, 0, 'l'},
		{"rootfs", required_argument, 0, 'r'},
		{"same-pod-of", required_argument, 0, 'P'},
		{"seccomp-keep", required_argument, 0, 'k'},
		{"symlink", required_argument, 0, 'S'},
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
		opt = getopt_long(argc, argv, "eshainpuUvk:l:r:b:B:S:c:",
				long_opt, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'a':
			ns_args.child_args |= CLONE_NEWIPC | CLONE_NEWNET
				| CLONE_NEWPID | CLONE_NEWUTS;
			break;
		case 'i':
			ns_args.child_args |= CLONE_NEWIPC;
			break;
		case 'n':
			ns_args.child_args |= CLONE_NEWNET;
			break;
		case 'p':
			ns_args.child_args |= CLONE_NEWPID;
			break;
		case 'u':
			ns_args.child_args |= CLONE_NEWUTS;
			break;
		case 'e':
			ns_args.exec_file = optarg;
			break;
		case 's':
			ns_args.hostname = optarg;
			break;
		case 'g':
			ns_args.graphics_enabled = true;
			ns_args.session = getenv("XDG_SESSION_TYPE");
			ns_args.display = getenv("DISPLAY");
			break;
		case 'v':
			enable_verbose = 1;
			break;
		case 'k':
			ns_args.seccomp_filter = optarg;
			break;
		case 'x':
		{
			char* endptr;
			ns_args.ns_user = strtol(optarg, &endptr, 10);
			if (ns_args.ns_user < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid uid: %s", optarg);
			break;
		}
		case 'X':
		{
			char *endptr;
			ns_args.ns_group = strtol(optarg, &endptr, 10);
			if (ns_args.ns_group < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid gid: %s", optarg);
			break;
		}
		case 'P':
		{
			char *endptr;
			ns_args.pod_pid = strtol(optarg, &endptr, 10);
			if (ns_args.ns_group < 0 || endptr[0] != 0)
				errx(EXIT_FAILURE, "Invalid pid: %s", optarg);
			break;
		}
		case 'l':
			ns_args.lsm_context = optarg;
			break;
		case 'r':
			ns_args.rootfs = optarg;
			break;
		case 'b':
			handle_mount_opts(&(ns_args.mount_list), optarg,
					MOUNT_RW);
			break;
		case 'B':
			handle_mount_opts(&ns_args.mount_list, optarg,
					MOUNT_RO);
			break;
		case 'S':
			handle_mount_opts(&ns_args.link_list, optarg, SYMLINK);
			break;
		case 'c':
			ns_args.chdir = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			/* don't bother with invalid options here */
			break;
		}
	}

	ns_args.term = getenv("TERM");

	if (ns_args.hostname && !(ns_args.child_args & CLONE_NEWUTS))
		errx(EXIT_FAILURE, "--hostname is valid only with --unshare-uts"
			       "option");

	/* FIXME: pod is not working yet, nsexec would need a new binary with
	 * CAP_SYS_ROOT to enter in an existing namespace
	 **/
	if (ns_args.pod_pid && ns_args.child_args ^ (SIGCHLD | CLONE_NEWNS
				| CLONE_NEWUSER))
		errx(EXIT_FAILURE, "--same-pod-of can't be used with unshare "
					"flags\n");
}

int main(int argc, char **argv)
{
	pid_t pid;
	int pstatus;

	/* don't allow this tool be executed as root */
	if (geteuid() == 0)
		errx(EXIT_FAILURE, "%s was designed to be executed as non-root."
				" Aborting", argv[0]);

	handle_arguments(argc, argv);

	/* use the unparsed options in execvp later */
	ns_args.global_argv = argv + optind;

	/* this will make the child process to wait for the parent setup */
	wait_fd = eventfd(0, EFD_CLOEXEC);
	if (wait_fd == -1)
		err(EXIT_FAILURE, "eventfd");

	if (ns_args.child_args & CLONE_NEWNET)
		setup_veth_names(ns_args.veth_h, ns_args.veth_ns);

	pid = syscall(__NR_clone, ns_args.child_args, NULL);
	if (pid == -1)
		err(EXIT_FAILURE, "clone");

	/* child, setup the new tmpfs, and call the proper exec routine */
	else if (pid == 0)
		child_func();

	/* parent, set user mapping and the necessary network */
	set_maps(pid, "uid_map", &ns_args);
	set_maps(pid, "gid_map", &ns_args);

	if (ns_args.child_args & CLONE_NEWNET)
		create_bridge(pid, ns_args.veth_h, ns_args.veth_ns);

	verbose("Child pid: %d\n", pid);

	/* write to eventfd after setting uid maps and network if needed */
	if (write(wait_fd, &val, sizeof(val)) < 0)
		err(EXIT_FAILURE, "write error on signaling child process");

	if (waitpid(pid, &pstatus, 0) == -1)
		err(EXIT_FAILURE, "waitpid");

	/* return the exit code from the container's process */
	return WEXITSTATUS(pstatus);
}
