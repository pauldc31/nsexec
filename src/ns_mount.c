#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h> /* CLONE_NEW* */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "helper.h"

/* map user 1000 to user 0 (root) inside namespace */
void set_maps(pid_t pid, const char *map, int ns_user, int ns_group) {
	int fd, data_len;
	char path[PATH_MAX], data[30];
	bool map_user = !strncmp(map, "uid_map", 7);

	if (sprintf(data, "%d %d 1\n", map_user ? ns_user : ns_group
				, map_user ? getuid() : getgid()) < 0)
		err(EXIT_FAILURE, "set_maps data");

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

void setup_mountns(int child_args, bool graphics_enabled)
{
	struct mount_setup {
		char *dirn;
		char *mntd;
	};

	struct mount_setup *mp, mount_list[] = {
		{"newroot", NULL},
		{"newroot/bin", "oldroot/bin"},
		{"newroot/dev", NULL},
		{"newroot/dev/pts", NULL},
		{"newroot/dev/shm", NULL},
		{"newroot/etc/","oldroot/etc/"},
		{"newroot/lib", "oldroot/lib"},
		{"newroot/lib64", "oldroot/lib64"},
		{"newroot/tmp", NULL},
		{"newroot/usr", "oldroot/usr"},
		{NULL, NULL}
	};

	/* 9         + 4    + 7 (bigger dev string) + 21 (with null) */
	/* /oldroot/ + dev/ + urandom*/
	/* /newroot/ + dev/ + urandom*/
	char dev_opath[21], dev_npath[21], base_path[PATH_MAX];
	const char **devp, *sym_devs[] = {"full", "null", "random", "tty",
		"urandom", NULL};

	/* prepare sandbox base dir */
	if (snprintf(base_path, PATH_MAX, "/tmp/.ns_exec-%d", getuid()) < 0)
		err(EXIT_FAILURE, "prepare_tmpfs sprintf");

	if (mkdir(base_path, 0755) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkdir base_path err");

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

		} else if (!strncmp(session, "wayland", 7)) {
			if (symlink("oldroot/run/user/1000/wayland-0",
				"newroot/tmp/wayland-0") < 0)
				err(EXIT_FAILURE, "symlink Wayland");

			if (setenv("XDG_RUNTIME_DIR", "/tmp", 1) < 0)
				err(EXIT_FAILURE, "setenv failed");
		}
	}

	struct mount_setup *ms, dev_symlinks[] = {
		{"/proc/self/fd", "newroot/dev/fd"},
		{"/proc/self/fd/0", "newroot/dev/stdin"},
		{"/proc/self/fd/1", "newroot/dev/stdout"},
		{"/proc/self/fd/2", "newroot/dev/stderr"},
		{NULL, NULL}
	};

	for (ms = dev_symlinks; ms->dirn; ms++) {
		int ret = symlink(ms->dirn, ms->mntd);
		if (ret && errno != EEXIST)
			err(EXIT_FAILURE, "linking %s", ms->mntd);
	}

	/* if newpid was specified, mount a new proc */
	if (child_args & CLONE_NEWPID) {
		if (mkdir("newroot/proc", 0755) == -1)
			err(EXIT_FAILURE, "mkdir /proc");

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

	if (symlink("/dev/pts/ptmx", "/dev/ptmx") == -1)
		err(EXIT_FAILURE, "symlnk ptmx failed");
}
