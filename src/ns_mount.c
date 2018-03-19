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

/* simplify error handling and boilerplate mount code */
static void mount_help(char *src, char *dst, char *typ, long flags, char *data)
{
	if (mount(src, dst, typ, flags, data) < 0)
		err(EXIT_FAILURE, "mount %s -> %s, type: %s", src, dst, typ);
}

/*
 * Expects a mount with src and dst like below:
 * 	/tmp/UNIX,/etc/UNIX
 **/
void handle_mount_opts(struct NS_ARGS *args, char *str_mount, MOUNT_FLAG flag)
{
	struct MOUNT_LIST *entry, *iter;
	char *src, *dst, *saveptr;

	entry = (struct MOUNT_LIST *)malloc(sizeof(struct MOUNT_LIST));
	entry->mount_type = flag;
	entry->next = NULL;

	src = strtok_r(str_mount, ",", &saveptr);
	if (!src)
		errx(EXIT_FAILURE, "Wrong src bind paths: %s", str_mount);

	dst = strtok_r(NULL, ",", &saveptr);
	if (!dst)
		errx(EXIT_FAILURE, "Wrong dst bind paths: %s", str_mount);

	entry->src = src;
	entry->dst = dst;

	if (!args->mount_list) {
		args->mount_list = entry;
		return;
	}

	/* for now, just iterates over the mount list until the end */
	iter = args->mount_list;
	while (iter->next)
		iter = iter->next;
	iter->next = entry;
}

static void execute_additional_mounts(struct NS_ARGS *ns_args, char *src_prefix,
		char *dst_prefix)
{
	struct MOUNT_LIST *iter;
	char dst[PATH_MAX];
	char src[PATH_MAX];

	for (iter = ns_args->mount_list; iter; iter = iter->next) {
		int flags = MS_BIND;
		snprintf(dst, PATH_MAX, "%s%s", dst_prefix ? dst_prefix : "",
				iter->dst);
		snprintf(src, PATH_MAX, "%s%s", src_prefix ? src_prefix : "",
				iter->src);

		mount_help(src, dst, NULL, flags, NULL);

		/* WORKAROUND: https://bugzilla.redhat.com/show_bug.cgi?id=584484 */
		if (iter->mount_type == MOUNT_RO) {
			flags |= MS_REMOUNT | MS_RDONLY;
			mount_help(src, dst, NULL, flags, NULL);
		}
	}
}

static void mount_new_proc(struct NS_ARGS *ns_args, char *bpath)
{
	char proc_path[PATH_MAX];
	sprintf(proc_path, "%s/proc", bpath ? bpath : "");

	/* if newpid was specified, mount a new proc */
	if (ns_args->child_args & CLONE_NEWPID) {
		if (mkdir(proc_path, 0755) == -1 && errno != EEXIST)
			err(EXIT_FAILURE, "mkdir /proc");

		mount_help("proc", proc_path, "proc", 0, NULL);
	}
}

static void set_graphics(bool graphics_enabled, const char *session,
		const char *display)
{
	/* check for both Xorg or Wayland */
	if (graphics_enabled) {
		if (!session)
			errx(EXIT_FAILURE, "XDG_SESSION_TYPE not defined");

		if (!strncmp(session, "x11", 3)) {
			if (mkdir("newroot/tmp/.X11-unix", 0755) == -1)
				err(EXIT_FAILURE, "mkdir X11 failed");

			mount_help("oldroot/tmp/.X11-unix",
				"newroot/tmp/.X11-unix" , NULL,
				MS_BIND | MS_REC, NULL);
		} else if (!strncmp(session, "wayland", 7)) {
			if (symlink("oldroot/run/user/1000/wayland-0",
				"newroot/tmp/wayland-0") < 0)
				err(EXIT_FAILURE, "symlink Wayland");
			if (setenv("XDG_RUNTIME_DIR", "/tmp", 1) < 0)
				err(EXIT_FAILURE, "setenv failed");
		}
		if (setenv("DISPLAY", display, 1) < 0)
			err(EXIT_FAILURE, "set display");
	}
}

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

void setup_mountns(struct NS_ARGS *ns_args)
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
		{"newroot/mnt", NULL},
		{"newroot/tmp", NULL},
		{"newroot/usr", "oldroot/usr"},
		{NULL, NULL}
	};

	const char *session = getenv("XDG_SESSION_TYPE");
	const char *display = getenv("DISPLAY");
	const char *term = getenv("TERM");

	/* 9         + 4    + 7 (bigger dev string) + 21 (with null) */
	/* /oldroot/ + dev/ + urandom*/
	/* /newroot/ + dev/ + urandom*/
	char dev_opath[21], dev_npath[21], bpath[PATH_MAX] = {0};
	const char **devp, *sym_devs[] = {"full", "null", "random", "tty",
		"urandom", NULL};

	if (clearenv())
		err(EXIT_FAILURE, "clearenv");

	if (setenv("PATH", "/usr/bin:/bin/:/usr/sbin:/sbin:/usr/local/bin:"
				"/usr/local/sbin", 1) < 0)
		err(EXIT_FAILURE, "set path");

	if (term && setenv("TERM", term, 1) < 0)
		err(EXIT_FAILURE, "set term");

	/* set / as slave, so changes from here won't be propagated to parent
	 * namespace */
	mount_help(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL);

	if (ns_args->rootfs) {
		if (chroot(ns_args->rootfs) == -1)
			err(EXIT_FAILURE, "chroot newroot");

		if (chdir("/") == -1)
			err(EXIT_FAILURE, "rootfs chdir");

		set_graphics(ns_args->graphics_enabled, session, display);
		mount_new_proc(ns_args, NULL);

		return;
	}

	/* prepare sandbox base dir */
	if (snprintf(bpath, PATH_MAX, "/tmp/.ns_exec-%d", getuid()) < 0)
		err(EXIT_FAILURE, "prepare_tmpfs sprintf");

	if (mkdir(bpath, 0755) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkdir bpath err");

	mount_help("", bpath, "tmpfs", MS_NOSUID | MS_NODEV, NULL);

	if (chdir(bpath) == -1)
		err(EXIT_FAILURE, "chdir");

	/* prepare pivot_root environment */
	if (mkdir("oldroot", 0755) == -1)
		err(EXIT_FAILURE, "oldroot");

	/* there is not a wrapper in glibc for pivot_root */
	if (syscall(__NR_pivot_root, bpath, "oldroot") == -1)
		err(EXIT_FAILURE, "pivot_root");

	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir to new root");

	for (mp = mount_list; mp->dirn; mp++) {
		if (mkdir(mp->dirn, 0755) == -1)
			err(EXIT_FAILURE, "mkdir %s\n", mp->dirn);

		if (mp->mntd)
			mount_help(mp->mntd, mp->dirn, NULL,
					MS_BIND | MS_RDONLY, NULL);
	}

	execute_additional_mounts(ns_args, "/oldroot", "/newroot");
	mount_new_proc(ns_args, "/newroot");

	mount_help("devpts", "newroot/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=620");

	/* bind-mount /dev devices from hosts, following what bubblewrap does
	 * when using user-namespaces
	 * */
	/* FIXME: This can be umounted by container, how to fix it?? */
	for (devp = sym_devs; *devp; devp++) {
		sprintf(dev_opath, "oldroot/dev/%s", *devp);
		sprintf(dev_npath, "newroot/dev/%s", *devp);

		if (creat(dev_npath, 0666) == -1)
			err(EXIT_FAILURE, "creat failed for %s", dev_npath);

		mount_help(dev_opath, dev_npath, NULL, MS_BIND, NULL);
	}

	set_graphics(ns_args->graphics_enabled, session, display);

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

	/* remount oldroot no not propagate to parent namespace */
	mount_help("oldroot", "oldroot", NULL, MS_REC | MS_PRIVATE, NULL);

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
