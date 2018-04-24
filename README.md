# nsexec

[![Build Status](https://travis-ci.org/marcosps/nsexec.svg?branch=master)](https://travis-ci.org/marcosps/nsexec/)

----

The nsexec is just an experiment, inspired by [bubblewrap](https://github.com/projectatomic/bubblewrap)
and [lxc](https://github.com/lxc/lxc) in order to learn all the concepts used by
Linux containers, by using the same ideas an techniques used by both project.

This tool is designed to be executed by an oridnary user. So, running as root
will return an error. User namespace and mount namespaces are used by default.

### building
------------

Dependencies:

	libcap
	libnl-route-3.0
	libseccomp
	libselinux (optinal)
	libuuid
	shadow-utils (for new{u,g}idmap

nsexec uses meson to as build system. To build and install nsexec:

	meson build
	(to enable selinux: meson -D enable-selinux=true build)
	cd build
	ninja
	sudo ninja install

### Using nsexec
----------------

First, you need to map your user inside /etc/subuid and /etc/subgid, like below:

	<your_username>:1000:65536

For more information about uidmaps, take a look [here](https://stgraber.org/2017/06/15/custom-user-mappings-in-lxd-containers/)

After this is set, you can run the command below, to receive a new bash with
**root** user and all namespace active:

	nsexec --unshare-all

If you have downloaded a rootfs, make sure the owner of the all files of that
rootfs belongs to <your_username> and execute:

	nsexec --unshare-all --rootfs <path_to_your_rootfs>
