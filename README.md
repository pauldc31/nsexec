nsexec
======

The nsexec is just an experiment, inspired by [bubblewrap](https://github.com/projectatomic/bubblewrap)
and [lxc](https://github.com/lxc/lxc) in order to learn all the concepts used by
Linux containers, by using the same ideas an techniques used by both project.

### building
------------

Currently nsexec has two dependencies:

	* libcap
	* libnl-route-3.0

nsexec uses meson to as build system. To build and install nsexec:

	meson build
	cd build
	ninja
	sudo ninja install
	sudo chmod +s /usr/bin/nsexec_nic

nsexec_nic is a binary that is responsible to manage network interfaces, so it
needs to be executed as root (or have CAP_NET_ADMIN).

### Using nsexec
----------------

Where is a small example of how to execute nsexec with all namespaces active:

	nsexec --unshare-all --exec-file bash