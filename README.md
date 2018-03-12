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

nsexec uses meson to as build system. To build and install nsexec:

	meson build
	(to enable selinux: meson -D enable-selinux=true build)
	cd build
	ninja
	sudo ninja install

### Using nsexec
----------------

Where is a small example of how to start a new bash with all namespaces active:

	nsexec --unshare-all
