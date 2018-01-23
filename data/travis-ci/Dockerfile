FROM fedora:latest
MAINTAINER Marcos Paulo de Souza <marcos.souza.org@gmail.com>

RUN dnf -y update
RUN dnf -y install \
	meson ninja-build git \
	gcc clang \
	libcap-devel libnl3-devel libuuid-devel
RUN dnf clean all

RUN git clone https://github.com/marcosps/nsexec
RUN cd nsexec

CMD [ "/bin/bash" ]
