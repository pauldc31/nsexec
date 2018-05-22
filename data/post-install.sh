#!/bin/bash

# just add the setcap if user is root
if [ "$UID" = "0" ]; then
	setcap cap_net_admin+ep "$MESON_INSTALL_PREFIX"/bin/nsexec_nic
fi
