#!/bin/bash

setcap cap_net_admin+ep "$MESON_INSTALL_PREFIX"/bin/nsexec_nic
