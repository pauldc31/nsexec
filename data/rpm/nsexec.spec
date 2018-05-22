Name:           nsexec
Version:        0.1
Release:        1%{?dist}
Summary:        nsexec summary

License:        GPLv2
URL:            github
Source0:        https://github.com/marcosps/nsexec/archive/master.zip

BuildRequires:  meson
BuildRequires:  gcc libuuid-devel libseccomp-devel libcap-devel

%description
nsexec desc

# FIXME: use %Name
%global _vpath_srcdir nsexec-master

%prep
%autosetup -c

%build
%meson
%meson_build

%install
%meson_install

%files
/usr/bin/nsexec
/usr/bin/nsexec_nic
/usr/share/bash-completion/completions/nsexec
# FIXME: check these files
#%license LICENSE.txt
#rm -rf $RPM_BUILD_ROOT

%changelog
* Sat May 19 2018 Marcos Paulo de Souza <marcos.souza.org@gmail.com>
-
