Name:           nsexec
Version:        0.1
Release:        1%{?dist}
Summary:        nsexec summary

License:        GPLv2
URL:            github
Source0:        https://github.com/marcosps/nsexec/archive/master.zip

BuildRequires:  meson
BuildRequires:  gcc

%description
nsexec desc

%global _vpath_srcdir nsexec-master

%prep
%autosetup -c

%build
%meson
%meson_build

%install
%meson_install

%check
%meson_test

rm -rf $RPM_BUILD_ROOT
%make_install

%files
%license add-license-file-here
%doc add-docs-here

%changelog
* Sat May 19 2018 Marcos Paulo de Souza <marcos.souza.org@gmail.com>
-

