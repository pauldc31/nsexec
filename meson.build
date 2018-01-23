project('nsexec', 'c'
	, default_options: [
		'prefix=/usr',
		'sysconfdir=/etc',
	])

cc = meson.get_compiler('c')

c_args = [
	'-Wextra',
	'-Werror',
	'-Wshadow',
	'-Wformat=2',
	'-fstack-protector-strong',
	'-D_FORTIFY_SOURCE=2',
	'-Wduplicated-cond',
	'-Wduplicated-branches',
	'-Wlogical-op',
	'-Wjump-misses-init',
	'-O2'
]

foreach arg : c_args
	if cc.has_argument(arg)
		add_project_arguments(arg, language: 'c')
	endif
endforeach

add_project_link_arguments('-fstack-protector-strong', '-flto'
		, '-Wl,-z,relro,-z,now', language: 'c')

dep_libnl = dependency('libnl-route-3.0')
dep_uuid = dependency('uuid')
dep_libcap = dependency('libcap', required: false)

if not dep_libcap.found()
	dep_libcap = dependency('libcap-ng')
endif

executable('nsexec', 'src/nsexec.c'
	, install: true
	, dependencies: [dep_libcap, dep_libnl, dep_uuid])

executable('nsexec_nic', 'src/nsexec_nic.c'
	, install: true
	, dependencies: [dep_libnl])

pkgconfig = find_program('pkg-config')
runcmd = run_command(pkgconfig
	, '--variable=completionsdir'
	, 'bash-completion')

# assume bash-complete is installed and working
install_data(sources: 'data/completions/bash/nsexec'
	, install_dir: runcmd.stdout().strip())

meson.add_install_script('data/post-install.sh')
