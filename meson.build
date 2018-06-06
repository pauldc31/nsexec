project('nsexec', 'c'
	, default_options: [
		'prefix=/usr',
		'sysconfdir=/etc',
	])

pkgconfig = find_program('pkg-config')
runcmd = run_command(pkgconfig
	, '--variable=completionsdir'
	, 'bash-completion')

# assume bash-complete is installed and working
install_data(sources: 'data/completions/bash/nsexec'
	, install_dir: runcmd.stdout().strip())

meson.add_install_script('data/post-install.sh')

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
dep_libcap = dependency('libcap')
dep_seccomp = dependency('libseccomp')

libs = [dep_libnl, dep_uuid, dep_libcap, dep_seccomp]

enable_selinux = get_option('enable-selinux')
if enable_selinux
	libs += [dependency('libselinux')]
	add_project_arguments('-DHAVE_SELINUX', language: 'c')
endif

executable('nsexec_nic', 'src/nsexec_nic.c'
	, install: true
	, dependencies: [dep_libnl])

nsexec = executable('nsexec'
	, [
		'src/lsm.c'
		, 'src/nsexec.c'
		, 'src/ns_mount.c'
		, 'src/ns_network.c'
		, 'src/ns_seccomp.c'
	]
	, install: true
	, dependencies: libs)

test('help output', nsexec, args: ['-h'])
test('unshare-net and cat resolv.conf', nsexec, args: ['--unshare-net', '--',
				'cat', '/etc/resolv.conf'])
test('set hostname', nsexec, args: ['--unshare-uts', '--hostname', 'dummy',
			'--', 'sh', '-c', '[ "$HOSTNAME" = "dummy" ]'])
test('root UID', nsexec, args: ['--unshare-all', '--',
			'sh', '-c', '[ "$UID" = "0" ]'])
test('ordinary UID', nsexec, args: ['--unshare-all', '--uid', '1000', '--',
			'sh', '-c', '[ "$UID" = "1000" ]'])
test('root GID', nsexec, args: ['--unshare-all', '--',
			'sh', '-c', '[ "$(id -g)" = "0" ]'])
test('ordinary GID', nsexec, args: ['--unshare-all', '--gid', '1000', '--',
			'sh', '-c', '[ "$(id -g)" = "1000" ]'])
