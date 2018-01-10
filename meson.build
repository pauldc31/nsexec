project('nsexec', 'c'
	, default_options: ['prefix=/usr'])
add_project_arguments(['-Wall', '-Werror', '-Wextra'
		, '-Og', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2'
		], language: 'c')
add_project_link_arguments('-fstack-protector-strong', '-flto'
		, '-Wl,-z,relro,-z,now', language: 'c')

dep_libcap = dependency('libcap')
dep_libnl = dependency('libnl-route-3.0')
executable('nsexec', 'src/nsexec.c'
	, install: true
	, dependencies: [dep_libcap, dep_libnl])

executable('nsexec_nic', 'src/nsexec_nic.c'
	, install: true
	, dependencies: [dep_libnl])

pkgconfig = find_program('pkg-config')
runcmd = run_command(pkgconfig
	, '--variable=completionsdir'
	, 'bash-completion')

# assume bash-complete is installed and working
install_data(sources: 'completions/bash/nsexec'
	, install_dir: runcmd.stdout().strip())
