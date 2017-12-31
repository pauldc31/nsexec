project('nsexec', 'c'
	, default_options: ['prefix=/usr'])
add_project_arguments(['-Wall', '-Werror', '-Wextra'
		, '-Og', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2'
		], language: 'c')
add_project_link_arguments('-fstack-protector-strong', '-flto'
		, '-Wl,-z,relro,-z,now', language: 'c')

dep_libcap = dependency('libcap')
executable('ns_exec', 'src/ns_exec.c'
	, install: true
	, dependencies: [dep_libcap])

pkgconfig = find_program('pkg-config')
runcmd = run_command(pkgconfig
	, '--define-variable='
	, '--variable=completionsdir'
	, 'bash-completion')

# assume bash-complete is installed and working
install_data(sources: 'completions/bash/ns_exec'
	, install_dir: runcmd.stdout().strip())
