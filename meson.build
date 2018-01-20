project('nsexec', 'c'
	, default_options: ['prefix=/usr'])
add_project_arguments(['-Werror', '-Wextra', '-Wshadow', '-Wformat=2'
		, '-Og', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2'
		], language: 'c')

compiler = meson.get_compiler('c')

if compiler.has_argument('-Wduplicated-cond')
	add_project_arguments('-Wduplicated-cond', language: 'c')
endif

if compiler.has_argument('-Wduplicated-branches')
	add_project_arguments('-Wduplicated-branches', language: 'c')
endif

if compiler.has_argument('-Wlogical-op')
	add_project_arguments('-Wlogical-op', language: 'c')
endif

if compiler.has_argument('-Wjump-misses-init')
	add_project_arguments('-Wjump-misses-init', language: 'c')
endif

add_project_link_arguments('-fstack-protector-strong', '-flto'
		, '-Wl,-z,relro,-z,now', language: 'c')

dep_libcap = dependency('libcap')
dep_libnl = dependency('libnl-route-3.0')
dep_uuid = dependency('uuid')

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
