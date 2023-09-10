project('tcpWinSD', 'c',
    version: '0.8.11',
    license: 'GPLv2+',
    default_options: [
        'warning_level=2',
        'buildtype=release',
        'c_std=gnu99'
    ],
    #meson_version: '>= 0.45.0',
)

plugin_name = meson.project_name()

os = host_machine.system()

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
	join_paths('..', 'basicStats', 'src'), # <--
)

src = [
    join_paths('src', plugin_name + '.c'),
    join_paths('..', '..', 'utils', 'chksum.c'),
]

shared_module(plugin_name,
    sources: src,
    include_directories: inc,
    name_suffix: 'so',
)
