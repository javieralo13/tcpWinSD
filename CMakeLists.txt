cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(_plugin_name tcpWin)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.8.11
    LANGUAGES    C
)

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.c
        ../../utils/chksum.c
)

set_target_properties(${_plugin_name}
    PROPERTIES
        C_STANDARD          99
        C_EXTENSIONS        ON
        C_STANDARD_REQUIRED ON
)

target_include_directories(${_plugin_name}
    PRIVATE
        ../../utils
        ../../tranalyzer2/src
)

target_compile_options(${_plugin_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
)

if (APPLE)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _DARWIN_C_SOURCE
    )
    set_target_properties(${_plugin_name}
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
elseif (UNIX)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _GNU_SOURCE
    )
endif()

set_target_properties(${_plugin_name}
    PROPERTIES
        SUFFIX ".so"
)
