# FindLibssh.cmake
# Finds the libssh library and sets variables for use in CMake

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSSH QUIET libssh)
endif()

find_path(Libssh_INCLUDE_DIR
    NAMES libssh/libssh.h
    HINTS
        ${LIBSSH_INCLUDE_DIRS}
        /usr/include
        /usr/local/include
)

find_library(Libssh_LIBRARY
    NAMES ssh libssh
    HINTS
        ${LIBSSH_LIBRARY_DIRS}
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libssh
    REQUIRED_VARS Libssh_LIBRARY Libssh_INCLUDE_DIR
)

if(Libssh_FOUND)
    if(NOT TARGET libssh::libssh)
        add_library(libssh::libssh UNKNOWN IMPORTED)
        set_target_properties(libssh::libssh PROPERTIES
            IMPORTED_LOCATION "${Libssh_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${Libssh_INCLUDE_DIR}"
        )
    endif()
    set(Libssh_LIBRARIES ${Libssh_LIBRARY})
    set(Libssh_INCLUDE_DIRS ${Libssh_INCLUDE_DIR})
endif()

mark_as_advanced(Libssh_INCLUDE_DIR Libssh_LIBRARY)