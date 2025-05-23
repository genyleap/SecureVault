# FindJsonCpp.cmake
# Finds the jsoncpp library and sets variables for use in CMake

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(JSONCPP QUIET jsoncpp)
endif()

find_path(JsonCpp_INCLUDE_DIR
    NAMES json/json.h
    HINTS
        ${JSONCPP_INCLUDE_DIRS}
        /usr/include/jsoncpp
        /usr/local/include/jsoncpp
)

find_library(JsonCpp_LIBRARY
    NAMES jsoncpp
    HINTS
        ${JSONCPP_LIBRARY_DIRS}
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JsonCpp
    REQUIRED_VARS JsonCpp_LIBRARY JsonCpp_INCLUDE_DIR
)

if(JsonCpp_FOUND)
    if(NOT TARGET jsoncpp)
        add_library(jsoncpp UNKNOWN IMPORTED)
        set_target_properties(jsoncpp PROPERTIES
            IMPORTED_LOCATION "${JsonCpp_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${JsonCpp_INCLUDE_DIR}"
        )
    endif()
    set(JsonCpp_LIBRARIES ${JsonCpp_LIBRARY})
    set(JsonCpp_INCLUDE_DIRS ${JsonCpp_INCLUDE_DIR})
endif()

mark_as_advanced(JsonCpp_INCLUDE_DIR JsonCpp_LIBRARY)