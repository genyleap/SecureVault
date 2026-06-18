# Minimum CMake version for C++23 and modern features
cmake_minimum_required(VERSION 3.26)

# Project definition
project(SecureVault
    LANGUAGES CXX
    VERSION 1.0
    DESCRIPTION "SecureVault Backup System"
)

# Set C++ standard to 23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Allow CMake to use vcpkg toolchain if specified
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Add custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(SECUREVAULT_AUTO_INSTALL_BREW_DEPS "Automatically install missing Homebrew dependencies on macOS" ON)

# Install missing Homebrew dependencies before package discovery.
if(APPLE AND SECUREVAULT_AUTO_INSTALL_BREW_DEPS)
    find_program(HOMEBREW_EXECUTABLE brew)
    if(NOT HOMEBREW_EXECUTABLE)
        message(FATAL_ERROR "Homebrew is required for automatic dependency installation but was not found. Install Homebrew or configure with -DSECUREVAULT_AUTO_INSTALL_BREW_DEPS=OFF.")
    endif()

    set(SECUREVAULT_BREW_DEPS
        libarchive
        curl
        zlib
        jsoncpp
        libssh
    )

    foreach(DEP IN LISTS SECUREVAULT_BREW_DEPS)
        execute_process(
            COMMAND "${HOMEBREW_EXECUTABLE}" list --formula "${DEP}"
            RESULT_VARIABLE BREW_HAS_DEP
            OUTPUT_QUIET
            ERROR_QUIET
        )

        if(NOT BREW_HAS_DEP EQUAL 0)
            message(STATUS "Installing missing Homebrew dependency: ${DEP}")
            execute_process(
                COMMAND "${HOMEBREW_EXECUTABLE}" install "${DEP}"
                RESULT_VARIABLE BREW_INSTALL_RESULT
                OUTPUT_VARIABLE BREW_INSTALL_STDOUT
                ERROR_VARIABLE BREW_INSTALL_STDERR
            )
            if(NOT BREW_INSTALL_RESULT EQUAL 0)
                message(FATAL_ERROR "Failed to install '${DEP}' with Homebrew.\n${BREW_INSTALL_STDOUT}\n${BREW_INSTALL_STDERR}")
            endif()
        endif()

        execute_process(
            COMMAND "${HOMEBREW_EXECUTABLE}" --prefix "${DEP}"
            RESULT_VARIABLE BREW_PREFIX_RESULT
            OUTPUT_VARIABLE BREW_PREFIX_OUTPUT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(BREW_PREFIX_RESULT EQUAL 0)
            list(APPEND CMAKE_PREFIX_PATH "${BREW_PREFIX_OUTPUT}")
        endif()
    endforeach()
endif()

# Add Homebrew paths for macOS (keg-only libraries)
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/libarchive")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/libssh")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/curl")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/zlib")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/jsoncpp")
endif()

# Find required packages
find_package(LibArchive REQUIRED)
find_package(Libssh QUIET MODULE)
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(JsonCpp REQUIRED MODULE)

# Platform-specific definitions
if(WIN32)
    add_definitions(-D_WIN32)
elseif(UNIX AND NOT APPLE)
    add_definitions(-D_LINUX)
else()
    add_definitions(-D_MACOS)
endif()

# Collect source and header files
set(SOURCE_FILES
    src/backup.cpp
    src/database_backup.cpp
    src/file_backup.cpp
    src/notification.cpp
    src/backup_config.cpp
    src/backup_api.cpp
)

if(Libssh_FOUND)
    list(APPEND SOURCE_FILES src/remote_transfer.cpp)
else()
    message(WARNING "Libssh not found: building without SFTP transfer support")
    list(APPEND SOURCE_FILES src/remote_transfer_stub.cpp)
endif()

set(HEADER_FILES
    include/backup.hpp
    include/file_backup.hpp
    include/remote_transfer.hpp
    include/notification.hpp
    include/backup_config.hpp
    include/backup_api.hpp
)

# Add main executable
add_executable(backup ${SOURCE_FILES} ${HEADER_FILES})

# Link libraries for main executable
target_link_libraries(backup PRIVATE
    LibArchive::LibArchive
    CURL::libcurl
    ZLIB::ZLIB
    jsoncpp
)

if(Libssh_FOUND)
    target_link_libraries(backup PRIVATE libssh::libssh)
endif()

# Include directories for main executable
target_include_directories(backup PRIVATE
    ${LibArchive_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
    ${JsonCpp_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
)

if(Libssh_FOUND)
    target_include_directories(backup PRIVATE ${Libssh_INCLUDE_DIRS})
endif()

# Installation rules
install(TARGETS backup
    RUNTIME DESTINATION bin
)

install(FILES "${CMAKE_SOURCE_DIR}/backup_config.json"
    DESTINATION etc/securevault
)

# Set default configuration paths
set(CONFIG_PATH "backup_config.json")

target_compile_definitions(backup PRIVATE CONFIG_PATH="${CONFIG_PATH}")

# Ensure C++23 support
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|MSVC")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13")
        message(FATAL_ERROR "GCC version must be at least 13 for C++23 support")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "16")
        message(FATAL_ERROR "Clang version must be at least 16 for C++23 support")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.29")
        message(FATAL_ERROR "MSVC version must be at least 19.29 for C++23 support")
    endif()
else()
    message(WARNING "Unknown compiler; C++23 support not guaranteed")
endif()

# Enable warnings and optimizations
target_compile_options(backup PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2 -std=c++23>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2 /std:c++latest>
)
