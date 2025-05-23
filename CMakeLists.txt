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

# Add Homebrew paths for macOS (keg-only libraries)
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/libarchive")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/libssh")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/libcurl")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/zlib")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/jsoncpp")
endif()

# Find required packages
find_package(LibArchive REQUIRED)
find_package(Libssh REQUIRED MODULE)
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
    src/remote_transfer.cpp
    src/notification.cpp
    src/backup_config.cpp
    src/backup_api.cpp
)

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
    libssh::libssh
    CURL::libcurl
    ZLIB::ZLIB
    jsoncpp
)

# Include directories for main executable
target_include_directories(backup PRIVATE
    ${LibArchive_INCLUDE_DIRS}
    ${Libssh_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
    ${JsonCpp_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
)

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
