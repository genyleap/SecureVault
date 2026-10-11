cmake_minimum_required(VERSION 3.26)
project(SecureVault VERSION 2.0 LANGUAGES CXX
    DESCRIPTION "Native C++23 backup, encrypted storage and disaster recovery")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(SECUREVAULT_BUILD_CORE "Build the original tar/database backup engine" ON)
option(SECUREVAULT_LEGACY_RESTIC "Build deprecated Restic compatibility tools" OFF)
option(SECUREVAULT_REQUIRE_SFTP "Require libssh for core SFTP" ON)
option(SECUREVAULT_AUTO_INSTALL_BREW_DEPS "Install Homebrew dependencies automatically" OFF)

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH
        /opt/homebrew/opt/libarchive /opt/homebrew/opt/libssh
        /opt/homebrew/opt/curl /opt/homebrew/opt/zlib
        /opt/homebrew/opt/jsoncpp /opt/homebrew/opt/openssl@3)
endif()

find_package(JsonCpp REQUIRED MODULE)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Independent C++23 encrypted snapshot engine (no Restic executable).
add_library(securevault_vault STATIC src/vault.cpp)
target_include_directories(securevault_vault PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(securevault_vault PUBLIC OpenSSL::Crypto)
target_compile_options(securevault_vault PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)
add_executable(securevault-vault src/vault_main.cpp)
target_link_libraries(securevault-vault PRIVATE securevault_vault)
install(TARGETS securevault-vault RUNTIME DESTINATION bin)

if(SECUREVAULT_BUILD_CORE)
    find_package(LibArchive REQUIRED)
    find_package(Libssh QUIET MODULE)
    find_package(CURL REQUIRED)
    find_package(ZLIB REQUIRED)
    if(SECUREVAULT_REQUIRE_SFTP AND NOT Libssh_FOUND)
        message(FATAL_ERROR "libssh is required; use SECUREVAULT_REQUIRE_SFTP=OFF only for local development")
    endif()
endif()

if(APPLE)
    foreach(libtarget IN ITEMS
        LibArchive::LibArchive CURL::libcurl ZLIB::ZLIB jsoncpp libssh::libssh)
        if(TARGET "${libtarget}")
            get_target_property(dirs "${libtarget}" INTERFACE_INCLUDE_DIRECTORIES)
            if(dirs)
                set(clean_dirs)
                foreach(dir IN LISTS dirs)
                    if(NOT dir MATCHES "[.]sdk/usr/include/?$")
                        list(APPEND clean_dirs "${dir}")
                    endif()
                endforeach()
                set_property(TARGET "${libtarget}" PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES "${clean_dirs}")
            endif()
        endif()
    endforeach()
endif()

# Deprecated compatibility only. Default builds have zero Restic runtime dependency.
if(SECUREVAULT_LEGACY_RESTIC)
add_library(securevault_operations STATIC
    src/operations.cpp src/operations_backup.cpp
    src/operations_pitr.cpp src/operations_binlog.cpp)
target_include_directories(securevault_operations PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(securevault_operations PUBLIC jsoncpp)
target_compile_options(securevault_operations PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)

add_executable(securevault-ops src/ops_main.cpp)
target_link_libraries(securevault-ops PRIVATE securevault_operations)
endif()

if(SECUREVAULT_BUILD_CORE)
    set(core_sources
        src/restore.cpp src/backup.cpp src/database_backup.cpp
        src/file_backup.cpp src/notification.cpp src/backup_config.cpp
        src/backup_api.cpp)
    if(Libssh_FOUND)
        list(APPEND core_sources src/remote_transfer.cpp)
    else()
        message(WARNING "Building backup without optional SFTP backend")
        list(APPEND core_sources src/remote_transfer_stub.cpp)
    endif()
    add_executable(backup ${core_sources})
    target_include_directories(backup PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_link_libraries(backup PRIVATE LibArchive::LibArchive
        CURL::libcurl ZLIB::ZLIB jsoncpp)
    if(Libssh_FOUND)
        target_link_libraries(backup PRIVATE libssh::libssh)
    endif()
    target_compile_definitions(backup PRIVATE CONFIG_PATH="backup_config.json")
    target_compile_options(backup PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>)
    install(TARGETS backup RUNTIME DESTINATION bin)
endif()

include(CTest)
if(BUILD_TESTING AND UNIX)
    add_executable(securevault-vault-tests tests/vault_tests.cpp)
    target_link_libraries(securevault-vault-tests PRIVATE securevault_vault)
    target_compile_options(securevault-vault-tests PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)
    add_test(NAME securevault-vault COMMAND securevault-vault-tests)

    if(SECUREVAULT_LEGACY_RESTIC)
    add_executable(securevault-native-tests tests/native_tests.cpp)
    target_link_libraries(securevault-native-tests PRIVATE securevault_operations)
    target_compile_options(securevault-native-tests PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)
    add_test(NAME securevault-native COMMAND securevault-native-tests)

    # Runs a REAL Restic roundtrip entirely in a disposable local fixture
    # repository. Restic is optional; missing binary is a reported skip.
    add_executable(securevault-restic-e2e-tests tests/restic_e2e_tests.cpp)
    target_link_libraries(securevault-restic-e2e-tests PRIVATE securevault_operations)
    target_compile_options(securevault-restic-e2e-tests PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)
    add_test(NAME securevault-restic-real COMMAND securevault-restic-e2e-tests)
    set_tests_properties(securevault-restic-real PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 1800)
    endif() # SECUREVAULT_LEGACY_RESTIC

    if(SECUREVAULT_BUILD_CORE)
        add_executable(securevault-backup-tests tests/backup_tests.cpp)
        target_link_libraries(securevault-backup-tests PRIVATE
            LibArchive::LibArchive jsoncpp)
        add_test(NAME securevault-backup
            COMMAND securevault-backup-tests $<TARGET_FILE:backup>)
    endif()
endif()

if(SECUREVAULT_LEGACY_RESTIC)
    install(TARGETS securevault-ops RUNTIME DESTINATION bin)
endif()
install(FILES backup_config.json DESTINATION etc/securevault)
install(FILES DISASTER-RECOVERY.md PITR-READINESS.md DESTINATION share/doc/securevault)
