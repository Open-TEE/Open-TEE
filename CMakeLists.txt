# Open-TEE - Open Source TEE Emulator
# Root CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2015-2024 Open-TEE project

# Require CMake 3.25 minimum, use policies up to 4.1 when available
cmake_minimum_required(VERSION 3.25...4.1)

project(OpenTEE
    VERSION 0.0.1
    DESCRIPTION "Open Source implementation of GlobalPlatform TEE"
    HOMEPAGE_URL "https://github.com/Open-TEE"
    LANGUAGES C CXX
)

# ============================================================================
# Build Options
# ============================================================================

option(OPENTEE_BUILD_TESTS "Build test applications" ON)
option(OPENTEE_BUILD_EXAMPLES "Build example TAs and CAs" ON)
option(OPENTEE_ENABLE_LOGGING "Enable logging support" ON)
option(OPENTEE_INSTALL_TAS "Install Trusted Applications" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# ============================================================================
# CMake Configuration (3.25+ features)
# ============================================================================

# Use C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (_GNU_SOURCE)

# Enable color diagnostics for better IDE/terminal output (3.24+)
set(CMAKE_COLOR_DIAGNOSTICS ON)

# Generate compile_commands.json for IDE integration (Emacs, VS Code, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set default build type if not specified (using block() for scoped variables)
block(SCOPE_FOR VARIABLES)
    if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        message(STATUS "Setting build type to 'Debug' as none was specified.")
        set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
        set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
            "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
    endif()
endblock()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add cmake/ directory to module path using cmake_path (3.20+)
cmake_path(APPEND CMAKE_CURRENT_SOURCE_DIR "cmake" OUTPUT_VARIABLE _cmake_module_dir)
list(APPEND CMAKE_MODULE_PATH "${_cmake_module_dir}")

# ============================================================================
# Compiler Flags
# ============================================================================

# Common warning flags
add_compile_options(
    -Wall
    -Wextra
    -Wpointer-arith
    # Debug: Use -Og for debugging with optimization (satisfies _FORTIFY_SOURCE)
    # NixOS hardening adds _FORTIFY_SOURCE by default, which requires optimization
    $<$<CONFIG:Debug>:-g3>
    $<$<CONFIG:Debug>:-Og>
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
)

# Define logging macro if enabled
if(OPENTEE_ENABLE_LOGGING)
    add_compile_definitions(OT_LOGGING)
endif()

# ============================================================================
# Find Dependencies
# ============================================================================

# Use pkg-config for finding dependencies
find_package(PkgConfig REQUIRED)

# Required system libraries
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ZLIB - try CMake first, fall back to pkg-config
block(SCOPE_FOR VARIABLES)
    find_package(ZLIB QUIET)
    if(NOT ZLIB_FOUND)
        pkg_check_modules(ZLIB REQUIRED zlib)
        # Create imported target to match FindZLIB
        add_library(ZLIB::ZLIB INTERFACE IMPORTED GLOBAL)
        set_target_properties(ZLIB::ZLIB PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${ZLIB_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${ZLIB_LIBRARIES}"
        )
    endif()
endblock()

# Find libelf via pkg-config or manual search
block(SCOPE_FOR VARIABLES PROPAGATE LIBELF_LIBRARIES LIBELF_INCLUDE_DIRS LIBELF_LIBRARY LIBELF_INCLUDE_DIR)
    pkg_check_modules(LIBELF QUIET libelf)
    if(NOT LIBELF_FOUND)
        find_library(LIBELF_LIBRARY NAMES elf)
        find_path(LIBELF_INCLUDE_DIR NAMES libelf.h gelf.h PATH_SUFFIXES libelf)
        if(NOT LIBELF_LIBRARY OR NOT LIBELF_INCLUDE_DIR)
            message(FATAL_ERROR "libelf not found")
        endif()
        set(LIBELF_LIBRARIES ${LIBELF_LIBRARY})
        set(LIBELF_INCLUDE_DIRS ${LIBELF_INCLUDE_DIR})
    else()
        set(LIBELF_LIBRARY ${LIBELF_LIBRARIES})
        set(LIBELF_INCLUDE_DIR ${LIBELF_INCLUDE_DIRS})
    endif()
endblock()

# Find libuuid via pkg-config or manual search
block(SCOPE_FOR VARIABLES PROPAGATE UUID_LIBRARIES UUID_INCLUDE_DIRS UUID_LIBRARY UUID_INCLUDE_DIR)
    pkg_check_modules(UUID QUIET uuid)
    if(NOT UUID_FOUND)
        find_library(UUID_LIBRARY NAMES uuid)
        find_path(UUID_INCLUDE_DIR NAMES uuid/uuid.h)
        if(NOT UUID_LIBRARY OR NOT UUID_INCLUDE_DIR)
            message(FATAL_ERROR "libuuid not found")
        endif()
        set(UUID_LIBRARIES ${UUID_LIBRARY})
        set(UUID_INCLUDE_DIRS ${UUID_INCLUDE_DIR})
    else()
        set(UUID_LIBRARY ${UUID_LIBRARIES})
        set(UUID_INCLUDE_DIR ${UUID_INCLUDE_DIRS})
    endif()
endblock()

# Find librt (realtime extensions) - usually part of glibc
find_library(RT_LIBRARY NAMES rt)
if(NOT RT_LIBRARY)
    set(RT_LIBRARY "")  # May be part of libc on some systems
endif()

# Find libdl (dynamic loader) - usually part of glibc
find_library(DL_LIBRARY NAMES dl)
if(NOT DL_LIBRARY)
    set(DL_LIBRARY "")  # May be part of libc on some systems
endif()

# Find libcrypt
find_library(CRYPT_LIBRARY NAMES crypt)
if(NOT CRYPT_LIBRARY)
    set(CRYPT_LIBRARY "")
endif()

# Find FUSE (optional, for omnishare)
pkg_check_modules(FUSE fuse)

# Find mbedtls (for InternalApi crypto)
block(SCOPE_FOR VARIABLES)
    pkg_check_modules(MBEDTLS REQUIRED mbedcrypto)
    if(MBEDTLS_FOUND)
        # Create imported target if not automatically created
        if(NOT TARGET MbedTLS::mbedcrypto)
            add_library(MbedTLS::mbedcrypto INTERFACE IMPORTED GLOBAL)
            set_target_properties(MbedTLS::mbedcrypto PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${MBEDTLS_LIBRARIES}"
                INTERFACE_LINK_DIRECTORIES "${MBEDTLS_LIBRARY_DIRS}"
            )
        endif()
    endif()
endblock()

# ============================================================================
# Installation Directories
# ============================================================================

include(GNUInstallDirs)

# Custom installation directory for TAs
set(OPENTEE_TA_DIR "${CMAKE_INSTALL_LIBDIR}/TAs" CACHE PATH
    "Installation directory for Trusted Applications")

# ============================================================================
# Subdirectories
# ============================================================================

# Core libraries (order matters for dependencies)
add_subdirectory(libtee)
add_subdirectory(emulator)
add_subdirectory(libomnishare)
add_subdirectory(libtee_pkcs11)

# Trusted Applications
add_subdirectory(TAs)

# Client Applications
add_subdirectory(CAs)

# Tests
if(OPENTEE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

add_subdirectory(virtualdisplay-qt)

# ============================================================================
# Configuration Summary
# ============================================================================

message(STATUS "")
message(STATUS "Open-TEE Configuration Summary")
message(STATUS "==============================")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  TA directory:   ${OPENTEE_TA_DIR}")
message(STATUS "")
message(STATUS "  Options:")
message(STATUS "    Build tests:    ${OPENTEE_BUILD_TESTS}")
message(STATUS "    Build examples: ${OPENTEE_BUILD_EXAMPLES}")
message(STATUS "    Enable logging: ${OPENTEE_ENABLE_LOGGING}")
message(STATUS "")
message(STATUS "  Dependencies:")
message(STATUS "    OpenSSL:  ${OPENSSL_VERSION}")
message(STATUS "    ZLIB:     ${ZLIB_VERSION_STRING}")
message(STATUS "    libelf:   ${LIBELF_LIBRARY}")
message(STATUS "    libuuid:  ${UUID_LIBRARY}")
if(FUSE_FOUND)
    message(STATUS "    FUSE:     ${FUSE_VERSION}")
else()
    message(STATUS "    FUSE:     Not found (omnishare-fuse will not be built)")
endif()
message(STATUS "")

# ============================================================================
# CMake Build Instructions (see README.md for full details)
# ============================================================================
# Basic build:
#   cmake -B build -G Ninja
#   cmake --build build
#
# Using presets (CMake 3.25+):
#   cmake --preset dev
#   cmake --build --preset dev
#
# Using workflow presets (CMake 3.25+):
#   cmake --workflow --preset dev    # Configure + Build + Test
#
# IDE support:
#   compile_commands.json is generated automatically in the build directory
#   Symlink to project root: ln -sf build/compile_commands.json .
