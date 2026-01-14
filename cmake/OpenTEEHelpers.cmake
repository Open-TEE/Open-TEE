# OpenTEEHelpers.cmake
# Helper functions and macros for Open-TEE CMake build
#
# SPDX-License-Identifier: Apache-2.0
#
# Requires CMake 3.25+ for block() and cmake_path() support

# ============================================================================
# Function: opentee_add_ta
#
# Add a Trusted Application (shared library with special install location)
#
# Usage:
#   opentee_add_ta(NAME <name>
#       SOURCES <source1> [source2 ...]
#       [INCLUDE_DIRS <dir1> ...]
#       [LINK_LIBRARIES <lib1> ...]
#       [COMPILE_DEFINITIONS <def1> ...]
#   )
# ============================================================================
function(opentee_add_ta)
    cmake_parse_arguments(PARSE_ARGV 0 TA
        ""                          # Options (flags)
        "NAME"                      # Single-value arguments
        "SOURCES;INCLUDE_DIRS;LINK_LIBRARIES;COMPILE_DEFINITIONS"  # Multi-value arguments
    )

    # Validate required arguments
    if(NOT TA_NAME)
        message(FATAL_ERROR "opentee_add_ta: NAME is required")
    endif()
    if(NOT TA_SOURCES)
        message(FATAL_ERROR "opentee_add_ta: SOURCES is required")
    endif()

    # Create shared library
    add_library(${TA_NAME} SHARED)

    # Add sources using target_sources (modern CMake pattern)
    target_sources(${TA_NAME} PRIVATE ${TA_SOURCES})

    # TA-specific compile definitions
    target_compile_definitions(${TA_NAME} PRIVATE
        TA_PLUGIN
        _GNU_SOURCE
        ${TA_COMPILE_DEFINITIONS}
    )

    # Include directories
    if(TA_INCLUDE_DIRS)
        target_include_directories(${TA_NAME} PRIVATE ${TA_INCLUDE_DIRS})
    endif()

    # Link libraries - all TAs need InternalApi
    target_link_libraries(${TA_NAME} PRIVATE
        InternalApi
        ${TA_LINK_LIBRARIES}
    )

    # Set output directory using cmake_path
    cmake_path(APPEND CMAKE_BINARY_DIR "TAs" OUTPUT_VARIABLE _ta_output_dir)

    # Remove version suffix from shared library (libfoo.so instead of libfoo.so.0.0.0)
    set_target_properties(${TA_NAME} PROPERTIES
        VERSION ""
        SOVERSION ""
        PREFIX "lib"
        LIBRARY_OUTPUT_DIRECTORY "${_ta_output_dir}"
    )

    # Install to TA directory
    if(OPENTEE_INSTALL_TAS)
        install(TARGETS ${TA_NAME}
            LIBRARY DESTINATION ${OPENTEE_TA_DIR}
            COMPONENT runtime
        )
    endif()
endfunction()

# ============================================================================
# Function: opentee_add_ca
#
# Add a Client Application (executable that uses TEE)
#
# Usage:
#   opentee_add_ca(NAME <name>
#       SOURCES <source1> [source2 ...]
#       [INCLUDE_DIRS <dir1> ...]
#       [LINK_LIBRARIES <lib1> ...]
#       [COMPILE_DEFINITIONS <def1> ...]
#   )
# ============================================================================
function(opentee_add_ca)
    cmake_parse_arguments(PARSE_ARGV 0 CA
        ""
        "NAME"
        "SOURCES;INCLUDE_DIRS;LINK_LIBRARIES;COMPILE_DEFINITIONS"
    )

    # Validate required arguments
    if(NOT CA_NAME)
        message(FATAL_ERROR "opentee_add_ca: NAME is required")
    endif()
    if(NOT CA_SOURCES)
        message(FATAL_ERROR "opentee_add_ca: SOURCES is required")
    endif()

    # Create executable and add sources
    add_executable(${CA_NAME})
    target_sources(${CA_NAME} PRIVATE ${CA_SOURCES})

    # Compile definitions
    if(CA_COMPILE_DEFINITIONS)
        target_compile_definitions(${CA_NAME} PRIVATE ${CA_COMPILE_DEFINITIONS})
    endif()

    # Include directories
    if(CA_INCLUDE_DIRS)
        target_include_directories(${CA_NAME} PRIVATE ${CA_INCLUDE_DIRS})
    endif()

    # Link libraries - all CAs typically need libtee
    target_link_libraries(${CA_NAME} PRIVATE
        tee
        ${CA_LINK_LIBRARIES}
    )

    # Install
    install(TARGETS ${CA_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT runtime
    )
endfunction()
