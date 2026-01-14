# libtee - TEE Client API Library
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Library: tee (libtee.so)
# ============================================================================

add_library(tee
    src/com_protocol.c
    src/tee_client_api.c
    src/tee_logging.c
)

# Public include directory (for consumers of this library)
target_include_directories(tee
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        # Emulator headers needed for tee_logging.c
        ${CMAKE_SOURCE_DIR}/emulator/include
        ${CMAKE_SOURCE_DIR}/emulator/internal_api
)

# Link dependencies
target_link_libraries(tee
    PRIVATE
        Threads::Threads
        ZLIB::ZLIB
        ${RT_LIBRARY}
        ${CRYPT_LIBRARY}
        ${UUID_LIBRARY}
)

# Compiler settings
target_compile_definitions(tee PRIVATE
    _GNU_SOURCE
)

# Library versioning (libtee.so.0.0.0)
set_target_properties(tee PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

# Create an alias for use in the build tree
add_library(OpenTEE::tee ALIAS tee)

# ============================================================================
# pkg-config file
# ============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/libtee.pc.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/libtee.pc
    @ONLY
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS tee
    EXPORT OpenTEETargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install headers separately to avoid path issues
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/opentee
    FILES_MATCHING PATTERN "*.h"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libtee.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
