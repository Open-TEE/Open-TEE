# libtee_pkcs11 - PKCS#11 Provider Library
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Library: tee_pkcs11 (libtee_pkcs11.so)
# ============================================================================

add_library(tee_pkcs11
    src/hal_gp.c
    src/mutex_manager.c
    src/pkcs11_crypto.c
    src/pkcs11_general.c
    src/pkcs11_object.c
    src/pkcs11_session_slot.c
)

target_include_directories(tee_pkcs11
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(tee_pkcs11
    PUBLIC
        tee
    PRIVATE
        Threads::Threads
)

target_compile_definitions(tee_pkcs11 PRIVATE _GNU_SOURCE)

set_target_properties(tee_pkcs11 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    PUBLIC_HEADER "include/cryptoki.h;include/pkcs11.h;include/pkcs11f.h;include/pkcs11t.h"
)

add_library(OpenTEE::tee_pkcs11 ALIAS tee_pkcs11)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS tee_pkcs11
    EXPORT OpenTEETargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
