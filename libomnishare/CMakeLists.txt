# libomnishare - OmniShare Client Library
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Library: omnishare (libomnishare.so)
# ============================================================================

add_library(omnishare
    src/omnishare.c
)

target_include_directories(omnishare
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(omnishare
    PUBLIC
        tee
)

target_compile_definitions(omnishare PRIVATE _GNU_SOURCE)

set_target_properties(omnishare PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    PUBLIC_HEADER "include/omnishare.h"
)

add_library(OpenTEE::omnishare ALIAS omnishare)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS omnishare
    EXPORT OpenTEETargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
