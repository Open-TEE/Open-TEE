# CAs - Client Applications
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# Include helper functions
include(OpenTEEHelpers)

# ============================================================================
# CA: conn_test (Connection Test Client)
# ============================================================================

opentee_add_ca(
    NAME conn_test
    SOURCES
        conn_test_app/conn_test_app.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/conn_test_app
)

# ============================================================================
# CA: example_sha1 (SHA1 Example Client)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ca(
        NAME example_sha1
        SOURCES
            example_sha1_ca/example_sha1_ca.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/example_sha1_ca
    )
endif()

# ============================================================================
# CA: usr_study (User Study Client)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ca(
        NAME usr_study
        SOURCES
            usr_study_ca/usr_study_ca.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/usr_study_ca
    )
endif()

# ============================================================================
# CA: svc_test (Services Test Client)
# ============================================================================

opentee_add_ca(
    NAME svc_test
    SOURCES
        services_test/services_test.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/services_test
)

# ============================================================================
# CA: sign_tee_ecdsa_256 (ECDSA Signing via TEE)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ca(
        NAME sign_tee_ecdsa_256
        SOURCES
            example_conversion/sign_tee_ecdsa_256.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/example_conversion
    )
endif()

# ============================================================================
# CA: sign_non_tee_ecdsa_256 (ECDSA Signing without TEE - uses mbedcrypto)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    # This one doesn't use libtee, it uses mbedcrypto directly
    add_executable(sign_non_tee_ecdsa_256
        example_conversion/sign_non_tee_ecdsa_256.c
    )

    target_include_directories(sign_non_tee_ecdsa_256
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/example_conversion
    )

    target_link_libraries(sign_non_tee_ecdsa_256
        PRIVATE
            MbedTLS::mbedcrypto
    )

    install(TARGETS sign_non_tee_ecdsa_256
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# ============================================================================
# CA: trusted_ui_example_ca (Trusted User Interface Example)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ca(
        NAME trusted_ui_example_ca
        SOURCES
            trusted_ui_example_ca/trusted_ui_example_ca.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/trusted_ui_example_ca
        LINK_LIBRARIES
            OpenSSL::Crypto
    )
endif()

# ============================================================================
# CA: omnishare-fuse (OmniShare FUSE Filesystem)
# ============================================================================

if(FUSE_FOUND)
    add_executable(omnishare-fuse
        omnishare_fuse/omnishare_fuse.c
    )

    target_include_directories(omnishare-fuse
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/omnishare_fuse
            ${FUSE_INCLUDE_DIRS}
    )

    target_compile_definitions(omnishare-fuse
        PRIVATE
            _FILE_OFFSET_BITS=64
            FUSE_USE_VERSION=26
    )

    target_link_libraries(omnishare-fuse
        PRIVATE
            omnishare
            ${FUSE_LIBRARIES}
    )

    install(TARGETS omnishare-fuse
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
else()
    message(STATUS "FUSE not found - omnishare-fuse will not be built")
endif()
