# TAs - Trusted Applications
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# Include helper functions
include(OpenTEEHelpers)

# ============================================================================
# TA: example_ta (Basic Example TA)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ta(
        NAME example_ta
        SOURCES
            example_ta/example_ta.c
            example_ta/open_tee_conf.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/example_ta
    )
endif()

# ============================================================================
# TA: example_digest_ta (Digest/Hash Example)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ta(
        NAME example_digest
        SOURCES
            example_digest_ta/example_digest_ta.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/example_digest_ta
    )
endif()

# ============================================================================
# TA: sign_ecdsa_256 (ECDSA Signing Example)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ta(
        NAME sign_ecdsa_256
        SOURCES
            example_conversion/sign_ecdsa_256.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/example_conversion
    )
endif()

# ============================================================================
# TA: ta_conn_test (Connection Test TA)
# Note: This TA includes internal API tests (crypto, storage, ta2ta)
# ============================================================================

opentee_add_ta(
    NAME ta_conn_test
    SOURCES
        ta_conn_test_app/ta_conn_test_app.c
        ${CMAKE_SOURCE_DIR}/tests/internal_api/crypto_test.c
        ${CMAKE_SOURCE_DIR}/tests/internal_api/storage_test.c
        ${CMAKE_SOURCE_DIR}/tests/internal_api/ta2ta_test.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/ta_conn_test_app
        ${CMAKE_CURRENT_SOURCE_DIR}/ta2ta_conn_test_app
        ${CMAKE_SOURCE_DIR}/tests/internal_api
)

# ============================================================================
# TA: ta2ta_conn_test (TA-to-TA Connection Test)
# ============================================================================

opentee_add_ta(
    NAME ta2ta_conn_test
    SOURCES
        ta2ta_conn_test_app/ta2ta_conn_test_app.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/ta2ta_conn_test_app
)

# ============================================================================
# TA: ta_panic_crash (Panic/Crash Test TA)
# ============================================================================

if(OPENTEE_BUILD_TESTS)
    opentee_add_ta(
        NAME ta_panic_crash
        SOURCES
            ta_panic_crash/ta_panic_crash.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/ta_panic_crash
    )
endif()

# ============================================================================
# TA: ta_services (General Services TA)
# ============================================================================

opentee_add_ta(
    NAME ta_services
    SOURCES
        ta_services/ta_services.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/ta_services
)

# ============================================================================
# TA: user_study (User Study TA)
# ============================================================================

if(OPENTEE_BUILD_EXAMPLES)
    opentee_add_ta(
        NAME user_study
        SOURCES
            usr_study_ta/usr_study_ta.c
        INCLUDE_DIRS
            ${CMAKE_CURRENT_SOURCE_DIR}/usr_study_ta
    )
endif()

# ============================================================================
# TA: omnishare_ta (OmniShare TA)
# Note: omnishare_ta has size_t/uint32_t API compatibility issues on 64-bit.
# The TA passes uint32_t* where size_t* is expected. Disabling for now.
# ============================================================================

# TODO: Fix omnishare_ta.c to use size_t instead of uint32_t for output lengths
# opentee_add_ta(
#     NAME omnishare_ta
#     SOURCES
#         omnishare_ta/omnishare_ta.c
#     INCLUDE_DIRS
#         ${CMAKE_CURRENT_SOURCE_DIR}/omnishare_ta
# )
message(STATUS "omnishare_ta: Skipped (size_t/uint32_t API incompatibility on 64-bit)")

# ============================================================================
# TA: pkcs11_ta (PKCS#11 Cryptographic Token TA)
# ============================================================================

opentee_add_ta(
    NAME pkcs11_ta
    SOURCES
        # Common utilities
        pkcs11_ta/common/compat.c
        # GlobalPlatform implementation
        pkcs11_ta/gp/crypto.c
        pkcs11_ta/gp/object.c
        pkcs11_ta/gp/open_tee_conf.c
        pkcs11_ta/gp/pkcs11_application.c
        pkcs11_ta/gp/pkcs11_session.c
        pkcs11_ta/gp/pkcs11_ta.c
        pkcs11_ta/gp/slot_token.c
        pkcs11_ta/gp/utils.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_ta
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_ta/common
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_ta/gp
        ${CMAKE_SOURCE_DIR}/libtee_pkcs11/include
)
