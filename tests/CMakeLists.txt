# tests - Test Applications
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# Include helper functions
include(OpenTEEHelpers)

# ============================================================================
# Test: pkcs11_test (PKCS#11 Test Application)
# ============================================================================

add_executable(pkcs11_test
    pkcs11/pkcs11_test_app.c
)

target_include_directories(pkcs11_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11
        ${CMAKE_SOURCE_DIR}/libtee_pkcs11/include
)

target_link_libraries(pkcs11_test
    PRIVATE
        tee_pkcs11
        tee
)

target_compile_definitions(pkcs11_test PRIVATE _GNU_SOURCE)

# Register as a CTest test
add_test(NAME pkcs11_test COMMAND pkcs11_test)

# ============================================================================
# Internal API Test Libraries (loaded as TAs)
# ============================================================================

# These are test TAs that exercise the internal API

# CryptoTest TA
opentee_add_ta(
    NAME CryptoTest
    SOURCES
        internal_api/crypto_test.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
)

# StorageTest TA
opentee_add_ta(
    NAME StorageTest
    SOURCES
        internal_api/storage_test.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
)

# TA2TA Test TA
opentee_add_ta(
    NAME ta2taTest
    SOURCES
        internal_api/ta2ta_test.c
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
        ${CMAKE_SOURCE_DIR}/TAs/ta2ta_conn_test_app
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS pkcs11_test
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT tests
)
