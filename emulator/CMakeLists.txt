# emulator - Open-TEE Engine (TEE Emulator)
# CMakeLists.txt
#
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Library: CommonApi (shared utility library)
# ============================================================================

add_library(CommonApi SHARED
    common/com_protocol.c
    common/elf_read.c
    common/epoll_wrapper.c
    common/tee_list.c
    common/tee_logging.c
)

target_include_directories(CommonApi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/opentee>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/common
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
        ${LIBELF_INCLUDE_DIR}
)

target_link_libraries(CommonApi
    PRIVATE
        ${LIBELF_LIBRARY}
        ZLIB::ZLIB
)

target_compile_definitions(CommonApi PRIVATE _GNU_SOURCE)

set_target_properties(CommonApi PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

add_library(OpenTEE::CommonApi ALIAS CommonApi)

# ============================================================================
# Library: ManagerApi (TEE Manager/Dispatcher)
# ============================================================================

add_library(ManagerApi SHARED
    manager/ext_storage_stream_api_posix.c
    manager/io_thread.c
    manager/io_thread_tui.c
    manager/logic_thread.c
    manager/logic_thread_tui.c
    manager/mainloop.c
    manager/opentee_manager_storage_api.c
    manager/shm_mem.c
    manager/ta_dir_watch.c
    manager/tui_timeout.c
)

target_include_directories(ManagerApi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/manager>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/common
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api/storage
        ${UUID_INCLUDE_DIR}
)

target_link_libraries(ManagerApi
    PUBLIC
        CommonApi
    PRIVATE
        Threads::Threads
        ${DL_LIBRARY}
        ${RT_LIBRARY}
        ${UUID_LIBRARY}
)

target_compile_definitions(ManagerApi PRIVATE _GNU_SOURCE)

set_target_properties(ManagerApi PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

add_library(OpenTEE::ManagerApi ALIAS ManagerApi)

# ============================================================================
# Library: InternalApi (TEE Internal API for TAs)
# ============================================================================

add_library(InternalApi SHARED
    # Core internal API
    internal_api/callbacks.c
    internal_api/opentee_internal_api.c
    internal_api/tee_bigint.c
    internal_api/tee_cancellation.c
    internal_api/tee_internal_client_api.c
    internal_api/tee_memory.c
    internal_api/tee_panic.c
    internal_api/tee_time_api.c

    # Crypto operations
    internal_api/crypto/crypto_ae.c
    internal_api/crypto/crypto_asym.c
    internal_api/crypto/crypto_cipher.c
    internal_api/crypto/crypto_digest.c
    internal_api/crypto/crypto_generate_random.c
    internal_api/crypto/crypto_key_derive.c
    internal_api/crypto/crypto_mac.c
    internal_api/crypto/crypto_utils.c
    internal_api/crypto/tee_crypto_api.c

    # Storage operations
    internal_api/storage/data_stream_api.c
    internal_api/storage/enumerator_api.c
    internal_api/storage/persistent_object_api.c
    internal_api/storage/storage_utils.c
    internal_api/storage/tee_storage_api.c
    internal_api/storage/transient_object_api.c

    # Trusted User Interface
    internal_api/tee_tui_api.c
)

target_include_directories(InternalApi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/internal_api>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/internal_api/crypto>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/internal_api/storage>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/manager>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/common
)

target_link_libraries(InternalApi
    PUBLIC
        CommonApi
    PRIVATE
        OpenSSL::Crypto
        MbedTLS::mbedcrypto
        Threads::Threads
        ${RT_LIBRARY}
)

target_compile_definitions(InternalApi PRIVATE _GNU_SOURCE)

set_target_properties(InternalApi PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

add_library(OpenTEE::InternalApi ALIAS InternalApi)

# ============================================================================
# Library: LauncherApi (TA Loader and Process Management)
# ============================================================================

add_library(LauncherApi SHARED
    launcher/launcher_mainloop.c
    launcher/ta_internal_thread.c
    launcher/ta_internal_thread_tui.c
    launcher/dynamic_loader.c
    launcher/ta_io_thread.c
    launcher/ta_process.c
    launcher/ta_signal_handler.c
    ../cmp/cmp.c
)

target_include_directories(LauncherApi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/launcher>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../cmp
        ${CMAKE_CURRENT_SOURCE_DIR}/common
        ${CMAKE_CURRENT_SOURCE_DIR}/internal_api
)

target_link_libraries(LauncherApi
    PUBLIC
        CommonApi
        InternalApi
    PRIVATE
        Threads::Threads
        ${DL_LIBRARY}
        ${RT_LIBRARY}
)

target_compile_definitions(LauncherApi PRIVATE _GNU_SOURCE)

set_target_properties(LauncherApi PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

add_library(OpenTEE::LauncherApi ALIAS LauncherApi)

# ============================================================================
# Executable: opentee-engine (Main Entry Point)
# ============================================================================

add_executable(opentee-engine
    opentee-main/args.c
    opentee-main/conf_parser.c
    opentee-main/ini.c
    opentee-main/main.c
)

target_include_directories(opentee-engine
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/opentee-main
)

target_link_libraries(opentee-engine
    PRIVATE
        CommonApi
        ManagerApi
        LauncherApi
        Threads::Threads
        ${DL_LIBRARY}
)

# Enable dynamic symbol resolution for plugin loading
set_target_properties(opentee-engine PROPERTIES
    ENABLE_EXPORTS TRUE
)

target_compile_definitions(opentee-engine PRIVATE _GNU_SOURCE)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS
        CommonApi ManagerApi InternalApi LauncherApi opentee-engine
    EXPORT OpenTEETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install public headers (skip symlinks - they point to libtee headers which are installed separately)
# Only install actual header files, not symlinks
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/opentee
    FILES_MATCHING PATTERN "*.h"
    PATTERN "com_protocol.h" EXCLUDE
    PATTERN "tee_logging.h" EXCLUDE
    PATTERN "tee_shared_data_types.h" EXCLUDE
)

install(DIRECTORY internal_api/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/opentee
    FILES_MATCHING PATTERN "*.h"
)
