LOCAL_PATH := $(call my-dir)

local_c_includes := $(LOCAL_PATH)/../../emulator/include

############################################################
# Storage tests library
############################################################
include $(CLEAR_VARS)

LOCAL_MODULE := libstorage_test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := storage_test.c
LOCAL_C_INCLUDES := $(local_c_includes)
LOCAL_CFLAGS :=  -rdynamic -DANDROID -DOT_LOGGING -g -O0
LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi
include $(BUILD_SHARED_LIBRARY)

############################################################
# Crypto tests
############################################################
include $(CLEAR_VARS)

LOCAL_MODULE := libcrypto_test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := crypto_test.c
LOCAL_C_INCLUDES := $(local_c_includes)
LOCAL_CFLAGS := -DANDROID -DOT_LOGGING
LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi
include $(BUILD_SHARED_LIBRARY)

