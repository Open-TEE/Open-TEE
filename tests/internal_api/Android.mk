LOCAL_PATH := $(call my-dir)

############################################################
# Storage tests library
############################################################
include $(CLEAR_VARS)

LOCAL_MODULE := libStorageTest
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := storage_test.c
LOCAL_CFLAGS :=  -rdynamic -DANDROID -DOT_LOGGING -g -O0
LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi
include $(BUILD_SHARED_LIBRARY)

############################################################
# Crypto tests
############################################################
include $(CLEAR_VARS)

LOCAL_MODULE := crypto_test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := crypto_test.c
LOCAL_CFLAGS := -DANDROID -DOT_LOGGING
LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi
include $(BUILD_SHARED_LIBRARY)

