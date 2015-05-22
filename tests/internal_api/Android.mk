LOCAL_PATH := $(call my-dir)

############################################################
# Storage tests binary
############################################################
include $(CLEAR_VARS)

LOCAL_MODULE := storage_test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := storage_test.c \
		../../emulator/manager/opentee_manager_storage_api.c \
		../../emulator/manager/ext_storage_stream_api_posix.c \
		../../emulator/common/tee_list.c

LOCAL_CFLAGS :=  -rdynamic -DANDROID -DOT_LOGGING

LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

include $(BUILD_EXECUTABLE)

############################################################
# Crypto tests
############################################################
#include $(CLEAR_VARS)

#LOCAL_MODULE := crypto_test
#LOCAL_MODULE_TAGS := optional
#LOCAL_SRC_FILES := crypto_test.c
#LOCAL_CFLAGS := -DANDROID -DOT_LOGGING

#LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

#include $(BUILD_EXECUTABLE)
