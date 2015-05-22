LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libta_storage_test

LOCAL_SRC_FILES := \
		    storage_test_ta.c \
		    ../../tests/internal_api/storage_test.c

LOCAL_C_INCLUDES    :=	\
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/../include \
			$(LOCAL_PATH)/../../emulator/launcher \
			$(LOCAL_PATH)/../../emulator/internal_api

LOCAL_CFLAGS := -DANDROID -g -O0 -DTA_PLUGIN -DTA_STORAGE_TEST

LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_SHARED_LIBRARY)
