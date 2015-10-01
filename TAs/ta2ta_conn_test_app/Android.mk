LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libta2ta_conn_test_app

LOCAL_SRC_FILES := \
		    ta2ta_conn_test_app.c

LOCAL_C_INCLUDES    :=	\
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/../include

LOCAL_CFLAGS := -DANDROID -g -O0 -DTA_PLUGIN

LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_SHARED_LIBRARY)
