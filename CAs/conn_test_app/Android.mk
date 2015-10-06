LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  conn_test_app
LOCAL_SRC_FILES	    :=  conn_test_app.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    := $(LOCAL_PATH) \
                       $(LOCAL_PATH)/../../libtee/include


LOCAL_SHARED_LIBRARIES := libdl libtee

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_EXECUTABLE)
