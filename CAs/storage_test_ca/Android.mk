LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  storage_test_ca
LOCAL_SRC_FILES	    :=  storage_test_ca.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    :=

LOCAL_SHARED_LIBRARIES := libdl libtee

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_EXECUTABLE)
