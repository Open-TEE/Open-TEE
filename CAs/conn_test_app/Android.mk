LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  conn_test_app
LOCAL_SRC_FILES	    :=   \
				conn_test_app.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    :=  \


LOCAL_SHARED_LIBRARIES := libdl libtee

include $(BUILD_EXECUTABLE)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
