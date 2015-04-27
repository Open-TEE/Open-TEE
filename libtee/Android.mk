LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libtee

LOCAL_SRC_FILES := \
				src/com_protocol.c \
				src/tee_client_api.c

LOCAL_C_INCLUDES    :=	\
				$(LOCAL_PATH)/include \
				external/zlib



LOCAL_SHARED_LIBRARIES := libc libdl libz

LOCAL_EXPORT_C_INCLUDE_DIRS := \
				$(LOCAL_PATH)/include

LOCAL_C_FLAGS := -DANDROID -lz -DOT_LOGGING

include $(BUILD_SHARED_LIBRARY)