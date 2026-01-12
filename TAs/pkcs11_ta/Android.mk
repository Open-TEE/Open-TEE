LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libta_pkcs11

LOCAL_SRC_FILES := \
	gp/crypto.c \
	gp/pkcs11_application.c \
	gp/pkcs11_session.c \
	gp/pkcs11_ta.c \
	gp/object.c \
	gp/open_tee_conf.c \
	gp/slot_token.c \
	gp/utils.c \
    ../../emulator/common/tee_list.c \
    common/compat.c

LOCAL_C_INCLUDES    :=	\
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/common \
			$(LOCAL_PATH)/../include \
			$(LOCAL_PATH)/../../emulator/include

LOCAL_CFLAGS := -DANDROID -g -O0 -DTA_PLUGIN

LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_SHARED_LIBRARY)
