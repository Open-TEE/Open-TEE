LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

local_shared_libraries := libtee
local_c_flags :=

local_src_files :=                          \
                src/hal_gp.c                \
                src/pkcs11_crypto.c	    \
                src/pkcs11_general.c        \
                src/pkcs11_object.c         \
                src/mutex_manager.c	    \
                src/pkcs11_session_slot.c

local_c_includes := \
                $(LOCAL_PATH)/src		    \
                $(LOCAL_PATH)/include

local_export_c_include_dirs := $(LOCAL_PATH)/include

#################################################
# Target dynamic library

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(local_src_files)
LOCAL_C_INCLUDES += $(local_c_includes)
LOCAL_CFLAGS += $(local_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(local_export_c_include_dirs)
LOCAL_SHARED_LIBRARIES += libc $(local_shared_libraries)
LOCAL_MODULE := libtee_pkcs11
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := libtee_pkcs11
LOCAL_COPY_HEADERS += \
               include/cryptoki.h \
               include/pkcs11f.h  \
               include/pkcs11.h   \
               include/pkcs11t.h
include $(BUILD_SHARED_LIBRARY)

###############################################
# Target static library

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(local_src_files)
LOCAL_C_INCLUDES += $(local_c_includes)
LOCAL_CFLAGS += $(local_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(local_export_c_include_dirs)
LOCAL_STATIC_LIBRARIES += libc
LOCAL_SHARED_LIBRARIES += $(local_shared_libraries)
LOCAL_MODULE := libtee_pkcs11_static
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := libtee_pkcs11_static
LOCAL_COPY_HEADERS += \
               include/cryptoki.h \
               include/pkcs11f.h  \
               include/pkcs11.h   \
               include/pkcs11t.h
include $(BUILD_STATIC_LIBRARY)

