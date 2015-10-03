LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

local_shared_libraries := libtee
local_c_flags :=

local_src_files :=                          \
                src/omnishare.c

local_c_includes := \
                $(LOCAL_PATH)/src		    \
                $(LOCAL_PATH)/include       \
                $(LOCAL_PATH)/../libtee/include

local_export_c_include_dirs := $(LOCAL_PATH)/include

#################################################
# Target dynamic library

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(local_src_files)
LOCAL_C_INCLUDES += $(local_c_includes)
LOCAL_CFLAGS += $(local_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(local_export_c_include_dirs)
LOCAL_SHARED_LIBRARIES += libc $(local_shared_libraries)
LOCAL_MODULE := libomnishare
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := libomnishare
LOCAL_COPY_HEADERS += \
               include/omnishare.h
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
LOCAL_MODULE := libomnishare_static
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := libomnishare_static
LOCAL_COPY_HEADERS += \
               include/omnishare.h
include $(BUILD_STATIC_LIBRARY)
