LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := pkcs11_test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := pkcs11_test_app.c

LOCAL_SHARED_LIBRARIES := libc libdl libtee libtee_pkcs11

include $(BUILD_EXECUTABLE)
