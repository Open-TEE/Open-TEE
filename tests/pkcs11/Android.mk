LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(BUILD_WITH_SECURITY_FRAMEWORK),chaabi_token)

LOCAL_MODULE := pkcs11_test
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := pkcs11_test_app.c

LOCAL_STATIC_LIBRARIES := libc libdx_cc7_static libtee_pkcs11_static
LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

endif #Chaabi token build
