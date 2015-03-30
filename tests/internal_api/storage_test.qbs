import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    destinationDirectory: '.'

    cpp.defines: ["OT_LOGGING"]

    files: ["storage_test.c",
	   		"../../emulator/manager/opentee_manager_storage_api.c",
	   		"../../emulator/manager/ext_storage_stream_api_posix.c",
	   		"../../emulator/common/tee_list.c",
    		]
}
