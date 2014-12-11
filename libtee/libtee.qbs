import qbs

DynamicLibrary {
    name: "tee"
    Depends { name: "cpp" }
    cpp.includePaths: ["include"]
    cpp.dynamicLibraries: ["rt", "z"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: "include"
    }

    files: [
        "include/com_protocol.h",
        "include/tee_client_api.h",
        "include/tee_logging.h",
        "include/tee_shared_data_types.h",
        "src/com_protocol.c",
        "src/tee_client_api.c",
    ]
}
