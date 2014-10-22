import qbs

DynamicLibrary {
    name: "tee"
    Depends { name: "cpp" }
    cpp.includePaths: ["include"]
    cpp.dynamicLibraries: ["uuid", "rt", "crypt"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: "include"
    }

    files: [
        "include/socket_help.h",
        "include/tee_client_api.h",
        "include/tee_emu_client_api.h",
        "include/tee_logging.h",
        "include/tee_shared_data_types.h",
        "include/tee_ta_propertie.h",
        "src/socket_help.c",
        "src/tee_client_api_emu_ipc.c",
        "src/utils.h",
        "src/utils.c",
    ]
}
