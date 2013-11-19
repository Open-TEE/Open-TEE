import qbs

DynamicLibrary {
    Depends { name: "cpp" }
    Properties {
        condition: 1
        cpp.includePaths: ["include"]
        cpp.dynamicLibraries: ["uuid", "rt", "crypt"]
    }

    files: ["include/tee_client_api.h", 'src/open_emu_ipc/tee_client_api_emu_ipc.c',
    'src/open_emu_ipc/list.h', 'src/open_emu_ipc/list.c',
    'src/open_emu_ipc/utils.h', 'src/open_emu_ipc/utils.c',]
}

