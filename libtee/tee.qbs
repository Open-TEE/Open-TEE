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

    files: ["include/tee_client_api.h", "include/tee_emu_client_api.h",
        'src/open_emu_ipc/tee_client_api_emu_ipc.c',
        'src/open_emu_ipc/list.h', 'src/open_emu_ipc/list.c',
        'src/open_emu_ipc/utils.h', 'src/open_emu_ipc/utils.c'
    ]
}
