import qbs

DynamicLibrary {
    name: "storage_test_ta"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    cpp.includePaths: ["../include" , "../../emulator/launcher"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN","TA_STORAGE_TEST"]

    files: ["storage_test_ta.c",
    		"../include/tee_ta_properties.h",
    		"../../tests/internal_api/storage_test.c"
    		]
}
