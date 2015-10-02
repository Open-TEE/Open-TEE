import qbs

DynamicLibrary {
    name: "ta_conn_test_app"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }
    Depends { name: "crypto_test" }
    Depends { name: "storage_test" }

    cpp.includePaths: ["../include", "../../tests/internal_api"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN","_FORTIFY_SOURCE=2"]

    files: ["conn_test_ctl.h",
            "ta_conn_test_app.c",
            "../include/tee_ta_properties.h",
            "../../tests/internal_api/storage_test.h",
            "../../tests/internal_api/crypto_test.h"
    ]
}
