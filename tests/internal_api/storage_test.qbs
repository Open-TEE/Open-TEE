import qbs

CppApplication {
    name: "storage_test"
    type: "dynamiclibrary"

    Depends { name: "InternalApi" }

    destinationDirectory: '.'

    cpp.defines: ["OT_LOGGING"]

    files: ["storage_test.c",
            "storage_test.h",
            "../../libtee/include/tee_logging.h"
    ]
}
