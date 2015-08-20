import qbs

CppApplication {
    name: "crypto_test"
    type: "dynamiclibrary"

    Depends { name: "InternalApi" }

    destinationDirectory: '.'

    cpp.defines: ["OT_LOGGING"]

    files: ["crypto_test.c",
            "crypto_test.h",
            "../../libtee/include/tee_logging.h"
    ]
}
