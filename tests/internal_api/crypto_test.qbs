import qbs

CppApplication {
    name: "crypto_test"
    type: "application"

    destinationDirectory: '.'

    cpp.debugInformation: true

    cpp.defines: ["OT_LOGGING"]

    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    files: ["crypto_test.c"]
}
