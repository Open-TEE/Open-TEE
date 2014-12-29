import qbs

CppApplication {
    name: "trusted_ui_example_ca"

    Depends { name: "tee" }
    Depends { name: "OpenSSL" }

    destinationDirectory: '.'

    files: ['trusted_ui_example_ca.c']
}
