import qbs

CppApplication {
    name: "pkcs11_test"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee_pkcs11" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['pkcs11_test_app.c']
}
