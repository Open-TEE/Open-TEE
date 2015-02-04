import qbs

CppApplication {
    type: "application"
    name: "storage_test_ca"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['storage_test_ca.c']
}
