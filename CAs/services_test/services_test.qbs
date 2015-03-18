import qbs

CppApplication {
    type: "application"
    name: "services_test"
    Group {
        fileTagsFilter: "application"
        qbs.install: true
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['services_test.c']
}
