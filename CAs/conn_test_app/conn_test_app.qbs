import qbs

CppApplication {
    type: "application"
    name: "conn_test_app"
    Group {
        fileTagsFilter: "application"
        qbs.install: true
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['conn_test_app.c']
}
