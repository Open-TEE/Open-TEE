import qbs

CppApplication {
    type: "application"
    name: "conn_test_app"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['conn_test_app.c']
}
