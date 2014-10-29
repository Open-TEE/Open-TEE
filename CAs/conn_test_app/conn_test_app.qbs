import qbs

CppApplication {
    type: "application"
    name: "conn_test_app"
    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['conn_test_app.c']
}
