import qbs

CppApplication {
    type: "application"
    name: "conn_without_param_ca"
    Group {
        fileTagsFilter: "application"
        qbs.install: true
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ["conn_without_param_ca.c"]
}
