import qbs

CppApplication {
    type: "application"
    name: "conn_without_param_ca"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ["conn_without_param_ca.c"]
}
