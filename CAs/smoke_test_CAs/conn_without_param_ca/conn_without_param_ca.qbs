import qbs

CppApplication {
    type: "application"
    name: "conn_without_param_ca"
    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ["conn_without_param_ca.c"]
}
