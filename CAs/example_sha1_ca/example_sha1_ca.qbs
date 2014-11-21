import qbs

CppApplication {
    type: "application"
    name: "example_sha1_ca"
    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['example_sha1_ca.c']
}
