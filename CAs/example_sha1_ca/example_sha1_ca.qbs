import qbs

CppApplication {
    type: "application"
    name: "example_sha1_ca"
    Group {
        fileTagsFilter: "application"
        qbs.install: true
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['example_sha1_ca.c']
}
