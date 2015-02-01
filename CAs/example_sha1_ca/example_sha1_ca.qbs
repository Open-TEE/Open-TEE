import qbs

CppApplication {
    type: "application"
    name: "example_sha1_ca"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['example_sha1_ca.c']
}
