import qbs

CppApplication {
    type: "application"
    name: "usr_study_ca"
    Group {
        fileTagsFilter: "application"
        qbs.install: true
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['usr_study_ca.c', 'usr_study_ta_ctrl.h']
}
