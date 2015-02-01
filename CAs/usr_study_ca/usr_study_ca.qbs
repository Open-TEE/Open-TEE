import qbs

CppApplication {
    type: "application"
    name: "usr_study_ca"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['usr_study_ca.c', 'usr_study_ta_ctrl.h']
}
