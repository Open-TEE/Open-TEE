import qbs

CppApplication {
    type: "application"
    name: "usr_study_ca"
    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['usr_study_ca.c', 'usr_study_ta_ctrl.h']
}
