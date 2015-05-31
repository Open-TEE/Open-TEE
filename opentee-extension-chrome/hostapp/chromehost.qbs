import qbs

CppApplication {
    type: "application"
    name: "chromehost"
    cpp.includePaths: ['./include/']
    Depends { name: "tee" }
    Depends { name: "tee_pkcs11" }
    consoleApplication: true
    destinationDirectory: '.'
    files: ['main.cpp', 'include/base64/base64.cpp']
}
