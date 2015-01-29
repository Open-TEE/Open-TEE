import qbs

DynamicLibrary {
    name: "tee_pkcs11"
    Depends { name: "cpp" }
    Depends { name: "tee" }
    cpp.includePaths: ["include"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        cpp.includePaths: "include"
    }

    files: [
        "include/pkcs11.h",
        "include/pkcs11t.h",
        "include/pkcs11f.h",
        "src/pkcs11_object.c",
    ]
}
