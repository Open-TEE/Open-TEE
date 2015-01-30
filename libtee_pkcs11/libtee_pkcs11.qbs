import qbs

DynamicLibrary {
    name: "tee_pkcs11"
    Depends { name: "cpp" }
    Depends { name: "tee" }
    cpp.includePaths: ["include"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        Depends { name: "tee" }
        cpp.includePaths: "include"
    }

    files: [
        "include/cryptoki.h",
        "include/pkcs11.h",
        "include/pkcs11t.h",
        "include/pkcs11f.h",
        "src/commands.h",
        "src/hal.h",
        "src/hal_gp.c",
        "src/pkcs11_crypto.c",
        "src/pkcs11_general.c",
        "src/pkcs11_object.c",
        "src/pkcs11_session_slot.c",
    ]
}
