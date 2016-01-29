import qbs

DynamicLibrary {
    name: "pkcs11_ta"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include", "./common"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
        "../include/tee_ta_properties.h",
        "../../emulator/include/tee_list.h",
        "../../emulator/common/tee_list.c",
    ]
    Group {
        name: "Common Functionality"
        prefix: "common/"
        files: [
            "commands.h",
            "compat.c",
            "compat.h",
            "cryptoki.h",
            "pkcs11t.h",
            "token_conf.h",
        ]
    }

    Group {
        name: "GP Functionality"
        prefix: "gp/"
        files: [
            "crypto.h",
            "crypto.c",
            "pkcs11_application.c",
            "pkcs11_application.h",
            "pkcs11_session.c",
            "pkcs11_session.h",
            "pkcs11_ta.c",
            "object.h",
            "object.c",
            "open_tee_conf.c",
            "slot_token.c",
            "slot_token.h",
            "utils.c",
            "utils.h",
        ]
    }
}
