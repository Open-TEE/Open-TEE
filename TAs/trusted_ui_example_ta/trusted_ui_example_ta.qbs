import qbs

DynamicLibrary {
    name: "trusted_ui_example_ta"

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
        "trusted_ui_example_ta.c",
        "../include/tee_ta_properties.h",
        "open_tee_conf.c",
    ]
}
