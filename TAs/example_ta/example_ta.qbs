import qbs

DynamicLibrary {
    name: "example_ta"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
        "example_ta.c",
        "../include/tee_ta_properties.h",
        "open_tee_conf.c",
    ]
}
