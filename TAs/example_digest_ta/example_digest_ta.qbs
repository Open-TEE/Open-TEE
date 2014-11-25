import qbs

DynamicLibrary {
    name: "example_digest_ta"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["example_digest_ta.c", "../include/tee_ta_properties.h"]
}
