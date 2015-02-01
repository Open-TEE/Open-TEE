import qbs

DynamicLibrary {
    name: "signeleton_and_not_multi_ta"
    Group {
        fileTagsFilter: "dynamiclibrary"
        qbs.install: true
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["signeleton_and_not_multi_ta.c", "../../include/tee_ta_properties.h"]
}
