import qbs

DynamicLibrary {
    name: "ta_conn_test_app"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: ["ta_conn_test_app.c", "../include/tee_ta_properties.h"]
}
