import qbs

DynamicLibrary {
    name: "ta2ta_conn_test_app"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "TAs"
    }

    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN","_FORTIFY_SOURCE=2"]

    files: ["ta2ta_conn_test_app.c", 
    	    "../include/tee_ta_properties.h"]
}
