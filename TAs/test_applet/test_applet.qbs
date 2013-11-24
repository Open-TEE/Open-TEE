import qbs

DynamicLibrary {
    name: "test_applet"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.defines: ["TA_PLUGIN"]

    files: ["test_applet.c"]
}
