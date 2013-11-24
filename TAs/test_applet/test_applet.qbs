import qbs

DynamicLibrary {
    name: "test_applet"
    Depends { name: "cpp" }
    Depends { name: "internal" }

    cpp.defines: ["TA_PLUGIN"]

    files: ["test_applet.c"]
}
