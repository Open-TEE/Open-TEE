import qbs

DynamicLibrary {
    name: "omnishare"
    Group {
        name: "project-install"
        fileTagsFilter: "dynamiclibrary"
        qbs.install: false
        qbs.installDir: "lib"
    }

    Depends { name: "cpp" }
    Depends { name: "tee" }

    cpp.includePaths: ["include"]
    cpp.dynamicLibraries: ["dl", "pthread"]

    destinationDirectory: '.'

    Export {
        Depends { name: "cpp" }
        Depends { name: "tee" }
        cpp.includePaths: "include"
    }

    files: [
        "include/omnishare.h",
        "src/omnishare.c",
        "src/omnishare_private.h",
    ]
}
