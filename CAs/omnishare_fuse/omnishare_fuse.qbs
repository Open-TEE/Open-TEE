import qbs
import qbs.Probes

CppApplication {
    type: "application"
    name: "omnishare_fuse"
    Group {
        name: "project-install"
        fileTagsFilter: "application"
        qbs.install: false
        qbs.installDir: "bin"
    }

    Depends { name: "cpp" }
    Depends { name: "omnishare" }

    Probes.PkgConfigProbe {
        id: fuseConfig
        name: "fuse"
    }

    cpp.cFlags: fuseConfig.cflags
    cpp.linkerFlags: fuseConfig.libs

    cpp.defines: ["OT_LOGGING", "FUSE_USE_VERSION=26"]

    consoleApplication: true
    destinationDirectory: '.'

    files: ["tee_logging.h", 'omnishare_fuse.c']
}
