import qbs

CppApplication {
    name: "test_tui_socket"
    type: "application"

    destinationDirectory: '.'

    cpp.debugInformation: true
    Depends { name: "tee" }

    files: ["test_tui_socket.c"]
}
