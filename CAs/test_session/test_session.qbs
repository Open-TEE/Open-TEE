import qbs

CppApplication {
    type: "application"
    name: "test_session"
    Depends { name: "tee" }
    consoleApplication: true
    destinationDirectory: '.'

    files: ['test_session.c']
}

//CppApplication {
//    type: "application"
//    name: "test_write_sock"
//    Depends { name: "tee" }
//    files: "src/raw_socket.c"
//}
