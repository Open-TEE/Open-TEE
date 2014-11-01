import qbs

Project {
    name: "clients"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "test_session/test_session.qbs",
    ]
}

