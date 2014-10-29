import qbs

Project {
    name: "test_client"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "test_session/test_session.qbs",
    ]
}

