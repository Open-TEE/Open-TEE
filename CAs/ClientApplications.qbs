import qbs

Project {
    name: "ClientApplications"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "test_session/test_session.qbs",
        "smoke_test_CAs/smoke_test_CAs.qbs",
        "example_sha1_ca/example_sha1_ca.qbs",
        "storage_test_ca/storage_test_ca.qbs",
        "usr_study_ca/usr_study_ca.qbs",
        "services_test/services_test.qbs",
    ]
}

