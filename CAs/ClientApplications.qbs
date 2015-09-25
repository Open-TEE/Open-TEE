import qbs

Project {
    name: "ClientApplications"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "example_sha1_ca/example_sha1_ca.qbs",
        "usr_study_ca/usr_study_ca.qbs",
        "services_test/services_test.qbs",
    ]
}

