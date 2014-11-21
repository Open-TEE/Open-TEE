import qbs

Project {
    name: "TrustedApplications"
    references: [
        "ta_conn_test_app/ta_conn_test_app.qbs",
        "smoke_test_TAs/smoke_test_TAs.qbs",
        "example_sha1_ta/example_sha1_ta.qbs",
    ]
}
