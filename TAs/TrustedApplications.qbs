import qbs

Project {
    name: "TrustedApplications"
    references: [
        "ta_conn_test_app/ta_conn_test_app.qbs",
        "smoke_test_TAs/smoke_test_TAs.qbs"
    ]
}
