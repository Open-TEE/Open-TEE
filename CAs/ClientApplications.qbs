import qbs

Project {
    name: "ClientApplications"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "test_session/test_session.qbs",
	"smoke_test_CAs/smoke_test_CAs.qbs",
    ]
}

