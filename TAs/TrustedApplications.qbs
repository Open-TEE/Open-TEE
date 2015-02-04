import qbs
import qbs.File

Project {
    name: "TrustedApplications"
    references: {
        var applets = [
                    "ta_conn_test_app/ta_conn_test_app.qbs",
                    "smoke_test_TAs/smoke_test_TAs.qbs",
                    "example_digest_ta/example_digest_ta.qbs",
                    "storage_test_ta/storage_test_ta.qbs",
                    "usr_study_ta/usr_study_ta.qbs",
                ]

        if (File.exists(sourceDirectory + "/TAs/pkcs11_ta/pkcs11_ta.qbs")) {
            applets.push("pkcs11_ta/pkcs11_ta.qbs")
        }
        return applets
    }
}
