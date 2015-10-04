import qbs
import qbs.File

Project {
    name: "TrustedApplications"
    references: {
        var applets = [
                    "ta_conn_test_app/ta_conn_test_app.qbs",
                    "example_digest_ta/example_digest_ta.qbs",
                    "usr_study_ta/usr_study_ta.qbs",
                    "ta_services/ta_services.qbs",
                    "ta2ta_conn_test_app/ta2ta_conn_test_app.qbs",
                    "omnishare_ta/omnishare_ta.qbs"
                ]

        if (File.exists(sourceDirectory + "/TAs/pkcs11_ta/pkcs11_ta.qbs")) {
            applets.push("pkcs11_ta/pkcs11_ta.qbs")
        }
        return applets
    }
}
