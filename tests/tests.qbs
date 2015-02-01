import qbs

Project {
    name: "tests"
    references: [
        "internal_api/storage_test.qbs",
        "internal_api/crypto_test.qbs",
        "pkcs11/pkcs11_test.qbs"
    ]
}


