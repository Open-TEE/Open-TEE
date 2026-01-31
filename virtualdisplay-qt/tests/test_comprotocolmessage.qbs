import qbs

CppApplication {
    name: 'test_comprotocolmessage'
    destinationDirectory: '.'

    cpp.cxxLanguageVersion: "c++14"

    Depends {
        name: "Qt"
        submodules: ["test"]
    }

    Depends {
        name: "tee"
    }

    files: [
        '../comprotocolmessage.cpp',
        '../comprotocolmessage.hpp',
	'test_comprotocolmessage.cpp',
	'test_comprotocolmessage.hpp'
    ]
}
