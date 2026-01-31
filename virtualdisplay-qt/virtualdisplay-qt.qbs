import qbs

CppApplication {
    name: 'virtualdisplay-qt'
    destinationDirectory: '.'

    cpp.cxxLanguageVersion: "c++14"
    cpp.dynamicLibraries: ['z']
    cpp.includePaths: ['../msgpack-c/include']
    cpp.cxxFlags: ['-ftemplate-depth=512']

    Depends { name: "tee" }

    Depends {
        name: "Qt"
        submodules: ["gui", "widgets", "network"]
    }

    files: [
	'comprotocolsocket.cpp',
	'comprotocolsocket.hpp',
	'comprotocolmessage.cpp',
	'comprotocolmessage.hpp',
        'main.cpp',
        'mainwindow.cpp',
        'mainwindow.hpp',
        'mainwindow.ui',
        'settingsdialog.cpp',
        'settingsdialog.hpp',
        'settingsdialog.ui',
        'trusteduiwidget.cpp',
	'trusteduiwidget.hpp',
	'tuiprotocol.cpp',
	'tuiprotocol.hpp',
	'tuiservice.cpp',
	'tuiservice.hpp',
	'tuisettings.hpp',
	'tuistate.cpp',
	'tuistate.hpp',
    ]
}
