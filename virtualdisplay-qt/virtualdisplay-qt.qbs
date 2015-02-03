import qbs

CppApplication {
    name: 'virtualdisplay-qt'
    destinationDirectory: '.'

    Depends { name: "tee" }

    Depends {
        name: "Qt"
        submodules: ["gui", "widgets"]
    }

    files: [
        'main.cpp',
        'mainwindow.cpp',
        'mainwindow.hpp',
        'mainwindow.ui',
        'settingsdialog.cpp',
        'settingsdialog.hpp',
        'settingsdialog.ui',
        'trusteduiwidget.cpp',
        'trusteduiwidget.hpp'
    ]
}
