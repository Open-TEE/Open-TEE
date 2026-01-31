#-------------------------------------------------
#
# Project created by QtCreator 2014-12-22T14:13:29
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = virtualdisplay-qt
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    settingsdialog.cpp \
    trusteduiwidget.cpp

HEADERS  += mainwindow.hpp \
    settingsdialog.hpp \
    trusteduiwidget.hpp

FORMS    += mainwindow.ui \
    settingsdialog.ui
