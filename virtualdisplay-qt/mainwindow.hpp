#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QCloseEvent>
#include <QMainWindow>
#include <QScopedPointer>

#include "settingsdialog.hpp"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void openSettingsDialog();
    bool close();
    void closeEvent(QCloseEvent *event);

private:
    QScopedPointer <Ui::MainWindow> ui_;
    SettingsDialog settings_;
};

#endif // MAINWINDOW_H
