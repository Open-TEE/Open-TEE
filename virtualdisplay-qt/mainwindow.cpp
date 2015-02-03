#include "mainwindow.hpp"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui_(new Ui::MainWindow)
{
    ui_->setupUi(this);

    connect(ui_->actionSettings, SIGNAL(triggered()), this, SLOT(openSettingsDialog()));
    connect(ui_->actionQuit, SIGNAL(triggered()), this, SLOT(close()));
}

MainWindow::~MainWindow()
{
}

void MainWindow::openSettingsDialog()
{
    // Show settings dialog
    settings_.show();
}

bool MainWindow::close()
{
    // Call the superclass close function
    QMainWindow::close();

    // Close settings dialog in case it has been opened
    settings_.close();

    // Return true to indicate that window was closed
    return true;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // Close window first
    close();

    // Accept the event
    event->accept();
}
