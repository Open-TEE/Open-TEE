/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "trusteduiwidget.hpp"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui_(new Ui::MainWindow),
    tui_widget_(new TrustedUIWidget)
{
    ui_->setupUi(this);

    connect(ui_->actionSettings, SIGNAL(triggered()), this, SLOT(openSettingsDialog()));
    connect(ui_->actionQuit, SIGNAL(triggered()), this, SLOT(close()));

    // Connect Trusted UI Widget to Status bar
    connect(tui_widget_.data(),
	    SIGNAL(statusMessage(const QString &)),
	    this,
	    SLOT(showStatusBarMessage(const QString&)));

    this->setCentralWidget(tui_widget_.data());

    tui_widget_->start();
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

void MainWindow::showStatusBarMessage(const QString &msg)
{
    ui_->statusBar->showMessage(msg);
}
