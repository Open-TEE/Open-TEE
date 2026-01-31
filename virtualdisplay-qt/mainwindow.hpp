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

#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QCloseEvent>
#include <QMainWindow>
#include <QScopedPointer>

#include "settingsdialog.hpp"

namespace Ui {
class MainWindow;
}

class TrustedUIWidget;

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
    void showStatusBarMessage(const QString &msg);

private:
    QScopedPointer <Ui::MainWindow> ui_;
    QScopedPointer <TrustedUIWidget> tui_widget_;
    SettingsDialog settings_;
};

#endif // MAINWINDOW_HPP
