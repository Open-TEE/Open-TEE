#ifndef TRUSTEDUIWIDGET_H
#define TRUSTEDUIWIDGET_H

#include <QWidget>

class TrustedUIWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrustedUIWidget(QWidget *parent = 0);
    ~TrustedUIWidget();
};

#endif // TRUSTEDUIWIDGET_H
