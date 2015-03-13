#ifndef TRUSTEDUIWIDGET_HPP
#define TRUSTEDUIWIDGET_HPP

#include <QWidget>
#include <QSharedPointer>

#include "tuiservice.hpp"
#include "comprotocolsocket.hpp"

class TUIState;

class TrustedUIWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrustedUIWidget(QWidget *parent = 0);
    ~TrustedUIWidget();

    bool start();
    void stop();

public slots:
    void changeColor();

signals:
    void statusMessage(const QString &msg);

private:
    void sendDisplayInitMsg();

    QSharedPointer <TUIState> state_;
    ComProtocolSocket socket_;
    TUIService service_;
};

#endif // TRUSTEDUIWIDGET_HPP
