#ifndef TRUSTEDUIWIDGET_HPP
#define TRUSTEDUIWIDGET_HPP

#include <QWidget>
#include <QSharedPointer>

#include <QFormLayout>
#include <QVector>
#include <QLabel>
#include <QLineEdit>

#include "tuiprotocol.hpp"
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

    // TODO: HACK
    void displayScreen(TUIProtocol::DisplayScreenRequest req);
    void respond();

signals:
    void statusMessage(const QString &msg);

private:
    void cleanupScreen();

    void sendDisplayInitMsg();

    QSharedPointer <TUIState> state_;
    ComProtocolSocket socket_;
    TUIService service_;

    // TODO: HACK
    QFormLayout layout_;
    QVector < QLineEdit* > layout_widgets_;
};

#endif // TRUSTEDUIWIDGET_HPP
