#ifndef TEST_COMPROTOCOLMESSAGE_HPP
#define TEST_COMPROTOCOLMESSAGE_HPP

#include <QtTest/QtTest>

class TestComProtocolMessage : public QObject
{
    Q_OBJECT
private slots:
    void serialize_and_deserialize();
};

#endif // TEST_COMPROTOCOLMESSAGE_HPP
