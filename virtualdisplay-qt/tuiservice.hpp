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

#ifndef TUISERVICE_HPP
#define TUISERVICE_HPP

#include <QObject>
#include <QSharedPointer>

#include "comprotocolmessage.hpp"

class TUIState;

/***
 * \brief Class that handles incoming messages from Socket,
 *        deserializes them, calls the appropriate function in TUI State,
 *        and serializes and send back the response.
 */
class TUIService : public QObject
{
    Q_OBJECT

public:
    explicit TUIService(QSharedPointer <TUIState> state,
		        QObject *parent = NULL);
    ~TUIService();

signals:
    void sendMessage(const ComProtocolMessage& msg);

public slots:
    void messageReceived(const ComProtocolMessage& msg);

private:
    void check_text_format(QByteArray &response, const QByteArray &msg);
    void get_screen_info(QByteArray &response, const QByteArray &msg);
    void init_session(QByteArray &response);
    void close_session(QByteArray &response);
    void display_screen(QByteArray &response, const QByteArray &msg);

    QSharedPointer <TUIState> state_;
};

#endif // TUISERVICE_HPP
