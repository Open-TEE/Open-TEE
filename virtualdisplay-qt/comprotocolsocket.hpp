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

#ifndef COMPROTOCOLSOCKET_HPP
#define COMPROTOCOLSOCKET_HPP

#include <QObject>
#include <QLocalSocket>

#include "comprotocolmessage.hpp"

class ComProtocolSocket : public QObject
{
	Q_OBJECT

public:
	explicit ComProtocolSocket(QObject *parent = NULL);
	~ComProtocolSocket();

	/***
	 * \brief Opens the socket connection.
	 * @return Returns true on success, false otherwise.
	 */
	bool start();

	/***
	 * \brief Closes the socket connection.
	 */
	void stop();

public slots:
	/***
	 * \brief Sends message through socket.
	 * @param msg Message to be sent.
	 * @return True on success, false otherwise.
	 */
	bool sendMessage(const ComProtocolMessage& msg);

signals:
	/***
	* \brief This signal is emitted when new message is succesfully received through socket.
	* @param msg Message
	*/
	void messageReceived(const ComProtocolMessage& msg);

	/***
	 * \brief This signal is emitted when socket is disconnected.
	 */
	void disconnected();

private slots:
	/***
	 * \brief Internal message handler. Called by QLocalSocket when message has been received.
	 */
	void receiveMessage();

private:
	/***
	 * \brief Convenience function for calculating CRC32 checksum.
	 * @param data Byte Array to calculate checksum for
	 * @return CRC32 checksum of data in bytearray
	 */
	static uint64_t calculateChecksum(const QByteArray &data);

	QLocalSocket socket_;
};

#endif // COMPROTOCOLSOCKET_HPP
