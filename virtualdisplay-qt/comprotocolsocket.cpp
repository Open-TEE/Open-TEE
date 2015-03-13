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

#include "comprotocolsocket.hpp"

// For crc32 function
#include <zlib.h>

// com_msg_hdr and com_transport_info structs
extern "C" {
#include "com_protocol.h"
}

const QString socket_file = "/tmp/open_tee_tui_display";

ComProtocolSocket::ComProtocolSocket(QObject *parent) :
	QObject(parent),
	socket_(this)
{
	// TODO: Socket error handling

	connect(&socket_, SIGNAL(readyRead()), this, SLOT(receiveMessage()));
}

ComProtocolSocket::~ComProtocolSocket()
{
	stop();
}

bool ComProtocolSocket::start()
{
	socket_.connectToServer(socket_file);
	if (!socket_.waitForConnected(30000))
	{
		qDebug() << "Error connecting to socket: " << socket_.errorString();
		return false;
	}

	qDebug() << "Listening socket " << socket_file;
	return true;
}

void ComProtocolSocket::stop()
{
	socket_.disconnectFromServer();

	emit disconnected();

	if (!socket_.waitForDisconnected(1000))
	{
		qDebug() << "Error disconnecting socket: " << socket_.errorString();
	}
}

bool ComProtocolSocket::sendMessage(const ComProtocolMessage& msg)
{
	// Generate transport info header
	com_transport_info info = { .start = COM_MSG_START,
		                    .data_len = static_cast <uint32_t> (msg.getRawData().size()),
				    .checksum = calculateChecksum(msg.getRawData()) };

	// Concatenate data into one continuous buffer
	QByteArray msg_bytes(reinterpret_cast <char *> (&info), sizeof(info));
	msg_bytes.append(msg.getRawData());

	// Write the message to socket
	qint64 bytes_written = socket_.write(msg_bytes);

	// Return true if data was successfully written
	const bool success = bytes_written != -1 && bytes_written == msg_bytes.size();

	if (!success)
		stop();

	return success;
}

void ComProtocolSocket::receiveMessage()
{
	// Read the "com_protocol" -header first
	com_transport_info info;
	socket_.read(reinterpret_cast <char *> (&info), sizeof(info));

	// Read the rest of the stuff
	ComProtocolMessage msg(socket_.read(info.data_len));

	// Check if message is of expected size
	if (msg.getRawData().size() != static_cast <int> (info.data_len)) {
		qDebug() << "Socket Error: received data size mismatch";

		// Error
		stop();
		return;
	}

	// Check message CRC32
	if (info.checksum != calculateChecksum(msg.getRawData()))
	{
		qDebug() << "Error: Received message checksum does not match";
		return;
	}

	// Emit the signal if no problems
	emit messageReceived(msg);
}

uint64_t ComProtocolSocket::calculateChecksum(const QByteArray &data)
{
	return crc32(0, reinterpret_cast <const unsigned char *> (data.data()), data.size());
}
