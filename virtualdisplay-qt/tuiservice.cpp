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

#include <QDebug>
#include <QDataStream>

#include "tuiservice.hpp"
#include "tuiprotocol.hpp"
#include "tuistate.hpp"

extern "C" {
#include "com_protocol.h"
}

TUIService::TUIService(QSharedPointer <TUIState> state,
		       QObject *parent) :
	QObject(parent),
	state_(state)
{
}

TUIService::~TUIService()
{
}

void TUIService::messageReceived(const ComProtocolMessage& msg)
{
	// Verify that the message at least has the size of its header
	if (msg.getRawData().size() < static_cast <qint64> (sizeof(com_msg_hdr)))
		return;

	// Expect to get only query type of messages and
	// within the name set of Trusted UI messages.
	if (msg.getHeader().msg_type == 0)
		return;

	// ByteArray for response message
	QByteArray response;

	qDebug() << "msg_name: " << msg.getHeader().msg_name;

	// Determine service to be called
	// TODO: Deserialize params
	switch (msg.getHeader().msg_name) {
		case COM_MSG_NAME_TUI_CHECK_TEXT_FORMAT: {
			qDebug() << "check_text_format";
			check_text_format(response, msg.getPayload());
			break;
		}
		case COM_MSG_NAME_TUI_GET_SCREEN_INFO: {
			qDebug() << "get_screen_info";
			get_screen_info(response, msg.getPayload());
			break;
		}
		case COM_MSG_NAME_TUI_INIT_SESSION: {
			qDebug() << "init_session";
			init_session(response);
			break;
		}
		case COM_MSG_NAME_TUI_CLOSE_SESSION: {
			qDebug() << "close_session";
			close_session(response);
			break;
		}
		case COM_MSG_NAME_TUI_DISPLAY_SCREEN: {
			qDebug() << "display_screen";
			display_screen(response, msg.getPayload());
			break;
		}
		default: {
			return;
			break;
		}
	}

	// TODO: Send response
	com_msg_hdr response_header = msg.getHeader();

	// Set header message type as response,
	// retaining rest of the header contents
	response_header.msg_type = COM_TYPE_RESPONSE;

	ComProtocolMessage response_msg(response_header, response);

	emit sendMessage(response_msg);
}

template <typename MSGTYPE>
void msgpack_unpack(const QByteArray &msg, MSGTYPE &msgpack_struct)
{
	msgpack::unpacked result;
	msgpack::unpack(result, msg.data(), msg.size());
	msgpack::object o = result.get();

	o.convert(msgpack_struct);
}

class ByteArrayStream {
public:
	ByteArrayStream(QByteArray *ba):
		bytearray_(ba) {}

	ByteArrayStream& write (const char* s, size_t n)
	{
		bytearray_->append(s, n);

		return *this;
	}
private:
	QByteArray *bytearray_;
};

template <typename MSGTYPE>
void msgpack_pack(QByteArray &msg, MSGTYPE &msgpack_struct)
{
	ByteArrayStream out(&msg);
	msgpack::pack(out, msgpack_struct);
}

void TUIService::check_text_format(QByteArray &response, const QByteArray &msg)
{
	// Deserialize parameters
	TUIProtocol::CheckTextFormatRequest req;
	msgpack_unpack(msg, req);

	// Call TUI State for CheckTextFormat
	TUIProtocol::CheckTextFormatResponse resp;
	std::tie(resp.ret(), resp.width(), resp.height(), resp.lastIndex()) =
		state_->checkTextFormat(QString::fromStdString(req.text()));

	// Serialize response
	msgpack_pack(response, resp);
}

void TUIService::get_screen_info(QByteArray &response, const QByteArray &msg)
{
	// Deserialize parameters
	TUIProtocol::GetScreenInfoRequest req;
	msgpack_unpack(msg, req);

	// Serialize response
	TUIProtocol::GetScreenInfoResponse resp;
	resp.ret() = 1;
	msgpack_pack(response, resp);
}

void TUIService::init_session(QByteArray &response)
{
	// Serialize response
	TUIProtocol::InitSessionResponse resp(state_->initSession());
	msgpack_pack(response, resp);
}

void TUIService::close_session(QByteArray &response)
{
	// Serialize response
	TUIProtocol::CloseSessionResponse resp(state_->closeSession());
	msgpack_pack(response, resp);
}

void TUIService::display_screen(QByteArray &response, const QByteArray &msg)
{
	// Deserialize parameters
	TUIProtocol::DisplayScreenRequest req;
	msgpack_unpack(msg, req);

	// Serialize response
	TUIProtocol::DisplayScreenResponse resp;

	resp.ret() = 1;

	for (auto ef : req.entryFields()) {
		resp.entryFieldInput().push_back("foo");
	}

	msgpack_pack(response, resp);

	Q_ASSERT(req.entryFields().size() == resp.entryFieldInput().size());
}
