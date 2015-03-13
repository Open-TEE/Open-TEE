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

#ifndef TUISTATE_HPP
#define TUISTATE_HPP

#include <QObject>
#include <QSharedPointer>

#include <tuple>

#include "comprotocolmessage.hpp"
#include "tuiprotocol.hpp"
#include "tuisettings.hpp"

/***
 * \brief Class that maintains the State of Trusted User Interface.
 */
class TUIState : public QObject
{
	Q_OBJECT

public:
	enum State {
		TUI_STATE_DISCONNECTED,
		TUI_STATE_CONNECTED,
		TUI_STATE_SESSION,
		TUI_STATE_DISPLAY
	};

	explicit TUIState(QObject *parent = NULL);
	~TUIState();

	std::tuple <uint32_t, uint32_t, uint32_t, uint32_t> checkTextFormat(const QString &text);

	TUIProtocol::GetScreenInfoResponse getScreenInfo(TUIProtocol::GetScreenInfoRequest req);

	uint32_t initSession();

	uint32_t closeSession();

	uint32_t displayScreen();

public slots:
	void connected();

	void disconnected();

private:
	State current_state_;
	TUISettings settings_;
};

#endif // TUISTATE_HPP
