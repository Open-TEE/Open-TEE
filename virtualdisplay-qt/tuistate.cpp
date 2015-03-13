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

#include "tuistate.hpp"

#include <QChar>
#include <QFont>
#include <QFontMetrics>
#include <QSize>

#include <algorithm>

extern "C" {
#include "tee_shared_data_types.h"
}

TUIState::TUIState(QObject *parent) :
	QObject(parent),
	current_state_(TUI_STATE_DISCONNECTED),
	settings_()
{
}

TUIState::~TUIState()
{
}

std::tuple <uint32_t, uint32_t, uint32_t, uint32_t> TUIState::checkTextFormat(const QString &text)
{
	uint32_t ret = TEE_SUCCESS;

	// TODO: Use default font for now, change later.
	QFont font;
	QFontMetrics fm(font);

	// Find last printable character
	QString::size_type lastIndex;
	for (lastIndex = 0; lastIndex < text.length(); ++lastIndex) {
		if (!fm.inFont(text.at(lastIndex))) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			break;
		}
	}

	// If last index is 0, let it be 0, otherwise decrement by 1
	lastIndex = lastIndex > 0 ? lastIndex - 1 : 0;

	// Get the size of text from font metrics
	QSize size = fm.size(0, text);

	return std::make_tuple(ret, size.width(), size.height(), lastIndex);
}

TUIProtocol::GetScreenInfoResponse TUIState::getScreenInfo(TUIProtocol::GetScreenInfoRequest req)
{
	uint32_t ret = req.nbEntryFields() > settings_.maxEntryFields ? TEE_ERROR_NOT_SUPPORTED : TEE_SUCCESS;

	std::array <TUIProtocol::ButtonInfo, 6> buttonInfos;
	std::transform (settings_.buttonInfos.begin(),
			settings_.buttonInfos.end(),
			buttonInfos.begin(),
			[] (const ButtonInfo &in) -> TUIProtocol::ButtonInfo {
				return TUIProtocol::ButtonInfo(in.buttonText.toStdString(),
							       in.buttonWidth,
							       in.buttonHeight,
							       in.buttonTextCustom,
							       in.buttonImageCustom);
			});

	return TUIProtocol::GetScreenInfoResponse(ret,
						  settings_.grayscaleBitsDepth,
						  settings_.redBitsDepth,
						  settings_.greenBitsDepth,
						  settings_.blueBitsDepth,
						  settings_.widthInch,
						  settings_.heightInch,
						  settings_.maxEntryFields,
						  settings_.entryFieldLabelWidth,
						  settings_.entryFieldLabelHeight,
						  settings_.maxEntryFieldLength,
						  settings_.labelColor[0],
						  settings_.labelColor[1],
						  settings_.labelColor[2],
						  settings_.labelWidth,
						  settings_.labelHeight,
						  buttonInfos);
}

uint32_t TUIState::initSession()
{
	// State transition: Connected -> Session
	if (current_state_ == TUI_STATE_CONNECTED) {
		current_state_ = TUI_STATE_SESSION;
		// TODO: Start timeout timer

		return TEE_SUCCESS;
	}
	return TEE_ERROR_BAD_STATE;
}

uint32_t TUIState::closeSession()
{
	// State transition: Session -> Connected
	if (current_state_ == TUI_STATE_SESSION) {
		current_state_ = TUI_STATE_CONNECTED;
		return TEE_SUCCESS;
	} else if (current_state_ == TUI_STATE_DISPLAY) {
		return TEE_ERROR_BUSY;
	}

	return TEE_ERROR_BAD_STATE;
}

uint32_t TUIState::displayScreen()
{
	// TODO: Implement
	if (current_state_ != TUI_STATE_SESSION)
		return TEE_ERROR_BAD_STATE;

	return 1;
}

void TUIState::connected()
{
	// TODO: Connection logic

	// State transition:
	// Disconnected -> Connected
	current_state_ = current_state_ == TUI_STATE_DISCONNECTED
		       ? TUI_STATE_CONNECTED : current_state_;
}

void TUIState::disconnected()
{
	// TODO: Disconnection logic
	current_state_ = TUI_STATE_DISCONNECTED;
}
