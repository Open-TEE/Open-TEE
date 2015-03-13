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

#ifndef TUISETTINGS_HPP
#define TUISETTINGS_HPP

extern "C" {
#include "../emulator/include/tee_tui_data_types.h"
}
#include <QString>
#include <array>

struct ButtonInfo{
	QString buttonText;
	uint32_t buttonWidth = 100;
	uint32_t buttonHeight = 50;
	bool buttonTextCustom = true;
	bool buttonImageCustom = true;
};

struct TUISettings {
	uint32_t grayscaleBitsDepth = 8;
	uint32_t redBitsDepth = 8;
	uint32_t greenBitsDepth = 8;
	uint32_t blueBitsDepth = 8;
	uint32_t widthInch = 150;
	uint32_t heightInch = 150;
	uint32_t maxEntryFields = 4;
	uint32_t entryFieldLabelWidth = 200;
	uint32_t entryFieldLabelHeight = 100;
	uint32_t maxEntryFieldLength = 255;
	uint8_t labelColor[3] = {0, 0, 0};
	uint32_t labelWidth = 600;
	uint32_t labelHeight = 200;
	std::array <ButtonInfo, 6> buttonInfos;
};

#endif // TUISETTINGS_HPP
