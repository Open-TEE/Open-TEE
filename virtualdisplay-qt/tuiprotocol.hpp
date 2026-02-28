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

#ifndef TUIPROTOCOL_HPP
#define TUIPROTOCOL_HPP

#include <string>
#include <vector>
#include <array>
#include <msgpack.hpp>

namespace TUIProtocol
{
	struct CheckTextFormatRequest {
		CheckTextFormatRequest() {}
		CheckTextFormatRequest(const std::string& t) : text(t) {}
		std::string text;
		MSGPACK_DEFINE(text);
	};

	struct CheckTextFormatResponse {
		CheckTextFormatResponse() {}
		CheckTextFormatResponse(uint32_t r,
					uint32_t w,
					uint32_t h,
					uint32_t l) : ret(r), width(w), height(h), lastIndex(l) {}
		uint32_t ret;
		uint32_t width;
		uint32_t height;
		uint32_t lastIndex;
		MSGPACK_DEFINE(ret, width, height, lastIndex);
	};

	struct GetScreenInfoRequest {
		GetScreenInfoRequest() {}
		GetScreenInfoRequest(uint32_t s,
				     uint32_t nb) : screenOrientation(s), nbEntryFields(nb) {}
		uint32_t screenOrientation;
		uint32_t nbEntryFields;
		MSGPACK_DEFINE(screenOrientation, nbEntryFields);
	};

	struct ButtonInfo {
		ButtonInfo() {}
		ButtonInfo(const std::string &t,
			   uint32_t bWidth,
			   uint32_t bHeight,
			   bool bTextCustom,
			   bool bImageCustom) :
			text(t),
			buttonWidth(bWidth),
			buttonHeight(bHeight),
			buttonTextCustom(bTextCustom),
			buttonImageCustom(bImageCustom)
		{}
		std::string text;
		uint32_t buttonWidth;
		uint32_t buttonHeight;
		bool buttonTextCustom;
		bool buttonImageCustom;
		MSGPACK_DEFINE(text,
			       buttonWidth,
			       buttonHeight,
			       buttonTextCustom,
			       buttonImageCustom);
	};

	struct GetScreenInfoResponse {
		GetScreenInfoResponse() {}
		GetScreenInfoResponse(uint32_t r,
				      uint32_t grayBD,
				      uint32_t redBD,
				      uint32_t greenBD,
				      uint32_t blueBD,
				      uint32_t wI,
				      uint32_t hI,
				      uint32_t mEF,
				      uint32_t eFLW,
				      uint32_t eFLH,
				      uint32_t mEFL,
				      uint8_t lCR,
				      uint8_t lCG,
				      uint8_t lCB,
				      uint32_t lW,
				      uint32_t lH,
				      const std::array <TUIProtocol::ButtonInfo, 6> &bIs) :
					ret(r),
					grayscaleBitsDepth(grayBD),
					redBitsDepth(redBD),
					greenBitsDepth(greenBD),
					blueBitsDepth(blueBD),
					widthInch(wI),
					heightInch(hI),
					maxEntryFields(mEF),
					entryFieldLabelWidth(eFLW),
					entryFieldLabelHeight(eFLH),
					maxEntryFieldLength(mEFL),
					labelColorRed(lCR),
					labelColorGreen(lCG),
					labelColorBlue(lCB),
					labelWidth(lW),
					labelHeight(lH),
					buttonInfos(bIs) {}
		uint32_t ret;
		uint32_t grayscaleBitsDepth;
		uint32_t redBitsDepth;
		uint32_t greenBitsDepth;
		uint32_t blueBitsDepth;
		uint32_t widthInch;
		uint32_t heightInch;
		uint32_t maxEntryFields;
		uint32_t entryFieldLabelWidth;
		uint32_t entryFieldLabelHeight;
		uint32_t maxEntryFieldLength;
		uint8_t labelColorRed;
		uint8_t labelColorGreen;
		uint8_t labelColorBlue;
		uint32_t labelWidth;
		uint32_t labelHeight;
		std::array <ButtonInfo, 6> buttonInfos;
		MSGPACK_DEFINE(ret,
			       grayscaleBitsDepth,
			       redBitsDepth,
			       greenBitsDepth,
			       blueBitsDepth,
			       widthInch,
			       heightInch,
			       maxEntryFields,
			       entryFieldLabelWidth,
			       entryFieldLabelHeight,
			       maxEntryFieldLength,
			       labelColorRed,
			       labelColorGreen,
			       labelColorBlue,
			       labelWidth,
			       labelHeight,
			       buttonInfos);
	};

	struct InitSessionResponse {
		InitSessionResponse() {}
		InitSessionResponse(uint32_t r): ret(r) {}
		uint32_t ret;
		MSGPACK_DEFINE(ret);
	};

	struct CloseSessionResponse {
		CloseSessionResponse() {}
		CloseSessionResponse(uint32_t r): ret(r) {}
		uint32_t ret;
		MSGPACK_DEFINE(ret);
	};

	struct Image {
		Image() {}
		Image(uint32_t s,
		      const std::string &iD,
		      uint32_t w,
		      uint32_t h):
			source(s), imageData(iD), width(w), height(h) {}
		uint32_t source;
		std::string imageData;
		uint32_t width;
		uint32_t height;
		MSGPACK_DEFINE(source, imageData, width, height);
	};

	struct ScreenLabel {
		ScreenLabel() {}
		ScreenLabel(const std::string &t,
			    uint32_t tXO,
			    uint32_t tYO,
			    uint8_t tCR,
			    uint8_t tCG,
			    uint8_t tCB,
			    const Image &i,
			    uint32_t iXO,
			    uint32_t iYO) :
			text(t),
			textXOffset(tXO),
			textYOffset(tYO),
			textColorRed(tCR),
			textColorGreen(tCG),
			textColorBlue(tCB),
			image(i),
			imageXOffset(iXO),
			imageYOffset(iYO) {}
		std::string text;
		uint32_t textXOffset;
		uint32_t textYOffset;
		uint8_t textColorRed;
		uint8_t textColorGreen;
		uint8_t textColorBlue;
		Image image;
		uint32_t imageXOffset;
		uint32_t imageYOffset;
		MSGPACK_DEFINE(text,
			       textXOffset,
			       textYOffset,
			       textColorRed,
			       textColorGreen,
			       textColorBlue,
			       image,
			       imageXOffset,
			       imageYOffset);
	};

	struct Button {
		Button() {}
		Button(bool d,
		       const std::string &t,
		       const Image &i) : defaults(d), text(t), image(i) {}
		bool defaults;
		std::string text;
		Image image;
		MSGPACK_DEFINE(defaults, text, image);
	};

	struct ScreenConfiguration {
		ScreenConfiguration() {}
		ScreenConfiguration(uint32_t sO,
				    const ScreenLabel &sL,
				    const std::array <Button, 6> &b,
				    const std::array <bool, 6> &rB) :
			screenOrientation(sO),
			screenLabel(sL),
			buttons(b),
			requestedButtons(rB) {}
		uint32_t screenOrientation;
		ScreenLabel screenLabel;
		std::array <Button, 6> buttons;
		std::array <bool, 6> requestedButtons;
		MSGPACK_DEFINE(screenOrientation, screenLabel, buttons, requestedButtons);
	};

	struct EntryField {
		EntryField() {}
		EntryField(const std::string &l,
			   uint32_t m,
			   uint32_t t,
			   uint32_t minEL,
			   uint32_t maxEL,
			   uint32_t bL):
			label(l),
			mode(m),
			type(t),
			minExpectedLength(minEL),
			maxExpectedLength(maxEL),
			bufferLength(bL) {}
		std::string label;
		uint32_t mode;
		uint32_t type;
		uint32_t minExpectedLength;
		uint32_t maxExpectedLength;
		uint32_t bufferLength;
		MSGPACK_DEFINE(label,
			       mode,
			       type,
			       minExpectedLength,
			       maxExpectedLength,
			       bufferLength);
	};

	struct DisplayScreenRequest {
		DisplayScreenRequest() {}
		DisplayScreenRequest(const ScreenConfiguration &sC,
				     bool cTUIS,
				     const std::vector <EntryField> &eF) :
			screenConfiguration(sC), closeTUISession(cTUIS), entryFields(eF) {}
		ScreenConfiguration screenConfiguration;
		bool closeTUISession;
		std::vector <EntryField> entryFields;
		MSGPACK_DEFINE(screenConfiguration, closeTUISession, entryFields);
	};

	struct DisplayScreenResponse {
		DisplayScreenResponse() {}
		DisplayScreenResponse(uint32_t r,
				      std::vector < std::string > eFI,
				      uint32_t sB) :
			ret(r), entryFieldInput(eFI), selectedButton(sB) {}
		uint32_t ret;
		std::vector <std::string> entryFieldInput;
		uint32_t selectedButton;
		MSGPACK_DEFINE(ret, entryFieldInput, selectedButton);
	};
}

#endif // TUIPROTOCOL_HPP
