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
	using msgpack::define;
	using msgpack::type::tuple;

	struct CheckTextFormatRequest : define < std::string > {
		CheckTextFormatRequest() {}
		CheckTextFormatRequest(const std::string& text) :
			define_type(text) {}
		std::string& text() { return *this; }
	};

	struct CheckTextFormatResponse :
		define < tuple < uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t > > {
		CheckTextFormatResponse() {}
		CheckTextFormatResponse(uint32_t ret,
					uint32_t width,
					uint32_t height,
					uint32_t lastIndex) :
			define_type(msgpack_type(ret, width, height, lastIndex)) {}
		uint32_t& ret() { return msgpack::type::get<0>(*this); }
		uint32_t& width() { return msgpack::type::get<1>(*this); }
		uint32_t& height() { return msgpack::type::get<2>(*this); }
		uint32_t& lastIndex() { return msgpack::type::get<3>(*this); }

	};

	struct GetScreenInfoRequest :
		define < tuple < uint32_t,
				 uint32_t > > {
		GetScreenInfoRequest() {}
		GetScreenInfoRequest(uint32_t screenOrientation,
				     uint32_t nbEntryFields) :
			define_type(msgpack_type(screenOrientation,
						 nbEntryFields)) {}
		uint32_t &screenOrientation() { return msgpack::type::get<0>(*this); }
		uint32_t &nbEntryFields() { return msgpack::type::get<1>(*this); }
	};

	struct ButtonInfo :
		define < tuple < std::string,
				 uint32_t,
				 uint32_t,
				 bool,
				 bool > > {
		ButtonInfo() {}
		ButtonInfo(const std::string &text,
			   uint32_t buttonWidth,
			   uint32_t buttonHeight,
			   bool buttonTextCustom,
			   bool buttonImageCustom) :
			define_type(msgpack_type(text,
						 buttonWidth,
						 buttonHeight,
						 buttonTextCustom,
						 buttonImageCustom)) {}
		std::string &text() { return msgpack::type::get<0>(*this); }
		uint32_t &buttonWidth() { return msgpack::type::get<1>(*this); }
		uint32_t &buttonHeight() { return msgpack::type::get<2>(*this); }
		bool &buttonTextCustom() { return msgpack::type::get<3>(*this); }
		bool &buttonImageCustom() { return msgpack::type::get<4>(*this); }
	};

	struct GetScreenInfoResponse :
		define < tuple < uint32_t,
		                 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint8_t,
				 uint8_t,
				 uint8_t,
				 uint32_t,
				 uint32_t,
				 std::array <TUIProtocol::ButtonInfo, 6> > > {
		GetScreenInfoResponse() {}
		GetScreenInfoResponse(uint32_t ret,
				      uint32_t grayscaleBitsDepth,
				      uint32_t redBitsDepth,
				      uint32_t greenBitsDepth,
				      uint32_t blueBitsDepth,
				      uint32_t widthInch,
				      uint32_t heightInch,
				      uint32_t maxEntryFields,
				      uint32_t entryFieldLabelWidth,
				      uint32_t entryFieldLabelHeight,
				      uint32_t maxEntryFieldLength,
				      uint8_t labelColorRed,
				      uint8_t labelColorGreen,
				      uint8_t labelColorBlue,
				      uint32_t labelWidth,
				      uint32_t labelHeight,
				      const std::array <TUIProtocol::ButtonInfo, 6> &buttonInfos) :
			define_type(msgpack_type(ret,
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
						 buttonInfos)) {}
		uint32_t &ret() { return msgpack::type::get<0>(*this); }
		uint32_t &grayscaleBitsDepth() { return msgpack::type::get<1>(*this); }
		uint32_t &redBitsDepth() { return msgpack::type::get<2>(*this); }
		uint32_t &greenBitsDepth() { return msgpack::type::get<3>(*this); }
		uint32_t &blueBitsDepth() { return msgpack::type::get<4>(*this); }
		uint32_t &widthInch() { return msgpack::type::get<5>(*this); }
		uint32_t &heightInch() { return msgpack::type::get<6>(*this); }
		uint32_t &maxEntryFields() { return msgpack::type::get<7>(*this); }
		uint32_t &entryFieldLabelWidth() { return msgpack::type::get<8>(*this); }
		uint32_t &entryFieldLabelHeight() { return msgpack::type::get<9>(*this); }
		uint32_t &maxEntryFieldLength() { return msgpack::type::get<10>(*this); }
		uint8_t &labelColorRed() { return msgpack::type::get<11>(*this); }
		uint8_t &labelColorGreen() { return msgpack::type::get<12>(*this); }
		uint8_t &labelColorBlue() { return msgpack::type::get<13>(*this); }
		uint32_t &labelWidth() { return msgpack::type::get<14>(*this); }
		uint32_t &labelHeight() { return msgpack::type::get<15>(*this); }
		std::array <ButtonInfo, 6> &buttonInfos() { return msgpack::type::get<16>(*this); }
	};

	struct InitSessionResponse :
		define < tuple < uint32_t > > {
		InitSessionResponse() {}
		InitSessionResponse(uint32_t ret):
			define_type(msgpack_type(ret)) {}
		uint32_t& ret() { return msgpack::type::get<0>(*this); }
	};

	struct CloseSessionResponse :
		define < tuple < uint32_t > > {
		CloseSessionResponse() {}
		CloseSessionResponse(uint32_t ret):
			define_type(msgpack_type(ret)) {}
		uint32_t& ret() { return msgpack::type::get<0>(*this); }
	};

	struct Image :
		define < tuple < uint32_t,
				 std::string,
				 uint32_t,
				 uint32_t > > {
		Image() {}
		Image(uint32_t source,
		      const std::string &imageData,
		      uint32_t width,
		      uint32_t height):
			define_type(msgpack_type(source,
						 imageData,
						 width,
						 height)) {}
		uint32_t &source() { return msgpack::type::get<0>(*this); }
		std::string &imageData() { return msgpack::type::get<1>(*this); }
		uint32_t &width() { return msgpack::type::get<2>(*this); }
		uint32_t &height() { return msgpack::type::get<3>(*this); }
	};

	struct ScreenLabel :
		define < tuple < std::string,
				 uint32_t,
				 uint32_t,
				 uint8_t,
				 uint8_t,
				 uint8_t,
				 Image,
				 uint32_t,
				 uint32_t > > {
		ScreenLabel() {}
		ScreenLabel(const std::string &text,
			    uint32_t textXOffset,
			    uint32_t textYOffset,
			    uint8_t textColorRed,
			    uint8_t textColorGreen,
			    uint8_t textColorBlue,
			    const Image &image,
			    uint32_t imageXOffset,
			    uint32_t imageYOffset) :
			define_type(msgpack_type(text,
						 textXOffset,
						 textYOffset,
						 textColorRed,
						 textColorBlue,
						 textColorGreen,
						 image,
						 imageXOffset,
						 imageYOffset)) {}
		std::string &text() { return msgpack::type::get<0>(*this); }
		uint32_t &textXOffset() { return msgpack::type::get<1>(*this); }
		uint32_t &textYOffset() { return msgpack::type::get<2>(*this); }
		uint8_t &textColorRed() { return msgpack::type::get<3>(*this); }
		uint8_t &textColorGreen() { return msgpack::type::get<4>(*this); }
		uint8_t &textColorBlue() { return msgpack::type::get<5>(*this); }
		Image &image() { return msgpack::type::get<6>(*this); }
		uint32_t &imageXOffset() { return msgpack::type::get<7>(*this); }
		uint32_t &imageYOffset() { return msgpack::type::get<8>(*this); }
	};

	struct Button :
		define < tuple < bool, std::string, Image > > {
		Button() {}
		Button(bool defaults,
		       const std::string &text,
		       const Image &image) :
			define_type(msgpack_type(defaults,
						 text,
						 image)) {}
		bool &defaults() { return msgpack::type::get<0>(*this);  }
		std::string &text() { return msgpack::type::get<1>(*this); }
		Image &image() { return msgpack::type::get<2>(*this); }
	};

	struct ScreenConfiguration :
		define < tuple < uint32_t,
				 ScreenLabel,
				 std::array <Button, 6>,
				 std::array <bool, 6> > > {
		ScreenConfiguration() {}
		ScreenConfiguration(uint32_t screenOrientation,
				    const ScreenLabel &screenLabel,
				    const std::array <Button, 6> &buttons,
				    const std::array <bool, 6> &requestedButtons) :
			define_type(msgpack_type(screenOrientation,
						 screenLabel,
						 buttons,
						 requestedButtons)) {}
		uint32_t &screenOrientation() { return msgpack::type::get<0>(*this); }
		ScreenLabel &screenLabel() { return msgpack::type::get<1>(*this); }
		std::array <Button, 6> &buttons() { return msgpack::type::get<2>(*this); }
		std::array <bool, 6> &requestedButtons() { return msgpack::type::get<3>(*this); }
	};

	struct EntryField :
		define < tuple < std::string,
		                 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t,
				 uint32_t > > {
		EntryField() {}
		EntryField(const std::string &label,
			   uint32_t mode,
			   uint32_t type,
			   uint32_t minExpectedLength,
			   uint32_t maxExpectedLength,
			   uint32_t bufferLength):
			define_type(msgpack_type(label,
						 mode,
						 type,
						 minExpectedLength,
						 maxExpectedLength,
						 bufferLength)) {}
		std::string &label() { return msgpack::type::get<0>(*this); }
		uint32_t &mode() { return msgpack::type::get<1>(*this); }
		uint32_t &type() { return msgpack::type::get<2>(*this); }
		uint32_t &minExpectedLength() { return msgpack::type::get<3>(*this); }
		uint32_t &maxExpectedLength() { return msgpack::type::get<4>(*this); }
		uint32_t &bufferLength() { return msgpack::type::get<5>(*this); }
	};

	struct DisplayScreenRequest :
		define < tuple < ScreenConfiguration,
				 bool,
				 std::vector <EntryField> > > {
		DisplayScreenRequest() {}
		DisplayScreenRequest(const ScreenConfiguration &screenConfiguration,
				     bool closeTUISession,
				     const std::vector <EntryField> &entryFields) :
			define_type(msgpack_type(screenConfiguration,
						 closeTUISession,
						 entryFields)) {}
		ScreenConfiguration &screenConfiguration() { return msgpack::type::get<0>(*this); }
		bool &closeTUISession() { return msgpack::type::get<1>(*this); }
		std::vector <EntryField> &entryFields() { return msgpack::type::get<2>(*this); }
	};

	struct DisplayScreenResponse :
		define < tuple < uint32_t,
				 std::vector < std::string >,
				 uint32_t > > {
		DisplayScreenResponse() {}
		DisplayScreenResponse(uint32_t ret,
				      std::vector < std::string > entryFieldInput,
				      uint32_t selectedButton) :
			define_type(msgpack_type(ret,
						 entryFieldInput,
						 selectedButton)) {}
		uint32_t &ret() { return msgpack::type::get<0>(*this); }
		std::vector <std::string> &entryFieldInput()
		{
			return msgpack::type::get<1>(*this);
		}
		uint32_t &selectedButton() { return msgpack::type::get<2>(*this); }
	};
}

#endif // TUIPROTOCOL_HPP
