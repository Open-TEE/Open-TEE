/*****************************************************************************
** Copyright (C) 2026 Mika Tammi                                            **
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
#include "test_tuiprotocol.hpp"
#include "../tuiprotocol.hpp"
#include "../tuiservice.hpp"

void TestTUIProtocol::test_check_text_format_request()
{
	TUIProtocol::CheckTextFormatRequest req;
	req.text = "String for testing the CheckTextFormatRequest.";
	QByteArray req_serialized;
	msgpack_pack(req_serialized, req);

	TUIProtocol::CheckTextFormatRequest req2;
	msgpack_unpack(req_serialized, req2);

	QCOMPARE(req.text, req2.text);
}

QTEST_MAIN(TestTUIProtocol)
