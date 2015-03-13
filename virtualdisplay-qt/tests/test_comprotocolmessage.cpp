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

#include "test_comprotocolmessage.hpp"
#include "../comprotocolmessage.hpp"

void TestComProtocolMessage::serialize_and_deserialize()
{
    QByteArray source = "AABBCCDDEEFFaabbccddeeff";
    uint8_t name = 18;
    uint8_t type = 1;
    uint64_t session_id = 39481083;

    ComProtocolMessage msg1(name, type, session_id, source);

    QCOMPARE(msg1.getPayload(), source);
    QCOMPARE(msg1.getHeader().msg_name, name);
    QCOMPARE(msg1.getHeader().msg_type, type);
    QCOMPARE(msg1.getHeader().sess_id, session_id);

    ComProtocolMessage msg2(msg1.getRawData());

    QCOMPARE(msg2.getRawData(), msg1.getRawData());
    QCOMPARE(msg2.getPayload(), source);
    QCOMPARE(msg2.getHeader().msg_name, name);
    QCOMPARE(msg2.getHeader().msg_type, type);
    QCOMPARE(msg2.getHeader().sess_id, session_id);

    ComProtocolMessage msg3(msg1.getHeader(), msg1.getPayload());
    QCOMPARE(msg3.getRawData(), msg1.getRawData());
    QCOMPARE(msg3.getPayload(), source);
    QCOMPARE(msg3.getHeader().msg_name, name);
    QCOMPARE(msg3.getHeader().msg_type, type);
    QCOMPARE(msg3.getHeader().sess_id, session_id);
}

QTEST_MAIN(TestComProtocolMessage)
