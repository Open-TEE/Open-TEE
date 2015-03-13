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

#include "comprotocolmessage.hpp"

ComProtocolMessage::ComProtocolMessage(const com_msg_hdr header,
                                       const QByteArray &payload)
{
    // Serialize header into byte array
    data_ = QByteArray(reinterpret_cast <const char *> (&header), sizeof(header));

    // Append payload to byte array
    data_.append(payload);
}

ComProtocolMessage::ComProtocolMessage(const uint8_t msg_name,
                                       const uint8_t msg_type,
                                       const uint64_t sess_id,
                                       const QByteArray &payload) :
    ComProtocolMessage(com_msg_hdr { sess_id, msg_name, msg_type }, payload)
{
}

ComProtocolMessage::ComProtocolMessage(const QByteArray &raw_message) :
    data_(raw_message)
{
}

ComProtocolMessage::~ComProtocolMessage()
{
}

com_msg_hdr ComProtocolMessage::getHeader() const
{
    com_msg_hdr header;

    // Deserialize header from byte array
    if (static_cast <unsigned int> (data_.size()) >= sizeof(header)) {
        memcpy(&header, data_.data(), sizeof(header));
    }

    return header;
}

QByteArray ComProtocolMessage::getPayload() const
{
    return data_.right(data_.size() - sizeof(com_msg_hdr));
}

QByteArray ComProtocolMessage::getRawData() const
{
    return data_;
}
