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

#ifndef COMPROTOCOLMESSAGE_HPP
#define COMPROTOCOLMESSAGE_HPP

#include <QByteArray>

extern "C" {
#include "com_protocol.h"
}

/***
 * \brief Encapsulates one Com Protocol message.
 *        Used for serialization and deserialization of messages.
 */
class ComProtocolMessage
{
public:
    /***
     * \brief Construct message from header and payload.
     *        Used for serialization.
     * @param header Header for message.
     * @param payload Payload data for the message.
     */
    explicit ComProtocolMessage(const com_msg_hdr header,
                                const QByteArray &payload);
    /***
     * \brief Construct message from name, type and payload.
     *        Used for serialization.
     * @param msg_name 8-bit identifier for message name.
     * @param msg_type Message type as in Query (==1) or Response (==0).
     * @param payload Payload data for the message.
     */
    explicit ComProtocolMessage(const uint8_t msg_name,
                                const uint8_t msg_type,
                                const uint64_t sess_id,
                                const QByteArray &payload);

    /***
     * \brief Construct message from raw data.
     *        Used for deserialization.
     * @param raw_message Raw data of message.
     */
    explicit ComProtocolMessage(const QByteArray &raw_message);

    virtual ~ComProtocolMessage();

    /***
     * \brief Returns header of the message
     * \return Header of the message.
     */
    com_msg_hdr getHeader() const;

    /***
     * \brief Returns message payload.
     * \return Message payload.
     */
    QByteArray getPayload() const;

    /***
     * \brief Returns message in raw serialized form.
     * \return Message in serialized form.
     */
    QByteArray getRawData() const;

private:
    QByteArray data_;
};

#endif // COMPROTOCOLMESSAGE_HPP
