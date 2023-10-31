/*****************************************************************************
** Copyright (C) 2015 Brian McGillion.                                      **
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

#ifndef OMNISHARE_PRIVATE_H
#define OMNISHARE_PRIVATE_H

#include <stdint.h>

/*!
 * \brief The key_chain_data struct
 * Structure to hold all of the key hirarachy needed to protect the keys
 */
struct key_chain_data {
	uint32_t key_count;	/*!< The number of keys in the chain */
	uint32_t key_len;	/*!< The size of each key */
	uint8_t keys[];		/*!< The keys themselves */
};

#endif // OMNISHARE_PRIVATE_H

