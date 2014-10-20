/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#ifndef __TEE_TA_PROPERTIE_H__
#define __TEE_TA_PROPERTIE_H__

/* How to add/insert ta properties to our ta:
 * Use SET_TA_PROPERTIE macro in our source (.c) file.
 *
 * Example:
 * SET_TA_PROPERTIE({ 0x3E93632E, 0xA710, 0x469E,  \
 *        { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 } }, 512, 255, 1, 1, 1)
 */


#include <stdlib.h>
#include <stdbool.h>

#include "tee_shared_data_types.h"

#define PROPERTIE_SEC_NAME ".ta_properties"

#define SET_TA_PROPERTIE(...) struct gpd_ta_config ta_pro \
	__attribute__ ((section(PROPERTIE_SEC_NAME))) = { __VA_ARGS__ };

/*!
* \brief The gpd_ta_config struct
* This structure defines the Standard Configuration Properties of an applet as outlined in
* table 4-11 of the Internal API spec
*/
struct gpd_ta_config {
	TEE_UUID appID;
	size_t dataSize;
	size_t stackSize;
	bool singletonInstance;
	bool multiSession;
	bool instanceKeepAlive;
};

#endif /* __TEE_TA_PROPERTIE_H__ */
