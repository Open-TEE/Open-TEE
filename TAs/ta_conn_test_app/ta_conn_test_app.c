/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#include "tee_internal_api.h"
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
    { 0x3E93632E, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 } }, 512, 255, 1,
    1, 1)
#endif

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	int i;
	paramTypes = paramTypes;
	sessionContext = sessionContext;
	uint8_t *mem_data = (uint8_t *)(params[1].memref.buffer);

	OT_LOG(LOG_ERR, "Calling the Open session entry point");

	OT_LOG(LOG_ERR, "param value is %d", params[0].value.a);

	OT_LOG(LOG_ERR, "param mem data size is %zu", params[1].memref.size);

	if (params[1].memref.buffer == NULL)
		OT_LOG(LOG_ERR, "NULL ???????????????");

	for (i = 0; i < 20; i++) {
		OT_LOG(LOG_ERR, "Mem value : %c", mem_data[i]);
		/* return some data to the user */
		mem_data[i] = 'y';
	}

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	OT_LOG(LOG_ERR, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	sessionContext = sessionContext;
	commandID = commandID;
	paramTypes = paramTypes;
	params = params;

	OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	return TEE_SUCCESS;
}
