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

#include <time.h>
#include <stdlib.h>

#include "tee_internal_api.h"
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
    { 0x12345678, 0x1234, 0x1234, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'f' } }, 512, 255, 1,
    0, 0)
#endif

static uint32_t naive_return_value_generator()
{
	/* Logic:
	 * TEE_SUCCESS is return zero
	 * Error return is > 0
	 * -->Do not care about exact error code, it is just positive value */
	return (rand() % 100) % 3;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	//OT_LOG(LOG_ERR, "Calling the create entry point");

	if (!naive_return_value_generator())
		return TEE_ERROR_GENERIC;
	else
		return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	//OT_LOG(LOG_ERR, "Calling the Destroy entry point");

	if (!naive_return_value_generator() != TEE_SUCCESS)
		exit(4); /* TA_STATE_PANICKED */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;

	//OT_LOG(LOG_ERR, "Calling the Open session entry point");

	if (!naive_return_value_generator())
		return TEE_ERROR_GENERIC;
	else
		return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	//OT_LOG(LOG_ERR, "Calling the Close session entry point");

	if (!naive_return_value_generator() != TEE_SUCCESS)
		exit(4); /* TA_STATE_PANICKED */
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	sessionContext = sessionContext;
	commandID = commandID;
	paramTypes = paramTypes;
	params = params;

	//OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	if (!naive_return_value_generator())
		return TEE_ERROR_GENERIC;
	else
		return TEE_SUCCESS;
}
