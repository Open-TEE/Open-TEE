/*****************************************************************************
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#include "panic_crash_ctl.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'P', 'A', 'N', 'I', 'C', 'R', 'A', 'S'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif


static TEE_Result cause_crash_if_need(uint32_t cmd)
{
	uint32_t *nullptr = NULL;
	
	if (cmd == CMD_PANIC) {
		OT_LOG(LOG_ERR, "TEST: TA will panic");
		TEE_Panic(PANIC_RETURNCODE);
	} else if (cmd == CMD_SEG_FAULT) {
		OT_LOG(LOG_ERR, "TEST: TA will cause segfault");
		*nullptr = 1;
	} else if (cmd == CMD_NO_CRASH) {
		// Nothing
	} else {
		OT_LOG(LOG_ERR, "Not supported command [%u]", cmd);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the create entry point");

	/* Never panics/crash, because we would never reach
	 * open session / invoke commands */
	
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the Destroy entry point");
	
	// No panics/crash. CA would need more "sophisticated" code
	// for detecting panics/crashes
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
					      void **sessionContext)
{
	sessionContext = sessionContext;
	
	OT_LOG(LOG_INFO, "Calling the Open session entry point");

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected value in type as index 0 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return cause_crash_if_need(params[0].value.a);
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;
	
	OT_LOG(LOG_INFO, "Calling the Close session entry point");

	// No panics/crash. CA would need more "sophisticated" code
	// for detecting panics/crashes
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	sessionContext = sessionContext;
	paramTypes = paramTypes;
	params = params;

	OT_LOG(LOG_INFO, "Calling the invoke command entry point");

	return cause_crash_if_need(commandID);
}
