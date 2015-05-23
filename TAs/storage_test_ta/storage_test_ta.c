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


#include "tee_internal_api.h" /* TA envrionment */
#include "tee_logging.h" /* OpenTEE logging functions */
#include "com_protocol.h"

#include "ta_ctl_resources.h"
#include "ta_internal_thread.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'S', 'T', 'O', 'R', 'A', 'G', 'E', '0'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		0, /* multiSession */
		0) /* instanceKeepAlive */
#endif

/* Test Commands identifier */
#define TEST_PERSISTENT	0x00000001
#define TEST_MSG	0x00001000
#define CRASH	0x0000FA17

int ta_storage_test(int count);


TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	/* Run one round of testcases */
	ta_storage_test(1);


	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");
	/* No functionality */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	/* Parameter type is not needed */
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;

	/* Run one round of testcases */
	ta_storage_test(1);

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
	paramTypes = paramTypes;

	OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	if (commandID == TEST_PERSISTENT) {
		int count = params[0].value.a;
		while (count--)
			ta_storage_test(params[0].value.b);

	} else if (commandID == TEST_MSG) {
		int count2 = params[0].value.a;
		while (count2--) {
			int count = params[0].value.b;
			while (count--)	{
				TEE_Result retVal = TEE_SUCCESS;
				struct com_mgr_invoke_cmd_payload payload, returnPayload;

				payload.size = count;
				payload.data = TEE_Malloc(payload.size, 0);
				TEE_MemFill(payload.data, 0x77, payload.size);

				if (payload.data) {

					retVal = TEE_InvokeMGRCommand(TEE_TIMEOUT_INFINITE,
												  COM_MGR_CMD_ID_TEST_COMM,
												  &payload, &returnPayload);

					if ((retVal == TEE_SUCCESS) &&
					    (returnPayload.size-sizeof(struct com_mgr_invoke_cmd_payload)) == payload.size) {
						bool check = true;
						unsigned int n;
						for (n = 0; n < payload.size && check; n++)	{
							char *s = payload.data;
							char *r = returnPayload.data;
							check = s[n] == r[payload.size-1-n];
						}


						TEE_Free(returnPayload.data);
						if (!check)
							return TEE_ERROR_COMMUNICATION;
					} else if (retVal == TEE_SUCCESS &&
							   returnPayload.size == 0 &&
							   returnPayload.size == payload.size) {
						/* this is ok */
					} else {
						return TEE_ERROR_COMMUNICATION;
					}


					TEE_Free(payload.data);
				}
			}
		}
	} else {
		OT_LOG(LOG_ERR, "Unknow command ID");
	}

	return TEE_SUCCESS;
}


