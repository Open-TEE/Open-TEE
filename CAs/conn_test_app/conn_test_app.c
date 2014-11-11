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

/* Simple application for testing entry point functions calling.
 * Application will be updated as manager process development goes forward */

#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
	0x3E93632E, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 }
};

#define DUMMY_DATA_SIZE 1024

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_SharedMemory inout_mem;
	TEEC_Operation operation;
	TEEC_Result ret;
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;
	uint8_t dummy_data_arr[DUMMY_DATA_SIZE];
	int32_t dummy_value = 55;
	int i;

	memset((void *)&inout_mem, 0, sizeof(inout_mem));
	memset((void *)&operation, 0, sizeof(operation));
	memset(dummy_data_arr, 'x', sizeof(dummy_data_arr));

	printf("START: conn test app\n");

	/* Initialize context */
	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", ret);
		goto end_1;
	} else {
		printf("initiliazed\n");
	}

	inout_mem.buffer = dummy_data_arr;
	inout_mem.size = DUMMY_DATA_SIZE;
	inout_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(&context, &inout_mem);
	if (ret != TEE_SUCCESS) {
		printf("Failed to register shared memory");
		goto end_1;
	}

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
						TEEC_NONE, TEEC_NONE);

	operation.params[0].value.a = dummy_value;
	operation.params[1].memref.parent = &inout_mem;

	/* Open session */
	printf("Openning session: ");
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method, NULL, &operation,
			       &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("opened\n");

		/* ensure that the first 20 bytes of the data have been over written by the TA
		 * adding an extra 5 bytes here as an indication that the orig data is still intact
		 */
		for (i = 0; i < 25; i++)
			printf("%c", dummy_data_arr[i]);
		printf("\n");
	}

	/* Invoke command */
	printf("Invoking command: ");
	ret = TEEC_InvokeCommand(&session, 0, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
		goto end_3;
	} else {
		printf("invoked\n");
	}

	/* Cleanup used connection/resources */

end_3:
	printf("Closing session: ");
	TEEC_CloseSession(&session);
	printf("Closed\n");

end_2:
	TEEC_ReleaseSharedMemory(&inout_mem);
	printf("Finalizing ctx: ");
	TEEC_FinalizeContext(&context);
	printf("Finalized\n");

end_1:
	printf("END: conn test app\n");
	exit(ret);
}
