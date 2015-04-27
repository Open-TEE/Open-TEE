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
#define SHARED_MEMORY_COUNT 3

#define PRIIINTF(...) printf(__VA_ARGS__)

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_SharedMemory inout_mem[3];
	TEEC_Operation operation;
	TEEC_Result ret;
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;
	uint8_t dummy_data_arr[3][DUMMY_DATA_SIZE];
	int32_t dummy_value = 55;
	int i, i_shm, runs = 1000, i_test;

	memset((void *)&inout_mem, 0, sizeof(inout_mem));
	memset((void *)&operation, 0, sizeof(operation));
	memset(dummy_data_arr, 'x', sizeof(dummy_data_arr));

	PRIIINTF("START: conn test app\n");

	/* Initialize context */
	PRIIINTF("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		PRIIINTF("TEEC_InitializeContext failed: 0x%x\n", ret);
		goto end_1;
	} else {
		PRIIINTF("initiliazed\n");
	}


	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
					TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);

	operation.params[0].value.a = dummy_value;

	for (i_shm = 0; i_shm < SHARED_MEMORY_COUNT; i_shm++) {
		inout_mem[i_shm].buffer = dummy_data_arr[i_shm];
		inout_mem[i_shm].size = DUMMY_DATA_SIZE;
		inout_mem[i_shm].flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

		ret = TEEC_RegisterSharedMemory(&context, &inout_mem[i_shm]);
		if (ret != TEE_SUCCESS) {
			PRIIINTF("Failed to register shared memory");
			i_shm--;
			goto end_2;
		}
		operation.params[1 + i_shm].memref.parent = &inout_mem[i_shm];
	}

	while (runs--) {
		if ((runs%10) == 0)
			PRIIINTF("runs: %i/1000\n", runs);

		/* Open session */
		PRIIINTF("Openning session: ");

		memset(dummy_data_arr[0], 'X', DUMMY_DATA_SIZE);
		ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
					NULL, &operation, &return_origin);
		if (ret != TEEC_SUCCESS) {
			PRIIINTF("TEEC_OpenSession failed: 0x%x\n", ret);
			goto end_2;
		} else {
			PRIIINTF("opened\n");

			/* ensure that the first 20 bytes of the data have been over written
			 * by the TA adding an extra 5 bytes here as an indication that the
			 * orig data is still intact
			 */
			for (i = 0; i < 25; i++)
				PRIIINTF("%c", dummy_data_arr[0][i]);
			PRIIINTF("\n");
		}

		/* Invoke command */
		PRIIINTF("Invoking command: ");
		ret = TEEC_InvokeCommand(&session, 0, &operation, &return_origin);
		if (ret != TEEC_SUCCESS) {
			PRIIINTF("TEEC_InvokeCommand failed: 0x%x\n", ret);
			goto end_3;
		} else {
			PRIIINTF("invoked\n");
		}

		/* Invoke command many times*/
		i_test = 1000;
		while (i_test--) {

			if ((i_test%100) == 0)
				PRIIINTF("memtest: %i/1000\n", i_test);


			memset(dummy_data_arr, 2, sizeof(dummy_data_arr));

			ret = TEEC_InvokeCommand(&session, 1, &operation, &return_origin);
			if (ret != TEEC_SUCCESS) {
				PRIIINTF("TEEC_InvokeCommand failed: 0x%x\n", ret);
				goto end_3;
			} else {
				int n = 20;

				while (n--) {
					if (dummy_data_arr[0][n] != 3 ||
					    dummy_data_arr[1][n] != 6 ||
					    dummy_data_arr[2][n] != 10) {
						PRIIINTF("Data incorrect: 3=0x%x 6=0x%x 10=0x%x\n",
							dummy_data_arr[0][n],
							dummy_data_arr[1][n],
							dummy_data_arr[2][n]);
						goto end_3;
					}
				}
			}
		}

		/* Cleanup used connection/resources */

end_3:
		PRIIINTF("Closing session: ");
		TEEC_CloseSession(&session);
		PRIIINTF("Closed\n");
	}

end_2:
	while (i_shm >= 0)
		TEEC_ReleaseSharedMemory(&inout_mem[i_shm--]);

	PRIIINTF("Finalizing ctx: ");
	TEEC_FinalizeContext(&context);
	PRIIINTF("Finalized\n");

end_1:
	PRIIINTF("END: conn test app\n");
	exit(ret);
}
