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
	0x12345678, 0x8765, 0x4321, { 'S', 'H', 'A', '1', '0', '0', '0', '0'}
};

/* Data buffer sizes */
#define DATA_SIZE	256
#define SHA1_SIZE	20

/* SHA1 TA command IDs */
#define SHA1_UPDATE	0x00000001
#define SHA1_DO_FINAL	0x00000002

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_SharedMemory in_mem;
	TEEC_SharedMemory out_mem;
	TEEC_Result ret;
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;
	char data[DATA_SIZE];
	uint8_t sha1[SHA1_SIZE];
	int i;

	printf("START: example SHA1 calc app\n");

	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&out_mem, 0, sizeof(out_mem));
	memset((void *)&operation, 0, sizeof(operation));
	memset(data, 'y', DATA_SIZE);
	memset(sha1, 0, SHA1_SIZE);

	/* Initialize context */
	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", ret);
		goto end_1;
	} else {
		printf("initiliazed\n");
	}

	/* Open session */
	printf("Openning session: ");
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
			       NULL, NULL, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("opened\n");
	}

	/* Register shared memory for initial hash */

	/* Data */
	in_mem.buffer = data;
	in_mem.size = DATA_SIZE;
	in_mem.flags = TEEC_MEM_INPUT;

	ret = TEEC_RegisterSharedMemory(&context, &in_mem);
	if (ret != TEE_SUCCESS) {
		printf("Failed to register DATA shared memory\n");
		goto end_3;
	}
	printf("Registered in mem..\n");

	/* Fill operation parameters */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	operation.params[0].memref.parent = &in_mem;

	/* Invoke command */
	printf("Invoking command: Update sha1: ");
	ret = TEEC_InvokeCommand(&session, SHA1_UPDATE, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
		goto end_3;
	} else {
		printf("done\n");
	}

	/* register a shared memory region to hold the output of the sha1 operation */
	out_mem.buffer = sha1;
	out_mem.size = SHA1_SIZE;
	out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(&context, &out_mem);
	if (ret != TEE_SUCCESS) {
		printf("Failed to allocate SHA1 shared memory\n");
		goto end_3;
	}
	printf("Registered out mem..\n");

	/*
	 * Send some more data to calculate the hash over, this will be added to the origional hash
	 * .  This is not strictly needed it is a test for passing 2 memref params in a single
	 * operation
	 */
	memset(data, 'Z', DATA_SIZE);

	/* Fill operation parameters */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
						TEEC_NONE, TEEC_NONE);
	/*
	 * reuse the origional input shared memory, because we have just updated the contents
	 * of the buffer
	 */
	operation.params[0].memref.parent = &in_mem;
	operation.params[1].memref.parent = &out_mem;

	/* Invoke command */
	printf("Invoking command: Do final sha1: ");
	ret = TEEC_InvokeCommand(&session, SHA1_DO_FINAL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
		goto end_4;
	} else {
		printf("done\n");
	}

	/* Printf sha1 buf */
	printf("Calculated sha1: ");
	for (i = 0; i < SHA1_SIZE; i++)
		printf("%02x", sha1[i]);
	printf("\n");

	/* Cleanup used connection/resources */

end_4:

	printf("Releasing shared out memory..\n");
	TEEC_ReleaseSharedMemory(&out_mem);

end_3:
	printf("Releasing shared in memory..\n");
	TEEC_ReleaseSharedMemory(&in_mem);
	printf("Closing session..\n");
	TEEC_CloseSession(&session);

end_2:

	printf("Finalizing ctx..\n");
	TEEC_FinalizeContext(&context);
end_1:

	printf("END: example SHA1 calc app\n");
	exit(ret);
}
