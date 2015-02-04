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
	0x12345678, 0x8765, 0x4321, { 'S', 'T', 'O', 'R', 'A', 'G', 'E', '0'}
};


/* Commands */
#define TEST_PERSISTENT	0x00000001
#define TEST_MSG	0x00001000
#define CRASH	0x0000FA17

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_Result ret;
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;

	printf("START: storage test app\n");

	memset((void *)&operation, 0, sizeof(operation));

	/* Initialize context */
	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", ret);
		goto end_1;
	} else {
		printf("initiliazed\n");
	}

	/* Open session is expecting HASH algorithm */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Open session */
	printf("Openning session: ");
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
			       NULL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("opened\n");
	}

	/* Register shared memory for initial hash */

	/* Invoke command */
	printf("test comms: ");
	operation.params[0].value.a = 1;
	operation.params[0].value.b = 10000;
	ret = TEEC_InvokeCommand(&session, TEST_MSG, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
		goto end_4;
	} else {
		printf("done\n");
	}

	/* Invoke command */
	printf("storagetest: ");
	operation.params[0].value.a = 1;
	operation.params[0].value.b = 1;

	ret = TEEC_InvokeCommand(&session, TEST_PERSISTENT, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
		goto end_4;
	} else {
		printf("done\n");
	}
	printf("Closing session..\n");

end_4:
	TEEC_CloseSession(&session);

end_2:

	printf("Finalizing ctx..\n");
	TEEC_FinalizeContext(&context);
end_1:

	printf("END: storage test app\n");
	exit(ret);
}
