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

static TEEC_UUID uuid = {
	0x12345678, 0x1234, 0x1234, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

int main(int argc, char **argv)
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_Result ret;
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;

	argc = argc;

	printf("START: conn test app\n");

	/* Fill in connected TA last byte */
	uuid.clockSeqAndNode[7] = argv[1][0];

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
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method, NULL, NULL,
			       &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("opened\n");
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
	printf("Finalizing ctx: ");
	TEEC_FinalizeContext(&context);
	printf("Finalized\n");

end_1:
	printf("END: conn test app\n");
	exit(ret);
}
