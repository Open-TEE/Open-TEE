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

/* Simple application for testing entry point functions calling.
 * Application will be updated as manager process development goes forward */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sign_ecdsa_256_ctrl.h"
#include "tee_client_api.h"

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation = {0};
	TEEC_SharedMemory in_mem = {0};
	TEEC_SharedMemory out_mem = {0};
	TEEC_Result tee_rv;
	unsigned char hash[32];
	unsigned char sig[72];

	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&out_mem, 0, sizeof(out_mem));
	memset((void *)&operation, 0, sizeof(operation));
	memset(hash, 0x23, 32);

	tee_rv = TEEC_InitializeContext(NULL, &context);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
		goto end_1;
	}

	tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
		goto end_2;
	}

	in_mem.buffer = hash;
	in_mem.size = 32;
	in_mem.flags = TEEC_MEM_INPUT;

	tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to register IN shared memory\n");
		goto end_3;
	}

	out_mem.buffer = sig;
	out_mem.size = 72;
	out_mem.flags = TEEC_MEM_OUTPUT;

	tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to allocate OUT shared memory\n");
		goto end_3;
	}

	operation.paramTypes =
	    TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
	operation.params[0].memref.parent = &in_mem;
	operation.params[1].memref.parent = &out_mem;
	tee_rv = TEEC_InvokeCommand(&session, SIGN_ECDSA_256_SIGN, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		goto end_4;
	}

	// Signature stored: operation.params[1].memref

end_4:
	TEEC_ReleaseSharedMemory(&out_mem);

end_3:
	TEEC_ReleaseSharedMemory(&in_mem);
	TEEC_CloseSession(&session);
end_2:
	TEEC_FinalizeContext(&context);
end_1:
	exit(tee_rv);
}
