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

#include "tee_client_api.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>


int main()
{
	TEEC_Context context;
	TEEC_Result ret;
	TEEC_SharedMemory shared_mem;

	printf("Starting\n");

	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS)
		printf("Error Connecting to the daemon: 0x%x\n", ret);

	shared_mem.size = 1024;
	shared_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_INPUT;

	ret = TEEC_AllocateSharedMemory(&context, &shared_mem);
	if (ret != TEEC_SUCCESS) {
		printf("Error allocating memory: 0x%x\n", ret);
		printf("Error is %s: %d\n", strerror(errno), errno);
	}

	printf("Session entering while loop\n");
	fflush(stdout);
	TEEC_ReleaseSharedMemory(&shared_mem);

	while(1) {

	}
	return 0;
}
