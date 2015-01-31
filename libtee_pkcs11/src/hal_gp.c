/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

#include "hal.h"
#include "tee_client_api.h"

#include <stdlib.h>

CK_RV hal_initialize_context(void **tee_context)
{
	TEEC_Context *context;
	int ret;

	if (tee_context == NULL)
		return CKR_ARGUMENTS_BAD;

	context = calloc(1, sizeof(TEEC_Context));
	if (context == NULL)
		return CKR_HOST_MEMORY;

	ret = TEEC_InitializeContext(NULL, context);
	if (ret != TEEC_SUCCESS) {
		free(context);
		return CKR_GENERAL_ERROR;
	}

	*tee_context = context;
	return CKR_OK;
}

CK_RV hal_finalize_context(void *tee_context)
{
	if (tee_context == NULL)
		return CKR_ARGUMENTS_BAD;

	TEEC_FinalizeContext(tee_context);

	free(tee_context);

	return CKR_OK;
}
