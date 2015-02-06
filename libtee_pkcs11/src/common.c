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

#include "cryptoki.h"
#include "common.h"
#include "tee_client_api.h"

static CK_RV lib_shm_register(TEEC_SharedMemory *reg_shm_1, TEEC_SharedMemory *reg_shm_2,
			      TEEC_SharedMemory *reg_shm_3, TEEC_SharedMemory *reg_shm_4)
{
	if (reg_shm_1 && TEEC_RegisterSharedMemory(g_tee_context, reg_shm_1) != TEEC_SUCCESS)
		goto err_1;

	if (reg_shm_2 && TEEC_RegisterSharedMemory(g_tee_context, reg_shm_2) != TEEC_SUCCESS)
		goto err_2;

	if (reg_shm_3 && TEEC_RegisterSharedMemory(g_tee_context, reg_shm_3) != TEEC_SUCCESS)
		goto err_3;

	if (reg_shm_4 && TEEC_RegisterSharedMemory(g_tee_context, reg_shm_4) != TEEC_SUCCESS)
		goto err_4;

	return CKR_OK;

err_4:
	TEEC_ReleaseSharedMemory(reg_shm_3);
err_3:
	TEEC_ReleaseSharedMemory(reg_shm_2);
err_2:
	TEEC_ReleaseSharedMemory(reg_shm_1);
err_1:
	return CKR_GENERAL_ERROR;
}

static CK_RV lib_shm_release(TEEC_SharedMemory *reg_shm_1, TEEC_SharedMemory *reg_shm_2,
			     TEEC_SharedMemory *reg_shm_3, TEEC_SharedMemory *reg_shm_4)
{
	if (reg_shm_1)
		TEEC_ReleaseSharedMemory(reg_shm_1);

	if (reg_shm_2)
		TEEC_ReleaseSharedMemory(reg_shm_2);

	if (reg_shm_3)
		TEEC_ReleaseSharedMemory(reg_shm_3);

	if (reg_shm_4)
		TEEC_ReleaseSharedMemory(reg_shm_4);

	return CKR_OK;
}

LINK_SHM_FN(SHM_FN_RV_TYPE, SHM_LIB_REG_FN, SHM_PARAMS_NAME)
LINK_SHM_FN(SHM_FN_RV_TYPE, SHM_LIB_FREE_FN, SHM_PARAMS_NAME)
