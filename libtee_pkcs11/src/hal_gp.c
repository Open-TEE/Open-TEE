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

#include "commands.h"
#include "hal.h"
#include "tee_client_api.h"

#include <stdlib.h>
#include <string.h>

/*!
 * \brief g_tee_context
 * A context that is created towards the TEE
 */
TEEC_Context *g_tee_context;

/*!
 * \brief g_control_session
 * A session that is used for command and control messages, NOT PKCS#11 sessions
 */
TEEC_Session *g_control_session;

static const TEEC_UUID uuid = {
	0x12345678, 0x8765, 0x4321, { 'P', 'K', 'C', 'S', '1', '1', 'T', 'A'}
};

bool is_lib_initialized()
{
	return g_tee_context != NULL;
}

CK_RV hal_initialize_context()
{
	int ret = CKR_OK;
	uint32_t return_origin;
	TEEC_Operation operation;

	memset(&operation, 0, sizeof(TEEC_Operation));

	if (g_tee_context)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	g_tee_context = calloc(1, sizeof(TEEC_Context));
	if (g_tee_context == NULL)
		return CKR_HOST_MEMORY;

	g_control_session = calloc(1, sizeof(TEEC_Session));
	if (g_control_session == NULL) {
		ret = CKR_HOST_MEMORY;
		goto err_out;
	}

	ret = TEEC_InitializeContext(NULL, g_tee_context);
	if (ret != TEEC_SUCCESS) {
		ret =  CKR_GENERAL_ERROR;
		goto err_out;
	}

	/* open the command and control session */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						TEEC_NONE, TEEC_NONE);
	operation.params[0].value.a = TEE_CONTROL_SESSION;

	ret = TEEC_OpenSession(g_tee_context, g_control_session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		ret =  CKR_GENERAL_ERROR;
		goto err_out;
	}

	return ret;

err_out:
	free(g_tee_context);
	free(g_control_session);
	g_tee_context = NULL;
	g_control_session = NULL;

	return ret;
}

CK_RV hal_finalize_context()
{
	if (g_tee_context == NULL || g_control_session == NULL)
		return CKR_OK; /* nothing to be done */

	TEEC_CloseSession(g_control_session);
	TEEC_FinalizeContext(g_tee_context);

	free(g_control_session);
	free(g_tee_context);
	g_control_session = NULL;
	g_tee_context = NULL;

	return CKR_OK;
}

CK_RV hal_init_token(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	TEEC_Operation operation;
	TEEC_SharedMemory pin_mem;
	TEEC_SharedMemory label_mem;
	uint32_t return_origin;
	CK_RV ret = 0;

	memset(&operation, 0, sizeof(TEEC_Operation));
	memset(&pin_mem, 0, sizeof(TEEC_SharedMemory));
	memset(&label_mem, 0, sizeof(TEEC_SharedMemory));

	pin_mem.buffer = pPin;
	pin_mem.size = ulPinLen;
	pin_mem.flags = TEEC_MEM_INPUT;

	label_mem.buffer = pLabel;
	label_mem.size = 32; /* hard coded size according to spec */
	label_mem.flags = TEEC_MEM_INPUT;

	ret = TEEC_RegisterSharedMemory(g_tee_context, &pin_mem);
	if (ret != TEE_SUCCESS)
		goto out1;

	ret = TEEC_RegisterSharedMemory(g_tee_context, &label_mem);
	if (ret != TEE_SUCCESS)
		goto out2;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT,
						TEEC_MEMREF_WHOLE, TEEC_NONE);

	operation.params[0].memref.parent = &pin_mem;
	operation.params[1].value.a = ulPinLen;
	operation.params[2].memref.parent = &label_mem;

	ret = TEEC_InvokeCommand(g_control_session, TEE_INIT_TOKEN, &operation, &return_origin);
	if (ret != 0)
		ret = CKR_GENERAL_ERROR;

out2:
	TEEC_ReleaseSharedMemory(&label_mem);
out1:
	TEEC_ReleaseSharedMemory(&pin_mem);

	return ret;
}

CK_RV hal_crypto_init(uint32_t command_id,
		      CK_SESSION_HANDLE hSession,
		      CK_MECHANISM_PTR pMechanism,
		      CK_OBJECT_HANDLE hKey)
{
	command_id = command_id;
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	/* Not yet implemented */

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV hal_crypto(uint32_t command_id,
		 CK_SESSION_HANDLE hSession,
		 CK_BYTE_PTR src,
		 CK_ULONG src_len,
		 CK_BYTE_PTR dst,
		 CK_ULONG_PTR dst_len)
{
	command_id = command_id;
	hSession = hSession;
	src = src;
	src_len = src_len;
	dst = dst;
	dst_len = dst_len;

	/* Not yet implemented */

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV hal_crypto_update(uint32_t command_id,
			CK_SESSION_HANDLE hSession,
			CK_BYTE_PTR src,
			CK_ULONG src_len,
			CK_BYTE_PTR dst,
			CK_ULONG_PTR dst_len)
{
	command_id = command_id;
	hSession = hSession;
	src = src;
	src_len = src_len;
	dst = dst;
	dst_len = dst_len;

	/* Not yet implemented */

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV hal_crypto_final(uint32_t command_id,
			CK_SESSION_HANDLE hSession,
			CK_BYTE_PTR dst,
			CK_ULONG_PTR dst_len)
{
	command_id = command_id;
	hSession = hSession;
	dst = dst;
	dst_len = dst_len;

	/* Not yet implemented */

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV hal_get_info(uint32_t command_id, void *data, uint32_t *data_size)
{
	TEEC_Operation operation;
	TEEC_SharedMemory data_mem;
	uint32_t return_origin;
	CK_RV ret = 0;

	memset(&operation, 0, sizeof(TEEC_Operation));
	memset(&data_mem, 0, sizeof(TEEC_SharedMemory));

	data_mem.buffer = data;
	data_mem.size = *data_size;
	data_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(g_tee_context, &data_mem);
	if (ret != TEE_SUCCESS)
		goto out;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INOUT,
						TEEC_NONE, TEEC_NONE);

	operation.params[0].memref.parent = &data_mem;
	operation.params[1].value.a = *data_size;

	ret = TEEC_InvokeCommand(g_control_session, command_id, &operation, &return_origin);
	if (ret == TEEC_ERROR_SHORT_BUFFER)
		ret = CKR_BUFFER_TOO_SMALL;
	else if (ret != 0)
		ret = CKR_GENERAL_ERROR;

	*data_size = operation.params[1].value.a;

out:
	TEEC_ReleaseSharedMemory(&data_mem);

	return ret;
}
