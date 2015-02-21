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
#include <stdio.h>

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

uint64_t g_application_nonce;

static const TEEC_UUID uuid = {
	0x12345678, 0x8765, 0x4321, { 'P', 'K', 'C', 'S', '1', '1', 'T', 'A'}
};

static CK_RV serialize_template_into_shm(TEEC_SharedMemory *shm,
					 CK_ATTRIBUTE_PTR pTemplate,
					 CK_ULONG ulCount)
{
	uint32_t pos = 0, i;

	/* Calculating the size that is needed for serializing tempalte it to into on buffer */
	for (i = 0; i < ulCount; i++)
		shm->size += pTemplate[i].ulValueLen;

	shm->size += ulCount * sizeof(pTemplate->type);
	shm->size += ulCount * sizeof(pTemplate->ulValueLen);
	shm->size += sizeof(ulCount);

	shm->buffer = calloc(1, shm->size);
	if (!shm->buffer)
		return CKR_HOST_MEMORY;

	/* Serialize template into buffer. Schema:
	 * |------------------------------------------------------------------------------------|
	 * | Attr count		| Attribute type,	| ulValueLen,		| pValue	|
	 * | sizeof(ulCount)	| sizeof (type)		| sizeog (ulValueLen)	| ulValueLen	|
	 * |------------------------------------------------------------------------------------|
	 *			|---------------- appers Attr count times ----------------------|
	 * First line is what and second line is telling its size. */

	memcpy((uint8_t *)shm->buffer, &ulCount, sizeof(ulCount));
	pos += sizeof(ulCount);

	for (i = 0; i < ulCount; ++i) {

		/* Attribute type */
		memcpy((uint8_t *)shm->buffer + pos, &pTemplate[i].type, sizeof(pTemplate[i].type));
		pos += sizeof(pTemplate[i].type);

		/* ulValueLen */
		memcpy((uint8_t *)shm->buffer + pos,
		       &pTemplate[i].ulValueLen, sizeof(pTemplate[i].ulValueLen));
		pos += sizeof(pTemplate[i].ulValueLen);

		/* pValue */
		memcpy((uint8_t *)shm->buffer + pos, pTemplate[i].pValue, pTemplate[i].ulValueLen);
		pos += pTemplate[i].ulValueLen;
	}

	return CKR_OK;
}

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
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
						TEEC_NONE, TEEC_NONE);

	ret = TEEC_OpenSession(g_tee_context, g_control_session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		ret =  CKR_GENERAL_ERROR;
		goto err_out;
	}

	memcpy(&g_application_nonce, &operation.params[0].value.a, sizeof(int32_t));
	g_application_nonce |= operation.params[2].value.b;

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

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

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

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

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


CK_RV hal_open_session(CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession)
{
	TEEC_Operation operation;
	uint32_t return_origin;
	CK_RV ret = 0;

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	memset(&operation, 0, sizeof(TEEC_Operation));

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
						TEEC_NONE, TEEC_NONE);
	operation.params[0].value.a = flags;

	ret = TEEC_InvokeCommand(g_control_session, TEE_CREATE_PKCS11_SESSION, &operation,
				 &return_origin);
	if (ret != 0)
		ret = CKR_GENERAL_ERROR;

	*phSession = operation.params[1].value.a;

	return CKR_OK;
}

CK_RV hal_close_session(CK_SESSION_HANDLE hSession)
{
	TEEC_Operation operation;
	uint32_t return_origin;

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	memset(&operation, 0, sizeof(TEEC_Operation));

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						TEEC_NONE, TEEC_NONE);
	operation.params[0].value.a = hSession;

	return TEEC_InvokeCommand(g_control_session, TEE_CLOSE_PKCS11_SESSION, &operation,
				  &return_origin);
}

CK_RV hal_close_all_session()
{
	uint32_t return_origin;

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return TEEC_InvokeCommand(g_control_session, TEE_CLOSE_ALL_PKCS11_SESSION, NULL,
				  &return_origin);
}

CK_RV hal_get_session_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	TEEC_Operation operation;
	TEEC_SharedMemory data_mem;
	uint32_t return_origin;
	CK_RV ret = 0;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	memset(&operation, 0, sizeof(TEEC_Operation));
	memset(&data_mem, 0, sizeof(TEEC_SharedMemory));

	data_mem.buffer = pInfo;
	data_mem.size = sizeof(CK_SESSION_INFO);
	data_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(g_tee_context, &data_mem);
	if (ret != TEE_SUCCESS)
		goto out;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT,
						TEEC_NONE, TEEC_NONE);

	operation.params[0].memref.parent = &data_mem;
	operation.params[1].value.a = hSession;

	ret = TEEC_InvokeCommand(g_control_session, TEE_GET_SESSION_INFO,
				 &operation, &return_origin);

out:
	TEEC_ReleaseSharedMemory(&data_mem);

	return ret;
}

CK_RV hal_create_object(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount,
			CK_OBJECT_HANDLE_PTR phObject)
{
	TEEC_SharedMemory in_shm = {0};
	TEEC_Operation operation = {0};
	TEEC_Result teec_ret;
	CK_RV ck_rv;

	/* Object handle is valid if this function succeeds */
	*phObject = CKR_OBJECT_HANDLE_INVALID;

	/* Serialize template into buffer (function allocating a buffer!) */
	ck_rv = serialize_template_into_shm(&in_shm, pTemplate, ulCount);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Register shared memory. It is used for trasfering template into TEE environment */
	in_shm.flags = TEEC_MEM_INPUT;
	if (TEEC_RegisterSharedMemory(g_tee_context, &in_shm) != CKR_OK) {
		free(in_shm.buffer);
		return CKR_GENERAL_ERROR;
	}

	/* Fill operation */
	operation.params[0].memref.parent = &in_shm;
	operation.params[2].value.a = in_shm.size;
	operation.params[3].value.a = hSession;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_OUTPUT,
						TEEC_VALUE_INOUT, TEEC_VALUE_INPUT);

	/* Hand over execution to TEE */
	teec_ret = TEEC_InvokeCommand(g_control_session, TEE_CREATE_OBJECT, &operation, NULL);

	/* Shared momory was INPUT and it have served its purpose */
	TEEC_ReleaseSharedMemory(&in_shm);
	free(in_shm.buffer);

	/* Something went wrong and problem is origin from frame work */
	if (teec_ret != TEEC_SUCCESS)
		return CKR_GENERAL_ERROR;

	/* Extract return values from operation and return */
	*phObject = operation.params[1].value.a;
	return operation.params[1].value.b;
}
