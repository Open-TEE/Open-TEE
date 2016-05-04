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

#include "omnishare.h"
#include "omnishare_private.h"
#include "tee_client_api.h"

#include <string.h>

static const TEEC_UUID omnishare_uuid = {
	0x12345678, 0x8765, 0x4321, { 'O', 'M', 'N', 'I', 'S', 'H', 'A', 'R'}
};

/* Context an session that are persistant for the duration of a connection */
static TEEC_Context g_context;
static TEEC_Session g_session;

/*
 * Here we can see that the generate_root_key function acts as a static / standalone / singleton
 * with respect to creating a context, session, invoking a command and cleaning up. It is
 * a example of creating potentially multiple concurrent sessions to the same TEE and TA are
 * possible, depending on the policy that the TEE defines in its configuration.
 */
uint32_t omnishare_generate_root_key(uint8_t *key, uint32_t *key_size)
{
	TEEC_Context context = {0};
	TEEC_Session session = {0};
	TEEC_Operation operation = {0};
	TEEC_Result ret;
	TEEC_SharedMemory inout_mem = {0};
	uint32_t retOrigin = 0;

	if (!key || !key_size || key_size == 0)
		return TEEC_ERROR_BAD_PARAMETERS;
	/*
	 * Initialize context, opening a connection to a specific TEE, passing NULL here uses the
	 * default one for libtee, Open-TEE
	 */
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS)
		return ret;

	/*
	 * Now create a session to connect to the omnishare TA. There are no special
	 * params to pass as part of the open-session
	 */
	ret = TEEC_OpenSession(&context, &session, &omnishare_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &retOrigin);
	if (ret != TEEC_SUCCESS)
		goto out_1;

	/*
	 * Associate the input data with a shared memory structure that can be used to
	 * transfer it to the TA
	 */
	inout_mem.buffer = key;
	inout_mem.size = *key_size;
	inout_mem.flags = TEEC_MEM_OUTPUT;

	/*
	 * The shared memory is associated with the context, because it is shared with the TEE
	 * itself and made accessible by the TEE to the TA.
	 */
	ret = TEEC_RegisterSharedMemory(&context, &inout_mem);
	if (ret != TEEC_SUCCESS)
		goto out_2;

	/* Set the parameter types that we are sending to the TA */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	operation.params[0].memref.parent = &inout_mem;

	/* Invoke command */
	ret = TEEC_InvokeCommand(&session, CMD_CREATE_ROOT_KEY, &operation, &retOrigin);

	/*
	 * Copy back the updated buffer size. The shared memory buffer means that the user provided
	 * paramater key is already upto date. If the ret is TEEC_ERROR_SHORT_BUFFER, this can be
	 * used to let the caller know how big the required buffer actually is.
	 */
	*key_size = operation.params[0].memref.size;

	/*
	 * Cleanup any allocated shared memory
	 */
	TEEC_ReleaseSharedMemory(&inout_mem);

out_2:
	/*
	 * Close up session to the
	 */
	TEEC_CloseSession(&session);

out_1:
	/*
	 * Clean up the connection to the TEE
	 */
	TEEC_FinalizeContext(&context);

	return ret;

}

uint32_t omnishare_init(uint8_t *root_key, uint32_t size)
{
	TEEC_Operation operation = {0};
	TEEC_Result ret;
	TEEC_SharedMemory in_mem = {0};
	uint32_t retOrigin = 0;

	if (!root_key || size == 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * Initialize a persistant context for this connection
	 */
	ret = TEEC_InitializeContext(NULL, &g_context);
	if (ret != TEEC_SUCCESS)
		return ret;

	/*
	 * Associate the input data with a shared memory structure that can be used to
	 * transfer the root key as part of the open session
	 */
	in_mem.buffer = root_key;
	in_mem.size = size;
	in_mem.flags = TEEC_MEM_INPUT;

	/*
	 * Register the memory
	 */
	ret = TEEC_RegisterSharedMemory(&g_context, &in_mem);
	if (ret != TEEC_SUCCESS)
		goto out_err;

	/* Set the parameter types that we are sending to the TA */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	operation.params[0].memref.parent = &in_mem;

	/*
	 * Now create a persistant session to connect to the omnishare TA. The root key is
	 * passed as part of this open session
	 */
	ret = TEEC_OpenSession(&g_context, &g_session, &omnishare_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, &operation, &retOrigin);

	/*
	 * Cleanup any allocated shared memory
	 */
	TEEC_ReleaseSharedMemory(&in_mem);

	/*
	 * Check the return value from the open session, if it is a success return
	 * otherwise we should cleanup the context connection
	 */
	if (ret == TEE_SUCCESS)
		return ret;


out_err:
	/*
	 * Clean up the connection to the TEE
	 */
	TEEC_FinalizeContext(&g_context);

	return ret;
}

uint32_t omnishare_do_crypto(uint8_t *key_chain, uint32_t key_count, uint32_t key_len,
			     uint8_t op_cmd, uint8_t *src, uint32_t src_len,
			     uint8_t *dest, uint32_t *dest_len)
{
	TEEC_Operation operation = {0};
	TEEC_Result ret;
	TEEC_SharedMemory src_mem = {0};
	TEEC_SharedMemory dest_mem = {0};
	TEEC_SharedMemory key_mem = {0};
	uint32_t retOrigin = 0;
	struct key_chain_data *kc_data;
	uint32_t have_src = TEEC_NONE;
	uint32_t have_keys = TEEC_NONE;


	if (!dest || dest_len == 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* set the sub command ID that is being passed to the TA */
	operation.params[1].value.a = op_cmd;

	/* the enc and dec operations require an input buffer on which to act */
	if (op_cmd == OM_OP_DECRYPT_FILE || op_cmd == OM_OP_ENCRYPT_FILE) {
		if (!src || src_len == 0) {
			ret = TEEC_ERROR_BAD_PARAMETERS;
			goto free_shm;
		}

		src_mem.buffer = src;
		src_mem.size = src_len;
		src_mem.flags = TEEC_MEM_INPUT;

		ret = TEEC_RegisterSharedMemory(&g_context, &src_mem);
		if (ret != TEEC_SUCCESS)
			goto free_shm;

		operation.params[2].memref.parent = &src_mem;
		have_src = TEEC_MEMREF_WHOLE;
	}

	if (key_chain && key_count != 0 && key_len != 0) {
		/* Alloc used shared memory for our key chain */
		key_mem.size = key_count * key_len + sizeof(struct key_chain_data);
		key_mem.flags = TEEC_MEM_INPUT;

		/*
		 * Request that the TEE allocates shared memory for us, as it should be the
		 * most efficient way.
		 */
		ret = TEEC_AllocateSharedMemory(&g_context, &key_mem);
		if (ret != TEE_SUCCESS)
			goto free_shm;

		kc_data = (struct key_chain_data *)key_mem.buffer;
		kc_data->key_count = key_count;
		kc_data->key_len = key_len;
		memcpy(kc_data->keys, key_chain, key_count * key_len);

		operation.params[0].memref.parent = &key_mem;
		have_keys = TEEC_MEMREF_WHOLE;
	}

	/*
	 * Register the return buffer
	 */
	dest_mem.buffer = dest;
	dest_mem.size = *dest_len;
	dest_mem.flags = TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(&g_context, &dest_mem);
	if (ret != TEEC_SUCCESS)
		goto free_shm;

	operation.params[3].memref.parent = &dest_mem;

	/*
	 * Set the parameter types that we are sending to the TA
	 */
	operation.paramTypes = TEEC_PARAM_TYPES(have_keys, TEEC_VALUE_INPUT,
						have_src, TEEC_MEMREF_WHOLE);


	/* Invoke command */
	ret = TEEC_InvokeCommand(&g_session, CMD_DO_CRYPTO, &operation, &retOrigin);

	/* Inform the caller of the number of bytes actually used in the destination buffer */
	*dest_len = operation.params[3].memref.size;

free_shm:
	TEEC_ReleaseSharedMemory(&key_mem);
	TEEC_ReleaseSharedMemory(&src_mem);
	TEEC_ReleaseSharedMemory(&dest_mem);

	return ret;
}

void omnishare_finalize(void)
{
	TEEC_CloseSession(&g_session);
	TEEC_FinalizeContext(&g_context);

	memset(&g_session, 0, sizeof(TEEC_Session));
	memset(&g_context, 0, sizeof(TEEC_Context));
}
