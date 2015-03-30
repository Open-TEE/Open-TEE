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

/* NOTE!!
 *
 * This is an example. It might not have the most perfect design choices and implementation.
 * It is servinc purpose of showing how you could do the most simplest SHA/MD5 hash
 *
 * NOTE!!
 */

#include "tee_internal_api.h" /* TA envrionment */
#include "tee_logging.h" /* OpenTEE logging functions */

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'D', 'I', 'G', 'E', 'S', 'T', '0', '0'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif

/* Hash TA command IDs for this applet */
#define HASH_UPDATE	0x00000001
#define HASH_DO_FINAL	0x00000002

/* Hash algorithm identifier */
#define HASH_MD5	0x00000001
#define HASH_SHA1	0x00000002
#define HASH_SHA224	0x00000003
#define HASH_SHA256	0x00000004
#define HASH_SHA384	0x00000005
#define HASH_SHA512	0x00000006

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	/* No functionality */

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");

	/* No functionality */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	algorithm_Identifier hash;

	/* Parameter type is not needed */
	paramTypes = paramTypes;

	OT_LOG(LOG_ERR, "Calling the Open session entry point");

	switch (params[0].value.a) {
	case HASH_MD5:
		hash = TEE_ALG_MD5;
		break;

	case HASH_SHA1:
		hash = TEE_ALG_SHA1;
		break;

	case HASH_SHA224:
		hash = TEE_ALG_SHA224;
		break;

	case HASH_SHA256:
		hash = TEE_ALG_SHA256;
		break;

	case HASH_SHA384:
		hash = TEE_ALG_SHA384;
		break;

	case HASH_SHA512:
		hash = TEE_ALG_SHA512;
		break;

	default:
		OT_LOG(LOG_ERR, "Unknow hash algorithm");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_AllocateOperation((TEE_OperationHandle *)sessionContext,
				     hash, TEE_MODE_DIGEST, 0);
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Close session entry point");

	TEE_FreeOperation(sessionContext);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	paramTypes = paramTypes;

	OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	if (commandID == HASH_UPDATE) {

		TEE_DigestUpdate(sessionContext, params[0].memref.buffer, params[0].memref.size);

	} else if (commandID == HASH_DO_FINAL) {

		return TEE_DigestDoFinal(sessionContext, params[0].memref.buffer,
				params[0].memref.size, params[1].memref.buffer,
				(uint32_t *)&params[1].memref.size);

	} else {
		OT_LOG(LOG_ERR, "Unknow command ID");
	}

	return TEE_SUCCESS;
}
