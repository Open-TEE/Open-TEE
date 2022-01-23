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

/* NOTE!!
 *
 * This is an example. It might not have the most perfect design choices and implementation.
 * It is servinc purpose of showing how you could do the most simplest SHAXXX/MD5 hash
 *
 * NOTE!!
 */

#include "tee_internal_api.h"
#include "tee_logging.h"

#include "sign_ecdsa_256_ctrl.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'S', 'I', 'G', 'N', 'S', 'I', 'G', 'N'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	char objID[] = "signkey";
	uint32_t objID_len = 7;
	TEE_ObjectHandle signkey = NULL;
	TEE_Result rv = TEE_ERROR_GENERIC;
	TEE_Attribute params = {0};
	TEE_OperationHandle sign_operation = NULL;

	OT_LOG(LOG_ERR, "Calling the create entry point");
	
	rv = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &signkey);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Transient object alloc failed [0x%x]", rv);
		goto out;
	}
	
	params.attributeID = TEE_ATTR_ECC_CURVE;
	params.content.value.a = TEE_ECC_CURVE_NIST_P256;
	
	rv = TEE_GenerateKey(signkey, 256, &params, 1);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Key generation failed [0x%x]", rv);
		goto out;
	}
	
	rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					objID, objID_len,
					TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_EXCLUSIVE,
					signkey,
					NULL, 0, NULL);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Persistent object create failed [0x%x]", rv);
		goto out;
	}
			
	rv = TEE_AllocateOperation(&sign_operation,
				   TEE_ALG_ECDSA_SHA256, TEE_MODE_SIGN, 256);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Operation allocation failed [0x%x]", rv);
		goto out;
	}

	rv = TEE_SetOperationKey(sign_operation, signkey);
	if (rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Operation key set failed [0x%x]", rv);
		goto out;
	}

	TEE_SetInstanceData(sign_operation);
	
 out:
	if (rv != TEE_SUCCESS)
		TEE_FreeOperation(sign_operation);
	TEE_FreeTransientObject(signkey);
	return rv;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	TEE_FreeOperation(TEE_GetInstanceData());
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
					      void **sessionContext)
{
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;
	
	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	TEE_Result rv = TEE_ERROR_GENERIC;

	sessionContext = sessionContext;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0 OR 1");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (commandID) {
	case SIGN_ECDSA_256_SIGN:
		rv = TEE_AsymmetricSignDigest(TEE_GetInstanceData(), NULL, 0,
				      params[0].memref.buffer, params[0].memref.size,
				      params[1].memref.buffer, &params[1].memref.size);
		if (rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "Sign failed");
		}
		break;
	default:
		rv = TEE_ERROR_BAD_PARAMETERS;
	}
	
	return rv;
}
