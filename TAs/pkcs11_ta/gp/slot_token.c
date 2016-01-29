/*****************************************************************************
** Copyright (C) 2016 Open-TEE project.                                     **
** Copyright (C) 2016 Atte Pellikka                                         **
** Copyright (C) 2016 Brian McGillion                                       **
** Copyright (C) 2016 Tanel Dettenborn                                      **
** Copyright (C) 2016 Ville Kankainen                                       **
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

#include <string.h>

#include "tee_internal_api.h"

#include "slot_token.h"
#include "cryptoki.h"
#include "commands.h"
#include "token_conf.h"
#include "compat.h"

/* should be read from secure storage */
CK_TOKEN_INFO g_token;

static char SO_PASSWORD_ID[] = "password0";
static char USER_PASSWORD_ID[] = "password1";
static char TOKEN_STORE[] = "TOKEN_STORE";

/* TODO this is just a dummy place holder, it must be filled with real mechanisms */
struct mechanisms g_supported_algos[] = {
{
	.algo = CKM_AES_CBC,
	.info = {
		.ulMinKeySize = 128,
		.ulMaxKeySize = 256,
		.flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT
	}
},
{
	.algo =  CKM_MD5_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_SHA1_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_SHA256_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_SHA384_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_SHA512_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_MD5,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_HW | CKF_DIGEST
	}
},
{
	.algo =    CKM_SHA_1,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_HW | CKF_DIGEST
	}
},
{
	.algo =    CKM_SHA256,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_HW | CKF_DIGEST
	}
},
{
	.algo =    CKM_SHA384,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_HW | CKF_DIGEST
	}
},
{
	.algo =    CKM_SHA512,
	.info = {
		.ulMinKeySize = 0,
		.ulMaxKeySize = 0,
		.flags = CKF_HW | CKF_DIGEST
	}
},
{
	.algo =   CKM_MD5_HMAC,
	.info = {
		.ulMinKeySize = 64,
		.ulMaxKeySize = 512,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA_1_HMAC,
	.info = {
		.ulMinKeySize = 80,
		.ulMaxKeySize = 512,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA256_HMAC,
	.info = {
		.ulMinKeySize = 192,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA384_HMAC,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA512_HMAC,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =   CKM_MD5_HMAC_GENERAL,
	.info = {
		.ulMinKeySize = 64,
		.ulMaxKeySize = 512,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA_1_HMAC,
	.info = {
		.ulMinKeySize = 80,
		.ulMaxKeySize = 512,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA256_HMAC_GENERAL,
	.info = {
		.ulMinKeySize = 192,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA384_HMAC_GENERAL,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =    CKM_SHA512_HMAC_GENERAL,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 1024,
		.flags = CKF_HW | CKF_SIGN | CKF_VERIFY
	}
},
{
	.algo =     CKM_RSA_PKCS,
	.info = {
		.ulMinKeySize = 256,
		.ulMaxKeySize = 2048,
		.flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT
	}
}
};

static uint32_t read_token_from_storage(CK_TOKEN_INFO *token)
{
	TEE_Result ret = 0;
	TEE_ObjectHandle object;
	TEE_ObjectInfo info;
	uint32_t count = 0;

	if (token == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, TOKEN_STORE, TEE_StrLen(TOKEN_STORE),
				       TEE_DATA_FLAG_ACCESS_READ, &object);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_ITEM_NOT_FOUND;

	TEE_GetObjectInfo(object, &info);

	if (sizeof(CK_TOKEN_INFO) != info.dataSize) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	ret = TEE_ReadObjectData(object, token, info.dataSize, &count);
	if (ret != TEE_SUCCESS || count != info.dataSize) {
		ret = TEE_ERROR_NO_DATA;
		goto out;
	}

out:
	TEE_CloseObject(object);
	return ret;
}

static uint32_t create_update_token_storage(CK_TOKEN_INFO *token)
{
	TEE_Result ret;

	if (token == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, TOKEN_STORE, TEE_StrLen(TOKEN_STORE),
					 TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
					 NULL, (void *)token, sizeof(CK_TOKEN_INFO), NULL);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_STORAGE_NO_SPACE;

	return 0;
}

static void populate_token(CK_TOKEN_INFO *token)
{
	TEE_MemFill(token->label, ' ', sizeof(token->label));

	TEE_MemFill(token->manufacturerID, ' ', sizeof(token->manufacturerID));
	TEE_MemMove((char *)token->manufacturerID, "OpenTEE", TEE_StrLen("OpenTEE"));

	TEE_MemFill(token->model, ' ', sizeof(token->model));
	TEE_MemMove((char *)token->model, "PKCS11_TEE", TEE_StrLen("PKCS11_TEE"));

	TEE_MemFill(token->serialNumber, ' ', sizeof(token->serialNumber));
	TEE_MemMove((char *)token->serialNumber, "1234567890123456",
		TEE_StrLen("1234567890123456"));

	token->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
	token->ulMaxSessionCount = MAX_SESSIONS;
	token->ulMaxRwSessionCount = MAX_SESSIONS;
	token->ulMaxPinLen = MAX_PIN_LEN;
	token->ulMinPinLen = MIN_PIN_LEN;
	token->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	token->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	token->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token->hardwareVersion.major = 0;
	token->hardwareVersion.minor = 1;
	token->firmwareVersion.major = 0;
	token->firmwareVersion.minor = 1;
}

TEE_Result initialize_token(bool from_user, uint32_t paramTypes, TEE_Param params[4])
{
	uint32_t ret = TEE_SUCCESS;

	if (from_user == true) {
		if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
		    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
		    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT)
			return TEE_ERROR_BAD_PARAMETERS;

		ret = check_password(CKU_SO, params[0].memref.buffer, params[1].value.a);
		if (ret != 0) {
			if (ret != CKR_USER_PIN_NOT_INITIALIZED)
				return ret;

			/* Token has been initialized from the userspace for the first the so
			 * set the SO pin to the one supplied */
			ret = set_password(CKU_SO, params[0].memref.buffer, params[1].value.a);
			if (ret != 0)
				return ret;
		}

		/* TODO DELETE ALL OBJECTS FOM SECURE STORAGE */

		/* initialize the new label for the token */
		TEE_MemFill(g_token.label, ' ', sizeof(g_token.label));
		TEE_MemMove((char *)g_token.label, params[2].memref.buffer, sizeof(g_token.label));

		/* update the token in the storage */
		ret = create_update_token_storage(&g_token);
	} else {
		ret = read_token_from_storage(&g_token);
		if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			/* first time so create the secure storage for the token */
			populate_token(&g_token);
			ret = create_update_token_storage(&g_token);
		}
	}

	return ret;
}

TEE_Result get_token_info(uint32_t paramTypes, TEE_Param params[4])
{
	if (!(TEE_PARAM_TYPE_GET(paramTypes, 0) & TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INOUT) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].value.a < sizeof(CK_TOKEN_INFO)) {
		params[1].value.a = sizeof(CK_TOKEN_INFO);
		return TEE_ERROR_SHORT_BUFFER; /* not enough space to return the token info */
	}

	TEE_MemMove(params[0].memref.buffer, (uint8_t *)&g_token, sizeof(g_token));

	/* report how much space we are actually sending back */
	params[0].memref.size = sizeof(g_token);
	params[1].value.a = sizeof(g_token);
	return 0;
}

TEE_Result get_mechanism_list(uint32_t paramTypes, TEE_Param params[4])
{
	if (!(TEE_PARAM_TYPE_GET(paramTypes, 0) & TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INOUT) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].value.a < sizeof(g_supported_algos)) {
		params[1].value.a = sizeof(g_supported_algos);
		return TEE_ERROR_SHORT_BUFFER; /* not enough space to return the mechanism list */
	}

	TEE_MemMove(params[0].memref.buffer, (uint8_t *)g_supported_algos,
		    sizeof(g_supported_algos));

	/* report how much space we are actually sending back */
	params[0].memref.size = sizeof(g_supported_algos);
	params[1].value.a = sizeof(g_supported_algos);
	return 0;
}

bool is_token_write_protected()
{
	return g_token.flags & CKF_WRITE_PROTECTED;
}

CK_RV mechanism_supported(CK_MECHANISM_TYPE mech_type, CK_ULONG key_size, TEE_OperationMode mode)
{
	uint32_t i;

	for (i = 0; i < sizeof(g_supported_algos) / sizeof(struct mechanisms); i++) {

		if (g_supported_algos[i].algo == mech_type) {

			/* Some operation does not require a key */
			if (key_size != 0 &&
			    !(g_supported_algos[i].info.ulMinKeySize < key_size ||
			      g_supported_algos[i].info.ulMaxKeySize > key_size))
				return CKR_MECHANISM_INVALID;

			switch (mode) {
			case TEE_MODE_DECRYPT:
				if (g_supported_algos[i].info.flags & CKF_DECRYPT)
					return CKR_OK;
				break;

			case TEE_MODE_ENCRYPT:
				if (g_supported_algos[i].info.flags & CKF_ENCRYPT)
					return CKR_OK;
				break;

			case TEE_MODE_DIGEST:
				if (g_supported_algos[i].info.flags & CKF_DIGEST)
					return CKR_OK;
				break;

			case TEE_MODE_SIGN:
				if (g_supported_algos[i].info.flags & CKF_SIGN)
					return CKR_OK;
				break;

			case TEE_MODE_VERIFY:
				if (g_supported_algos[i].info.flags & CKF_VERIFY)
					return CKR_OK;
				break;

			case TEE_MODE_MAC:
				if (g_supported_algos[i].info.flags & (CKF_VERIFY | CKF_VERIFY))
					return CKR_OK;
				break;

			case TEE_MODE_DERIVE:
				/* Not yet any operations for derive */
				return CKR_MECHANISM_INVALID;
			default:
				return CKR_MECHANISM_INVALID;
			}
		}
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV check_password(CK_USER_TYPE user_type, const char *passwd, uint32_t passwd_len)
{
	TEE_Result ret = 0;
	TEE_ObjectHandle object;
	TEE_ObjectInfo info;
	char *ID;
	int id_len;
	char *stored_passwd = NULL;
	uint32_t count = 0;

	if (passwd == NULL)
		return CKR_ARGUMENTS_BAD;

	if (user_type == CKU_SO) {
		ID = SO_PASSWORD_ID;
		id_len = TEE_StrLen(SO_PASSWORD_ID);
	} else if (user_type == CKU_USER) {
		ID = USER_PASSWORD_ID;
		id_len = TEE_StrLen(USER_PASSWORD_ID);
	} else {
		return CKR_ARGUMENTS_BAD;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, ID, id_len, TEE_DATA_FLAG_ACCESS_READ,
				       &object);
	if (ret != TEE_SUCCESS)
		return CKR_USER_PIN_NOT_INITIALIZED;

	TEE_GetObjectInfo(object, &info);

	if (passwd_len != info.dataSize) {
		ret = CKR_PIN_LEN_RANGE;
		goto out;
	}

	stored_passwd = TEE_Malloc(info.dataSize, 0);
	if (stored_passwd == NULL) {
		ret = CKR_GENERAL_ERROR;
		goto out;
	}

	ret = TEE_ReadObjectData(object, stored_passwd, info.dataSize, &count);
	if (ret != TEE_SUCCESS || count != info.dataSize) {
		ret = CKR_GENERAL_ERROR;
		goto out;
	}

	if (TEE_MemCompare((void *)stored_passwd, (void *)passwd, info.dataSize) != 0) {
		ret = CKR_PIN_INCORRECT;
		goto out;
	}

out:
	TEE_Free(stored_passwd);
	TEE_CloseObject(object);
	return ret;
}

CK_RV set_password(CK_USER_TYPE user_type, const char *passwd, uint32_t passwd_len)
{
	TEE_Result ret;
	char *ID;
	int id_len;

	if (passwd == NULL)
		return CKR_ARGUMENTS_BAD;

	if (passwd_len < MIN_PIN_LEN || passwd_len > MAX_PIN_LEN)
		return CKR_PIN_LEN_RANGE;

	if (user_type == CKU_SO) {
		ID = SO_PASSWORD_ID;
		id_len = TEE_StrLen(SO_PASSWORD_ID);
	} else if (user_type == CKU_USER) {
		ID = USER_PASSWORD_ID;
		id_len = TEE_StrLen(USER_PASSWORD_ID);
	} else {
		return CKR_ARGUMENTS_BAD;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, ID, id_len,
					 TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
					 NULL, (void *)passwd, passwd_len, NULL);
	if (ret != TEE_SUCCESS)
		return CKR_USER_PIN_NOT_INITIALIZED;

	if (ID == USER_PASSWORD_ID)
		g_token.flags |= CKF_USER_PIN_INITIALIZED;
	else
		/* assume token is initialized when we have an SO password */
		g_token.flags |= CKF_TOKEN_INITIALIZED;

	return 0;
}
