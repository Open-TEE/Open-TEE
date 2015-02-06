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
#include "hal.h"
#include "mutex_manager.h"

#include <stdlib.h>
#include <string.h>

/*!
 * \brief g_info
 * Information about this cryptoki implementation
 */
static const CK_INFO g_info = {
	{0x2, 0x14},	/*!< cryptoki 2.20 */
	"Intel",	/*!< manufacturer */
	0,		/*!< flags */
	"libtee_pkcs11",/*!< Description */
	{0, 1}		/*!< lib Ver */
};

/*!
 * \brief g_function_list
 * List of function entry points
 */
CK_FUNCTION_LIST g_function_list = {
	.version =				{0x2, 0x14},
	.C_Initialize =				C_Initialize,
	.C_Finalize  =				C_Finalize,
	.C_GetInfo  =				C_GetInfo,
	.C_GetFunctionList  =			C_GetFunctionList,
	.C_GetSlotList  =			C_GetSlotList,
	.C_GetSlotInfo  =			C_GetSlotInfo,
	.C_GetTokenInfo  =			C_GetTokenInfo,
	.C_GetMechanismList  =			C_GetMechanismList,
	.C_GetMechanismInfo  =			C_GetMechanismInfo,
	.C_InitToken  =				C_InitToken,
	.C_InitPIN  =				C_InitPIN,
	.C_SetPIN  =				C_SetPIN,
	.C_OpenSession  =			C_OpenSession,
	.C_CloseSession  =			C_CloseSession,
	.C_CloseAllSessions  =			C_CloseAllSessions,
	.C_GetSessionInfo  =			C_GetSessionInfo,
	.C_GetOperationState  =			C_GetOperationState,
	.C_SetOperationState  =			C_SetOperationState,
	.C_Login  =				C_Login,
	.C_Logout  =				C_Logout,
	.C_CreateObject  =			C_CreateObject,
	.C_CopyObject  =			C_CopyObject,
	.C_DestroyObject  =			C_DestroyObject,
	.C_GetObjectSize  =			C_GetObjectSize,
	.C_GetAttributeValue  =			C_GetAttributeValue,
	.C_SetAttributeValue  =			C_SetAttributeValue,
	.C_FindObjectsInit  =			C_FindObjectsInit,
	.C_FindObjects  =			C_FindObjects,
	.C_FindObjectsFinal  =			C_FindObjectsFinal,
	.C_EncryptInit  =			C_EncryptInit,
	.C_Encrypt  =				C_Encrypt,
	.C_EncryptUpdate  =			C_EncryptUpdate,
	.C_EncryptFinal  =			C_EncryptFinal,
	.C_DecryptInit  =			C_DecryptInit,
	.C_Decrypt  =				C_Decrypt,
	.C_DecryptUpdate  =			C_DecryptUpdate,
	.C_DecryptFinal  =			C_DecryptFinal,
	.C_DigestInit  =			C_DigestInit,
	.C_Digest  =				C_Digest,
	.C_DigestUpdate  =			C_DigestUpdate,
	.C_DigestFinal  =			C_DigestFinal,
	.C_SignInit  =				C_SignInit,
	.C_Sign  =				C_Sign,
	.C_SignUpdate  =			C_SignUpdate,
	.C_SignFinal  =				C_SignFinal,
	.C_SignRecoverInit  =			C_SignRecoverInit,
	.C_SignRecover  =			C_SignRecover,
	.C_VerifyInit  =			C_VerifyInit,
	.C_Verify  =				C_Verify,
	.C_VerifyUpdate  =			C_VerifyUpdate,
	.C_VerifyFinal  =			C_VerifyFinal,
	.C_VerifyRecoverInit  =			C_VerifyRecoverInit,
	.C_VerifyRecover  =			C_VerifyRecover,
	.C_DigestEncryptUpdate  =		C_DigestEncryptUpdate,
	.C_DecryptDigestUpdate  =		C_DecryptDigestUpdate,
	.C_SignEncryptUpdate  =			C_SignEncryptUpdate,
	.C_DecryptVerifyUpdate  =		C_DecryptVerifyUpdate,
	.C_GenerateKey  =			C_GenerateKey,
	.C_GenerateKeyPair  =			C_GenerateKeyPair,
	.C_WrapKey  =				C_WrapKey,
	.C_UnwrapKey  =				C_UnwrapKey,
	.C_DeriveKey  =				C_DeriveKey,
	.C_SeedRandom  =			C_SeedRandom,
	.C_GenerateRandom  =			C_GenerateRandom,
	.C_GetFunctionStatus  =			C_GetFunctionStatus,
	.C_CancelFunction  =			C_CancelFunction,
	.C_WaitForSlotEvent  =			C_WaitForSlotEvent,
};

/*
 * 11.4 GENERAL-PURPOSE FUNCTIONS
 */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	int non_null = 0;
	CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

	/* make the assumption that C_Initialize will be called from 1 thread hence to
	 * mutex support, especially because we are receiving the threading instructions
	 * as arguments
	 */

	/* TODO we are not currently planning to use locally created threads
	 * so we are not parsing the args->flags value for the state of
	 * CKF_LIBRARY_CANT_CREATE_OS_THREADS. but it will have to be checked
	 * if we plan to create threads of our own.
	 */
	if (args) {
		non_null = (args->CreateMutex != NULL) + (args->DestroyMutex != NULL) +
			   (args->LockMutex != NULL) + (args->UnlockMutex != NULL);

		/* Either no mutex callbacks should passed or all 4 should be passed */
		if (non_null > 0 && non_null < 4)
			return CKR_ARGUMENTS_BAD;

		if (non_null == 4)
			init_mutex_callbacks(args->CreateMutex, args->DestroyMutex,
					     args->LockMutex, args->UnlockMutex);
	}

	return hal_initialize_context();
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	hal_finalize_context();
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	if (!is_lib_initialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	memcpy(pInfo, &g_info, sizeof(CK_INFO));

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &g_function_list;
	return CKR_OK;
}

/*
 * 11.16 PARALLEL FUNCTION MANAGEMENT
 */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}
