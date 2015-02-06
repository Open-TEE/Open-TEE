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
#include "commands.h"

#include <stdlib.h>
#include <string.h>

/* the slot id that we will assign to the TEE */
#define TEE_SLOT_ID 1
/* The number of supported slots */
#define SLOT_COUNT 1

CK_SLOT_INFO g_slot_info = {
	.slotDescription = "TEE_BASED_SLOT",
	.manufacturerID = "Intel",
	.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT,
	.hardwareVersion = {0, 1},
	.firmwareVersion = {0, 1}
};

/* a list of all mechanisms supported by the TEE */
struct mechanisms *g_supported_mechanisms;
CK_MECHANISM_TYPE_PTR g_mechanism_types;
uint32_t g_mechanism_count = 16; /* try 16 as a default number of mechanisms */

/*
 * 11.5 SLOT AND TOKEN MANAGEMENT
 */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	/* in the TEE the token is always present, it is the TA */
	tokenPresent = tokenPresent;

	/* only support 1 slot */
	if (pSlotList != NULL && *pulCount >= SLOT_COUNT)
		pSlotList[0] = TEE_SLOT_ID;

	*pulCount = 1;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	pInfo = &g_slot_info;

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	uint32_t size = sizeof(CK_TOKEN_INFO);
	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	return hal_get_info(TEE_GET_TOKEN_INFO, pInfo, &size);
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
	flags = flags;
	pSlot = pSlot;
	pRserved = pRserved;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV populate_user_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
					  CK_ULONG_PTR pulCount)
{
	CK_RV ret = 0;
	ret = (*pulCount < g_mechanism_count) ? CKR_BUFFER_TOO_SMALL : 0;

	*pulCount = g_mechanism_count;
	if (ret)
		return ret;

	if (pMechanismList != NULL) {
		memcpy(pMechanismList, g_mechanism_types,
		       g_mechanism_count * sizeof(struct mechanisms));
	}

	return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV ret = 0;
	uint32_t size;
	uint32_t i;

	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	if (g_mechanism_types != NULL)
		return populate_user_mechanism_list(pMechanismList, pulCount);


	/* if we get here we have to retrieve the info from the TA */

	g_supported_mechanisms = calloc(g_mechanism_count, sizeof(struct mechanisms));
	if (g_supported_mechanisms == NULL)
		return CKR_HOST_MEMORY;

	do {
		size = g_mechanism_count * sizeof(struct mechanisms);
		ret = hal_get_info(TEE_GET_MECHANISM_LIST, g_supported_mechanisms, &size);

		if (ret == CKR_BUFFER_TOO_SMALL) {
			g_mechanism_count *= 2; /* increase space for the mechanisms and retry */

			struct mechanisms *tmp = realloc(g_supported_mechanisms, g_mechanism_count);
			if (tmp == NULL) {
				ret = CKR_HOST_MEMORY;
				goto err_out;
			}

			g_supported_mechanisms = tmp;
			continue; /* back to the top and try again */

		} else if (ret == CKR_OK) {
			/* get the actual number of mechanisms */
			g_mechanism_count = size / sizeof(struct mechanisms);
			g_mechanism_types = calloc(g_mechanism_count, sizeof(CK_MECHANISM_TYPE));
			if (g_mechanism_types == NULL) {
				ret = CKR_HOST_MEMORY;
				goto err_out;
			}

			/* extract all the supported types */
			for (i = 0; i < g_mechanism_count; i++)
				g_mechanism_types[i] = g_supported_mechanisms[i].algo;

			ret = populate_user_mechanism_list(pMechanismList, pulCount);

			break; /* we have gotten what we want */
		} else {
			goto err_out; /* some other error */
		}
	} while (1);

	return ret;

err_out:
	free(g_supported_mechanisms);
	g_supported_mechanisms = NULL;

	free(g_mechanism_types);
	g_mechanism_types = NULL;

	g_mechanism_count = 16;
	return ret;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	uint32_t i;

	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	for (i = 0; i < g_mechanism_count; i++) {
		if (g_supported_mechanisms[i].algo == type) {
			memcpy(pInfo, &g_supported_mechanisms[i].info, sizeof(CK_MECHANISM_INFO));
			return CKR_OK;
		}
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	return hal_init_token(pPin, ulPinLen, pLabel);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	hSession = hSession;
	pPin = pPin;
	ulPinLen = ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_UTF8CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	hSession = hSession;
	pOldPin = pOldPin;
	ulOldLen = ulOldLen;
	pNewPin = pNewPin;
	ulNewLen = ulNewLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * 11.6 SESSION MANAGEMENT
 */

CK_RV C_OpenSession(CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	slotID = slotID;
	flags = flags;
	pApplication = pApplication;
	Notify = Notify;
	phSession = phSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (slotID != TEE_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	hSession = hSession;
	pInfo = pInfo;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	hSession = hSession;
	pOperationState = pOperationState;
	pulOperationStateLen = pulOperationStateLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	hSession = hSession;
	pOperationState = pOperationState;
	ulOperationStateLen = ulOperationStateLen;
	hEncryptionKey = hEncryptionKey;
	hAuthenticationKey = hAuthenticationKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)
{
	hSession = hSession;
	userType = userType;
	pPin = pPin;
	ulPinLen = ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	hSession = hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}
