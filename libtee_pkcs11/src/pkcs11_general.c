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
#include "mutex_manager.h"
#include "hal.h"

#include <stdlib.h>
#include <string.h>

/*!
 * \brief g_tee_context
 * A context that is created towards the TEE
 */
static void *g_tee_context;

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
struct CK_FUNCTION_LIST g_function_list;

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
	if (g_tee_context)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

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

	return hal_initialize_context(&g_tee_context);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	if (g_tee_context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	hal_finalize_context(g_tee_context);
	g_tee_context = NULL;
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	memcpy(pInfo, &g_info, sizeof(CK_INFO));

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
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
