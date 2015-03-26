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

#ifndef __HAL_H_
#define __HAL_H_

#include <stdint.h>
#include <stdbool.h>
#include "cryptoki.h"
#include "commands.h"

/*!
 * \brief hal_initialize_context
 * Create a context towards the TEE, this is generally achieved by opening the TEE device
 * \return 0 on success
 */
CK_RV hal_initialize_context();

/*!
 * \brief hal_finalize_context
 * Close the connection to the TEE and free the context.
 * \return 0 on success
 */
CK_RV hal_finalize_context();

/*!
 * \brief hal_init_token
 * Initialize (or reinitialize the token)
 * \param pPin The SO pin code to use
 * \param ulPinLen The length of hte pin code
 * \param pLabel the 32 byte label to assign to the token
 * \return 0 on success
 */
CK_RV hal_init_token(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);

/*!
 * \brief hal_crypto_init
 * Initializes crypto operation at TEE
 * \param hSession
 * \param pMechanism
 * \param hKey
 * \return
 */
CK_RV hal_crypto_init(uint32_t command_id,
		      CK_SESSION_HANDLE hSession,
		      CK_MECHANISM_PTR pMechanism,
		      CK_OBJECT_HANDLE hKey);

/*!
 * \brief hal_crypto
 * Maps XX_crypto, xx_crypto_update and xx_crypto_final
 * \param command_id invoked command from TEE
 * \param hSession see PKCS11
 * \param src is operation target buffer. Accept NULL (crypto_final).
 * \param src_len is src buffer lenghtn in bytes
 * \param dst operation output is placed into dst buffer
 * \param dst_len is dst buffer length in bytes
 * \return
 */
CK_RV hal_crypto(uint32_t command_id,
		 CK_SESSION_HANDLE hSession,
		 CK_BYTE_PTR src,
		 CK_ULONG src_len,
		 CK_BYTE_PTR dst,
		 CK_ULONG_PTR dst_len);

/*!
 * \brief hal_verify_crypto
 * Verify crypto operation is special case, because it has two input buffer
 * \param hSession
 * \param msg
 * \param msg_len
 * \param sig
 * \param sig_len
 * \return
 */
CK_RV hal_verify_crypto(CK_SESSION_HANDLE hSession,
			CK_BYTE_PTR msg,
			CK_ULONG msg_len,
			CK_BYTE_PTR sig,
			CK_ULONG sig_len);

/*!
 * \brief hal_get_info
 * A generic function to populate an info structure (CK_SLOT_INFO, CK_TOKEN_INFO)
 * \param command_id The command to invoke
 * \param data The data structure that is to be populated
 * \param data_size The size of the structure that is to be populated
 * \return 0 on success
 */
CK_RV hal_get_info(uint32_t command_id, void *data, uint32_t *data_size);

/*!
 * \brief hal_open_session
 * Open a pkcs11 session to the Token (i.e. TA)
 * \param flags CK_SESSION_INFO flags
 * \param phSession The pointer to the session that we create
 * \return 0 on success
 */
CK_RV hal_open_session(CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession);

/*!
 * \brief hal_close_session
 * Close a pkcs11 session to the token
 * \param hSession The id of hte session to close
 * \return 0 on success
 */
CK_RV hal_close_session(CK_SESSION_HANDLE hSession);

/*!
 * \brief hal_close_all_session
 * Close all the sessions associated with this application
 * \return 0 on success
 */
CK_RV hal_close_all_session();

/*!
 * \brief hal_get_session_info
 * Get the info struct related to a session
 * \param hSession The id of the session
 * \param pInfo The struct to hold the return data in
 * \return 0 on success
 */
CK_RV hal_get_session_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

/*!
 * \brief hal_login
 * Log the application into the token
 * \param hSession The session to login with
 * \param userType The user mode to login (SO or USER)
 * \param pPin The pin code for the user
 * \param ulPinLen The length of the pin
 * \return 0 on success
 */
CK_RV hal_login(CK_SESSION_HANDLE hSession,
		CK_USER_TYPE userType,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen);

/*!
 * \brief hal_logout
 * Log the application out of the token
 * \param hSession The session that is open
 * \return 0 on success
 */
CK_RV hal_logout(CK_SESSION_HANDLE hSession);

/*!
 * \brief is_lib_initialized
 * Determine if the library has been properly initialized
 * \return true on success
 */
bool is_lib_initialized();

/*!
 * \brief hal_create_object
 * Creates an object inside TEE
 * \param hSession
 * \param pTemplate
 * \param ulCount
 * \param phObject
 * \return
 */
CK_RV hal_create_object(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount,
			CK_OBJECT_HANDLE_PTR phObject);

/*!
 * \brief hal_destroy_object
 * Destroys an object
 * \param hSession
 * \param hObject
 * \return
 */
CK_RV hal_destroy_object(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

/*!
 * \brief hal_init_pin
 * Initialize the normal users pin
 * \param hSession The current valid "R/W SO Function" session
 * \param pPin The pin code to set (or NULL if the device supports secure UI)
 * \param ulPinLen The length of the pin or 0 pPin is NULL
 * \return 0 on success
 */
CK_RV hal_init_pin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

/*!
 * \brief hal_set_pin
 * Change the Pin for the currently logged in user or the CKU_USER pin if the session is not logged
 * in
 * \param hSession The current valid session
 * \param pOldPin The old pin being replaced or NULL if trusted UI
 * \param ulOldLen the len or 0 if pOldPin is NULL
 * \param pNewPin The new pin or NULL of trusted UI
 * \param ulNewLen the len or 0 if pNewPin is NULL
 * \return 0 on success
 */
CK_RV hal_set_pin(CK_SESSION_HANDLE hSession,
		  CK_UTF8CHAR_PTR pOldPin,
		  CK_ULONG ulOldLen,
		  CK_UTF8CHAR_PTR pNewPin,
		  CK_ULONG ulNewLen);

/*!
 * \brief hal_generate_random
 * Generate random data
 * \param hSession The currently logged in session
 * \param RandomData The location that receives the random data
 * \param ulRandomLen The length of the data to be generated
 * \return 0 on success
 */
CK_RV hal_generate_random(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);

/*!
 * \brief hal_get_attribute_value
 * Getting attribute values from queried object.
 * \param hSession
 * \param hObject
 * \param pTemplate
 * \param ulCount
 * \return
 */
CK_RV hal_get_attribute_value(CK_SESSION_HANDLE hSession,
			      CK_OBJECT_HANDLE hObject,
			      CK_ATTRIBUTE_PTR pTemplate,
			      CK_ULONG ulCount);

/*!
 * \brief hal_find_objects_init
 * \param hSession
 * \param pTemplate
 * \param ulCount
 * \return
 */
CK_RV hal_find_objects_init(CK_SESSION_HANDLE hSession,
			    CK_ATTRIBUTE_PTR pTemplate,
			    CK_ULONG ulCount);
/*!
 * \brief hal_find_objects
 * \param hSession
 * \param phObject
 * \param ulMaxObjectCount
 * \param pulObjectCount
 * \return
 */
CK_RV hal_find_objects(CK_SESSION_HANDLE hSession,
		       CK_OBJECT_HANDLE_PTR phObject,
		       CK_ULONG ulMaxObjectCount,
		       CK_ULONG_PTR pulObjectCount);

/*!
 * \brief hal_find_objects_final
 * \param hSession
 * \return
 */
CK_RV hal_find_objects_final(CK_SESSION_HANDLE hSession);

#endif // HAL_H

