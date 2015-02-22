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


#endif // HAL_H

