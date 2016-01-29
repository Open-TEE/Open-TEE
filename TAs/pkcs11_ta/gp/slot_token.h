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

#ifndef __SLOT_TOKEN_H__
#define __SLOT_TOKEN_H__

#include "cryptoki.h"
#include <inttypes.h>
#include <stdbool.h>

#include "compat.h"
#include "cryptoki.h"

/*!
 * \brief initialize_token
 * Initialize the global token;
 * \param from_user Set to True if C_InitToken is used to invoke this function, false if the init
 * is being called as part of the TA initialization
 * \param paramTypes Format of the data sent from the userspace
 * \param params The in/out buffers to hold the token info
 * \return 0 on success
 */
TEE_Result initialize_token(bool from_user, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief get_token_info
 * Return the token related information to userspace
 * \param paramTypes Format of the data sent from the userspace
 * \param params The in/out buffers to hold the token info
 * \return 0 on success
 */
TEE_Result get_token_info(uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief get_mechanism_list
 * retrieve the list of supported mechanisms and their info
 * \param paramTypes Format of the data sent from the userspace
 * \param params The in/out buffers to hold the token info
 * \return 0 on success
 */
TEE_Result get_mechanism_list(uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief is_token_write_protected
 * Determine if the token is write protected, hence if we can only open RO sessions
 * \return true if the token is write protected
 */
bool is_token_write_protected();

/*!
 * \brief mechanism_supported
 * Function check if mechanism supported
 * \param mech_type
 * \param key_size
 * \param mode
 * \return
 */
CK_RV mechanism_supported(CK_MECHANISM_TYPE mech_type, CK_ULONG key_size, TEE_OperationMode mode);

/*!
 * \brief check_password
 * Check that the password that is being supplied matches the password that is stored
 * \param user_type Either User or SO
 * \param passwd The password
 * \param passwd_len Its length
 * \return 0 on success
 */
CK_RV check_password(CK_USER_TYPE user_type, const char *passwd, uint32_t passwd_len);

/*!
 * \brief set_password
 * Set the password for a given user
 * \param user_type The USER for whom the passowrd is being created
 * \param passwd
 * \param passwd_len
 * \return 0 on success
 */
CK_RV set_password(CK_USER_TYPE user_type, const char *passwd, uint32_t passwd_len);

#endif // SLOT_TOKEN_H
