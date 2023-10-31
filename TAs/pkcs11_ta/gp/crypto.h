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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "pkcs11_application.h"
#include "tee_internal_api.h"
#include "tee_list.h"

struct pkcs11_crypto_op {
	TEE_OperationHandle operation;
	TEE_OperationHandle operation_2; /* Might used the rirst operation helper operation */
	CK_MECHANISM_TYPE mechanism;
	CK_MAC_GENERAL_PARAMS hmac_general_output;
	uint32_t key_size; /* Key size in bits */
};

/*!
 * \brief crypto_init
 * Initializes crypto operation
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result crypto_init(struct application *app, uint32_t paramTypes, TEE_Param *params);

/*!
 * \brief crypto
 * Function will determ which crypto operation need to be executed
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result crypto(struct application *app, uint32_t paramTypes, TEE_Param *params);

/*!
 * \brief crypto
 * TEE_VERIFY operation is not fitting in a regular crypto operations. It is not returning
 * a buffer (eg. encrypted message). It taking two input buffer and returning an integer
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result crypto_verify(struct application *app, uint32_t paramTypes, TEE_Param *params);

/*!
 * \brief crypto_generate_random
 * Generate a random set of bytes
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result crypto_generate_random(struct application *app, uint32_t paramTypes, TEE_Param *params);

#endif
