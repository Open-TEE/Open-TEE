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

#ifndef COMMANDS_H
#define COMMANDS_H

#include "cryptoki.h"

/*!
 * \brief The mechanisms struct
 * This contains all the information about an algorith that an end user is interested in
 */
struct mechanisms {
	CK_MECHANISM_TYPE algo; /*!< The name of the algorithm */
	CK_MECHANISM_INFO info; /*!< Information about the keysizes and flags */
};

/* Message digesting functions */
#define TEE_DIGEST_INIT		0x00000001
#define TEE_DIGEST		0x00000002
#define TEE_DIGEST_UPDATE	0x00000003
#define	TEE_DIGEST_FINAL	0x00000004

/* Encryption functions */
#define TEE_ENCRYPT_INIT	0x00000005
#define TEE_ENCRYPT		0x00000006
#define TEE_ENCRYPT_UPDATE	0x00000007
#define	TEE_ENCRYPT_FINAL	0x00000008

/* Decryption functions */
#define TEE_DECRYPT_INIT	0x00000009
#define TEE_DECRYPT		0x0000000A
#define TEE_DECRYPT_UPDATE	0x0000000B
#define	TEE_DECRYPT_FINAL	0x0000000C

/* Signing and MACing functions */
#define TEE_SIGN_INIT		0x0000000D
#define TEE_SIGN		0x0000000E
#define TEE_SIGN_UPDATE		0x0000000F
#define	TEE_SIGN_FINAL		0x00000010

/* Functions for verifying signatures and MACs */
#define TEE_VERIFY_INIT		0x00000011
#define TEE_VERIFY		0x00000012
#define TEE_VERIFY_UPDATE	0x00000013
#define	TEE_VERIFY_FINAL	0x00000014

/* Functions for Slot and token control */
#define TEE_GET_SLOT_INFO	0x00000015
#define TEE_GET_TOKEN_INFO	0x00000016
#define TEE_INIT_TOKEN          0x00000017
#define TEE_GET_MECHANISM_LIST  0x00000018

/* Functions for session management */
#define TEE_CREATE_PKCS11_SESSION	0x00000019
#define TEE_CLOSE_PKCS11_SESSION	0x00000020
#define TEE_CLOSE_ALL_PKCS11_SESSION	0x00000021
#define TEE_GET_SESSION_INFO		0x00000022
#define TEE_LOGIN_SESSION		0x00000023
#define TEE_LOGOUT_SESSION		0x00000024
#define TEE_INIT_PIN			0x00000025
#define TEE_SET_PIN			0x00000026

/* Object management functions */
#define TEE_CREATE_OBJECT	0x000000A1
#define TEE_DESTROY_OBJECT	0x000000A2
#define TEE_GET_ATTR_VALUE	0x000000A3
#define TEE_SET_ATTR_VALUE	0x000000A4
#define TEE_FIND_OBJECTS_INIT	0x000000A5
#define TEE_FIND_OBJECTS	0x000000A6
#define TEE_FIND_OBJECTS_FINAL	0x000000A7

/* Crypto commands */
#define TEE_CRYPTO_INIT		0x000000C1
#define TEE_CRYPTO		0x000000C2
#define TEE_CRYPTO_UPDATE	0x000000C3
#define TEE_CRYPTO_FINAL	0x000000C4

/* Generate Random */
#define TEE_GENERATE_RANDOM     0x000000D1

#endif // COMMANDS_H

