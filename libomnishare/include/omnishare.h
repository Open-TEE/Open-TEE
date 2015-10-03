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

#ifndef __OMNISHARE_H__
#define __OMNISHARE_H__

#include <stdint.h>

/*
 * Commands that are supprted by the TA
 */
#define CMD_CREATE_ROOT_KEY 0x00000001
#define CMD_DO_CRYPTO 0X00000002


/*
 * The OPERATIONS that can be performed by doCrypto
 */
#define OM_OP_ENCRYPT_FILE 0
#define OM_OP_DECRYPT_FILE 1
#define OM_OP_CREATE_DIRECTORY_KEY 2

/*!
 * \brief omnishare_generate_root_key
 * Create a root AES key that is wrapped by the device bound RSA key
 * \param key [IN/OUT] A non-NULL buffer to return the wrapped device specific key
 * \param key_size [IN/OUT] the size of the buffer as input, and the actual size on output
 * \return 0 on success
 */
uint32_t omnishare_generate_root_key(uint8_t *key, uint32_t *key_size);

/*!
 * \brief omnishare_init
 * Initialize the Trusted application with the root key of the omnishare hirarachy. The root
 * key is encrypted with the device specific RSA Key before it is stored to the root directory of
 * the omnishare tree.
 * \param root_key [IN] The encrypted root key of the omnishare directory tree
 * \param size [IN] The size of the key blob in bytes
 * \return 0 on success
 */
uint32_t omnishare_init(uint8_t *root_key, uint32_t size);

/*!
 * \brief omnishare_do_crypto
 * Perform the main crypto graphic operations of omnishare
 * \param key_chain [IN] The chain of keys tha tlead from the root dir down to the level
 * where the current file operations are taking place.
 * \param key_count [IN] The number of keys in the keychain
 * \param key_len [IN] The size of each individual key
 * \param op_cmd [IN] Which operation to perform
 * \param src [IN] Data to be operated on, or NULL when creating keys
 * \param src_len [IN] Size of data to be acted on, or 0 when creating keys
 * \param dest [IN/OUT] Buffer to hold the output
 * \param dest_len [IN/OUT] Length of the buffer available for output, on out the actual length used
 * \return 0 on success
 */
uint32_t omnishare_do_crypto(uint8_t *key_chain, uint32_t key_count, uint32_t key_len,
			     uint8_t op_cmd, uint8_t *src, uint32_t src_len,
			     uint8_t *dest, uint32_t *dest_len);

/*!
 * \brief finalize
 * Cleanup the omnishare instance
 */
void omnishare_finalize(void);

#endif
