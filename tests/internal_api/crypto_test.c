/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
** Copyright (C) 2015 Intel Corporation.				    **
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

/* Extreme simply smoke tests. */

#include "crypto_test.h"
#include "../include/tee_internal_api.h"

/* Start Open-TEE spesifics. NOT GP Compliant. For debugin sake */
#include "../include/tee_logging.h"
#define PRI_STR(str)	    OT_LOG1(LOG_DEBUG, str);
#define PRI(str, ...)       OT_LOG1(LOG_DEBUG, "%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    OT_LOG1(LOG_DEBUG, " [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   OT_LOG1(LOG_DEBUG, " YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  OT_LOG1(LOG_DEBUG, "FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) OT_LOG1(LOG_DEBUG, "ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);
/* End Open-TEE spesifics */

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)
#define MAX_HASH_OUTPUT_LENGTH 64 /* sha512 */

/* sha256 (NIST) */
uint8_t sha256msg[] = "\x45\x11\x01\x25\x0e\xc6\xf2\x66\x52\x24\x9d\x59\xdc\x97\x4b\x73"
		      "\x61\xd5\x71\xa8\x10\x1c\xdf\xd3\x6a\xba\x3b\x58\x54\xd3\xae\x08"
		      "\x6b\x5f\xdd\x45\x97\x72\x1b\x66\xe3\xc0\xdc\x5d\x8c\x60\x6d\x96"
		      "\x57\xd0\xe3\x23\x28\x3a\x52\x17\xd1\xf5\x3f\x2f\x28\x4f\x57\xb8"
		      "\x5c\x8a\x61\xac\x89\x24\x71\x1f\x89\x5c\x5e\xd9\x0e\xf1\x77\x45"
		      "\xed\x2d\x72\x8a\xbd\x22\xa5\xf7\xa1\x34\x79\xa4\x62\xd7\x1b\x56"
		      "\xc1\x9a\x74\xa4\x0b\x65\x5c\x58\xed\xfe\x0a\x18\x8a\xd2\xcf\x46"
		      "\xcb\xf3\x05\x24\xf6\x5d\x42\x3c\x83\x7d\xd1\xff\x2b\xf4\x62\xac"
		      "\x41\x98\x00\x73\x45\xbb\x44\xdb\xb7\xb1\xc8\x61\x29\x8c\xdf\x61"
		      "\x98\x2a\x83\x3a\xfc\x72\x8f\xae\x1e\xda\x2f\x87\xaa\x2c\x94\x80"
		      "\x85\x8b\xec";

uint8_t sha256hash[] = "\x3c\x59\x3a\xa5\x39\xfd\xcd\xae\x51\x6c\xdf\x2f\x15\x00\x0f\x66"
		       "\x34\x18\x5c\x88\xf5\x05\xb3\x97\x75\xfb\x9a\xb1\x37\xa1\x0a\xa2";

/* RSA (NIST) */
uint8_t modulus[] = "\xa8\xd6\x8a\xcd\x41\x3c\x5e\x19\x5d\x5e\xf0\x4e\x1b\x4f\xaa\xf2"
		    "\x42\x36\x5c\xb4\x50\x19\x67\x55\xe9\x2e\x12\x15\xba\x59\x80\x2a"
		    "\xaf\xba\xdb\xf2\x56\x4d\xd5\x50\x95\x6a\xbb\x54\xf8\xb1\xc9\x17"
		    "\x84\x4e\x5f\x36\x19\x5d\x10\x88\xc6\x00\xe0\x7c\xad\xa5\xc0\x80"
		    "\xed\xe6\x79\xf5\x0b\x3d\xe3\x2c\xf4\x02\x6e\x51\x45\x42\x49\x5c"
		    "\x54\xb1\x90\x37\x68\x79\x1a\xae\x9e\x36\xf0\x82\xcd\x38\xe9\x41"
		    "\xad\xa8\x9b\xae\xca\xda\x61\xab\x0d\xd3\x7a\xd5\x36\xbc\xb0\xa0"
		    "\x94\x62\x71\x59\x48\x36\xe9\x2a\xb5\x51\x73\x01\xd4\x51\x76\xb5";

uint8_t public_exp[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03";

uint8_t private_exp[] = "\x1c\x23\xc1\xcc\xe0\x34\xba\x59\x8f\x8f\xd2\xb7\xaf\x37\xf1\xd3"
			"\x0b\x09\x0f\x73\x62\xae\xe6\x8e\x51\x87\xad\xae\x49\xb9\x95\x5c"
			"\x72\x9f\x24\xa8\x63\xb7\xa3\x8d\x6e\x3c\x74\x8e\x29\x72\xf6\xd9"
			"\x40\xb7\xba\x89\x04\x3a\x2d\x6c\x21\x00\x25\x6a\x1c\xf0\xf5\x6a"
			"\x8c\xd3\x5f\xc6\xee\x20\x52\x44\x87\x66\x42\xf6\xf9\xc3\x82\x0a"
			"\x3d\x9d\x2c\x89\x21\xdf\x7d\x82\xaa\xad\xca\xf2\xd7\x33\x4d\x39"
			"\x89\x31\xdd\xbb\xa5\x53\x19\x0b\x3a\x41\x60\x99\xf3\xaa\x07\xfd"
			"\x5b\x26\x21\x46\x45\xa8\x28\x41\x9e\x12\x2c\xfb\x85\x7a\xd7\x3b";

uint8_t rsa_msg[] = "\xd7\x38\x29\x49\x7c\xdd\xbe\x41\xb7\x05\xfa\xac\x50\xe7\x89\x9f"
		    "\xdb\x5a\x38\xbf\x3a\x45\x9e\x53\x63\x57\x02\x9e\x64\xf8\x79\x6b"
		    "\xa4\x7f\x4f\xe9\x6b\xa5\xa8\xb9\xa4\x39\x67\x46\xe2\x16\x4f\x55"
		    "\xa2\x53\x68\xdd\xd0\xb9\xa5\x18\x8c\x7a\xc3\xda\x2d\x1f\x74\x22"
		    "\x86\xc3\xbd\xee\x69\x7f\x9d\x54\x6a\x25\xef\xcf\xe5\x31\x91\xd7"
		    "\x43\xfc\xc6\xb4\x78\x33\xd9\x93\xd0\x88\x04\xda\xec\xa7\x8f\xb9"
		    "\x07\x6c\x3c\x01\x7f\x53\xe3\x3a\x90\x30\x5a\xf0\x62\x20\x97\x4d"
		    "\x46\xbf\x19\xed\x3c\x9b\x84\xed\xba\xe9\x8b\x45\xa8\x77\x12\x58";

uint8_t rsa_sig[] = "\x17\x50\x15\xbd\xa5\x0a\xbe\x0f\xa7\xd3\x9a\x83\x53\x88\x5c\xa0"
		    "\x1b\xe3\xa7\xe7\xfc\xc5\x50\x45\x74\x41\x11\x36\x2e\xe1\x91\x44"
		    "\x73\xa4\x8d\xc5\x37\xd9\x56\x29\x4b\x9e\x20\xa1\xef\x66\x1d\x58"
		    "\x53\x7a\xcd\xc8\xde\x90\x8f\xa0\x50\x63\x0f\xcc\x27\x2e\x6d\x00"
		    "\x10\x45\xe6\xfd\xee\xd2\xd1\x05\x31\xc8\x60\x33\x34\xc2\xe8\xdb"
		    "\x39\xe7\x3e\x6d\x96\x65\xee\x13\x43\xf9\xe4\x19\x83\x02\xd2\x20"
		    "\x1b\x44\xe8\xe8\xd0\x6b\x3e\xf4\x9c\xee\x61\x97\x58\x21\x63\xa8"
		    "\x49\x00\x89\xca\x65\x4c\x00\x12\xfc\xe1\xba\x65\x11\x08\x97\x50";

static int calc_digest(algorithm_Identifier hash_alg,
		       void *msg,
		       uint32_t msg_len,
		       void *hash,
		       uint32_t *hash_len)
{
	TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
	TEE_Result ret;

	ret = TEE_AllocateOperation(&operation, hash_alg, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed allocate digest operation");
		return 1;
	}

	ret = TEE_DigestDoFinal(operation, msg, msg_len, hash, hash_len);
	TEE_FreeOperation(operation);

	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Final failed");
		return 1;
	}

	return 0;
}

static uint32_t sha256_digest()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle digest_handler = (TEE_OperationHandle)NULL;
	TEE_OperationHandle digest_handler_2 = (TEE_OperationHandle)NULL;
	void *rand_msg = NULL;
	void *rand_msg_2 = NULL;
	char hash[64] = {0};
	char hash_2[64] = {0};
	uint32_t rand_msg_len = 1000;
	uint32_t hash_len = 64;
	uint32_t hash_len_2 = 64;
	uint32_t fn_ret = 1; /* Initialized error return */

	rand_msg = TEE_Malloc(rand_msg_len, 0);
	rand_msg_2 = TEE_Malloc(rand_msg_len, 0);
	if (rand_msg == NULL || rand_msg_2 == NULL) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_GenerateRandom(rand_msg, rand_msg_len);
	TEE_MemMove(rand_msg_2, rand_msg, rand_msg_len);

	ret = TEE_AllocateOperation(&digest_handler, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	ret = TEE_AllocateOperation(&digest_handler_2, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc second handler");
		goto err;
	}

	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);
	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);

	TEE_DigestUpdate(digest_handler_2, rand_msg_2, rand_msg_len);
	TEE_DigestUpdate(digest_handler_2, rand_msg_2, rand_msg_len);

	ret = TEE_DigestDoFinal(digest_handler, NULL, 0, hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed final first");
		goto err;
	}

	ret = TEE_DigestDoFinal(digest_handler_2, NULL, 0, hash_2, &hash_len_2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed final second");
		goto err;
	}

	if (hash_len_2 != hash_len) {
		PRI_FAIL("Length bhould be same");
		goto err;
	}

	if (TEE_MemCompare(hash, hash_2, hash_len_2)) {
		PRI_FAIL("Hashes should be same");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeOperation(digest_handler);
	TEE_FreeOperation(digest_handler_2);
	TEE_Free(rand_msg);
	TEE_Free(rand_msg_2);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t sha256_digest_nist()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle sha256_operation = (TEE_OperationHandle)NULL;
	char hash[64] = {0};
	uint32_t hash_len = MAX_HASH_OUTPUT_LENGTH, fn_ret = 1; /* Initialized error return */

	ret = TEE_AllocateOperation(&sha256_operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc sha256 handler");
		goto err;
	}

	ret = TEE_DigestDoFinal(sha256_operation,
				sha256msg, SIZE_OF_VEC(sha256msg), hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Final failed");
		goto err;
	}

	if (hash_len != SIZE_OF_VEC(sha256hash)) {
		PRI_FAIL("Length bhould be same");
		goto err;
	}

	if (TEE_MemCompare(hash, sha256hash, hash_len)) {
		PRI_FAIL("Hashes should be same");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeOperation(sha256_operation);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static int warp_sym_op(TEE_ObjectHandle key,
		       TEE_OperationMode mode,
		       void *IV,
		       size_t IV_len,
		       uint32_t alg,
		       void *in_chunk,
		       size_t in_chunk_len,
		       void *out_chunk,
		       size_t *out_chunk_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle handle = (TEE_OperationHandle)NULL;
	uint32_t write_bytes = 0;
	uint32_t total_write_bytes = 0;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	TEE_CipherInit(handle, IV, IV_len);

	write_bytes = *out_chunk_len;

	ret = TEE_CipherUpdate(handle, in_chunk, in_chunk_len, out_chunk, &write_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Updated failure : 0x%x", ret);
		goto err;
	}

	total_write_bytes += write_bytes;
	write_bytes = *out_chunk_len - total_write_bytes;

	ret = TEE_CipherDoFinal(handle, NULL, 0,
				(unsigned char *)out_chunk + total_write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Do final failure : 0x%x", ret);
		goto err;
	}

	*out_chunk_len = total_write_bytes + write_bytes;
	TEE_FreeOperation(handle);
	return 0;
err:
	TEE_FreeOperation(handle);
	return 1;
}

static uint32_t aes_256_cbc_enc_dec()
{
	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t plain_len = 32;
	size_t cipher_len = 32;
	size_t dec_plain_len = plain_len;
	size_t IVlen = 16;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}
	TEE_GenerateRandom(IV, IVlen);
	TEE_MemMove(plain, plain_msg, 5);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_sym_op(key, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len))
		goto err;

	if (warp_sym_op(key, TEE_MODE_DECRYPT, IV, IVlen, alg,
			cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, dec_plain_len)) {
		PRI_FAIL("Plain text is not matching");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t aes_128_cbc_enc_dec()
{
	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t plain_len = 32;
	size_t cipher_len = 32;
	size_t dec_plain_len = plain_len;
	size_t IVlen = 16;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}
	TEE_GenerateRandom(IV, IVlen);
	TEE_MemMove(plain, plain_msg, 5);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_sym_op(key, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len))
		goto err;

	if (warp_sym_op(key, TEE_MODE_DECRYPT, IV, IVlen, alg,
			cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, dec_plain_len)) {
		PRI_FAIL("Plain text is not matching");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static int warp_asym_op(TEE_ObjectHandle key,
			TEE_OperationMode mode,
			uint32_t alg,
			TEE_Attribute *params,
			uint32_t paramCount,
			void *in_chunk,
			uint32_t in_chunk_len,
			void *out_chunk,
			uint32_t *out_chunk_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle handle = (TEE_OperationHandle)NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	if (mode == TEE_MODE_SIGN) {

		ret = TEE_AsymmetricSignDigest(handle, params, paramCount,
					       in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Sign failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_VERIFY) {

		ret = TEE_AsymmetricVerifyDigest(handle, params, paramCount,
						 in_chunk, in_chunk_len, out_chunk, *out_chunk_len);
		if (ret == TEE_SUCCESS) {
			/* Do nothing */
		} else if (ret == TEE_ERROR_SIGNATURE_INVALID) {
			PRI_FAIL("Signature invalid");
			goto err;
		} else {
			PRI_FAIL("Verify failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_ENCRYPT) {

		ret = TEE_AsymmetricEncrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Encrypt failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_DECRYPT) {

		ret = TEE_AsymmetricDecrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Decrypt failed : 0x%x", ret);
			goto err;
		}

	} else {
		goto err;
	}

	TEE_FreeOperation(handle);
	return 0;

err:
	TEE_FreeOperation(handle);
	return 1;
}

static uint32_t rsa_sign_nist_sha1_pkcs()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char hash[64] = {0}; /*sha1*/
	char signature[256] = {0}; /* 1024 */
	uint32_t signature_len = 256, hash_len = 64;
	TEE_Attribute rsa_attrs[3];
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, fn_ret = 1; /* Init error return */;

	/* Modulo */
	rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
	rsa_attrs[0].content.ref.buffer = modulus;
	rsa_attrs[0].content.ref.length = SIZE_OF_VEC(modulus);

	/* Public exp */
	rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	rsa_attrs[1].content.ref.buffer = public_exp;
	rsa_attrs[1].content.ref.length = SIZE_OF_VEC(public_exp);

	/* Private exp */
	rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
	rsa_attrs[2].content.ref.buffer = private_exp;
	rsa_attrs[2].content.ref.length = SIZE_OF_VEC(private_exp);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 1024, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc object handler");
		goto err;
	}

	ret = TEE_PopulateTransientObject(object, (TEE_Attribute *)&rsa_attrs, 3);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA key population failed");
		goto err;
	}

	if (calc_digest(TEE_ALG_SHA1, rsa_msg, SIZE_OF_VEC(rsa_msg), hash, &hash_len))
		goto err;

	if (warp_asym_op(object, TEE_MODE_SIGN, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (void *)hash, hash_len, (void *)signature, &signature_len))
		goto err;

	if (SIZE_OF_VEC(rsa_sig) != signature_len) {
		PRI_FAIL("Signature length invalid");
		goto err;
	}

	if (TEE_MemCompare(rsa_sig, signature, signature_len)) {
		PRI_FAIL("Signature length invalid");
		goto err;
	}

	if (warp_asym_op(object, TEE_MODE_VERIFY, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (void *)hash, hash_len, (void *)signature, &signature_len))
		goto err;

	fn_ret = 0; /* OK */

err:
	TEE_FreeTransientObject(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t RSA_sig_and_ver()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
	char *dig_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	uint32_t dig_len = 20;
	uint32_t sig_len = 64;

	void *dig = NULL;
	void *sig = NULL;

	dig = TEE_Malloc(dig_len, 0);
	sig = TEE_Malloc(sig_len, 0);
	if (!dig || !sig) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(dig, dig_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(rsa_keypair, TEE_MODE_SIGN, rsa_alg, (TEE_Attribute *)NULL, 0,
			 dig, dig_len, sig, &sig_len))
		goto err;

	if (warp_asym_op(rsa_keypair, TEE_MODE_VERIFY, rsa_alg, (TEE_Attribute *)NULL, 0,
			 dig, dig_len, sig, &sig_len))
		goto err;

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(dig);
	TEE_Free(sig);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t HMAC_computation()
{
	TEE_Result ret;
	TEE_ObjectHandle hmac_key = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle hmac_handle = (TEE_OperationHandle)NULL;
	TEE_OperationHandle hmac_handle2 = (TEE_OperationHandle)NULL;
	size_t key_size = 256;
	uint32_t alg = TEE_ALG_HMAC_SHA256;
	uint32_t alg2 = TEE_ALG_HMAC_SHA256;
	char *seed_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	uint32_t mac_len = 64;
	size_t msg_len = 100;

	void *mac = NULL;
	void *msg = NULL;

	mac = TEE_Malloc(mac_len, 0);
	msg = TEE_Malloc(msg_len, 0);
	if (!mac || !msg) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(msg, seed_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_size, &hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(hmac_key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle, alg, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle2, alg2, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc second handler");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle, hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle2, hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set second operation key : 0x%x", ret);
		goto err;
	}

	TEE_MACInit(hmac_handle, NULL, 0);

	TEE_MACUpdate(hmac_handle, msg, msg_len);

	ret = TEE_MACComputeFinal(hmac_handle, NULL, 0, mac, &mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("First final failed : 0x%x", ret);
		goto err;
	}

	TEE_MACInit(hmac_handle2, NULL, 0);

	ret = TEE_MACCompareFinal(hmac_handle2, msg, msg_len, mac, mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("MAC Invalid");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(hmac_key);
	TEE_FreeOperation(hmac_handle);
	TEE_FreeOperation(hmac_handle2);
	TEE_Free(mac);
	TEE_Free(msg);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t RSA_keypair_enc_dec()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	uint32_t plain_len = 10;
	uint32_t cipher_len = 64;
	uint32_t dec_plain_len = 64;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;

	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain, plain_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, cipher, &cipher_len))
		goto err;

	if (warp_asym_op(rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, plain_len)) {
		PRI_FAIL("Decrypted not matching to original\n");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(plain);
	TEE_Free(dec_plain);
	TEE_Free(cipher);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}


static uint32_t set_key_and_rm_and_do_crypto()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle sign_op = (TEE_OperationHandle)NULL,
			verify_op = (TEE_OperationHandle)NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
	char *dig_seed = "TEST";
	uint32_t dig_len = 32, sig_len = 64;
	char dig[32] = {0}, sig[64] = {0};
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_MemMove(dig, dig_seed, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&sign_op, rsa_alg, TEE_MODE_SIGN, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc sign operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&verify_op, rsa_alg, TEE_MODE_VERIFY, key_size * 2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc verify operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(sign_op, rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set sign operation key : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(verify_op, rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set verify operation key : 0x%x", ret);
		goto err;
	}

	TEE_FreeTransientObject(rsa_keypair);
	rsa_keypair = (TEE_ObjectHandle)NULL;

	ret = TEE_AsymmetricSignDigest(sign_op, (TEE_Attribute *)NULL, 0,
				       dig, dig_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(verify_op, (TEE_Attribute *)NULL, 0,
					 dig, dig_len, sig, sig_len);
	if (ret == TEE_SUCCESS) {
		/* Do nothing */
	} else if (ret == TEE_ERROR_SIGNATURE_INVALID) {
		PRI_FAIL("Signature invalid");
		goto err;
	} else {
		PRI_FAIL("Verify failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(verify_op);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t read_key_and_do_crypto()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL,
			persisten_rsa_keypair = (TEE_ObjectHandle)NULL;
	char objID[] = "56c5d1b260704de30fe99f67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	uint32_t objID_len = 45;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5, key_size = 512;
	char *plain_msg = "TEST";
	uint32_t plain_len = 10, cipher_len = 64, dec_plain_len = 64,
			per_cipher_len = 64, per_dec_plain_len = 64;
	char plain[10] = {0}, cipher[64] = {0}, dec_plain[64] = {0},
			per_cipher[64] = {0}, per_dec_plain[64] = {0};
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_MemMove(plain, plain_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 (uint32_t)NULL, rsa_keypair, NULL, 0,
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &persisten_rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	/* Transient object */
	if (warp_asym_op(rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, cipher, &cipher_len))
		goto err;

	if (warp_asym_op(rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (dec_plain_len != plain_len || TEE_MemCompare(dec_plain, plain, plain_len)) {
		PRI_FAIL("Decrypted not matching to original\n");
		goto err;
	}

	/* Persistent object */
	if (warp_asym_op(persisten_rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, per_cipher, &per_cipher_len))
		goto err;

	if (warp_asym_op(persisten_rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)per_cipher, per_cipher_len,
			 per_dec_plain, &per_dec_plain_len))
		goto err;

	if (per_dec_plain_len != plain_len ||
	    TEE_MemCompare(dec_plain, per_dec_plain, dec_plain_len)) {
		PRI_FAIL("Persisten decrypted not matching plain text\n");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_CloseAndDeletePersistentObject(persisten_rsa_keypair);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

uint32_t crypto_test(uint32_t loop_count)
{
        uint32_t i, test_have_fail = 0;

	PRI_STR("START: crypto tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {

		if (sha256_digest() ||
		    sha256_digest_nist() ||
		    aes_256_cbc_enc_dec() ||
		    aes_128_cbc_enc_dec() ||
		    RSA_sig_and_ver() ||
		    RSA_keypair_enc_dec() ||
		    HMAC_computation() ||
		    set_key_and_rm_and_do_crypto() ||
		    read_key_and_do_crypto() ||
                    rsa_sign_nist_sha1_pkcs()) {
                        test_have_fail = 1;
                        break;
                }
	}

	PRI_STR("----Test-has-reached-end----\n");

	PRI_STR("END: crypto tests");

        return test_have_fail ? 1 : 0;
}
