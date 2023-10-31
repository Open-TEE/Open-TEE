/*****************************************************************************
** Copyright (C) 2015 Brian McGillion                                       **
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

#include <cryptoki.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR func_list;
static char user_pin[8] = "12345678";

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

/* At this point these are global vars */
static CK_OBJECT_HANDLE rsa_public_obj;
static CK_OBJECT_HANDLE rsa_private_obj;
static CK_OBJECT_HANDLE aes_secret_obj;
static CK_OBJECT_HANDLE hmac_256_trunc_obj;
static CK_OBJECT_HANDLE hmac_256_obj;
static CK_OBJECT_HANDLE get_attr_aes_temp_obj;

/* TODO: Find proper vector for RSA PKCS v1.5 encrypt/decrypt!!! */
uint8_t rsa_encrypt_msg[] = "\xe6\x3b\x5f\x79\xc7\x7c\x2f\x91\x2a\x8f\x7d\x4f\x39\xcb\xd7\x58";

/* RSA (NIST) */
uint8_t modulus[] = "\xa8\xd6\x8a\xcd\x41\x3c\x5e\x19\x5d\x5e\xf0\x4e\x1b\x4f\xaa\xf2"
		    "\x42\x36\x5c\xb4\x50\x19\x67\x55\xe9\x2e\x12\x15\xba\x59\x80\x2a"
		    "\xaf\xba\xdb\xf2\x56\x4d\xd5\x50\x95\x6a\xbb\x54\xf8\xb1\xc9\x17"
		    "\x84\x4e\x5f\x36\x19\x5d\x10\x88\xc6\x00\xe0\x7c\xad\xa5\xc0\x80"
		    "\xed\xe6\x79\xf5\x0b\x3d\xe3\x2c\xf4\x02\x6e\x51\x45\x42\x49\x5c"
		    "\x54\xb1\x90\x37\x68\x79\x1a\xae\x9e\x36\xf0\x82\xcd\x38\xe9\x41"
		    "\xad\xa8\x9b\xae\xca\xda\x61\xab\x0d\xd3\x7a\xd5\x36\xbc\xb0\xa0"
		    "\x94\x62\x71\x59\x48\x36\xe9\x2a\xb5\x51\x73\x01\xd4\x51\x76\xb5";

uint8_t public_exp[] = "\x00\x00\x00\x03";

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


/* AES128 (NIST) */
uint8_t aes_key[] = "\x1f\x8e\x49\x73\x95\x3f\x3f\xb0\xbd\x6b\x16\x66\x2e\x9a\x3c\x17";
uint8_t aes_IV[] = "\x2f\xe2\xb3\x33\xce\xda\x8f\x98\xf4\xa9\x9b\x40\xd2\xcd\x34\xa8";
uint8_t aes_msg[] = "\x45\xcf\x12\x96\x4f\xc8\x24\xab\x76\x61\x6a\xe2\xf4\xbf\x08\x22";
uint8_t aes_cipher[] = "\x0f\x61\xc4\xd4\x4c\x51\x47\xc0\x3c\x19\x5a\xd7\xe2\xcc\x12\xb2";

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

/* HMACSHA256 (truncated mac) (NIST) */
uint8_t hmacsha256key_trunc[] = "\x6f\x35\x62\x8d\x65\x81\x34\x35\x53\x4b\x5d\x67\xfb\xdb\x54\xcb"
				"\x33\x40\x3d\x04\xe8\x43\x10\x3e\x63\x99\xf8\x06\xcb\x5d\xf9\x5f"
				"\xeb\xbd\xd6\x12\x36\xf3\x32\x45";

uint8_t hmacsha256msg_trunc[] = "\x75\x2c\xff\x52\xe4\xb9\x07\x68\x55\x8e\x53\x69\xe7\x5d\x97\xc6"
				"\x96\x43\x50\x9a\x5e\x59\x04\xe0\xa3\x86\xcb\xe4\xd0\x97\x0e\xf7"
				"\x3f\x91\x8f\x67\x59\x45\xa9\xae\xfe\x26\xda\xea\x27\x58\x7e\x8d"
				"\xc9\x09\xdd\x56\xfd\x04\x68\x80\x5f\x83\x40\x39\xb3\x45\xf8\x55"
				"\xcf\xe1\x9c\x44\xb5\x5a\xf2\x41\xff\xf3\xff\xcd\x80\x45\xcd\x5c"
				"\x28\x8e\x6c\x4e\x28\x4c\x37\x20\x57\x0b\x58\xe4\xd4\x7b\x8f\xee"
				"\xed\xc5\x2f\xd1\x40\x1f\x69\x8a\x20\x9f\xcc\xfa\x3b\x4c\x0d\x9a"
				"\x79\x7b\x04\x6a\x27\x59\xf8\x2a\x54\xc4\x1c\xcd\x7b\x5f\x59\x2b";

uint8_t hmacsha256mac_trunc[] = "\x05\xd1\x24\x3e\x64\x65\xed\x96\x20\xc9\xae\xc1\xc3\x51\xa1\x86";

/* HMACSHA256 (NIST) */
uint8_t hmacsha256key[] = "\xc1\xd6\x08\x14\x37\x6a\xae\x39\xc4\x11\x12\x46\x35\x34\x85\x95"
			  "\x8f\x95\x55\x8f\xa3\x8f\xfc\x14\xe4\xa0\x98\x1d\x76\x24\x9b\x9f"
			  "\x87\x63\xc4\xb3\xe2\xce\x4e\xf5";

uint8_t hmacsha256msg[] = "\x97\xd2\x9a\xc5\xed\xe9\x4c\x0a\x50\x71\xe0\x09\x5e\x61\x02\x12"
			  "\x3d\x17\x26\x13\x2f\x9d\xc1\x02\x67\x2a\xb8\x7b\x1c\xec\x18\xab"
			  "\xdb\x04\x09\x6c\x21\xd3\xfd\xb1\x29\x74\x2d\x25\x03\x89\x46\x0f"
			  "\xe6\x3b\x5f\x79\xc7\x7c\x2f\x91\x2a\x8f\x7d\x4f\x39\xcb\xd7\x58"
			  "\x13\x9c\x87\x23\x66\xca\xc3\x5a\x40\xfe\x24\x83\x22\x82\x5a\xdf"
			  "\x57\x48\x1d\x92\x83\x2e\x66\x05\x7f\x80\xe0\x89\x64\xbe\x99\x3d"
			  "\xe6\xa0\xfe\x31\xe4\x58\x06\xcb\x3c\x17\xad\x6a\xe4\xd2\xa4\x4a"
			  "\x37\x46\x47\xa8\x8c\x3a\xcf\x26\x0d\x04\xc9\x70\xc7\x4e\xc7\x20";

uint8_t hmacsha256mac[] = "\x50\xdb\x0e\xcb\x5b\x31\x52\x4a\x69\x14\x26\x49\x30\xab\xcc\xae"
			  "\x0d\xa0\x7f\x01\xa2\xbb\xb9\x40\x82\x07\x15\x6f\x8e\x8a\x34\x0c";


/* Debug printing */
static void __attribute__((unused)) pri_buf_hex_format(const char *title,
						       const unsigned char *buf,
						       int buf_len)
{
	int i;
	printf("%s:", title);
	for (i = 0; i < buf_len; ++i) {

		if ((i % 32) == 0)
			printf("\n");


		printf("%02x ", buf[i]);
	}

	printf("\n");
}

#define PRI(str, ...)       printf("%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    printf(" [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   printf(" YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  printf("FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) printf("ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);

static void get_random_data(void *ptr, uint32_t len)
{
	FILE *urandom_fp;

	urandom_fp = fopen("/dev/urandom", "r");
	if (urandom_fp == NULL) {
		PRI("cant open urandom");
		exit(1); /* No return, just exit */
	}

	if (fread(ptr, 1, len, urandom_fp) != len) {
		PRI("urandom read error");
		exit(1); /* No return, just exit */
	}

	fclose(urandom_fp);
}

static void encrypt_and_decrypt(CK_SESSION_HANDLE session,
				CK_MECHANISM *mechanism)
{
	CK_BYTE_PTR msg, expected_cipher;
	CK_ULONG msg_len = 0, expected_cipher_len = 0, cipher_len = 0, decrypted_len = 0;
	CK_OBJECT_HANDLE encrypt_key, decrypt_key;
	char *mech_type, *cipher, *decrypted;
	CK_RV ret;

	/* Signature bufffer */
	if (mechanism->mechanism == CKM_AES_CBC) {
		expected_cipher = aes_cipher;
		expected_cipher_len = SIZE_OF_VEC(aes_cipher);
		msg = aes_msg;
		msg_len = SIZE_OF_VEC(aes_msg);
		decrypt_key = aes_secret_obj;
		encrypt_key = aes_secret_obj;
		mech_type = "CKM_AES_CBC";

	} else if (mechanism->mechanism == CKM_RSA_PKCS) {
		expected_cipher = NULL;
		expected_cipher_len = SIZE_OF_VEC(modulus);
		msg = rsa_encrypt_msg;
		msg_len = SIZE_OF_VEC(rsa_encrypt_msg);
		decrypt_key = rsa_private_obj;
		encrypt_key = rsa_public_obj;
		mech_type = "CKM_RSA_PKCS";

	} else {
		PRI_FAIL("Mechanism unknow");
		return;
	}

	cipher_len = expected_cipher_len;
	cipher = calloc(1, expected_cipher_len);
	decrypted_len = msg_len;
	decrypted = calloc(1, decrypted_len);

	if (cipher == NULL || decrypted == NULL) {
		PRI_FAIL("%s : Out of memory", mech_type)
		goto out;
	}

	ret = func_list->C_EncryptInit(session, mechanism, encrypt_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : EncryptInit(): %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	/* Get size */
	ret = func_list->C_Encrypt(session, (CK_BYTE_PTR)msg, msg_len, NULL, &cipher_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Encrypt() getting size: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	if (cipher_len != expected_cipher_len) {
		PRI_FAIL("%s : Getting invalid encrypt output size", mech_type);
		goto out;
	}

	/* Do the encryption */
	ret = func_list->C_Encrypt(session, (CK_BYTE_PTR)msg, msg_len,
				   (CK_BYTE_PTR)cipher, &cipher_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Encrypt(): %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	if (cipher_len != expected_cipher_len) {
		PRI_FAIL("%s : Invalid size after encryption", mech_type);
		goto out;
	}

	if (expected_cipher != NULL && memcmp(aes_cipher, cipher, cipher_len) != 0) {
		PRI_FAIL("%s : Not expexted encryption result", mech_type);
		goto out;
	}


	/* DECRYPTION*/

	ret = func_list->C_DecryptInit(session, mechanism, decrypt_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : DecryptInit(): %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	/* Get size */
	ret = func_list->C_Decrypt(session, (CK_BYTE_PTR)cipher, cipher_len, NULL, &decrypted_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_Decrypt() getting size: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	if (decrypted_len != msg_len) {
		PRI_FAIL("%s : Getting invalid decrypt output size", mech_type);
		goto out;
	}

	/* Do the decryption */
	ret = func_list->C_Decrypt(session, (CK_BYTE_PTR)cipher, cipher_len,
				   (CK_BYTE_PTR)decrypted, &decrypted_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Decrypt(): %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		goto out;
	}

	if (decrypted_len != msg_len) {
		PRI_FAIL("%s : Invalid size after decrypt", mech_type);
		goto out;
	}

	if (memcmp(msg, decrypted, decrypted_len) != 0) {
		PRI_FAIL("%s : decryption failure", mech_type);
		goto out;
	}

	PRI_OK("%s : -", mech_type)
out:
	free(cipher);
	free(decrypted);
}

static void sign_and_verify(CK_SESSION_HANDLE session,
			    CK_MECHANISM *mechanism)
{
	CK_MAC_GENERAL_PARAMS hmac_genera_param;
	CK_BYTE_PTR msg, expected_sig;
	CK_ULONG sig_len = 0, msg_len = 0, expected_sig_len = 0;
	CK_OBJECT_HANDLE sign_key, verify_key;
	char sig[512]; /* Avoiding malloc and reserving enough big buffer for all signatures */
	char *mech_type;
	CK_RV ret;

	/* Signature bufffer */
	if (mechanism->mechanism == CKM_SHA1_RSA_PKCS) {
		expected_sig = rsa_sig;
		expected_sig_len = SIZE_OF_VEC(rsa_sig);
		sig_len = SIZE_OF_VEC(rsa_sig); /* Signature buffer length */
		msg = rsa_msg;
		msg_len = SIZE_OF_VEC(rsa_msg);
		sign_key = rsa_private_obj;
		verify_key = rsa_public_obj;
		mech_type = "CKM_SHA1_RSA_PKCS";

	} else if (mechanism->mechanism == CKM_SHA256_HMAC) {
		expected_sig = hmacsha256mac;
		expected_sig_len = SIZE_OF_VEC(hmacsha256mac);
		sig_len = SIZE_OF_VEC(hmacsha256mac); /* Signature buffer length */
		msg = hmacsha256msg;
		msg_len = SIZE_OF_VEC(hmacsha256msg);
		sign_key = hmac_256_obj;
		verify_key = hmac_256_obj;
		mech_type = "CKM_SHA256_HMAC";

	} else if (mechanism->mechanism == CKM_SHA256_HMAC_GENERAL) {
		expected_sig = hmacsha256mac_trunc;
		expected_sig_len = SIZE_OF_VEC(hmacsha256mac_trunc);
		sig_len = SIZE_OF_VEC(hmacsha256mac_trunc); /* Signature buffer length */
		msg = hmacsha256msg_trunc;
		msg_len = SIZE_OF_VEC(hmacsha256msg_trunc);
		sign_key = hmac_256_trunc_obj;
		verify_key = hmac_256_trunc_obj;
		mech_type = "CKM_SHA256_HMAC_GENERAL";
		mechanism->pParameter = &hmac_genera_param;
		*(CK_MAC_GENERAL_PARAMS *)mechanism->pParameter = SIZE_OF_VEC(hmacsha256mac_trunc);
		mechanism->ulParameterLen = sizeof(CK_MAC_GENERAL_PARAMS);

	} else {
		PRI_FAIL("Mechanism unknow");
		return;
	}

	ret = func_list->C_SignInit(session, mechanism, sign_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Sign init: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	/* Get size */
	ret = func_list->C_Sign(session, NULL, 0, NULL, &sig_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_Sign() getting size: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	if (sig_len != expected_sig_len) {
		PRI_FAIL("%s : Getting invalid sign output size", mech_type);
		return;
	}


	ret = func_list->C_Sign(session, msg, msg_len, (CK_BYTE_PTR)sig, &sig_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Sign: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	if (expected_sig_len != sig_len) {
		PRI_FAIL("%s : Invalid size after signature: %lu", mech_type, sig_len);
		return;
	}

	if (memcmp(expected_sig, sig, sig_len) != 0) {
		PRI_FAIL("%s : Not expected signature", mech_type);
		return;
	} else {
		PRI_OK("%s : Signature OK", mech_type);
	}

	ret = func_list->C_VerifyInit(session, mechanism, verify_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Verify init: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Verify(session, msg, msg_len, (CK_BYTE_PTR)sig, sig_len);
	if (ret == CKR_OK) {
		PRI_OK("%s : Verified OK", mech_type);
	} else if (ret == CKR_SIGNATURE_INVALID) {
		PRI_FAIL("%s :Invalid signature", mech_type);
	} else {
		PRI_FAIL("%s : Verify : %lu : 0x%x", mech_type, ret, (uint32_t)ret);
	}
}

static void sign_and_verify_with_update(CK_SESSION_HANDLE session,
					CK_MECHANISM *mechanism)
{
	CK_ULONG i, update_loop_count = 2;
	CK_MAC_GENERAL_PARAMS hmac_genera_param;
	CK_ULONG sig_len = 0, expected_sig_len = 0;
	CK_OBJECT_HANDLE sign_key, verify_key;
	char sig[512]; /* Avoiding malloc and reserving enough big buffer for all signatures */
	char *mech_type;
	CK_RV ret;

	/* Random data */
	CK_ULONG random_data_len = 10;
	char random_data[random_data_len];
	get_random_data(random_data, random_data_len);

	/* Signature bufffer */
	if (mechanism->mechanism == CKM_SHA1_RSA_PKCS) {
		expected_sig_len = SIZE_OF_VEC(rsa_sig);
		sig_len = SIZE_OF_VEC(rsa_sig); /* Signature buffer length */
		sign_key = rsa_private_obj;
		verify_key = rsa_public_obj;
		mech_type = "CKM_SHA1_RSA_PKCS";

	} else if (mechanism->mechanism == CKM_SHA256_HMAC) {
		expected_sig_len = SIZE_OF_VEC(hmacsha256mac);
		sig_len = SIZE_OF_VEC(hmacsha256mac); /* Signature buffer length */
		sign_key = hmac_256_obj;
		verify_key = hmac_256_obj;
		mech_type = "CKM_SHA256_HMAC";

	} else if (mechanism->mechanism == CKM_SHA256_HMAC_GENERAL) {
		expected_sig_len = SIZE_OF_VEC(hmacsha256mac_trunc);
		sig_len = SIZE_OF_VEC(hmacsha256mac_trunc); /* Signature buffer length */
		sign_key = hmac_256_trunc_obj;
		verify_key = hmac_256_trunc_obj;
		mech_type = "CKM_SHA256_HMAC_GENERAL";
		mechanism->pParameter = &hmac_genera_param;
		*(CK_MAC_GENERAL_PARAMS *)mechanism->pParameter = SIZE_OF_VEC(hmacsha256mac_trunc);
		mechanism->ulParameterLen = sizeof(CK_MAC_GENERAL_PARAMS);

	} else {
		PRI_FAIL("Mechanism unknow");
		return;
	}


	/* This test will fail if rsa_sign_ver fails! */

	ret = func_list->C_SignInit(session, mechanism, sign_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Sign init: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	for (i = 0; i < update_loop_count; ++i) {

		ret = func_list->C_SignUpdate(session, (CK_BYTE_PTR)random_data, random_data_len);
		if (ret != CKR_OK) {
			PRI_FAIL("%s : signUpdate: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
			return;
		}
	}

	/* Get size */
	ret = func_list->C_SignFinal(session, NULL, &sig_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_SignFinal() getting size: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	if (expected_sig_len != sig_len) {
		PRI_FAIL("%s : Getting invalid sign output size", mech_type);
		return;
	}

	ret = func_list->C_SignFinal(session, (CK_BYTE_PTR)sig, &sig_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : signFinal: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	/* Signature done */
	if (expected_sig_len != sig_len) {
		PRI_FAIL("%s : Invalid size of signature: %lu", mech_type, sig_len);
		return;
	}

	/* Verify */

	ret = func_list->C_VerifyInit(session, mechanism, verify_key);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : Verify init: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
		return;
	}

	for (i = 0; i < update_loop_count; ++i) {

		ret = func_list->C_VerifyUpdate(session, (CK_BYTE_PTR)random_data, random_data_len);
		if (ret != CKR_OK) {
			PRI_FAIL("%s : VerifyUpdate: %lu : 0x%x", mech_type, ret, (uint32_t)ret);
			return;
		}
	}

	ret = func_list->C_VerifyFinal(session, (CK_BYTE_PTR)sig, sig_len);
	if (ret == CKR_OK) {
		PRI_OK("%s : Verified OK", mech_type);
	} else if (ret == CKR_SIGNATURE_INVALID) {
		PRI_FAIL("%s :Invalid signature", mech_type);
	} else {
		PRI_FAIL("%s : Verify : %lu : 0x%x", mech_type, ret, (uint32_t)ret);
	}
}

static void hash(CK_SESSION_HANDLE session,
		 CK_MECHANISM *mechanism)
{
	CK_BYTE_PTR msg, expected_hash;
	CK_ULONG hash_len = 0, msg_len = 0, expected_hash_len = 0, biggest_hash_len = 64; /*sha512*/
	char hash[biggest_hash_len]; /* Avoiding malloc. Reserving enough big buffer for all hash */
	char *mech_type;
	CK_RV ret;

	/* Signature bufffer */
	if (mechanism->mechanism == CKM_SHA256) {
		expected_hash = sha256hash;
		expected_hash_len = SIZE_OF_VEC(sha256hash);
		msg = sha256msg;
		msg_len = SIZE_OF_VEC(sha256msg);
		mech_type = "CKM_SHA256";

	} else {
		PRI_FAIL("Mechanism unknow");
		return;
	}

	ret = func_list->C_DigestInit(session, mechanism);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_DigestInit() %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	/* Getting the size */
	ret = func_list->C_Digest(session, NULL, 0, NULL, &hash_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_Digest() getting output size %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	if (hash_len != expected_hash_len) {
		PRI_FAIL("%s : Not expected hash output size", mech_type);
		return;
	}

	ret = func_list->C_Digest(session, msg, msg_len, (CK_BYTE_PTR)hash, &hash_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_Digest() %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	if (hash_len != expected_hash_len) {
		PRI_FAIL("%s : Hash length is invalid", mech_type);
		return;
	}

	if (memcmp(hash, expected_hash, expected_hash_len) != 0) {
		PRI_FAIL("%s : Not expected hash", mech_type);
	} else {
		PRI_OK("%s : OK", mech_type);
	}
}

static void hash_update(CK_SESSION_HANDLE session,
			CK_MECHANISM *mechanism)
{
	CK_ULONG i, update_loop_count = 2;
	CK_BYTE_PTR msg;
	CK_ULONG hash_len = 0, msg_len = 0, expected_hash_len = 0, biggest_hash_len = 64; /*sha512*/
	char hash[biggest_hash_len]; /* Avoiding malloc. Reserving enough big buffer for all hash */
	char *mech_type;
	CK_RV ret;

	/* Signature bufffer */
	if (mechanism->mechanism == CKM_SHA256) {
		expected_hash_len = SIZE_OF_VEC(sha256hash);
		msg = sha256msg;
		msg_len = SIZE_OF_VEC(sha256msg);
		mech_type = "CKM_SHA256";

	} else {
		PRI_FAIL("Mechanism unknow");
		return;
	}

	ret = func_list->C_DigestInit(session, mechanism);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_DigestInit() %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	for (i = 0; i < update_loop_count; ++i) {

		ret = func_list->C_DigestUpdate(session, msg, msg_len);
		if (ret != CKR_OK) {
			PRI_FAIL("%s : C_DigestUpdate() %lu : 0x%x", mech_type, ret, (uint32_t)ret)
			return;
		}
	}

	/* Getting the size */
	ret = func_list->C_DigestFinal(session, NULL, &hash_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_DigestFinal() getting output length %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	if (hash_len != expected_hash_len) {
		PRI_FAIL("%s : Not expected hash output size", mech_type);
		return;
	}

	ret = func_list->C_DigestFinal(session, (CK_CHAR_PTR)hash, &hash_len);
	if (ret != CKR_OK) {
		PRI_FAIL("%s : C_DigestFinal() %lu : 0x%x", mech_type, ret, (uint32_t)ret)
		return;
	}

	if (hash_len != expected_hash_len) {
		PRI_FAIL("%s : Hash length is invalid", mech_type);
	} else {
		PRI_OK("%s : OK", mech_type);
	}
}

static void get_attr_value(CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE allow_mech = CKM_AES_CBC;
	CK_UTF8CHAR label[] = { "New label" };
	uint32_t label_len = sizeof(label) - 1;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL ck_true = CK_TRUE;
	CK_RV ret;

	/* get_attr_aes_temp_obj object attrs */
	CK_ATTRIBUTE attrs[7] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, &aes_key, SIZE_OF_VEC(aes_key)},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)},
		{CKA_LABEL, label, label_len}
	};

	/* Get label size */
	CK_ATTRIBUTE get_label_size_template = {CKA_LABEL, NULL_PTR, 0};

	/* Get label */
	CK_UTF8CHAR obj_label[20] = {0};
	CK_ATTRIBUTE get_label_template = {CKA_LABEL, &obj_label, 20};

	/* Invalid size */
	CK_KEY_TYPE obj_keyType;
	CK_UTF8CHAR obj_short_label[2];
	CK_ATTRIBUTE get_label_too_small_template[2] = {
		{CKA_KEY_TYPE, &obj_keyType, sizeof(obj_keyType)},
		{CKA_LABEL, &obj_short_label, 2}
	};

	/* Invalid attribute */
	CK_ATTRIBUTE get_invalid_attr = {CKA_SIGN, NULL_PTR, 0};

	ret = func_list->C_CreateObject(session, attrs, 7, &get_attr_aes_temp_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create object: %lu : 0x%x", ret, (uint32_t)ret)
		return;
	}

	/* Get label size */
	ret = func_list->C_GetAttributeValue(session, get_attr_aes_temp_obj, &get_label_size_template, 1);
	if (ret != CKR_OK) {
		PRI_FAIL("failed to get label size %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (get_label_size_template.ulValueLen != label_len) {
		PRI_FAIL("Wrong label size");
		return;
	}

	/* Get label */
	ret = func_list->C_GetAttributeValue(session, get_attr_aes_temp_obj, &get_label_template, 1);
	if (ret != CKR_OK) {
		PRI_FAIL("failed to get label %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (get_label_template.ulValueLen != label_len) {
		PRI_FAIL("Get wrong label size");
		return;
	}

	if (memcmp(obj_label, label, get_label_template.ulValueLen)) {
		PRI_FAIL("Wrong label");
		return;
	}

	/* Invalid size */
	ret = func_list->C_GetAttributeValue(session, get_attr_aes_temp_obj, get_label_too_small_template, 2);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		PRI_FAIL("failed to get short label %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (*((CK_KEY_TYPE *)get_label_too_small_template[0].pValue) != keyType) {
		PRI_FAIL("Invalid key type");
		return;
	}

	if ((CK_LONG)get_label_too_small_template[1].ulValueLen != -1) {
		PRI_FAIL("Expected -1 label size");
		return;
	}

	/* Invalid attribute */
	ret = func_list->C_GetAttributeValue(session, get_attr_aes_temp_obj, &get_invalid_attr, 1);
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID) {
		PRI_FAIL("failed to get invalid attribute %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if ((CK_LONG)get_invalid_attr.ulValueLen == -1) {
		PRI_FAIL("Should not found");
		return;
	}

	PRI_OK("-")
}

static int is_key_in_vector(CK_OBJECT_HANDLE *hObject,
			CK_ULONG hObject_count,
			CK_OBJECT_HANDLE queried_id)
{
	CK_ULONG i;

	for (i = 0; i < hObject_count; ++i) {

		if (hObject[i] == queried_id)
			return 1;
	}

	return 0;
}

static int find_object(CK_SESSION_HANDLE session,
		       CK_OBJECT_HANDLE **hObject,
		       CK_ULONG *find_object_count,
		       CK_ATTRIBUTE *find_template,
		       CK_ULONG find_template_count)
{
	CK_OBJECT_HANDLE *found_objects, *realloc_found_objects;
	uint32_t i = 0, object_fetcs_count = 10,
			block_size = sizeof(CK_OBJECT_HANDLE) * object_fetcs_count;
	CK_ULONG ulObjectCount;
	CK_RV ret;

	*find_object_count = 0;

	found_objects = calloc(1, block_size);
	if (found_objects == NULL) {
		PRI_FAIL("Out of memory");
		return 1;
	}

	/* Init find operation */
	ret = func_list->C_FindObjectsInit(session, find_template, find_template_count);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init find object %lu : 0x%x", ret, (uint32_t)ret);
		free(found_objects);
		return 1;
	}

	while (1) {
		ret = func_list->C_FindObjects(session, found_objects + (i * block_size),
					       object_fetcs_count, &ulObjectCount);
		if (ret != CKR_OK) {
			PRI_FAIL("Failed to find objects %lu : 0x%x", ret, (uint32_t)ret);
			free(found_objects);
			return 1;
		}

		*find_object_count += ulObjectCount;

		if (ulObjectCount == block_size) {

			++i;
			realloc_found_objects = realloc(found_objects, i * block_size);
			if(realloc_found_objects == NULL) {
				PRI_FAIL("Out of memory");
				free(found_objects);
				return 1;
			}

			found_objects = realloc_found_objects;

		} else {
			break;
		}
	}

	ret = func_list->C_FindObjectsFinal(session);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to finalize objects find %lu : 0x%x", ret, (uint32_t)ret);
		free(found_objects);
		return 1;
	}

	if (*found_objects == 0) {
		free(found_objects);
		found_objects = NULL;
	}
	*hObject = found_objects;
	return 0;
}

static void find_objects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE *hObject;
	CK_ULONG ulObjectCount;

	/* Get AES key object */
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_ATTRIBUTE aes_object[2] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
	};

	/* find object that have two common attributes */
	CK_MECHANISM_TYPE allow_mech = CKM_SHA1_RSA_PKCS;
	CK_ATTRIBUTE allow_object[1] = {
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};

	/* find object that have does not exist */
	CK_BBOOL temp; /* Not neede */
	CK_ATTRIBUTE not_existing_attribute[1] = {
		{CKA_OTP_LENGTH, &temp, sizeof(temp)}
	};

	/* Find aes key: KEY TYPE, CKA_CLASS, CKA_ID */
	char *aes_id = "aes_id";
	CK_ATTRIBUTE aes_id_attr[3] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_ID, &aes_id, sizeof(aes_id)}
	};




	/* Find all objects
	 * Note: This test result are not checked, because it depends our SS stated */
	if (find_object(session, &hObject, &ulObjectCount, NULL_PTR, 0))
		return;
	else
		PRI_YES("Found %lu objects", ulObjectCount);

	/* What should found is at least to this session created AES object */
	if (!is_key_in_vector(hObject, ulObjectCount, get_attr_aes_temp_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, aes_secret_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, rsa_private_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, rsa_public_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, hmac_256_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, hmac_256_trunc_obj))
		PRI_FAIL("Did not find all session object of this session");

	free(hObject);


	/* Get AES key object */
	if (find_object(session, &hObject, &ulObjectCount, aes_object, 2))
		return;
	else
		PRI_YES("Found %lu AES key object", ulObjectCount)

	/* What should found is at least to this session created AES object */
	if (!is_key_in_vector(hObject, ulObjectCount, get_attr_aes_temp_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, aes_secret_obj))
		PRI_FAIL("Failed to find 2 aes key that this session generated");

	free(hObject);


	/* find object that have two common attributes */
	if (find_object(session, &hObject, &ulObjectCount, allow_object, 1))
		return;
	else
		PRI_YES("Found %lu CKM_SHA1_RSA_PKCS allowed object", ulObjectCount);

	/* What should found is at least to this session created AES object */
	if (!is_key_in_vector(hObject, ulObjectCount, rsa_private_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, rsa_public_obj))
		PRI_FAIL("Failed to find 2 CKM_SHA1_RSA_PKCS allowed keys");

	free(hObject);


	/* find object that have does not exist */
	if (find_object(session, &hObject, &ulObjectCount, not_existing_attribute, 1))
		return;

	if (ulObjectCount != 0)
		PRI_FAIL("Object with this attribute should not be found!!");


	/* Find aes key: KEY TYPE, CKA_CLASS, CKA_ID */
	if (find_object(session, &hObject, &ulObjectCount, aes_id_attr, 3))
		return;
	else
		PRI_YES("Found KEY TYPE, CKA_CLASS, CKA_ID %lu", ulObjectCount);

	/* What should found is at least to this session created AES object */
	if (!is_key_in_vector(hObject, ulObjectCount, aes_secret_obj))
		PRI_FAIL("Failed to find AES key by KEY TYPE, CKA_CLASS and CKA_ID");

	free(hObject);


	PRI_OK("Find object test complited (result need to verified manualy)!!");
}

static void aes_test_update(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism = {CKM_AES_CBC, aes_IV, SIZE_OF_VEC(aes_IV)};
	uint8_t update_call_count = 5, i;
	CK_ULONG out_block_size;
	CK_RV ret;

	/* Random data */
	CK_ULONG random_data_len = update_call_count * SIZE_OF_VEC(aes_key);
	uint8_t random_data[random_data_len];

	/* Cipher */
	uint8_t cipher[random_data_len];
	CK_ULONG total_cipher_len = 0;

	/* Decrypt stuff */
	uint8_t decrypted[random_data_len];
	CK_ULONG totol_decrypted_len = 0;

	get_random_data(random_data, random_data_len);

	ret = func_list->C_EncryptInit(session, &mechanism, aes_secret_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init encrypt: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	for (i = 0; i < update_call_count; ++i) {

		out_block_size = SIZE_OF_VEC(aes_key);
		ret = func_list->C_EncryptUpdate(session,
						 random_data + (i * SIZE_OF_VEC(aes_key)),
						 SIZE_OF_VEC(aes_key),
						 cipher + (i * SIZE_OF_VEC(aes_key)),
						 &out_block_size);
		if (ret != CKR_OK) {
			PRI_FAIL("Failed to init encryptUpdate: %lu : 0x%x", ret, (uint32_t)ret);
			return;
		}

		total_cipher_len += out_block_size;
	}

	ret = func_list->C_EncryptFinal(session, NULL, 0);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init encryptFinal: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (random_data_len != total_cipher_len) {
		PRI_FAIL("Invalid size after encrypt");
		return;
	}

	/* Enrypt done */

	ret = func_list->C_DecryptInit(session, &mechanism, aes_secret_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init Decrypt: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	for (i = 0; i < update_call_count; ++i) {

		out_block_size = SIZE_OF_VEC(aes_key);
		ret = func_list->C_DecryptUpdate(session,
						 cipher + (i * SIZE_OF_VEC(aes_key)),
						 SIZE_OF_VEC(aes_key),
						 decrypted + (i * SIZE_OF_VEC(aes_key)),
						 &out_block_size);
		if (ret != CKR_OK) {
			PRI_FAIL("Failed to init encryptUpdate: %lu : 0x%x", ret, (uint32_t)ret);
			return;
		}

		totol_decrypted_len += out_block_size;
	}

	ret = func_list->C_DecryptFinal(session, NULL, 0);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init encryptFinal: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (random_data_len != totol_decrypted_len) {
		PRI_FAIL("Invalid size after decrypt");
		return;
	}

	if (memcmp(random_data, decrypted, totol_decrypted_len) != 0) {
		PRI_FAIL("decryption failure");
		return;
	} else {
		PRI_OK("-");
	}
}

static void create_objects(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_CLASS obj_class_secret = CKO_SECRET_KEY,
			obj_class_private = CKO_PRIVATE_KEY, obj_class_public = CKO_PUBLIC_KEY;;
	CK_KEY_TYPE keyType_aes = CKK_AES, keyType_rsa = CKK_RSA,
			keyType_gen_secret = CKK_GENERIC_SECRET;;
	char *aes_id = "aes_id";
	CK_RV ret;
	CK_MECHANISM_TYPE hmac_allow_mech = CKM_SHA256_HMAC,
			hmac_allow_mech_general = CKM_SHA256_HMAC_GENERAL,
			rsa_allow_mech[2] = {CKM_SHA1_RSA_PKCS, CKM_RSA_PKCS},
			aes_allow_mech = CKM_AES_CBC;

	/* AES key */
	CK_ATTRIBUTE aes_attrs[7] = {
		{CKA_CLASS, &obj_class_secret, sizeof(obj_class_secret)},
		{CKA_KEY_TYPE, &keyType_aes, sizeof(keyType_aes)},
		{CKA_VALUE, &aes_key, SIZE_OF_VEC(aes_key)},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &aes_allow_mech, sizeof(aes_allow_mech)},
		{CKA_ID, &aes_id, sizeof(aes_id)}
	};

	/* RSA private key object */
	CK_ATTRIBUTE pri_attrs[8] = {
		{CKA_CLASS, &obj_class_private, sizeof(obj_class_private)},
		{CKA_KEY_TYPE, &keyType_rsa, sizeof(keyType_rsa)},
		{CKA_MODULUS, &modulus, SIZE_OF_VEC(modulus)},
		{CKA_PRIVATE_EXPONENT, &private_exp, SIZE_OF_VEC(private_exp)},
		{CKA_PUBLIC_EXPONENT, &public_exp, SIZE_OF_VEC(public_exp)},
		{CKA_SIGN, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &rsa_allow_mech, sizeof(rsa_allow_mech)}
	};

	/* RSA Public key object */
	CK_ATTRIBUTE pub_attrs[7] = {
		{CKA_CLASS, &obj_class_public, sizeof(obj_class_public)},
		{CKA_KEY_TYPE, &keyType_rsa, sizeof(keyType_rsa)},
		{CKA_MODULUS, &modulus, SIZE_OF_VEC(modulus)},
		{CKA_PUBLIC_EXPONENT, &public_exp, SIZE_OF_VEC(public_exp)},
		{CKA_VERIFY, &ck_true, sizeof(ck_true)},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &rsa_allow_mech, sizeof(rsa_allow_mech)}
	};

	/* HMACsha256 */
	CK_ATTRIBUTE hmac256[6] = {
		{CKA_CLASS, &obj_class_secret, sizeof(obj_class_secret)},
		{CKA_KEY_TYPE, &keyType_gen_secret, sizeof(keyType_gen_secret)},
		{CKA_VALUE, &hmacsha256key, SIZE_OF_VEC(hmacsha256key)},
		{CKA_SIGN, &ck_true, sizeof(ck_true)},
		{CKA_VERIFY, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &hmac_allow_mech, sizeof(hmac_allow_mech)}
	};

	/* HMACsha256_trunc */
	CK_ATTRIBUTE hmac256_trunc[6] = {
		{CKA_CLASS, &obj_class_secret, sizeof(obj_class_secret)},
		{CKA_KEY_TYPE, &keyType_gen_secret, sizeof(keyType_gen_secret)},
		{CKA_VALUE, &hmacsha256key_trunc, SIZE_OF_VEC(hmacsha256key_trunc)},
		{CKA_SIGN, &ck_true, sizeof(ck_true)},
		{CKA_VERIFY, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &hmac_allow_mech_general, sizeof(hmac_allow_mech_general)}
	};


	/* AES key */
	ret = func_list->C_CreateObject(session, aes_attrs, 7, &aes_secret_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create AES object: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	/* RSA private key object */
	ret = func_list->C_CreateObject(session, pri_attrs, 8, &rsa_private_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create RSA private object: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	/* Public object can be created without login */
	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to logout: 0x%x", (uint32_t)ret);
		return;
	}

	/* RSA Public key object */
	ret = func_list->C_CreateObject(session, pub_attrs, 7, &rsa_public_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create RSA public object: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	/* HMACsha256 */
	ret = func_list->C_CreateObject(session, hmac256, 6, &hmac_256_obj);
	if (ret == CKR_OK) {
		PRI_FAIL("Should fail, because session is not logged in");
		return;
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)user_pin, sizeof(user_pin));
	if (ret != CKR_OK) {
		PRI_ABORT("Failed to login: 0x%x", (uint32_t)ret);
		exit(1);
	}

	ret = func_list->C_CreateObject(session, hmac256, 6, &hmac_256_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create HMACsha256 object: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	/* HMACsha256_trunc */
	ret = func_list->C_CreateObject(session, hmac256_trunc, 6, &hmac_256_trunc_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to create HMACsha256_trunc object: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	PRI_OK("-")
}

static void general_key_attrs_test(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_bbool_sens = 0, ck_bbool_extr = 0, ck_bbool_local = 0;
	CK_RV ret;

	/* Make sure that ALWAYS SENSITIVE and extractable is true */
	CK_ATTRIBUTE always_attrs[3] = {
		{CKA_ALWAYS_SENSITIVE, &ck_bbool_sens, sizeof(CK_BBOOL)},
		{CKA_NEVER_EXTRACTABLE, &ck_bbool_extr, sizeof(CK_BBOOL)},
		{CKA_LOCAL, &ck_bbool_local, sizeof(CK_BBOOL)},
	};

	ret = func_list->C_GetAttributeValue(session, aes_secret_obj, always_attrs, 3);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to get always/never attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if ((CK_LONG)always_attrs[0].ulValueLen == -1 || ck_bbool_sens != CK_TRUE) {
		PRI_FAIL("aes key is always been sensitive");
		return;
	}

	if ((CK_LONG)always_attrs[1].ulValueLen == -1 ||ck_bbool_extr != CK_TRUE) {
		PRI_FAIL("aes key is nver been extractable");
		return;
	}

	if ((CK_LONG)always_attrs[2].ulValueLen == -1 ||ck_bbool_local != CK_FALSE) {
		PRI_FAIL("aes key is not generated by TEE");
		return;
	}

	PRI_OK("-");
}

static void set_obj_attr(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_bbool_always_sens = 0, ck_bbool_never_extr = 0, ck_bbool_local = 0,
			ck_bbool_sens = 0, ck_bbool_extr = 0, ck_bool_enc = 0,
			ck_bbool_dec = 0, ck_true = CK_TRUE, ck_false = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_DES;
	CK_RV ret;

	/* Setting AES global key: Setting new attributes */
	CK_ATTRIBUTE set_attrs[2] = {
		{CKA_SENSITIVE, &ck_false, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &ck_false, sizeof(CK_BBOOL)}
	};

	/* Modify existing */
	CK_ATTRIBUTE mod_attrs[2] = {
		{CKA_ENCRYPT, &ck_false, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ck_false, sizeof(CK_BBOOL)}
	};

	/* Trying to set illegal attr */
	CK_ATTRIBUTE ill_attrs[2] = {
		{CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)}
	};

	/*  Confirm result: Make sure that ALWAYS SENSITIVE and extractable is true */
	CK_ATTRIBUTE confirm_attrs[8] = {
		{CKA_ALWAYS_SENSITIVE, &ck_bbool_always_sens, sizeof(CK_BBOOL)},
		{CKA_NEVER_EXTRACTABLE, &ck_bbool_never_extr, sizeof(CK_BBOOL)},
		{CKA_LOCAL, &ck_bbool_local, sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, &ck_bbool_sens, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &ck_bbool_extr, sizeof(CK_BBOOL)},
		{CKA_ENCRYPT, &ck_bool_enc, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ck_bbool_dec, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
	};



	/* Setting AES global key */
	ret = func_list->C_SetAttributeValue(session, aes_secret_obj, set_attrs, 2);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to set new attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	/* Modify existing */
	ret = func_list->C_SetAttributeValue(session, aes_secret_obj, mod_attrs, 2);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to modify existing attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	/* Trying to set illegal attr */
	ret = func_list->C_SetAttributeValue(session, aes_secret_obj, ill_attrs, 2);
	if (ret == CKR_OK) {
		PRI_FAIL("Failed this call should have fail %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	/*  Confirm result: Make sure that ALWAYS SENSITIVE and extractable is true */
	ret = func_list->C_GetAttributeValue(session, aes_secret_obj, confirm_attrs, 8);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to get confirm attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	if ((CK_LONG)confirm_attrs[0].ulValueLen == -1 || ck_bbool_always_sens != CK_FALSE) {
		PRI_FAIL("aes key is NOT always been sensitive");
		return;
	}

	if ((CK_LONG)confirm_attrs[1].ulValueLen == -1 || ck_bbool_never_extr != CK_FALSE) {
		PRI_FAIL("aes key is HAS been extractable");
		return;
	}

	if ((CK_LONG)confirm_attrs[2].ulValueLen == -1 || ck_bbool_local != CK_FALSE) {
		PRI_FAIL("aes key is not generated by TEE");
		return;
	}

	if ((CK_LONG)confirm_attrs[3].ulValueLen == -1 || ck_bbool_sens != CK_FALSE) {
		PRI_FAIL("aes key is NOT sensitive");
		return;
	}

	if ((CK_LONG)confirm_attrs[4].ulValueLen == -1 || ck_bbool_extr != CK_FALSE) {
		PRI_FAIL("aes key IS extractable");
		return;
	}

	if ((CK_LONG)confirm_attrs[5].ulValueLen == -1 || ck_bool_enc != CK_FALSE) {
		PRI_FAIL("aes key can't use with encrypt");
		return;
	}

	if ((CK_LONG)confirm_attrs[6].ulValueLen == -1 || ck_bbool_dec != CK_FALSE) {
		PRI_FAIL("aes key can't use with decrypt");
		return;
	}

	if ((CK_LONG)confirm_attrs[7].ulValueLen == -1 || keyType != CKK_AES) {
		PRI_FAIL("Not aes key??");
		return;
	}

	PRI_OK("-");
}

static void set_obj_attr_seccond(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_bbool_always_sens = 0, ck_bbool_never_extr = 0,
			ck_bbool_sens = 0, ck_bbool_extr = 0,
			ck_true = CK_TRUE, ck_false = CK_FALSE;
	CK_RV ret;

	/* Setting AES global key. Point of this test is to set
	 * sensitive/extractable attrs and check if they works */

	/* Setting new attributes */
	CK_ATTRIBUTE set_attrs[2] = {
		{CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &ck_false, sizeof(CK_BBOOL)}
	};

	/*  */


	/* Confirm result: Make sure that ALWAYS SENSITIVE and extractable is true */
	CK_ATTRIBUTE confirm_attrs[8] = {
		{CKA_ALWAYS_SENSITIVE, &ck_bbool_always_sens, sizeof(CK_BBOOL)},
		{CKA_NEVER_EXTRACTABLE, &ck_bbool_never_extr, sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, &ck_bbool_sens, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &ck_bbool_extr, sizeof(CK_BBOOL)},
	};

	ret = func_list->C_SetAttributeValue(session, aes_secret_obj, set_attrs, 2);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to set new attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	/* Confirm result: Make sure that ALWAYS SENSITIVE and extractable is true */
	ret = func_list->C_GetAttributeValue(session, aes_secret_obj, confirm_attrs, 8);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to get confirm attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}


	if ((CK_LONG)confirm_attrs[0].ulValueLen == -1 || ck_bbool_always_sens != CK_FALSE) {
		PRI_FAIL("aes key is NOT always been sensitive");
		return;
	}

	if ((CK_LONG)confirm_attrs[1].ulValueLen == -1 || ck_bbool_never_extr != CK_FALSE) {
		PRI_FAIL("aes key is HAS been extractable");
		return;
	}

	if ((CK_LONG)confirm_attrs[3].ulValueLen == -1 || ck_bbool_sens != CK_TRUE) {
		PRI_FAIL("aes key is sensitive");
		return;
	}

	if ((CK_LONG)confirm_attrs[4].ulValueLen == -1 || ck_bbool_extr != CK_FALSE) {
		PRI_FAIL("aes key IS extractable");
		return;
	}

	PRI_OK("-");
}

static void crypto_using_not_allowed_key(CK_SESSION_HANDLE session)
{
	/* After set function, aes is not allowed to use encrypt/decrypt */
	CK_MECHANISM mechanism = {CKM_AES_CBC, aes_IV, SIZE_OF_VEC(aes_IV)};
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_RV ret;

	/* Set key allow to enc/dec: Modify existing */
	CK_ATTRIBUTE mod_attrs[2] = {
		{CKA_ENCRYPT, &ck_true, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ck_false, sizeof(CK_BBOOL)}
	};

	ret = func_list->C_EncryptInit(session, &mechanism, aes_secret_obj);
	if (ret == CKR_OK) {
		PRI_FAIL("Key should not be able to use for encrypt");
		return;
	}

	/* Set key allow to enc/dec: Modify existing */
	ret = func_list->C_SetAttributeValue(session, aes_secret_obj, mod_attrs, 2);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to modify existing attrs %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_EncryptInit(session, &mechanism, aes_secret_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init encrypt: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_EncryptFinal(session, NULL, 0);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to init encryptFinal: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	/* DEcryption should not be still allowed */
	ret = func_list->C_DecryptInit(session, &mechanism, aes_secret_obj);
	if (ret == CKR_OK) {
		PRI_FAIL("Key should not be able to use for encrypt");
		return;
	}

	/* Logout and use RSA keys */
	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to logout: 0x%x", (uint32_t)ret);
		return;
	}

	mechanism.mechanism = CKM_SHA1_RSA_PKCS;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	ret = func_list->C_SignInit(session, &mechanism, rsa_private_obj);
	if (ret == CKR_OK) {
		PRI_FAIL("Private should not be availible if session logget out!");
		return;
	}

	ret = func_list->C_VerifyInit(session, &mechanism, rsa_public_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("VerifyInit: %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_VerifyFinal(session, NULL, 0);
	if (ret == CKR_OK) {
		PRI_FAIL("VerifyFinal: Should fail : %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)user_pin, sizeof(user_pin));
	if (ret != CKR_OK) {
		PRI_ABORT("Failed to login: 0x%x", (uint32_t)ret);
		exit(1);
	}

	PRI_OK("-");
}

static void sign_and_verify_tests(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism = {0, NULL_PTR, 0}; /* Default vals */

	/* RSA sign verify in on go */
	mechanism.mechanism = CKM_SHA1_RSA_PKCS;
	sign_and_verify(session, &mechanism);
	sign_and_verify_with_update(session, &mechanism);

	/* HMACSHA256 sign verify in on go */
	mechanism.mechanism = CKM_SHA256_HMAC;
	sign_and_verify(session, &mechanism);
	sign_and_verify_with_update(session, &mechanism);

	/* HMACSHA256 (trunc) sign verify in on go */
	mechanism.mechanism = CKM_SHA256_HMAC_GENERAL;
	sign_and_verify(session, &mechanism);
	sign_and_verify_with_update(session, &mechanism);
}

static void destroy_objects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE *hObject;
	CK_ULONG ulObjectCount;
	CK_RV ret;

	/* Remove two hmac keys and rest will be destroyed when session closed */

	ret = func_list->C_DestroyObject(session, hmac_256_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to remove hmac256 key");
		return;
	}

	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to logout: 0x%x", (uint32_t)ret);
		return;
	}

	ret = func_list->C_DestroyObject(session, hmac_256_trunc_obj);
	if (ret == CKR_OK) {
		PRI_FAIL("Should fail because session is not logged in");
		return;
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)user_pin, sizeof(user_pin));
	if (ret != CKR_OK) {
		PRI_ABORT("Failed to login: 0x%x", (uint32_t)ret);
		exit(1);
	}

	ret = func_list->C_DestroyObject(session, hmac_256_trunc_obj);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to remove hmac256_trunc key: 0x%x", (uint32_t)ret);
		return;
	}

	/* Verify that only hmac keys are destroyed */
	/* Find all objects
	 * Note: This test result are not checked, because it depends our SS stated */
	if (find_object(session, &hObject, &ulObjectCount, NULL_PTR, 0))
		return;
	else
		PRI_YES("Found %lu objects after destroy", ulObjectCount);

	/* What should found is at least to this session created AES object */
	if (!is_key_in_vector(hObject, ulObjectCount, get_attr_aes_temp_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, aes_secret_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, rsa_private_obj) ||
	    !is_key_in_vector(hObject, ulObjectCount, rsa_public_obj)) {
		PRI_FAIL("Did not find all session object of this session");
	} else {
		PRI_OK("-");
	}
}

static void encrypt_decrypt_tests(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism = {0, NULL_PTR, 0}; /* Default vals */

	/* AES */
	mechanism.mechanism = CKM_AES_CBC;
	mechanism.pParameter = aes_IV;
	mechanism.ulParameterLen = SIZE_OF_VEC(aes_IV);
	encrypt_and_decrypt(session, &mechanism);
	aes_test_update(session);

	/* RSA */
	mechanism.mechanism = CKM_RSA_PKCS;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	encrypt_and_decrypt(session, &mechanism);
}

static void token_object(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_bool = 0;
	CK_ATTRIBUTE get_cka_token = {CKA_TOKEN, &ck_bool, sizeof(CK_BBOOL)};
	CK_RV ret;

	/* All session created object are session object. Lets test one */

	ret = func_list->C_GetAttributeValue(session, aes_secret_obj, &get_cka_token, 1);
	if (ret != CKR_OK) {
		PRI_FAIL("Failed to get CKA_TOKEN value %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (*(CK_BBOOL *)get_cka_token.pValue != CK_FALSE) {
		PRI_FAIL("AES object should be by default as a session object");
		return;
	}

	PRI_OK("-");
}

static void hash_tests(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism = {0, NULL_PTR, 0}; /* Default vals */

	/* sha256 */
	mechanism.mechanism = CKM_SHA256;
	hash(session, &mechanism);
	hash_update(session, &mechanism);
}

static int initialize_token(CK_SLOT_ID slot_id)
{
	CK_SESSION_HANDLE session;
	CK_TOKEN_INFO token_info;
	CK_RV ret;
	char password[8] = "12345678";
	char label[] = "TEE_TOKEN1";

	memset(&token_info, 0, sizeof(token_info));

	ret = func_list->C_GetTokenInfo(slot_id, &token_info);
	if (ret != CKR_OK) {
		PRI("Failed to read the token info: %ld\n", ret);
		return -1;
	}

	/* see if we have a label assigned to the token, if so then no need to initialize it */
	if (token_info.label[0] != ' ' && token_info.label[0] != '\0')
		return 0;

	printf("Initializing TOKEN:\n");

	ret = func_list->C_InitToken(slot_id, (CK_BYTE_PTR)password,
				     sizeof(password), (CK_BYTE_PTR)label);
	if (ret != CKR_OK) {
		PRI("Failed to initialize the token");
		return -1;
	}

	/* Next open a session and login as the SO user, to set the normal user passowrd */
	ret = func_list->C_OpenSession(slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION,
				       NULL, NULL, &session);
	if (ret != CKR_OK) {
		PRI("Failed to Open session the library: 0x%x", (uint32_t)ret);
		return -1;
	}

	ret = func_list->C_Login(session, CKU_SO, (CK_BYTE_PTR)password, sizeof(password));
	if (ret != CKR_OK) {
		PRI("Failed to login as SO: 0x%x", (uint32_t)ret);
		goto err1;
	}

	ret = func_list->C_InitPIN(session, (CK_BYTE_PTR)user_pin, sizeof(user_pin));
	if (ret != CKR_OK) {
		PRI("Failed to initialize the user's pin: 0x%x", (uint32_t)ret);
		goto err2;
	}

err2:
	func_list->C_Logout(session);
err1:
	func_list->C_CloseSession(slot_id);

	if (ret == CKR_OK)
		printf("TOKEN initialized : OK!!\n");
	else
		printf("Failed to Initialize TOKEN\n");

	return ret;
}

int main()
{
	CK_SESSION_HANDLE session;
	CK_INFO info;
	CK_RV ret;
	CK_SLOT_ID available_slots[1];
	CK_ULONG num_slots = 1;

	printf("\nSTART: pkcs11 test app\n");

	printf("Initializing:\n");

	ret = C_GetFunctionList(&func_list);
	if (ret != CKR_OK || func_list == NULL) {
		PRI("Failed to get function list: %ld", ret);
		return 0;
	}

	ret = func_list->C_Initialize(NULL);
	if (ret != CKR_OK) {
		PRI("Failed to initialize the library: %ld", ret);
		return 0;
	}

	ret = C_GetInfo(&info);
	if (ret != CKR_OK) {
		PRI("Failed to get the library info: %ld", ret);
		return 0;
	}

	//PRI("Version : Major %d: Minor %d",
	       //info.cryptokiVersion.major, info.cryptokiVersion.minor);

	ret = func_list->C_GetSlotList(1, available_slots, &num_slots);
	if (ret != CKR_OK) {
		PRI("Failed to get the available slots: %ld", ret);
		return 0;
	}

	ret = initialize_token(available_slots[0]);
	if (ret != CKR_OK)
		return 0;

	ret = func_list->C_OpenSession(available_slots[0], CKF_RW_SESSION | CKF_SERIAL_SESSION,
				       NULL, NULL, &session);
	if (ret != CKR_OK) {
		PRI("Failed to Open session the library: 0x%x", (uint32_t)ret);
		return 0;
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)user_pin, sizeof(user_pin));
	if (ret != CKR_OK) {
		PRI("Failed to login: 0x%x", (uint32_t)ret);
		return 0;
	}

	printf("Ok\n");

	printf("----Begin-with-test-cases----\n");

	/* Basic smoke tests */
	create_objects(session);
	encrypt_decrypt_tests(session);
	sign_and_verify_tests(session);
	hash_tests(session);
	get_attr_value(session);
	find_objects(session);
	general_key_attrs_test(session);
	set_obj_attr(session);
	set_obj_attr_seccond(session);
	crypto_using_not_allowed_key(session);
	token_object(session);
	destroy_objects(session); /* Run this test as a last one */

	printf("----Test-has-reached-end----\n");

	printf("Closing up: ");

	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		PRI("Failed to logout: 0x%x", (uint32_t)ret);
		return 0;
	}

	func_list->C_CloseSession(session);

	ret = func_list->C_Finalize(NULL);
	if (ret != CKR_OK) {
		PRI("Failed to Finalize the library: %ld", ret);
		return 0;
	}

	printf("Ok\n");

	printf("END: pkcs11 test app\n\n");

	return 0;
}
