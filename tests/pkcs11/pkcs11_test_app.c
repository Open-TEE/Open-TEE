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

static void aes_test(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE hKey = 0;
	CK_MECHANISM_TYPE allow_mech = CKM_AES_CBC;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_RV ret;

	/* Nist vector */
	char key_hex[] = "1f8e4973953f3fb0bd6b16662e9a3c17";
	char IV_hex[] = "2fe2b333ceda8f98f4a99b40d2cd34a8";
	char plain_hex[] = "45cf12964fc824ab76616ae2f4bf0822";
	char know_result_hex[] = "0f61c4d44c5147c03c195ad7e2cc12b2";
	CK_ULONG i, key_len = 16, plain_len = key_len, iv_len = key_len,
			cipher_len = key_len, know_result_len = key_len ;
	char key[plain_len], plain[plain_len], IV[iv_len],
			cipher[cipher_len], know_result[know_result_len];
	char *i_key_hex = key_hex, *i_plain_hex = plain_hex,
			*i_iv_hex = IV_hex, *i_know_result_hex = know_result_hex;

	for(i = 0; i < key_len; i++) {
		sscanf(i_key_hex, "%2hhx", &key[i]);
		sscanf(i_plain_hex, "%2hhx", &plain[i]);
		sscanf(i_iv_hex, "%2hhx", &IV[i]);
		sscanf(i_know_result_hex, "%2hhx", &know_result[i]);
		i_key_hex += 2 * sizeof(char);
		i_plain_hex += 2 * sizeof(char);
		i_iv_hex += 2 * sizeof(char);
		i_know_result_hex += 2 * sizeof(char);
	}

	char decrypted[plain_len];
	CK_ULONG decrypted_len = plain_len;

	CK_MECHANISM mechanism = {CKM_AES_CBC, IV, iv_len};

	uint32_t attr_count = 6;
	CK_ATTRIBUTE attrs[6] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, &key, key_len},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};


	ret = func_list->C_CreateObject(session, attrs, attr_count, &hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to create object: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_EncryptInit(session, &mechanism, hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to init encrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_Encrypt(session, (CK_BYTE_PTR)plain, plain_len,
				   (CK_BYTE_PTR)cipher, &cipher_len);
	if (ret != CKR_OK) {
		printf("AES: Failed to encrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	if (decrypted_len != plain_len) {
		printf("AES: Invalid size after encryption\n");
		exit(4);
	}

	if (memcmp(know_result, cipher, cipher_len) != 0) {
		printf("AES: Not expexted encryption result\n");
		exit(4);
	}

	ret = func_list->C_DecryptInit(session, &mechanism, hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to init Decrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_Decrypt(session, (CK_BYTE_PTR)cipher, cipher_len,
				   (CK_BYTE_PTR)decrypted, &decrypted_len);
	if (ret != CKR_OK) {
		printf("AES: Failed to Decrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	if (decrypted_len != plain_len) {
		printf("AES: Invalid size after decrypt\n");
		exit(4);
	}

	if (memcmp(decrypted, plain, decrypted_len) != 0) {
		printf("AES: decryption failure\n");
		exit(4);
	}
}

static void rsa_keygen(CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY, pri_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_OBJECT_HANDLE hKey = 0;
	uint32_t attr_count, i;
	CK_RV ret;

	uint32_t key_size = 128; /* 1024bit */
	char mod_hex[] = "a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802aafbadbf25"
			 "64dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080ede679f50b3de32cf4"
			 "026e514542495c54b1903768791aae9e36f082cd38e941ada89baecada61ab0dd37ad536b"
			 "cb0a0946271594836e92ab5517301d45176b5";
	char pub_e_hex[] = "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "0000000000000000000000000000000000000010001";
	char pri_e_hex[] = "1c23c1cce034ba598f8fd2b7af37f1d30b090f7362aee68e5187adae49b9955c729f24a"
			   "863b7a38d6e3c748e2972f6d940b7ba89043a2d6c2100256a1cf0f56a8cd35fc6ee2052"
			   "44876642f6f9c3820a3d9d2c8921df7d82aaadcaf2d7334d398931ddbba553190b3a416"
			   "099f3aa07fd5b26214645a828419e122cfb857ad73b";
	char mod[key_size], pub_e[key_size], pri_e[key_size];
	char *i_mod_hex = mod_hex, *i_pub_e_hex = pub_e_hex, *i_pri_e_hex = pri_e_hex;

	for(i = 0; i < key_size; i++) {
		sscanf(i_mod_hex, "%2hhx", &mod[i]);
		sscanf(i_pub_e_hex, "%2hhx", &pub_e[i]);
		sscanf(i_pri_e_hex, "%2hhx", &pri_e[i]);
		i_mod_hex += 2 * sizeof(char);
		i_pub_e_hex += 2 * sizeof(char);
		i_pri_e_hex += 2 * sizeof(char);
	}

	/* Private key */
	attr_count = 4;
	CK_ATTRIBUTE pri_attrs[4] = {
		{CKA_CLASS, &pri_class, sizeof(pri_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_MODULUS, &mod, key_size},
		{CKA_PRIVATE_EXPONENT, &pri_e, key_size}
	};

	ret = func_list->C_CreateObject(session, pri_attrs, attr_count, &hKey);
	if (ret != CKR_OK) {
		printf("rsa_keygen: Failed to create RSA "
		       "private object: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	/* Pub key */
	attr_count = 4;
	CK_ATTRIBUTE pub_attrs[4] = {
		{CKA_CLASS, &pub_class, sizeof(pub_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_MODULUS, &mod, key_size},
		{CKA_PUBLIC_EXPONENT, &pub_e, key_size}
	};

	ret = func_list->C_CreateObject(session, pub_attrs, attr_count, &hKey);
	if (ret != CKR_OK) {
		printf("rsa_keygen :Failed to create RSA "
		       "public object: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}
}

static void rsa_sign_ver(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_true = CK_TRUE;
        CK_OBJECT_CLASS pri_class = CKO_PRIVATE_KEY, pub_class = CKO_PUBLIC_KEY;
	CK_MECHANISM_TYPE allow_mech = CKM_SHA1_RSA_PKCS;
	CK_KEY_TYPE keyType = CKK_RSA;
        CK_OBJECT_HANDLE pri_Key = 0, pub_Key = 0;
	uint32_t attr_count, i;
	CK_RV ret;
	CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};

	uint32_t key_size = 128, msg_len = key_size, know_result_len = key_size; /* 1024bit */
	char mod_hex[] = "a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802aafbadbf25"
			 "64dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080ede679f50b3de32cf4"
			 "026e514542495c54b1903768791aae9e36f082cd38e941ada89baecada61ab0dd37ad536b"
			 "cb0a0946271594836e92ab5517301d45176b5";
	char pub_e_hex[] = "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "00000000000000000000000000000000000000000000000000000000000000000000000"
			   "0000000000000000000000000000000000000000003";
	char pri_e_hex[] = "1c23c1cce034ba598f8fd2b7af37f1d30b090f7362aee68e5187adae49b9955c729f24a"
			   "863b7a38d6e3c748e2972f6d940b7ba89043a2d6c2100256a1cf0f56a8cd35fc6ee2052"
			   "44876642f6f9c3820a3d9d2c8921df7d82aaadcaf2d7334d398931ddbba553190b3a416"
			   "099f3aa07fd5b26214645a828419e122cfb857ad73b";
        char mod[key_size], pri_e[key_size], pub_e[key_size];
        char *i_mod_hex = mod_hex, *i_pri_e_hex = pri_e_hex, *i_pub_hex = pub_e_hex;
	for(i = 0; i < key_size; i++) {
		sscanf(i_mod_hex, "%2hhx", &mod[i]);
		sscanf(i_pri_e_hex, "%2hhx", &pri_e[i]);
                sscanf(i_pub_hex, "%2hhx", &pub_e[i]);
		i_mod_hex += 2 * sizeof(char);
		i_pri_e_hex += 2 * sizeof(char);
                i_pub_hex += 2 * sizeof(char);
	}

	/* Message: SHA1 */
	char msg_hex[] = "d73829497cddbe41b705faac50e7899fdb5a38bf3a459e536357029e64f8796ba47f4fe96"
			 "ba5a8b9a4396746e2164f55a25368ddd0b9a5188c7ac3da2d1f742286c3bdee697f9d546a"
			 "25efcfe53191d743fcc6b47833d993d08804daeca78fb9076c3c017f53e33a90305af0622"
			 "0974d46bf19ed3c9b84edbae98b45a8771258";
	char msg[msg_len];
	char *i_msg_hex = msg_hex;
	for(i = 0; i < msg_len; i++) {
		sscanf(i_msg_hex, "%2hhx", &msg[i]);
		i_msg_hex += 2 * sizeof(char);
	}

	/* Know result */
	char know_result_hex[] = "175015bda50abe0fa7d39a8353885ca01be3a7e7fcc55045744111362ee191447"
				 "3a48dc537d956294b9e20a1ef661d58537acdc8de908fa050630fcc272e6d0010"
				 "45e6fdeed2d10531c8603334c2e8db39e73e6d9665ee1343f9e4198302d2201b4"
				 "4e8e8d06b3ef49cee6197582163a8490089ca654c0012fce1ba6511089750";
	char know_result[know_result_len];
	char *i_know_result_hex = know_result_hex;
	for(i = 0; i < know_result_len; i++) {
		sscanf(i_know_result_hex, "%2hhx", &know_result[i]);
		i_know_result_hex += 2 * sizeof(char);
	}

	/* Signature bufffer */
	char sig[key_size];
	CK_ULONG sig_len = key_size;

        /* Create private key object */
	attr_count = 7;
	CK_ATTRIBUTE pri_attrs[7] = {
		{CKA_CLASS, &pri_class, sizeof(pri_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_MODULUS, &mod, key_size},
		{CKA_PRIVATE_EXPONENT, &pri_e, key_size},
		{CKA_PUBLIC_EXPONENT, &pub_e, key_size},
		{CKA_SIGN, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};

        ret = func_list->C_CreateObject(session, pri_attrs, attr_count, &pri_Key);
	if (ret != CKR_OK) {
		printf("Failed to create RSA private object: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

        /* Create Public key object */
	attr_count = 6;
	CK_ATTRIBUTE pub_attrs[6] = {
                {CKA_CLASS, &pub_class, sizeof(pri_class)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_MODULUS, &mod, key_size},
                {CKA_PUBLIC_EXPONENT, &pub_e, key_size},
                {CKA_VERIFY, &ck_true, sizeof(ck_true)},
                {CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
        };

        ret = func_list->C_CreateObject(session, pub_attrs, attr_count, &pub_Key);
        if (ret != CKR_OK) {
                printf("Failed to create RSA public object: %lu : 0x%x\n", ret, (uint32_t)ret);
                exit(4);
        }

        ret = func_list->C_SignInit(session, &mechanism, pri_Key);
	if (ret != CKR_OK) {
		printf("Failed to signature init: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_Sign(session, (CK_BYTE_PTR)msg, msg_len, (CK_BYTE_PTR)sig, &sig_len);
	if (ret != CKR_OK) {
		printf("Failed to sign: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	if (know_result_len != sig_len) {
		printf("RSA: Invalid size after signature : %lu\n", sig_len);
		exit(4);
	}

	if (memcmp(know_result, sig, sig_len) != 0) {

		printf("RSA: Not expected signature\n");
		exit(4);
	} else {
		printf("RSA: Signature OK\n");
	}

	ret = func_list->C_VerifyInit(session, &mechanism, pub_Key);
	if (ret != CKR_OK) {
		printf("Failed to verify init: %lu : 0x%x\n", ret, (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_Verify(session, (CK_BYTE_PTR)msg, msg_len, (CK_BYTE_PTR)sig, sig_len);
	if (ret == CKR_OK) {
		printf("RSA: Verified\n");
	} else if (ret == CKR_SIGNATURE_INVALID) {
		printf("RSA: Invalid signature\n");
	} else {
		printf("RSA: Failed to verify: %lu : 0x%x\n", ret, (uint32_t)ret);
	}
}

int main()
{
	CK_SESSION_HANDLE session;
	CK_INFO info;
	CK_RV ret;
	char pin[4] = "1234";

	ret = C_GetFunctionList(&func_list);
	if (ret != CKR_OK || func_list == NULL) {
		printf("Failed to get function list: %lu\n", ret);
		exit(1);
	}

	ret = func_list->C_Initialize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to initialize the library: %lu\n", ret);
		exit(2);
	}

	ret = C_GetInfo(&info);
	if (ret != CKR_OK) {
		printf("Failed to get the library info: %lu\n", ret);
		exit(3);
	}

	printf("Version : Major %d: Minor %d\n",
	       info.cryptokiVersion.major, info.cryptokiVersion.minor);

	ret = func_list->C_OpenSession(1, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	if (ret != CKR_OK) {
		printf("Failed to Open session the library: 0x%x\n", (uint32_t)ret);
		exit(4);
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, 4);
	if (ret != CKR_OK) {
		printf("Failed to login: 0x%x\n", (uint32_t)ret);
		exit(4);
	}

	aes_test(session);
	rsa_keygen(session);
	rsa_sign_ver(session);

	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		printf("Failed to logout: 0x%x\n", (uint32_t)ret);
		exit(4);
	}

	func_list->C_CloseSession(session);

	ret = func_list->C_Finalize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to Finalize the library: %lu\n", ret);
		exit(4);
	}

	return 0;
}
