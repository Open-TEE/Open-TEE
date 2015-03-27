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

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

/* RSA */
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


/* AES */
uint8_t aes_key[] = "\x1f\x8e\x49\x73\x95\x3f\x3f\xb0\xbd\x6b\x16\x66\x2e\x9a\x3c\x17";
uint8_t aes_IV[] = "\x2f\xe2\xb3\x33\xce\xda\x8f\x98\xf4\xa9\x9b\x40\xd2\xcd\x34\xa8";
uint8_t aes_msg[] = "\x45\xcf\x12\x96\x4f\xc8\x24\xab\x76\x61\x6a\xe2\xf4\xbf\x08\x22";
uint8_t aes_cipher[] = "\x0f\x61\xc4\xd4\x4c\x51\x47\xc0\x3c\x19\x5a\xd7\xe2\xcc\x12\xb2";

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

#define PRI(str, ...) printf("%s : " str "\n",  __func__, ##__VA_ARGS__);

static void aes_test(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism = {CKM_AES_CBC, aes_IV, SIZE_OF_VEC(aes_IV)};
	CK_BBOOL ck_true = CK_TRUE;
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE hKey = 0;
	CK_MECHANISM_TYPE allow_mech = CKM_AES_CBC;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_RV ret;
	char cipher[SIZE_OF_VEC(aes_cipher)];
	CK_ULONG cipher_len = SIZE_OF_VEC(aes_cipher);
	char decrypted[SIZE_OF_VEC(aes_msg)];
	CK_ULONG decrypted_len = SIZE_OF_VEC(aes_msg);

	CK_ATTRIBUTE attrs[6] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, &aes_key, SIZE_OF_VEC(aes_key)},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};

	ret = func_list->C_CreateObject(session, attrs, 6, &hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to create object: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_EncryptInit(session, &mechanism, hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to init encrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Encrypt(session, (CK_BYTE_PTR)aes_msg, SIZE_OF_VEC(aes_msg),
				   (CK_BYTE_PTR)cipher, &cipher_len);
	if (ret != CKR_OK) {
		printf("AES: Failed to encrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	if (cipher_len != SIZE_OF_VEC(aes_key)) {
		printf("AES: Invalid size after encryption\n");
		return;
	}

	if (memcmp(aes_cipher, cipher, cipher_len) != 0) {
		printf("AES: Not expexted encryption result\n");
		return;
	}

	ret = func_list->C_DecryptInit(session, &mechanism, hKey);
	if (ret != CKR_OK) {
		printf("AES: Failed to init Decrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Decrypt(session, (CK_BYTE_PTR)cipher, cipher_len,
				   (CK_BYTE_PTR)decrypted, &decrypted_len);
	if (ret != CKR_OK) {
		printf("AES: Failed to Decrypt: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	if (decrypted_len != SIZE_OF_VEC(aes_msg)) {
		printf("AES: Invalid size after decrypt\n");
		return;
	}

	if (memcmp(aes_msg, decrypted, decrypted_len) != 0) {
		printf("AES: decryption failure\n");
		return;
	}
}

static void rsa_sign_ver(CK_SESSION_HANDLE session)
{
	CK_BBOOL ck_true = CK_TRUE;
        CK_OBJECT_CLASS pri_class = CKO_PRIVATE_KEY, pub_class = CKO_PUBLIC_KEY;
	CK_MECHANISM_TYPE allow_mech = CKM_SHA1_RSA_PKCS;
	CK_KEY_TYPE keyType = CKK_RSA;
        CK_OBJECT_HANDLE pri_Key = 0, pub_Key = 0;
	CK_RV ret;
	CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};

	/* Signature bufffer */
	char sig[SIZE_OF_VEC(rsa_sig)];
	CK_ULONG sig_len = SIZE_OF_VEC(rsa_sig);

	/* Create private key object */
	CK_ATTRIBUTE pri_attrs[7] = {
		{CKA_CLASS, &pri_class, sizeof(pri_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_MODULUS, &modulus, SIZE_OF_VEC(modulus)},
		{CKA_PRIVATE_EXPONENT, &private_exp, SIZE_OF_VEC(private_exp)},
		{CKA_PUBLIC_EXPONENT, &public_exp, SIZE_OF_VEC(public_exp)},
		{CKA_SIGN, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};

	ret = func_list->C_CreateObject(session, pri_attrs, 7, &pri_Key);
	if (ret != CKR_OK) {
		printf("Failed to create RSA private object: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

        /* Create Public key object */
	CK_ATTRIBUTE pub_attrs[6] = {
                {CKA_CLASS, &pub_class, sizeof(pri_class)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_MODULUS, &modulus, SIZE_OF_VEC(modulus)},
		{CKA_PUBLIC_EXPONENT, &public_exp, SIZE_OF_VEC(public_exp)},
                {CKA_VERIFY, &ck_true, sizeof(ck_true)},
                {CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
        };

	ret = func_list->C_CreateObject(session, pub_attrs, 6, &pub_Key);
        if (ret != CKR_OK) {
                printf("Failed to create RSA public object: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
        }

        ret = func_list->C_SignInit(session, &mechanism, pri_Key);
	if (ret != CKR_OK) {
		printf("Failed to signature init: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Sign(session, (CK_BYTE_PTR)rsa_msg, SIZE_OF_VEC(rsa_msg),
				(CK_BYTE_PTR)sig, &sig_len);
	if (ret != CKR_OK) {
		printf("Failed to sign: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	if (SIZE_OF_VEC(rsa_sig) != sig_len) {
		printf("RSA: Invalid size after signature : %lu\n", sig_len);
		return;
	}

	if (memcmp(rsa_sig, sig, sig_len) != 0) {
		printf("RSA: Not expected signature\n");
		return;
	} else {
		printf("RSA: Signature OK\n");
	}

	ret = func_list->C_VerifyInit(session, &mechanism, pub_Key);
	if (ret != CKR_OK) {
		printf("Failed to verify init: %lu : 0x%x\n", ret, (uint32_t)ret);
		return;
	}

	ret = func_list->C_Verify(session, (CK_BYTE_PTR)rsa_msg, SIZE_OF_VEC(rsa_msg),
				  (CK_BYTE_PTR)sig, sig_len);
	if (ret == CKR_OK) {
		printf("RSA: Verified\n");
	} else if (ret == CKR_SIGNATURE_INVALID) {
		printf("RSA: Invalid signature\n");
	} else {
		printf("RSA: Failed to verify: %lu : 0x%x\n", ret, (uint32_t)ret);
	}
}

static void get_attr_value(CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_MECHANISM_TYPE allow_mech = CKM_AES_CBC;
	CK_UTF8CHAR label[] = { "New label" };
	uint32_t label_len = sizeof(label) - 1;
	CK_OBJECT_HANDLE obj_handle = 0;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL ck_true = CK_TRUE;
	CK_RV ret;

	CK_ATTRIBUTE attrs[7] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, &aes_key, SIZE_OF_VEC(aes_key)},
		{CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
		{CKA_DECRYPT, &ck_true, sizeof(ck_true)},
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)},
		{CKA_LABEL, label, label_len}
	};

	ret = func_list->C_CreateObject(session, attrs, 7, &obj_handle);
	if (ret != CKR_OK) {
		PRI("Failed to create object: %lu : 0x%x", ret, (uint32_t)ret)
		return;
	}

	/* Get label size */
	CK_ATTRIBUTE get_label_size_template = {CKA_LABEL, NULL_PTR, 0};
	ret = func_list->C_GetAttributeValue(session, obj_handle, &get_label_size_template, 1);
	if (ret != CKR_OK) {
		PRI("failed to get label size %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (get_label_size_template.ulValueLen != label_len) {
		PRI("Wrong label size");
		return;
	}

	/* Get label */
	CK_UTF8CHAR obj_label[20] = {0};
	CK_ATTRIBUTE get_label_template = {CKA_LABEL, &obj_label, 20};
	ret = func_list->C_GetAttributeValue(session, obj_handle, &get_label_template, 1);
	if (ret != CKR_OK) {
		PRI("failed to get label %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (get_label_template.ulValueLen != label_len) {
		PRI("Get wrong label size");
		return;
	}

	if (memcmp(obj_label, label, get_label_template.ulValueLen)) {
		PRI("Wrong label");
		return;
	}

	/* Invalid size */
	CK_KEY_TYPE obj_keyType;
	CK_UTF8CHAR obj_short_label[2];
	CK_ATTRIBUTE get_label_too_small_template[2] = {
		{CKA_KEY_TYPE, &obj_keyType, sizeof(obj_keyType)},
		{CKA_LABEL, &obj_short_label, 2}
	};
	ret = func_list->C_GetAttributeValue(session, obj_handle, get_label_too_small_template, 2);
	if (ret != CKR_BUFFER_TOO_SMALL) {
		PRI("failed to get short label %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if (*((CK_KEY_TYPE *)get_label_too_small_template[0].pValue) != keyType) {
		PRI("Invalid key type");
		return;
	}

	if ((CK_LONG)get_label_too_small_template[1].ulValueLen != -1) {
		PRI("Expected -1 label size");
		return;
	}

	/* Invalid attribute */
	CK_ATTRIBUTE get_invalid_attr = {CKA_SIGN, NULL_PTR, 0};
	ret = func_list->C_GetAttributeValue(session, obj_handle, &get_invalid_attr, 1);
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID) {
		PRI("failed to get invalid attribute %lu : 0x%x", ret, (uint32_t)ret);
		return;
	}

	if ((CK_LONG)get_invalid_attr.ulValueLen == -1) {
		PRI("Should not found");
		return;
	}

	PRI("Get attribute function OK")
}

static void find_objects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE hObject[10];
	CK_ULONG ulObjectCount;
	CK_RV ck_rv;

	/* Find all objects
	 * Note: This test result are not checked, because it depends our SS stated */
	ck_rv = func_list->C_FindObjectsInit(session, NULL_PTR, 0);
	if (ck_rv != CKR_OK) {
		PRI("Failed to init find object");
		return;
	}

	while (1) {
		ck_rv = func_list->C_FindObjects(session, hObject, 10, &ulObjectCount);
		if (ck_rv != CKR_OK) {
			PRI("Failed to find objects");
			return;
		}

		if (ulObjectCount != 10)
			break;
	}

	ck_rv = func_list->C_FindObjectsFinal(session);
	if (ck_rv != CKR_OK) {
		PRI("Failed to finalize objects find");
		return;
	}

	if (ulObjectCount != 3)
		PRI("Cant find all the object. There should be three object "
		    "(Depends our SS state, this might not be a problem)")

	/* Get AES key object */
	CK_KEY_TYPE keyType = CKK_AES;
	CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
	CK_ATTRIBUTE aes_object[2] = {
		{CKA_CLASS, &obj_class, sizeof(obj_class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
	};
	ck_rv = func_list->C_FindObjectsInit(session, aes_object, 2);
	if (ck_rv != CKR_OK) {
		PRI("Failed to init find object");
		return;
	}

	ck_rv = func_list->C_FindObjects(session, hObject, 10, &ulObjectCount);
	if (ck_rv != CKR_OK) {
		PRI("Failed to find objects");
		return;
	}

	ck_rv = func_list->C_FindObjectsFinal(session);
	if (ck_rv != CKR_OK) {
		PRI("Failed to finalize objects find");
		return;
	}

	/* If you have it clean state, it should find one object */
	if (ulObjectCount != 1)
		PRI("Expected to find only one AES key object (Depends our SS "
		    "state, this might not be a problem)")

	/* find object that have two common attributes */
	CK_MECHANISM_TYPE allow_mech = CKM_SHA1_RSA_PKCS;
	CK_ATTRIBUTE allow_object[1] = {
		{CKA_ALLOWED_MECHANISMS, &allow_mech, sizeof(allow_mech)}
	};

	ck_rv = func_list->C_FindObjectsInit(session, allow_object, 1);
	if (ck_rv != CKR_OK) {
		PRI("Failed to init find object");
		return;
	}

	ck_rv = func_list->C_FindObjects(session, hObject, 10, &ulObjectCount);
	if (ck_rv != CKR_OK) {
		PRI("Failed to find objects");
		return;
	}

	ck_rv = func_list->C_FindObjectsFinal(session);
	if (ck_rv != CKR_OK) {
		PRI("Failed to finalize objects find");
		return;
	}

	/* If you have it clean state, it should find one object */
	if (ulObjectCount != 2) {
		PRI("Expected to find two object (Depends our SS "
		    "state, this might not be a problem)")
	}

	PRI("Find object test complited");
}

int main()
{
	CK_SESSION_HANDLE session;
	CK_INFO info;
	CK_RV ret;
	CK_SLOT_ID available_slots[1];
	CK_ULONG num_slots = 1;
	char pin[8] = "12345678";

	ret = C_GetFunctionList(&func_list);
	if (ret != CKR_OK || func_list == NULL) {
		printf("Failed to get function list: %ld\n", ret);
		return 0;
	}

	ret = func_list->C_Initialize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to initialize the library: %ld\n", ret);
		return 0;
	}

	ret = C_GetInfo(&info);
	if (ret != CKR_OK) {
		printf("Failed to get the library info: %ld\n", ret);
		return 0;
	}

	printf("Version : Major %d: Minor %d\n",
	       info.cryptokiVersion.major, info.cryptokiVersion.minor);

	ret = func_list->C_GetSlotList(1, available_slots, &num_slots);
	if (ret != CKR_OK) {
		printf("Failed to get the available slots: %ld\n", ret);
		return 0;
	}

	ret = func_list->C_OpenSession(available_slots[0], CKF_RW_SESSION | CKF_SERIAL_SESSION,
				       NULL, NULL, &session);
	if (ret != CKR_OK) {
		printf("Failed to Open session the library: 0x%x\n", (uint32_t)ret);
		return 0;
	}

	ret = func_list->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, sizeof(pin));
	if (ret != CKR_OK) {
		printf("Failed to login: 0x%x\n", (uint32_t)ret);
		return 0;
	}

	/* Do aes signature and RSA sign/verfy */
	aes_test(session);
	rsa_sign_ver(session);
	get_attr_value(session);
	find_objects(session);

	ret = func_list->C_Logout(session);
	if (ret != CKR_OK) {
		printf("Failed to logout: 0x%x\n", (uint32_t)ret);
		return 0;
	}

	func_list->C_CloseSession(session);

	ret = func_list->C_Finalize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to Finalize the library: %ld\n", ret);
		return 0;
	}

	return 0;
}
