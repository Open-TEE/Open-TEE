/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

/* Extreme simply smoke tests. */

#include "storage_test.h"
#include "tee_internal_api.h"
#include "print_functions.h"

#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)

//Random, but valid, RSA components
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)
static uint8_t modulus[] = "\x88\x3e\x6b\x47\x4e\xdb\x4a\x36\xa4\xf4\x7f\x2f\x88\xc9\xdd\x96\x45\xf0\xee"
	"\x9e\x1d\xe9\xf5\xc4\x1d\x36\x2e\xbf\x1e\x61\x25\x52\x62\x62\x6e\xce\x95\xc8"
	"\xcb\xd7\x0e\x34\x37\xe1\x77\xf1\x32\x20\x2d\xa6\x1e\x6b\x4f\x9f\x94\x7d\xc9"
	"\x8e\xad\x78\x7e\xae\x75\xac\xed\x10\x7f\xca\xd2\x2f\xab\x79\x37\x8d\xc1\xeb"
	"\xec\x8b\xcb\x6a\x1d\x1b\x9a\xd8\x13\xd4\x6a\x4b\x65\x67\xa7\xa9\xae\x9c\x47"
	"\xb0\xfc\xc4\x46\xb9\xbc\x44\x6a\x1a\xb0\x29\x08\xc7\x3b\x0a\xd2\xea\x01\x40"
	"\x22\x24\x97\xd7\x80\xe0\x31\x89\xb6\x0b\x51\xef\x4c\x79\xb5\xfb\x51\x8c\xb2"
	"\x18\x49\xfe\x3c\xd6\x1a\x07\x20\x4e\xaa\x5a\xab\x80\x2e\xa9\x0c\x67\x00\xb4"
	"\xaa\xa1\xce\xbb\xc6\xb1\x57\x02\x0a\xfd\x65\xe3\xf8\x05\x1b\xf8\xec\x6c\x3d"
	"\xe2\x1c\x24\xf7\x9b\xf9\x82\x42\xe5\x91\x50\xf4\x21\x37\xce\x0f\xde\x85\x52"
	"\x13\x6d";
static uint8_t public_exp_4_bytes[] = "\x00\x00\x00\x03";


//Random, but valid, EC curve
static uint8_t ecc_qx_p256[] = "\x2a\xcb\x25\x56\x7e\x9d\x79\x5e\xe1\x99\xf9\x4f\xcf\xe5\x1b\xf5"
	"\x75\x6e\x36\xce\xe1\x3b\x4a\x24\x99\xd7\x9e\x40\x92\x71\xfd\x0c";
static uint8_t ecc_qy_p256[] = "\x05\xc0\xcb\xe6\x48\xc1\xdd\x02\x65\x33\x6e\x79\xf9\x71\x92\x99"
	"\x0f\x95\xf4\x27\x7f\xa0\x5c\x18\x62\x94\x6c\x9c\x91\xf3\x2d\x8d";
static uint8_t ecc_r_p256[] = "\xa6\xc8\xe7\x67\x34\xbb\x77\x95\x5f\x59\x2e\x3d\xed\x6b\xc7\xd1"
	"\x58\x82\x62\x7a\xbf\x97\x5e\x32\xcb\x3c\x82\x62\xeb\x96\x72\x68";


static uint32_t do_data_stream_write(bool fromStorage, bool addAesAttr);
static uint32_t do_data_position(bool fromStorage);

static uint32_t gen_rsa_key_pair_and_save_read()
{
	TEE_Result ret;
	TEE_ObjectHandle handler = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle handler2 = (TEE_ObjectHandle)NULL;
	size_t key_size = 512;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	void *data;
	size_t data_len = 12;
	uint32_t fn_ret = 1; /* Initialized error return */

	data = TEE_Malloc(data_len, 0);
	if (data == NULL)
		goto err;
	TEE_GenerateRandom(data, data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA keypair generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 flags, handler, data, data_len, (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &handler2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeTransientObject(handler);
	TEE_CloseAndDeletePersistentObject1(handler2);
	TEE_Free(data);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}


static uint32_t popu_rsa_pub_key()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_pubkey = NULL;
	uint32_t key_size = 2048;
	uint32_t param_count = 2, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params[2];
	
	// modulo
	params[0].attributeID = TEE_ATTR_RSA_MODULUS;
	params[0].content.ref.buffer = modulus;
	params[0].content.ref.length = SIZE_OF_VEC(modulus);

	// pub exp (4 byte random, lazyness)
	params[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	params[1].content.ref.buffer = public_exp_4_bytes;
	params[1].content.ref.length = SIZE_OF_VEC(public_exp_4_bytes);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_size, &rsa_pubkey);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_2;
	}

	ret = TEE_PopulateTransientObject(rsa_pubkey, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA public key population failed : 0x%x", ret);
		goto err_2;
	}

	fn_ret = 0; /* OK */

err_2:
	TEE_FreeTransientObject(rsa_pubkey);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t rename_per_obj_and_enum_and_open_renameObj()
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_ObjectEnumHandle iter_enum = (TEE_ObjectEnumHandle)NULL;
	TEE_ObjectInfo info;

	char original_obj_id[TEE_OBJECT_ID_MAX_LEN],
		obj_id[TEE_OBJECT_ID_MAX_LEN],
		new_obj_id[TEE_OBJECT_ID_MAX_LEN];
	size_t original_obj_id_len = 15,
		obj_id_len = TEE_OBJECT_ID_MAX_LEN,
		new_obj_id_len = 20,
		fn_ret = 1; /* Initialized error return */
	
	TEE_GenerateRandom(original_obj_id, original_obj_id_len);
	TEE_GenerateRandom(new_obj_id, new_obj_id_len);

	// Generate random object with random data
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)original_obj_id, original_obj_id_len, flags,
					 (TEE_ObjectHandle)NULL,
					 original_obj_id, original_obj_id_len, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed (original) : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator allocation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (first) : 0x%x", ret);
		goto err;
	}

	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_SUCCESS) {

			if (obj_id_len == original_obj_id_len &&
			    TEE_MemCompare(original_obj_id, obj_id, obj_id_len) == 0)
				break;
			else
				continue;

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			PRI_FAIL("Cant find created object");
			goto err;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	ret = TEE_RenamePersistentObject(object, original_obj_id, original_obj_id_len);
	if (ret != TEE_ERROR_ACCESS_CONFLICT) {
		PRI_FAIL("Object rename should have failed with TEE_ERROR_ACCESS_CONFLICT : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_RenamePersistentObject(object, new_obj_id, new_obj_id_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Object rename failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (second) : 0x%x", ret);
		goto err;
	}

	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_SUCCESS) {

			if (obj_id_len == new_obj_id_len &&
			    TEE_MemCompare(new_obj_id, obj_id, obj_id_len) == 0)
				break;
			else
				continue;

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			PRI_FAIL("Cant find renamed object");
			goto err;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	/* Continue to end */
	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		}

		PRI_FAIL("Enumerator get next failed (expected end) : 0x%x", ret);
		goto err;
	}

	ret = TEE_RenamePersistentObject(object, new_obj_id, new_obj_id_len);
	if (ret != TEE_ERROR_ACCESS_CONFLICT) {
		PRI_FAIL("Object rename should have failed with TEE_ERROR_ACCESS_CONFLICT : 0x%x", ret);
		goto err;
	}

	
	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);
	TEE_FreePersistentObjectEnumerator(iter_enum);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t data_stream_write_read()
{

	TEE_Result ret;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL, per_han = (TEE_ObjectHandle)NULL;
	size_t key_size = 256;
	char objID[] = "96c5d1b2607123430fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50, count = 0, read_data_buf = 100;
	uint32_t fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("AES key generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)objID, objID_len, flags, key, NULL, 0, &per_han);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(per_han, write_data, write_data_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len) {
		PRI_FAIL("Read data length mismatch (read[%lu]; expected[%lu])",
			 count, write_data_len);
		goto err;
	}
	
	if (TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -(int32_t)count, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len || TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -(int32_t)count, TEE_DATA_SEEK_END);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (third) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (third) : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len || TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data (third)");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, 5, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (fourth) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, 1, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (third) : 0x%x", ret);
		goto err;
	}

	if (count != 1 || TEE_MemCompare(write_data + 5, read_data, count)) {
		PRI_FAIL("Read byte does not matchs");
		goto err;
	}

	TEE_GetObjectInfo1(per_han, &info);
	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != 6) {
		PRI_FAIL("Incorrect position");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(per_han);
	TEE_CloseObject(key);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t object_data_size()
{
	TEE_Result ret;
	TEE_ObjectHandle handler = (TEE_ObjectHandle)NULL, transObj = NULL;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	char objID[] = "34c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64, data_len = 12;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	uint32_t fn_ret = 1; /* Initialized error return */
	char data[12] = {1};
	TEE_ObjectInfo info;

	ret = TEE_AllocateTransientObject(obj_type, key_size, &transObj);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(transObj, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to generate aes key : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 transObj, data, data_len,
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &handler);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(handler, &info);

	if (info.dataSize != data_len) {
		PRI_FAIL("Data size is not correct");
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Data position is not correct");
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeTransientObject(transObj);
	TEE_CloseAndDeletePersistentObject1(handler);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t multiple_writes()
{

	TEE_Result ret;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL, object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260704de30fedaf67e5b9227613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50, read_bytes = 0, write_count = 3;
	uint32_t i = 0, fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)objID, objID_len, flags, key, NULL, 0, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != 0) {
		PRI_FAIL("Object data size should be zero");
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object data position be zero");
		goto err;
	}

	for (i = 0; i < write_count; i++) {
		ret = TEE_WriteObjectData(object, write_data, write_data_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Write failed (%u) : 0x%x", i, ret);
			goto err;
		}
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != write_data_len * write_count) {
		PRI_FAIL("Incorrect position");
		goto err;
	}

	ret = TEE_SeekObjectData(object, write_data_len, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Read data should be same as write data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (second)");
		goto err;
	}

	if (info.dataPosition != write_data_len + write_data_len) {
		PRI_FAIL("Incorrect position (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(object, 25, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataPosition != write_data_len + write_data_len + 25) {
		PRI_FAIL("Incorrect position (third)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, 25, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != 25 || TEE_MemCompare(write_data + 25, read_data, 25)) {
		PRI_FAIL("Read data should be same as write data (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t persisten_object_write_and_read()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260704de30fedaf67e5b9227613abebff172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50;
	size_t read_bytes = 0, write_count = 3, i = 0;
	uint32_t fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

        ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, objID, objID_len, flags, &object);
        if (ret == TEE_SUCCESS) {
                PRI_FAIL("Open session should fail, because object is not existing");
                goto err;
	} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		/* OK */
	} else {
		PRI_FAIL("TEE_OpenPersistentObject : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 (TEE_ObjectHandle)NULL, NULL, 0, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	for (i = 0; i < write_count; i++) {
		ret = TEE_WriteObjectData(object, write_data, write_data_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Write failed (%ld) : 0x%x", i, ret);
			goto err;
		}
	}

	TEE_CloseObject(object);
	object = (TEE_ObjectHandle)NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object data position be zero");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Read data should be same as write data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(object, 25, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, 25, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != 25 || TEE_MemCompare(write_data + 25, read_data, 25)) {
		PRI_FAIL("Read data should be same as write data (second)");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (third)");
		goto err;
	}

	if (info.dataPosition != write_data_len + write_data_len) {
		PRI_FAIL("Incorrect position (third)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t persistent_initial_data(bool fromStorage)
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "1234d1b260aa4de30fedaf67e5b9123413abebff172a2b4e912d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ;
	char init_data[50] = {0}, read_data[100] = {0};
	size_t read_bytes = 0, init_data_len = 20;
	uint32_t fn_ret = 1; //Initialized error return
	TEE_ObjectInfo info;

	//Create write initial data
	TEE_GenerateRandom((void *)init_data, init_data_len);

	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, NULL, (void *)init_data, init_data_len,
						 (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}

		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       (void *)objID, objID_len, flags, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}

		
	} else {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
						 (TEE_ObjectHandle)NULL,
						 init_data, init_data_len, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}
	}
	
	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != init_data_len) {
		PRI_FAIL("Object size is not correct after init (initLen[%lu]; "
			 "info.size[%u])", init_data_len, info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}
	
	ret = TEE_ReadObjectData(object, read_data, init_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != init_data_len) {
		PRI_FAIL("Read data incorrect lenght (read_bytes[%lu]; init_data_len[%lu])",
			 read_bytes, init_data_len);
		goto err;
	}

	if (TEE_MemCompare(init_data, read_data, init_data_len)) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != init_data_len) {
		PRI_FAIL("Object size is not correct after read (initLen[%lu]; "
			 "info.size[%u])", init_data_len,info.dataSize);
		goto err;
	}

	if (info.dataPosition != init_data_len) {
		PRI_FAIL("Object position wrong (expectedPos[%lu]; "
			 "info.dataPosition[%u])", init_data_len, info.dataPosition);
		goto err;
	}
	
	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t persisten_object_init_data()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260aa4de30fedaf67e5b9227613abebff172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 20, read_bytes = 0;
	uint32_t fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 (TEE_ObjectHandle)NULL,
					 write_data, write_data_len, (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object init size is not correct after open");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	/* Gen new data */
	write_data_len = write_data_len * 2;
	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(object, write_data, write_data_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_CloseObject(object);
	object = (TEE_ObjectHandle)NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object size is not correct after open (second)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Not data is not updated (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t overwrite_persisten()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260aa4de30fedaf67e5b9227613abebff172a2b4e949994b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	size_t counter = 1, read_bytes = 0;
	uint32_t fn_ret = 1; /* Initialized error return */
	char read_data[10];
	TEE_ObjectInfo info;

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 TEE_DATA_FLAG_ACCESS_WRITE_META,
					 (TEE_ObjectHandle)NULL, (void *)&counter, sizeof(counter),
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 TEE_DATA_FLAG_ACCESS_WRITE_META,
					 (TEE_ObjectHandle)NULL, (void *)&counter, sizeof(counter),
					 (TEE_ObjectHandle *)NULL);
	if (ret == TEE_SUCCESS) {
		PRI_FAIL("Should not returning TEE_SUCCESs, because overwrite flag is not set");
		goto err;
	} else if (ret == TEE_ERROR_ACCESS_CONFLICT) {
		/* OK */
	} else {
		PRI_FAIL("Create random error : 0x%x", ret);
		goto err;
	}

	/* Open and update counter */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != sizeof(counter)) {
		PRI_FAIL("Object init size is not correct after open");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, sizeof(counter), &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != sizeof(counter) || TEE_MemCompare(&counter, read_data, sizeof(counter))) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	counter++;

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(object, &counter, sizeof(counter));
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_CloseObject(object);

	/* Re open and read data */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != sizeof(counter)) {
		PRI_FAIL("Object size is not correct after open (second)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, sizeof(counter), &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != sizeof(counter) || TEE_MemCompare(&counter, read_data, sizeof(counter))) {
		PRI_FAIL("Not data is not updated (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t data_stream_write()
{
	if (do_data_stream_write(true, true)) {
		return 1;
	}
	
	if (do_data_stream_write(false, true)) {
		return 1;
	}

	if (do_data_stream_write(true, false)) {
		return 1;
	}
	
	if (do_data_stream_write(false, false)) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;
}

static uint32_t do_data_stream_write(bool fromStorage, bool addAesAttr)
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL, transObj = NULL;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	char objID[] = "1234d1b260aa4de30fedaf67e111123413abebff172a2b4e912d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE;
	char data[50] = {0};
	size_t data_len = 27;
	uint32_t fn_ret = 1; //Initialized error return
	TEE_ObjectInfo info;

	//Create write initial data
	TEE_GenerateRandom(data, data_len);

	if (addAesAttr) {
		ret = TEE_AllocateTransientObject(obj_type, key_size, &transObj);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
			goto err;
		}

		ret = TEE_GenerateKey(transObj, key_size, NULL, 0);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Failed to generate aes key : 0x%x", ret);
			goto err;
		}
	}
	
	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, transObj, NULL, 0, (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}

		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, objID, objID_len, flags, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}

		
	} else {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
						 transObj, NULL, 0, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}
	}
	
	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != 0) {
		PRI_FAIL("Object size is not correct after init (initDataLen[0]; "
			 "info.size[%u])", info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}
	
	ret = TEE_WriteObjectData(object, data, data_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != data_len) {
		PRI_FAIL("Object size is not correct after write (initDataLen[%lu]; "
			 "info.size[%u])", data_len, info.dataSize);
		goto err;
	}

	if (info.dataPosition != data_len) {
		PRI_FAIL("Object position wrong (expectedPos[%lu]; "
			 "info.dataPosition[%u])", data_len, info.dataPosition);
		goto err;
	}
	
	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);
	TEE_FreeTransientObject(transObj);
	return fn_ret;		
}

static uint32_t data_position()
{
	if (do_data_position(true)) {
		return 1;
	}

	if (do_data_position(false)) {
		return 1;
	}

	PRI_OK("-");
	return 0;
}

static uint32_t do_data_position(bool fromStorage)
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL, transObj = NULL;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	char objID[] = "1234d1b260324de30fedaf67e111123413abebff172a2b4e912d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE;
	char data[50] = {0};
	size_t data_len = 27;
	uint32_t fn_ret = 1; //Initialized error return
	TEE_ObjectInfo info;

	//Create write initial data
	TEE_GenerateRandom(data, data_len);

	ret = TEE_AllocateTransientObject(obj_type, key_size, &transObj);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(transObj, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to generate aes key : 0x%x", ret);
		goto err;
	}

	
	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, transObj, data, data_len, (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}

		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, objID, objID_len, flags, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}

		
	} else {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
						 transObj, data, data_len, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}
	}
	
	TEE_GetObjectInfo1(object, &info);

	if (data_len != info.dataSize) {
		PRI_FAIL("Object size is not correct after init (initDataLen[%lu]; "
			 "info.size[%u])", data_len, info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}
	
	fn_ret = 0; //OK

err:
	TEE_CloseAndDeletePersistentObject1(object);
	TEE_FreeTransientObject(transObj);
	return fn_ret;
}

static uint32_t do_closeTransientObject(bool genKey, bool callClose)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	uint32_t fn_ret = 1; // Initialized error return
	TEE_Attribute aes_key = {0};
	uint8_t aes_cbc_key_128[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
	
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto out;
	}

	if (genKey) {
		TEE_GenerateKey(key, key_size, NULL, 0);
	} else {
		aes_key.attributeID = TEE_ATTR_SECRET_VALUE;
		aes_key.content.ref.length = key_size / 8;
		aes_key.content.ref.buffer = aes_cbc_key_128;
		
		ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_key, 1);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("RSA key population failed");
			goto err;
		}
	}

	if (callClose) {
		TEE_CloseObject(key);
	} else {
		TEE_FreeTransientObject(key);
	}

	key = NULL;
	
	fn_ret = 0; //Ok
 err:
	//Try closing anyway/again.
	//Anyway: Purpose of test is to test TEE_FreeTransientObject
	//Again: "key" set to NULL and function should work with NULL!
	TEE_FreeTransientObject(key);
 out:
	return fn_ret;	
}

static uint32_t closeTransientObject()
{
	if (do_closeTransientObject(true, true)) {
		return 1;
	}
	
	if (do_closeTransientObject(false, true)) {
		return 1;
	}

	if (do_closeTransientObject(true, false)) {
		return 1;
	}
	
	if (do_closeTransientObject(false, false)) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;	
}

static uint32_t truncate_per_object()
{
	TEE_Result ret;
	TEE_ObjectHandle perObj = NULL;
	uint32_t obj_type = TEE_TYPE_DATA;
	char objID[] = "1234d1b260324de30fedaf67e111123413abebff172a2b4e432d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ;
	char init_data[50] = {0}, read_data[50] = {0}; //reserve enough space
	size_t init_data_len = 20;
	size_t read_bytes = 0, read_buf_s = 50, fn_ret = 1; //Initialized error return
	char zeroBuffer[10] = {0};
	TEE_ObjectInfo info;

	//Create write initial data
	TEE_GenerateRandom(init_data, init_data_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 flags, NULL, init_data, init_data_len, &perObj);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}
	
	TEE_GetObjectInfo1(perObj, &info);

	if (info.objectType != obj_type) {
		PRI_FAIL("Object type is TEE_TYPE_DATA, but info [%u]", info.objectType);
		goto err;
	}
	
	if (init_data_len != info.dataSize) {
		PRI_FAIL("Object size is not correct after init (initDataLen[%lu]; "
			 "info.size[%u])", init_data_len, info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}

	ret = TEE_TruncateObjectData(perObj, 30);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Truncate persisten object failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(perObj, &info);
		
	if (30 != info.dataSize) {
		PRI_FAIL("Object size is not correct after truncate (truncateSize[30]; "
			 "info.size[%u])", info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (1) (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}

	ret = TEE_ReadObjectData(perObj, read_data, read_buf_s, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != 30) {
		PRI_FAIL("Read data is not expected lenght");
		goto err;
	}
	
	if (TEE_MemCompare(read_data, init_data, init_data_len)) {
		PRI_FAIL("Read data is not sames as initial data");
		goto err;
	}

	if (TEE_MemCompare(read_data+20, zeroBuffer, 10)) {
		PRI_FAIL("Truncation has not file to zero");
		goto err;
	}
	
	TEE_GetObjectInfo1(perObj, &info);
	if (info.dataPosition != 30) {
		PRI_FAIL("Object position wrong (2) (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}

	ret = TEE_TruncateObjectData(perObj, 25);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Truncate persisten object failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(perObj, &info);
		
	if (25 != info.dataSize) {
		PRI_FAIL("Object size is not correct after truncate (2) (truncateSize[30]; "
			 "info.size[%u])", info.dataSize);
		goto err;
	}

	if (info.dataPosition != 25) {
		PRI_FAIL("Object position wrong (3) (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}

	ret = TEE_TruncateObjectData(perObj, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Truncate persisten object failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(perObj, &info);
		
	if (0 != info.dataSize) {
		PRI_FAIL("Object size is not correct after truncate (4) (truncateSize[30]; "
			 "info.size[%u])", info.dataSize);
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object position wrong (4) (expectedPos[0]; "
			 "info.dataPosition[%u])", info.dataPosition);
		goto err;
	}
	fn_ret = 0; //OK

err:
	TEE_CloseAndDeletePersistentObject1(perObj);
	return fn_ret;	
}

static uint32_t enumerate_per_objecs()
{
	TEE_ObjectHandle obj1 = NULL, obj2 = NULL, obj3 = NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_ObjectEnumHandle iter_enum = NULL;
	TEE_ObjectInfo info;
	TEE_Result ret;
	uint32_t i = 0, fn_ret = 1;;

	uint8_t fromStorageObjID[TEE_OBJECT_ID_MAX_LEN];
	size_t fromStorageObjIDLen;
	
	char objID_1[] = "21367";
	size_t objID_1_len = 5;
	char objID_2[] = "213688";
	size_t objID_2_len = 6;
	char objID_3[] = "2136999";
	size_t objID_3_len = 7;

	uint32_t obj1_f = 1, obj2_f = 1, obj3_f = 1; //Not cleanest
	
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, objID_1, objID_1_len, flags,
					 NULL, NULL, 0, &obj1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed (obj1) : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator allocation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (first) : 0x%x", ret);
		goto err;
	}

	for (i = 0; i < 5; ++i) {
		fromStorageObjIDLen = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info,
						  fromStorageObjID, &fromStorageObjIDLen);
		if (ret == TEE_SUCCESS) {

			if (objID_1_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_1, fromStorageObjID, fromStorageObjIDLen)) {
				obj1_f = 0;
				continue;
			}

			if (objID_2_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_2, fromStorageObjID, fromStorageObjIDLen)) {
				obj2_f = 0;
				continue;
			}

			if (objID_3_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_3, fromStorageObjID, fromStorageObjIDLen)) {
				obj3_f = 0;
				continue;
			}

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	if (i != 1) {
		PRI_FAIL("Expected 1 object in storage (found[%d])", i);
		goto err;
	}

	if (obj1_f && !obj2_f && !obj3_f) {
		PRI_FAIL("Did not found all objects (1) (obj1[%u]; obj2[%u]; obj3[%u])", obj1_f, obj2_f, obj3_f);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, objID_2, objID_2_len, flags,
					 NULL, NULL, 0, &obj2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed (obj2) : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, objID_3, objID_3_len, flags,
					 NULL, NULL, 0, &obj3);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed (obj3) : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (second) : 0x%x", ret);
		goto err;
	}

	obj1_f = 1;
	obj2_f = 1;
	obj3_f = 1;
	
	for (i = 0; i < 5; ++i) {

		fromStorageObjIDLen = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info,
						  fromStorageObjID, &fromStorageObjIDLen);
		if (ret == TEE_SUCCESS) {

			if (objID_1_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_1, fromStorageObjID, fromStorageObjIDLen)) {
				obj1_f = 0;
				continue;
			}

			if (objID_2_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_2, fromStorageObjID, fromStorageObjIDLen)) {
				obj2_f = 0;
				continue;
			}

			if (objID_3_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_3, fromStorageObjID, fromStorageObjIDLen)) {
				obj3_f = 0;
				continue;
			}
			
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	if (i != 3) {
		PRI_FAIL("Expected 3 object in storage (found[%d])", i);
		goto err;
	}

	if (obj1_f || obj2_f || obj3_f) {
		PRI_FAIL("Did not found all objects (2) (obj1[%u]; obj2[%u]; obj3[%u])", obj1_f, obj2_f, obj3_f);
		goto err;
	}

	TEE_CloseAndDeletePersistentObject1(obj2);
	obj2 = NULL;

	obj1_f = 1;
	obj2_f = 1;
	obj3_f = 1;

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (third) : 0x%x", ret);
		goto err;
	}
	
	for (i = 0; i < 5; ++i) {

		fromStorageObjIDLen = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info,
						  fromStorageObjID, &fromStorageObjIDLen);
		if (ret == TEE_SUCCESS) {

			if (objID_1_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_1, fromStorageObjID, fromStorageObjIDLen)) {
				obj1_f = 0;
				continue;
			}

			if (objID_2_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_2, fromStorageObjID, fromStorageObjIDLen)) {
				obj2_f = 0;
				continue;
			}

			if (objID_3_len == fromStorageObjIDLen &&
			    !TEE_MemCompare(objID_3, fromStorageObjID, fromStorageObjIDLen)) {
				obj3_f = 0;
				continue;
			}
			
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	if (i != 2) {
		PRI_FAIL("Expected 2 object in storage (found[%d])", i);
		goto err;
	}

	if (obj1_f || obj3_f) {
		PRI_FAIL("Did not found all objects (3) (obj1[%u]; obj2[%u]; obj3[%u])", obj1_f, obj2_f, obj3_f);
		goto err;
	}
	
	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(obj1);
	TEE_CloseAndDeletePersistentObject1(obj2);
	TEE_CloseAndDeletePersistentObject1(obj3);
	TEE_FreePersistentObjectEnumerator(iter_enum);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t do_closePersistantObject(bool fromStorage)
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "1234d1b260bb4de30fedaf67e5b9123413abebff172a2b4e912d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ;
	char init_data[50] = {0};
	size_t init_data_len = 20;
	uint32_t fn_ret = 1; //Initialized error return

	//Create write initial data
	TEE_GenerateRandom((void *)init_data, init_data_len);

	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, NULL, (void *)init_data, init_data_len,
						 (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}

		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       (void *)objID, objID_len, flags, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}

		
	} else {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
						 (TEE_ObjectHandle)NULL,
						 init_data, init_data_len, &object);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}
	}

	TEE_CloseObject(object);
	object = NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CloseAndDeletePersistentObject1(object);
	object = NULL;
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("CloseAndDelete failed : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_ERROR_ITEM_NOT_FOUND) {
		PRI_FAIL("Open failed (should return TEE_ERROR_ITEM_NOT_FOUND) : 0x%x", ret);
		goto err;
	}
	
	fn_ret = 0; /* OK */
err:
	TEE_CloseAndDeletePersistentObject1(object);

	return fn_ret;
}

static uint32_t closePersistantObject()
{
	if (do_closePersistantObject(true)) {
		return 1;
	}

	if (do_closePersistantObject(false)) {
		return 1;
	}

	PRI_OK("-");
	return 0;
}

static uint32_t get_rsa_buffer_attr()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 1024;
	uint32_t fn_ret = 1; /* Initialized error return */
	uint8_t buf[256]; //will fit 1024 modulo
	size_t buf_len = 5;
	
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

	ret = TEE_GetObjectBufferAttribute(rsa_keypair,
					   TEE_ATTR_RSA_MODULUS,
					   buf, &buf_len);
	if (ret != TEE_ERROR_SHORT_BUFFER) {
		PRI_FAIL("Should have returned TEE_ERROR_SHORT_BUFFER "
			 "(TEE_ATTR_RSA_MODULUS) : 0x%x", ret);
		goto err;
	}

	if (buf_len != 128) {
		PRI_FAIL("buf_len should contain lenght (expected[128]; returned[%lu])", buf_len);
		goto err;
	}

	buf_len = 200;

	ret = TEE_GetObjectBufferAttribute(rsa_keypair,
					   TEE_ATTR_DSA_BASE,
					   buf, &buf_len);
	if (ret != TEE_ERROR_ITEM_NOT_FOUND) {
		PRI_FAIL("Should returned TEE_ERROR_ITEM_NOT_FOUND : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_GetObjectBufferAttribute(rsa_keypair,
					   TEE_ATTR_RSA_MODULUS,
					   buf, &buf_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to get TEE_ATTR_RSA_MODULUS : 0x%x", ret);
		goto err;
	}

	if (buf_len != 128) {
		PRI_FAIL("Not expected buf_len (expected[128]; returned[%lu])", buf_len);
		goto err;
	}

	buf_len = 200;
	ret = TEE_GetObjectBufferAttribute(rsa_keypair,
					   TEE_ATTR_RSA_PRIVATE_EXPONENT,
					   buf, &buf_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to get TEE_ATTR_RSA_PRIVATE_EXPONENT : 0x%x", ret);
		goto err;
	}
	
	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t do_popu_ecc(uint32_t obj_type)
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	uint32_t key_size = 256;
	uint32_t param_count = 4, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params[4] = {0};

	// Qx
	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = ecc_qx_p256;
	params[0].content.ref.length = SIZE_OF_VEC(ecc_qx_p256);

	// Qy
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = ecc_qy_p256;
	params[1].content.ref.length = SIZE_OF_VEC(ecc_qy_p256);

	if (obj_type == TEE_TYPE_ECDH_KEYPAIR ||
	    obj_type == TEE_TYPE_ECDSA_KEYPAIR) {
		// R
		params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
		params[2].content.ref.buffer = ecc_r_p256;
		params[2].content.ref.length = SIZE_OF_VEC(ecc_r_p256);
	} else {
		//Opentee Should not crash due this should ignored
		params[2].attributeID = TEE_ATTR_SECRET_VALUE;
		params[2].content.ref.buffer = NULL;
		params[2].content.ref.length = 3;
	}

	// Curve
	params[3].attributeID = TEE_ATTR_ECC_CURVE;
	params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
	params[3].content.value.b = 0;
	
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_2;
	}

	ret = TEE_PopulateTransientObject(key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("ECC key pair population failed : 0x%x", ret);
		goto err_2;
	}

	fn_ret = 0; // OK

err_2:
	TEE_FreeTransientObject(key);
	return fn_ret;	
}

static uint32_t populate_ecc()
{
	if (do_popu_ecc(TEE_TYPE_ECDSA_KEYPAIR)) {
		return 1;
	}

	if (do_popu_ecc(TEE_TYPE_ECDSA_PUBLIC_KEY)) {
		return 1;
	}

	PRI_OK("-");
	return 0;
}

static uint32_t is_buffer_empty(void *buf, size_t bufLen)
{
	uint8_t *buf8 = (uint8_t *)buf;
	if (buf8[0] == 0 && !TEE_MemCompare(buf8, buf8 + 1, bufLen - 1)) {
		return 1; //Empty
	}

	return 0;
}

static uint32_t do_gen_ecc_key(uint32_t obj_type,
			       uint32_t key_size,
			       uint32_t curve)
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	uint32_t param_count = 1, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params = {0};
	void *buffer = NULL;
	size_t bufferLen = 200;
	uint32_t a = 0, b = 0;

	params.attributeID = TEE_ATTR_ECC_CURVE;
	params.content.value.a = curve;
	
	buffer = TEE_Malloc(bufferLen, 0);
	if (buffer == NULL) {
		PRI_FAIL("Out of memory");
		goto err;
	}
	
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, &params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Key generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PRIVATE_VALUE,
					   buffer, &bufferLen);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to fetch TEE_ATTR_ECC_PRIVATE_VALUE : 0x%x", ret);
		goto err;
	}

	if (is_buffer_empty(buffer, bufferLen)) {
		PRI_FAIL("TEE_ATTR_ECC_PRIVATE_VALUE is all zeros");
		goto err;
	}

	ret = TEE_GetObjectValueAttribute(key, TEE_ATTR_ECC_CURVE, &a, &b);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to fetch TEE_ATTR_ECC_CURVE : 0x%x", ret);
		goto err;
	}

	if (a != curve) {
		PRI_FAIL("Wrong curve");
		goto err;
	}
	
	fn_ret = 0; // OK
 err:
	TEE_FreeTransientObject(key);
	TEE_Free(buffer);
	return fn_ret;
	
}

static uint32_t generate_ecc_key()
{
	
	if (do_gen_ecc_key(TEE_TYPE_ECDSA_KEYPAIR, 256, TEE_ECC_CURVE_NIST_P256)) {
		return 1;
	}

	if (do_gen_ecc_key(TEE_TYPE_ECDSA_KEYPAIR, 521, TEE_ECC_CURVE_NIST_P521)) {
		return 1;
	}
	
	if (do_gen_ecc_key(TEE_TYPE_ECDH_KEYPAIR, 256, TEE_ECC_CURVE_NIST_P256)) {
		return 1;
	}
	

	PRI_OK("-");
	return 0;
}

uint32_t storage_test(uint32_t loop_count)
{
	uint32_t i, test_have_fail = 0;

	PRI_STR("START: storage tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {
		
		if (generate_ecc_key() ||
		    populate_ecc() ||
		    popu_rsa_pub_key() ||
		    enumerate_per_objecs() ||
		    get_rsa_buffer_attr() ||
		    truncate_per_object() ||
		    persistent_initial_data(true) ||
		    persistent_initial_data(false) ||
		    object_data_size() ||
		    data_stream_write() ||
		    data_stream_write_read() ||
		    multiple_writes() ||
		    persisten_object_write_and_read() ||
		    persisten_object_init_data() ||
		    data_position() ||
		    overwrite_persisten() ||
		    gen_rsa_key_pair_and_save_read() ||
		    closeTransientObject() ||		    
		    closePersistantObject() ||
		    rename_per_obj_and_enum_and_open_renameObj()) {
			test_have_fail = 1;
			break;
		}
		
	}

	PRI_STR("----Test-has-reached-end----\n");

	PRI_STR("END: storage tests");

	return test_have_fail ? 1 : 0;
}
