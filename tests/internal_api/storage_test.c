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
#include "../include/tee_internal_api.h"

/* Start Open-TEE spesifics. NOT GP Compliant. For debugin sake */
#include "../include/tee_logging.h"

#include <syslog.h>
#define OT_LOG1(level, message, ...) syslog(level, message, ##__VA_ARGS__)

#define PRI_STR(str)	    OT_LOG1(LOG_DEBUG, str);
#define PRI(str, ...)       OT_LOG1(LOG_DEBUG, "%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    OT_LOG1(LOG_DEBUG, " [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   OT_LOG1(LOG_DEBUG, " YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  OT_LOG1(LOG_DEBUG, "FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) OT_LOG1(LOG_DEBUG, "ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);
/* Start Open-TEE spesifics. */

#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)

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
	TEE_ObjectHandle rsa_pubkey = (TEE_ObjectHandle)NULL;
	uint32_t key_size = 512;
	TEE_Attribute *params = (TEE_Attribute *)NULL;
	uint32_t param_count = 2, fn_ret = 1; /* Initialized error return */

	/* Do malloc */
	params = (TEE_Attribute *)TEE_Malloc(param_count * sizeof(TEE_Attribute), 0);
	if (params == NULL) {
		PRI_FAIL("Out of memory");
		return fn_ret;
	}
	params[0].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	params[1].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	if (params[0].content.ref.buffer == NULL || params[1].content.ref.buffer == NULL) {
		PRI_FAIL("Out of memory");
		goto err_1;
	}

	// modulo
	params[0].attributeID = TEE_ATTR_RSA_MODULUS;
	TEE_GenerateRandom(params[0].content.ref.buffer, KEY_IN_BYTES(key_size));
	params[0].content.ref.length = KEY_IN_BYTES(key_size);

	// pub exp (4 byte random, lazyness)
	params[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	TEE_GenerateRandom(params[1].content.ref.buffer, 4);
	params[1].content.ref.length = 4;


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
	TEE_Free(params[0].content.ref.buffer);
	TEE_Free(params[1].content.ref.buffer);
err_1:
	TEE_Free(params);

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
		PRI_FAIL("Read data length mismatch (read[%u]; expected[%u])",
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
			PRI_FAIL("Write failed (%u) : 0x%x", i, ret);
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
		PRI_FAIL("Object size is not correct after init (initLen[%u]; "
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
		PRI_FAIL("Read data incorrect lenght (read_bytes[%u]; init_data_len[%u])",
			 read_bytes, init_data_len);
		goto err;
	}

	if (TEE_MemCompare(init_data, read_data, init_data_len)) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != init_data_len) {
		PRI_FAIL("Object size is not correct after read (initLen[%u]; "
			 "info.size[%u])", init_data_len,info.dataSize);
		goto err;
	}

	if (info.dataPosition != init_data_len) {
		PRI_FAIL("Object position wrong (expectedPos[%u]; "
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
	size_t read_bytes = 0, data_len = 27;
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
			 "info.size[%u])", data_len, info.dataSize);
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
		PRI_FAIL("Object size is not correct after write (initDataLen[%u]; "
			 "info.size[%u])", data_len,info.dataSize);
		goto err;
	}

	if (info.dataPosition != data_len) {
		PRI_FAIL("Object position wrong (expectedPos[%u]; "
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
	size_t data_len = 27, read_bytes = 0;
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

	if (info.dataSize != info.dataSize) {
		PRI_FAIL("Object size is not correct after init (initDataLen[%u]; "
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
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
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

	if (init_data_len != info.dataSize) {
		PRI_FAIL("Object size is not correct after init (initDataLen[%u]; "
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
	char init_data[50] = {0}, read_data[100] = {0};
	size_t init_data_len = 20;
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
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
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
		PRI_FAIL("buf_len should contain lenght (expected[128]; returned[%u])", buf_len);
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
		PRI_FAIL("Not expected buf_len (expected[128]; returned[%u])", buf_len);
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

uint32_t storage_test(uint32_t loop_count)
{
	uint32_t i, test_have_fail = 0;

	PRI_STR("START: storage tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {
		
		if (popu_rsa_pub_key() ||
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
