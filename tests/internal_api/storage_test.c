/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Extreme simply smoke tests. If something than function name is printed -> FAIL */

/* NOTICE */
#include "../include/tee_internal_api.h"
#include "../include/tee_logging.h"
#include "../internal_api/tee_object_handle.h"

#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)


#ifdef TA_STORAGE_TEST
#define priiintf(...) OT_LOG(LOG_ERR, __VA_ARGS__)
#else
#define priiintf(...) printf(__VA_ARGS__)
#endif

#ifndef TA_STORAGE_TEST
#include "../../emulator/manager/opentee_manager_storage_api.h"
#define TEE_OpenPersistentObject MGR_TEE_OpenPersistentObject

#define TEE_CloseObject MGR_TEE_CloseObject
#define TEE_CreatePersistentObject MGR_TEE_CreatePersistentObject
#define TEE_RenamePersistentObject MGR_TEE_RenamePersistentObject
#define TEE_CloseAndDeletePersistentObject MGR_TEE_CloseAndDeletePersistentObject

/* object data handling */
#define TEE_ReadObjectData MGR_TEE_ReadObjectData
#define TEE_WriteObjectData MGR_TEE_WriteObjectData
#define TEE_TruncateObjectData MGR_TEE_TruncateObjectData
#define TEE_SeekObjectData MGR_TEE_SeekObjectData

/* object enumeration */
#define TEE_AllocatePersistentObjectEnumerator MGR_TEE_AllocatePersistentObjectEnumerator
#define TEE_FreePersistentObjectEnumerator MGR_TEE_FreePersistentObjectEnumerator
#define TEE_ResetPersistentObjectEnumerator MGR_TEE_ResetPersistentObjectEnumerator
#define TEE_StartPersistentObjectEnumerator MGR_TEE_StartPersistentObjectEnumerator
#define TEE_GetNextPersistentObject MGR_TEE_GetNextPersistentObject

#endif

/* pri_obj_attr */
static void __attribute__((unused)) pri_obj_attr(TEE_ObjectHandle object)
{
	size_t i, j;
	if (object == NULL)
		return;

	for (i = 0; i < object->attrs_count; ++i) {
		for (j = 0; j < object->attrs[i].content.ref.length; j++) {
			priiintf("%02x", ((unsigned char *)object->attrs[i].content.ref.buffer)[j]);
		}
		priiintf("\n");
	}
}

/* pri_and_cmp_attr */
static void __attribute__((unused)) pri_and_cmp_attr(TEE_ObjectHandle obj1, TEE_ObjectHandle obj2)
{
	size_t i, j, attr_count, cmp_len;

	if (obj1 == NULL || obj2 == NULL)
		return;

	if (obj1 > obj2)
		attr_count = obj1->attrs_count;
	else
		attr_count = obj2->attrs_count;

	priiintf("obj1: %d\n", obj1->attrs_count);
	priiintf("obj2: %d\n", obj2->attrs_count);

	for (i = 0; i < attr_count; ++i) {
		if (obj1->attrs_count > i) {
			priiintf("obj1: ");
			for (j = 0; j < obj1->attrs[i].content.ref.length; j++)
				priiintf("%02x",
				       ((unsigned char *)obj1->attrs[i].content.ref.buffer)[j]);
		} else {
			priiintf("obj1: -");
		}
		if (obj2->attrs_count > i) {
			priiintf("\nobj2: ");
			for (j = 0; j < obj2->attrs[i].content.ref.length; j++)
				priiintf("%02x",
				       ((unsigned char *)obj2->attrs[i].content.ref.buffer)[j]);
		} else {
			priiintf("\nobj2: -");
		}

		priiintf("\nCmp: ");

		if (obj1->attrs_count == obj2->attrs_count) {
			if (obj1->attrs[i].content.ref.length > obj2->attrs[i].content.ref.length)
				cmp_len = obj1->attrs[i].content.ref.length;
			else
				cmp_len = obj2->attrs[i].content.ref.length;

			if (!memcmp(obj1->attrs[i].content.ref.buffer,
				    obj2->attrs[i].content.ref.buffer, cmp_len)) {
				priiintf("Same1\n");
			} else {
				priiintf("NO\n");
			}
		} else {
			priiintf("can not cmp\n");
		}
	}
}

static void pri_void_buf(void *buf, size_t len)
{
	if (buf == NULL)
		return;

	size_t i;
	for (i = 0; i < len; ++i)
		priiintf("%02x", ((unsigned char *)buf)[i]);
	priiintf("\n");
}

static void __attribute__((unused)) pri_obj_data(TEE_ObjectHandle object)
{
	void *data = NULL;
	TEE_ObjectInfo info;
	uint32_t cur_pos;
	TEE_Result ret;
	uint32_t count = 0;

	if (object == NULL)
		return;

	TEE_GetObjectInfo(object, &info);

	data = calloc(1, info.dataSize);
	if (data == NULL) {
		priiintf("Fail: pri_obj_data(mem)\n");
	}

	cur_pos = info.dataPosition;

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: pri_obj_data(seek beginning)\n");
		goto err;
	}

	ret = TEE_ReadObjectData(object, data, info.dataSize, &count);
	if (ret != TEE_SUCCESS || count != info.dataSize) {
		priiintf("Fail: pri_obj_data(read)\n");
		goto err;
	}

	ret = TEE_SeekObjectData(object, cur_pos, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: pri_obj_data(set back prev pos)\n");
		goto err;
	}

	pri_void_buf(data, info.dataSize);

err:
	free(data);
}

static void __attribute__((unused)) pri_obj_info(TEE_ObjectInfo info)
{
	priiintf("Info structure:\n");
	priiintf("dataPosition:  %u\n", info.dataPosition);
	priiintf("dataSize:      %u\n", info.dataSize);
	priiintf("handleFlags:   %u\n", info.handleFlags);
	priiintf("maxObjectSize: %u\n", info.maxObjectSize);
	priiintf("objectSize:    %u\n", info.objectSize);
	priiintf("objectType:    %u\n", info.objectType);
	priiintf("objectUsage:   %u\n", info.objectUsage);
}

static void gen_rsa_key_pair_and_save_read()
{
	priiintf("  ####   gen_rsa_key_pair_and_save_read   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle handler = NULL;
	TEE_ObjectHandle handler2 = NULL;
	size_t key_size = 512;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void *data;
	size_t data_len = 12;

	data = malloc(data_len);
	if (data == NULL)
		goto err;
	memset(data, 0x83, data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);

	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		priiintf("Fail: no mem\n");
		goto err;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		priiintf("Fail: no sup\n");
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, NULL, 0);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: bad para\n");
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 handler, data, data_len, NULL);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per creation\n");
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
				       &handler2);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per open\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(handler);
	TEE_CloseAndDeletePersistentObject(handler2);

	free(data);
}

static void gen_rsa_key_pair_and_copy_public()
{
	priiintf("  ####   gen_rsa_key_pair_and_copy_public   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = NULL;
	TEE_ObjectHandle rsa_pubkey = NULL;
	size_t key_size = 512;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);

	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		priiintf("Fail: no mem\n");
		goto err;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		priiintf("Fail: no sup\n");
		goto err;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_size, &rsa_pubkey);

	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		priiintf("Fail: no mem\n");
		goto err;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		priiintf("Fail: no sup\n");
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, NULL, 0);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: bad para\n");
		goto err;
	}

	TEE_CopyObjectAttributes(rsa_pubkey, rsa_keypair);

err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_FreeTransientObject(rsa_pubkey);
}

static void free_attr(TEE_Attribute *params, size_t count)
{
	size_t i;

	if (params == NULL)
		return;

	for (i = 0; i < count; ++i)
		free(params[i].content.ref.buffer);
}

static void popu_rsa_pub_key()
{
	priiintf("  ####   popu_rsa_pub_key   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle rsa_pubkey = NULL;
	size_t key_size = 512;
	TEE_Attribute *params = NULL;
	size_t param_count = 2;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_size, &rsa_pubkey);

	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		priiintf("Fail: no mem\n");
		goto err;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		priiintf("Fail: no sup\n");
		goto err;
	}

	params = TEE_Malloc(param_count * sizeof(TEE_Attribute), 0);
	if (params == NULL)
		goto err;

	// modulo
	params[0].attributeID = TEE_ATTR_RSA_MODULUS;
	params[0].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	if (params[0].content.ref.buffer == NULL)
		goto err;
	memset(params[0].content.ref.buffer, 0x84, KEY_IN_BYTES(key_size));
	params[0].content.ref.length = KEY_IN_BYTES(key_size);

	// pub exp
	params[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	params[1].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	if (params[1].content.ref.buffer == NULL)
		goto err;
	memset(params[1].content.ref.buffer, 0x85, KEY_IN_BYTES(key_size));
	params[1].content.ref.length = KEY_IN_BYTES(key_size);

	ret = TEE_PopulateTransientObject(rsa_pubkey, params, param_count);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: popu\n");
		goto err;
	}

err:
	free_attr(params, param_count);
	free(params);
	TEE_FreeTransientObject(rsa_pubkey);
}

static void data_stream_write_read()
{
	priiintf("  ####   data_stream_write_read   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle handler = NULL;
	TEE_ObjectHandle per_han = NULL;
	size_t key_size = 512;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void *write_data = NULL;
	void *read_data = NULL;
	size_t data_size = 50;
	uint32_t count = 0;

	write_data = calloc(1, data_size);
	if (write_data == NULL)
		goto err;
	read_data = calloc(1, data_size);
	if (read_data == NULL)
		goto err;

	/* gen random data */
	memset(write_data, 0x86, data_size);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);

	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		priiintf("Fail: no mem\n");
		goto err;
	}

	if (ret == TEE_ERROR_NOT_SUPPORTED) {
		priiintf("Fail: no sup\n");
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, NULL, 0);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: bad para\n");
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 handler, NULL, 0, &per_han);

	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per creation\n");
		goto err;
	}

	ret = TEE_WriteObjectData(per_han, write_data, data_size);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per write\n");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per seek\n");
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, data_size, &count);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per read\n");
		goto err;
	}

	if (count != data_size ||
	    memcmp(read_data, write_data, count)) {
		priiintf("Fail: read and written data doesn't match\n");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -count, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per seek\n");
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, data_size, &count);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per read\n");
		goto err;
	}

	if (count != data_size ||
	    memcmp(read_data, write_data, count)) {
		priiintf("Fail: read and written data doesn't match\n");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -count, TEE_DATA_SEEK_END);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per seek\n");
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, data_size, &count);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per read\n");
		goto err;
	}

	if (count != data_size ||
	    memcmp(read_data, write_data, count)) {
		priiintf("Fail: read and written data doesn't match\n");
		goto err;
	}
err:
	TEE_CloseAndDeletePersistentObject(per_han);
	TEE_CloseObject(handler);
	free(write_data);
	free(read_data);
}

static void pure_data_obj_and_truncate_and_write()
{
	priiintf("  ####   pure_data_obj_and_truncate_and_write   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle handler = NULL;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void *init_data = NULL;
	size_t init_data_len = 10;
	void *write_data = NULL;
	size_t write_data_size = 10;

	init_data = malloc(init_data_len);
	if (init_data == NULL)
		goto err;
	memset(init_data, 0x87, init_data_len);

	write_data = calloc(1, write_data_size);
	if (write_data == NULL)
		goto err;
	memset(write_data, 0x88, write_data_size);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags, NULL,
					 init_data, init_data_len, &handler);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per creation\n");
		goto err;
	}

	TEE_TruncateObjectData(handler, 20);

	ret = TEE_SeekObjectData(handler, 5, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per seek\n");
		goto err;
	}

	ret = TEE_WriteObjectData(handler, write_data, write_data_size);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: per write\n");
		goto err;
	}

err:
	TEE_CloseAndDeletePersistentObject(handler);
	free(init_data);
	free(write_data);
}

static void gen_rand_per_data_obj(TEE_ObjectHandle *gen_obj, size_t data_len)
{
	void *ID = NULL;
	size_t ID_len = 30;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META;
	void *init_data = NULL;
	TEE_Result ret;

	init_data = malloc(data_len);
	if (init_data == NULL) {
		priiintf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	memset(init_data, 0x89, data_len);

	ID = malloc(ID_len);
	if (ID == NULL) {
		priiintf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	memset(ID, 0x90, ID_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)ID, ID_len, flags, NULL,
					 init_data, data_len, gen_obj);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen_rand_data_obj(per create)\n");
		goto err;
	}

err:
	free(ID);
	free(init_data);
	return;
}

static void gen_RSA_per_obj_with_data(TEE_ObjectHandle *gen_obj, size_t data_len)
{
	TEE_Result ret;
	TEE_ObjectHandle handler = NULL;
	size_t key_size = 512;
	void *ID = NULL;
	size_t ID_len = 30;
	uint32_t flags = 0xffffffff ^ TEE_DATA_FLAG_EXCLUSIVE;
	void *init_data = NULL;

	init_data = malloc(data_len);
	if (init_data == NULL) {
		priiintf("Fail: gen_rand_data_obj(inti_data mem)\n");
		goto err;
	}
	memset(init_data, 0x91, data_len);

	ID = malloc(ID_len);
	if (ID == NULL) {
		priiintf("Fail: gen_rand_data_obj(ID mem)\n");
		goto err;
	}
	memset(ID, 0x92, ID_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen_RSA_per_obj_with_data(alloc)\n");
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, NULL, 0);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen_RSA_per_obj_with_data(gen key)\n");
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, ID, ID_len, flags, handler, init_data,
					 data_len, gen_obj);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen_RSA_per_obj_with_data(per create)\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(handler);
	free(ID);
	free(init_data);
}

static void gen_per_objs_and_iter_with_enum()
{
	priiintf("  ####   gen_per_objs_and_iter_with_enum   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle obj1 = NULL;
	TEE_ObjectHandle obj2 = NULL;
	TEE_ObjectHandle obj3 = NULL;
	TEE_ObjectHandle obj_rsa = NULL;
	TEE_ObjectEnumHandle iter_enum1 = NULL;
	TEE_ObjectEnumHandle iter_enum2 = NULL;
	TEE_ObjectInfo info;
	void *ID = NULL;
	size_t ID_len = TEE_OBJECT_ID_MAX_LEN;

	ID = malloc(ID_len);
	if (ID == NULL) {
		priiintf("Fail: gen_rand_data_obj(ID mem)\n");
		goto err;
	}

	gen_rand_per_data_obj(&obj1, 10);
	gen_rand_per_data_obj(&obj2, 20);
	gen_rand_per_data_obj(&obj3, 30);
	gen_RSA_per_obj_with_data(&obj_rsa, 50);

	if (obj1 == NULL || obj2 == NULL || obj3 == NULL || obj_rsa == NULL) {
		priiintf("Fail: create err\n");
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum1);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter alloc\n");
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum2);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter alloc\n");
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum1, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter start\n");
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum2, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter start\n");
		goto err;
	}

	ret = TEE_GetNextPersistentObject(iter_enum1, &info, ID, &ID_len);
	if (ret == TEE_ERROR_GENERIC) {
		priiintf("Fail: iter1 next\n");
		goto err;
	}

	for (;;) {
		ret = TEE_GetNextPersistentObject(iter_enum2, &info, ID, &ID_len);
		if (ret == TEE_SUCCESS) {
			/* nothing */
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			priiintf("Fail: get next\n");
			goto err;
		}
	}

	TEE_FreePersistentObjectEnumerator(iter_enum2);
	iter_enum2 = NULL;

	TEE_ResetPersistentObjectEnumerator(iter_enum1);

	for (;;) {
		ret = TEE_GetNextPersistentObject(iter_enum1, &info, ID, &ID_len);
		if (ret == TEE_SUCCESS) {
			/* nothing */
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			priiintf("Fail: get next\n");
			goto err;
		}
	}

err:
	TEE_CloseAndDeletePersistentObject(obj1);
	TEE_CloseAndDeletePersistentObject(obj2);
	TEE_CloseAndDeletePersistentObject(obj3);
	TEE_CloseAndDeletePersistentObject(obj_rsa);
	TEE_FreePersistentObjectEnumerator(iter_enum1);
	TEE_FreePersistentObjectEnumerator(iter_enum2);
	free(ID);
}

static void rename_per_obj_and_enum_and_open_renameObj()
{
	priiintf("  ####   rename_per_obj_and_enum_and_open_renameObj   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle object = NULL;
	TEE_ObjectHandle object2 = NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_ObjectEnumHandle iter_enum = NULL;
	TEE_ObjectInfo info;
	void *new_ID = NULL;
	size_t new_ID_len = 15;
	void *ret_ID = NULL;
	size_t ret_ID_len = TEE_OBJECT_ID_MAX_LEN;

	new_ID = malloc(new_ID_len);
	ret_ID = malloc(ret_ID_len);
	if (ret_ID == NULL || new_ID == NULL) {
		priiintf("Fail: malloc ID\n");
		goto err;
	}
	memset(new_ID, 0x93, new_ID_len);

	gen_rand_per_data_obj(&object, 20);
	if (object == NULL) {
		priiintf("Fail: gen rand obj\n");
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter alloc\n");
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: iter start\n");
		goto err;
	}

	for (;;) {
		ret = TEE_GetNextPersistentObject(iter_enum, &info, ret_ID, &ret_ID_len);
		if (ret == TEE_SUCCESS) {
			/* continue */
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			priiintf("Fail: get next\n");
			goto err;
		}
	}

	ret = TEE_RenamePersistentObject(object, new_ID, new_ID_len);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: renam\n");
		goto err;
	}

	TEE_ResetPersistentObjectEnumerator(iter_enum);

	for (;;) {
		ret = TEE_GetNextPersistentObject(iter_enum, &info, ret_ID, &ret_ID_len);
		if (ret == TEE_SUCCESS) {
			/* continue */
		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			priiintf("Fail: get next\n");
			goto err;
		}
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)ret_ID, ret_ID_len, flags,
				       &object2);

	if (ret != TEE_ERROR_ACCESS_CONFLICT) {
		priiintf("Fail: should return access denied on secondary open\n");
		goto err;
	}

err:
	TEE_CloseObject(object);

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)ret_ID, ret_ID_len, flags,
				       &object2);
	if (ret != TEE_SUCCESS)
		priiintf("Fail: open persistent\n");

	TEE_CloseAndDeletePersistentObject(object2);
	TEE_FreePersistentObjectEnumerator(iter_enum);
	free(ret_ID);
	free(new_ID);
}

static void gen_des_key_56_112_168()
{
	priiintf("  ####   gen_des_key_56_112_168   ####\n");

	TEE_Result ret;
	TEE_ObjectHandle des = NULL;
	TEE_ObjectHandle des3_112 = NULL;
	TEE_ObjectHandle des3_168 = NULL;

	/* des */
	ret = TEE_AllocateTransientObject(TEE_TYPE_DES, 56, &des);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: des alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(des, 56, NULL, 0);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen des\n");
		goto err;
	}

	/* des3 112 */
	ret = TEE_AllocateTransientObject(TEE_TYPE_DES3, 112, &des3_112);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: des3_112 alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(des3_112, 112, NULL, 0);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen des3_112\n");
		goto err;
	}

	/* des3 168 */
	ret = TEE_AllocateTransientObject(TEE_TYPE_DES3, 168, &des3_168);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: des3_168 alloc\n");
		goto err;
	}

	ret = TEE_GenerateKey(des3_168, 168, NULL, 0);
	if (ret != TEE_SUCCESS) {
		priiintf("Fail: gen des3_168\n");
		goto err;
	}

err:
	TEE_FreeTransientObject(des);
	TEE_FreeTransientObject(des3_112);
	TEE_FreeTransientObject(des3_168);
	return;
}

#ifndef TA_STORAGE_TEST
int main()
{
	int start_count = 1;
#else
int ta_storage_test(int start_count)
{
#endif
	int count;
	openlog(NULL, 0, 0);



	priiintf(" #!# Start test #!#\n");
	count = start_count;
	while (count--)
		rename_per_obj_and_enum_and_open_renameObj();

	count = start_count;
	while (count--)
		gen_rsa_key_pair_and_save_read();

	count = start_count;
	while (count--)
		gen_rsa_key_pair_and_copy_public();

	count = start_count;
	while (count--)
		popu_rsa_pub_key();

	count = start_count;
	while (count--)
		data_stream_write_read();

	count = start_count;
	while (count--)
		pure_data_obj_and_truncate_and_write();

	count = start_count;
	while (count--)
		gen_per_objs_and_iter_with_enum();

	count = start_count;
	while (count--)
		rename_per_obj_and_enum_and_open_renameObj();

	count = start_count;
	while (count--)
		gen_des_key_56_112_168();

	priiintf(" #!# Test has reached end! #!#\n");

	closelog();
	return 0;
}
