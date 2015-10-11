/*****************************************************************************
** Copyright (C) 2015 Tanel Dettenborn                                      **
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

#include "tee_internal_api.h"
#include "tee_logging.h"

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
 * \brief The key_chain_data struct
 * Structure to hold all of the key hirarachy needed to protect the keys
 */
struct key_chain_data {
	uint32_t key_count;	/*!< The number of keys in the chain */
	uint32_t key_len;	/*!< The size of each key */
	uint8_t keys[];		/*!< The keys themselves */
};

/* GP framework is defining session context parameter for opensession, invokecmd and closesession
 * function. This context is allocated and placed into this parameter. */
struct session_ctx {
	uint8_t session_type;
};

/* VaLid session types */
#define OMS_CTX_TYPE_CREATE_ROOT_DIR    0x23
#define OMS_CTX_TYPE_DO_CRYPTO          0x24

/* Omnishare TEE spesific RSA key is generated once and only once at create entry point function.
 * RSA key is saved into secure storage (ss). */
static TEE_ObjectHandle oms_RSA_keypair_object;

/* Cached root directory AES key */
static TEE_ObjectHandle oms_AES_key_object;

/* Helper macro for converting bits to bytes. */
#define BYTES2BITS(bytes)	(bytes * 8)

/* This is defining the key sizes of omnishare. */
#define OMS_RSA_MODULO_SIZE	128
#define OMS_AES_SIZE		32
#define OMS_AES_IV_SIZE		16

/* Corresponding IV vector. For simplicity sake, the IV vector in every AES operation is kept
 * as a zero and this with AES CTR mode is very very unsecure, Very bad. */
static uint8_t oms_aes_iv[OMS_AES_IV_SIZE];


/* Setting TA properties */
#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
{ 0x12345678, 0x8765, 0x4321, { 'O', 'M', 'N', 'I', 'S', 'H', 'A', 'R'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif







/*
 *
 * Omnishare specific functions
 *
 */

/*!
 * \brief wrap_oms_RSA_operation
 * Function is using OmniShare TA specific key for executing RSA operation.
 * \param mode Supported mode are TEE_MODE_ENCRYPT and TEE_MODE_DECRYPT
 * \param in_data Input data
 * \param in_data_len Input data length
 * \param out_data Ouput data
 * \param out_data_len Output data length
 * \return GP return values.
 */
static TEE_Result wrap_oms_RSA_operation(TEE_OperationMode mode,/*TEE_OperationMod:TEECoreAPIp-138*/
					 void *in_data,
					 uint32_t in_data_len,
					 void *out_data,
					 uint32_t *out_data_len)
{
	TEE_OperationHandle rsa_operation = NULL; /* Opaque handle. */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* Allocating RSA operation. TEE_AllocateOperation: TEE Core API p-140 */
	tee_rv = TEE_AllocateOperation(&rsa_operation, TEE_ALG_RSAES_PKCS1_V1_5,
				       mode, BYTES2BITS(OMS_RSA_MODULO_SIZE));
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", tee_rv);
		goto err;
	}

	/* Setting operation key. RSA key handle is opened in create entry point.
	 * TEE_SetOperationKey: TEE Core API p-149 */
	tee_rv = TEE_SetOperationKey(rsa_operation, oms_RSA_keypair_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", tee_rv);
		goto err;
	}

	if (mode == TEE_MODE_ENCRYPT) {

		/* Encrypting. TEE_AsymmetricDecrypt: TEE Core API p-167 */
		tee_rv = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data,
					       in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed : 0x%x", tee_rv);
			goto err;
		}

	} else if (mode == TEE_MODE_DECRYPT) {

		/* Decrypting. TEE_AsymmetricDecrypt: TEE Core API p-167 */
		tee_rv = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data,
					       in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt failed : 0x%x", tee_rv);
			goto err;
		}

	} else {
		OT_LOG(LOG_ERR, "Unkown RSA mode type");
		goto err;
	}

err:
	/* Freeing operation. TEE_FreeOperation: TEE Core API p-144 */
	TEE_FreeOperation(rsa_operation);
	return tee_rv;
}

/*!
 * \brief wrap_aes_operation
 * Wraping an AES operation. Function will allocated operation and setting a key. Then it
 * will init a cipher operation and encrypt or decrypt data.
 * \param key GP key object. Key must be initialized
 * \param mode Valid mode are TEE_MODE_ENCRYPT and TEE_MODE_DECRYPT
 * \param in_data
 * \param in_data_len
 * \param out_data
 * \param out_data_len
 * \return GP return values.
 */
static TEE_Result wrap_aes_operation(TEE_ObjectHandle key, /* Opaque handle */
				     TEE_OperationMode mode, /* TEE_OperationMode: TEECoreAPIp-138*/
				     void *IV,
				     uint32_t IV_len,
				     void *in_data,
				     uint32_t in_data_len,
				     void *out_data,
				     uint32_t *out_data_len)
{
	TEE_OperationHandle aes_operation = NULL; /* Opaque handle */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* Allocating RSA operation. TEE_AllocateOperation: TEE Core API p-140 */
	tee_rv = TEE_AllocateOperation(&aes_operation,
				       TEE_ALG_AES_CTR, mode, BYTES2BITS(OMS_AES_SIZE));
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed (TEE_ALG_AES_CTR) : 0x%x", tee_rv);
		goto err;
	}

	/* Setting operation key. TEE_SetOperationKey: TEE Core API p-149 */
	tee_rv = TEE_SetOperationKey(aes_operation, key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", tee_rv);
		goto err;
	}

	/* Initing cipher operation.
	 * TEE_CipherInit: TEE Core API p-155 */
	TEE_CipherInit(aes_operation, IV, IV_len);

	/* Omnishare TA is supporting only small files and therefore there is no need for
	 * "pipeline" style encrypting or decrypting. The do final can do it in one go
	 * TEE_CipherDoFinal: TEE Core API p-157 */
	tee_rv = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data, out_data_len);
	if (tee_rv != TEE_SUCCESS)
		OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", tee_rv);

err:
	/* Freeing operation. TEE_FreeOperation: TEE Core API p-144 */
	TEE_FreeOperation(aes_operation);
	return tee_rv;
}

/*!
 * \brief create_oms_aes_key
 * Generates an AES key.
 * \param aes_key If buffer is not NULL, aes key is copied into this buffer
 * \param aes_key_size If buffer is not NULL, aes aes_key buffer size. Size is updated.
 * \param aes_key_object If parameter is not NULL, new aes key object is allocated with an aes key.
 * Note: aes_key_object should be freed after usage.
 * \return GP return values.
 */
static TEE_Result create_oms_aes_key(uint8_t *aes_key,
				     uint32_t *aes_key_size,
				     TEE_ObjectHandle *aes_key_object) /* Opaque handle */
{
	TEE_ObjectHandle new_aes_key_object = NULL; /* Opaque handle */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* Function is generating a transient object for AES key
	 * TEE_AllocateTransientObject: TEE Core API p-102 */
	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES,
					     BYTES2BITS(OMS_AES_SIZE), &new_aes_key_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		goto err;
	}

	/* Generating a key.
	 * TEE_GenerateKey: TEE Core API p-114 */
	tee_rv = TEE_GenerateKey(new_aes_key_object, BYTES2BITS(OMS_AES_SIZE), NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_Gener ateKey failed : 0x%x", tee_rv);
		goto err;
	}

	/* If aes key buffer is not NULL, we need to get the "raw" key from GP object */
	if (aes_key) {

		/* Checking if the output buffer is big enough. */
		if (aes_key_size == NULL) {
			OT_LOG(LOG_ERR, "Aes key buffer is not NULL, but key size is NULL");
			tee_rv = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		/* Getting the key from GP object. It is getting the key from AES transient object
		 * that we allocated at the beginning of function. No extra step for getting key,
		 * because object usage is not restricted by default
		 * TEE_GetObjectBufferAttribute: TEE Core API p-99 */
		tee_rv = TEE_GetObjectBufferAttribute(new_aes_key_object, TEE_ATTR_SECRET_VALUE,
						      aes_key, aes_key_size);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed: 0x%x", tee_rv);
			goto err;
		}
	}

	/* If caller want to have a handle to newly created key. If not, free newly created object*/
	if (aes_key_object)
		*aes_key_object = new_aes_key_object;
	else
		TEE_FreeTransientObject(new_aes_key_object); /* see below at err -label */

	return tee_rv;

err:
	/* If something went wrong, free all resources.
	 * TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(new_aes_key_object);
	if (aes_key && aes_key_size) {
		/* Setting aes key buffer to zero. This is just a cation precaution
		 * TEE_MemFill: TEE Core API p-88 */
		TEE_MemFill(aes_key, 0, *aes_key_size);
		*aes_key_size = 0;
	}
	return tee_rv;
}

/*!
 * \brief get_dir_key
 * Function is decrypting omnishare key chain. Key chain the first key is cached AES (provided
 * in open session function)
 * \param paramTypes
 * \param params
 * \param dir_key last key of the chain. User should free it after usage
 * \return GP return values.
 */
static TEE_Result get_dir_key(uint32_t paramTypes,
			       TEE_Param *params, /* TEE_Param: TEE Core API p-36 */
			       TEE_ObjectHandle *dir_key) /* Opaque handle */
{
	uint32_t next_aes_key_size = OMS_AES_SIZE;
	uint8_t next_aes_key[OMS_AES_SIZE];
	TEE_Attribute tee_aes_attr = {0}; /* TEE_Attribute: TEE Core API p-92 */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */
	struct key_chain_data *key_chain;
	uint32_t i = 0;

	/* Function is returning a handle to direcotry key and it will be allocated now.
	 * All directory keys are AES keys.
	 * TEE_AllocateTransientObject: TEE Core API p-102 */
	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, BYTES2BITS(OMS_AES_SIZE), dir_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto err;
	}

	/* Key chain first key is cached AES key, which were provided at open session function.
	 * Copiying the first AES key into object handle
	 * TEE_CopyObjectAttributes: TEE Core API p-112 */
	TEE_CopyObjectAttributes(*dir_key, oms_AES_key_object);

	/* If no key chain is provided, the first directory is created */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_NONE)
		return tee_rv;

	/* Something is passed at index zero. If it is a key chain, it should be buffer parameter
	 * and it should be as an input parameter */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Key chain is at index ZERO and it is a buffe parameter */
	key_chain = (struct key_chain_data *)params[0].memref.buffer;

	for (i = 0; i < key_chain->key_count; i++) {

		/* We have more keys than one. Lets read next key from key chain and decrypt it */
		next_aes_key_size = OMS_AES_SIZE;
		tee_rv = wrap_aes_operation(*dir_key, TEE_MODE_DECRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
					    key_chain->keys + (i * OMS_AES_SIZE), OMS_AES_SIZE,
					    next_aes_key, &next_aes_key_size);
		if (tee_rv != TEE_SUCCESS)
			goto err;

		/* Key chain next key is encrypted with the key what we have decrypted into
		 * next_aes_key -buffer. We need to use that key for next key or it even
		 * might be the last key. Now we could create a new transient object and
		 * populate that object, but we can reuse the the same object (allocated at
		 * the beginning of function). First we need to reset that object handle
		 * TEE_ResetTransientObject: TEE Core API p-106 */
		TEE_ResetTransientObject(*dir_key);

		/* Initing a TEE attribute. TEE_InitRefAttribute: TEE Core API p-111 */
		TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE,
				     next_aes_key, next_aes_key_size);

		/* Populating an uninitialzed transient object with previously decrypted key
		 * TEE_PopulateTransientObject: TEE Core API p-107 */
		tee_rv = TEE_PopulateTransientObject(*dir_key, &tee_aes_attr, 1);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
			goto err;
		}
	}

	return tee_rv;

err:
	/* If something went wrong, free all resources
	 * TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(*dir_key);
	return tee_rv;
}

/*!
 * \brief do_crypto_create_dir_key
 * Creates an AES key and encrypt it with directory key. This function is called when new
 * directory is created.
 * \param file_key
 * \param params
 * \return GP return values.
 */
static TEE_Result do_crypto_create_dir_key(TEE_ObjectHandle dir_key, /* Opaque handle */
					   TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	uint32_t aes_key_size = OMS_AES_SIZE;
	uint8_t aes_key[OMS_AES_SIZE];
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* First of all it need to be check if the output buffer at index three is big enough
	 * If is not big enough, return TEE_ERROR_SHORT_BUFFER error code and required size */
	if (aes_key_size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Buffer is big enough. Create key */
	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, NULL);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Encrypt the key into output buffer */
	return wrap_aes_operation(dir_key, TEE_MODE_ENCRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
				  aes_key, aes_key_size,
				  params[3].memref.buffer, (uint32_t *)&params[3].memref.size);
}

/*!
 * \brief do_crypto_encrypt_file
 * Creates a file key and using it for encrypting the file. The file key is placed to beginning
 * of the file
 * \param dir_key
 * \param params
 * \return
 */
static TEE_Result do_crypto_encrypt_file(TEE_ObjectHandle dir_key, /* Opaque handle */
					 TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	uint32_t aes_key_size = OMS_AES_SIZE;
	uint8_t aes_key[OMS_AES_SIZE];
	TEE_ObjectHandle new_file_key = NULL; /* Opaque handle */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */
	uint32_t write_bytes = params[3].memref.size;

	/* If output buffer is big enough to hold the encrypted key and encrypted data.
	 * encrypted data is same size as a plain data. If buffer is not big enough,
	 * return TEE_ERROR_SHORT_BUFFER and required size */
	if (aes_key_size + params[2].memref.size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size + params[2].memref.size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Create new file key */
	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, &new_file_key);
	if (tee_rv != TEE_SUCCESS)
		goto out;

	/* Encrypt file key into beginning of the file */
	tee_rv = wrap_aes_operation(dir_key, TEE_MODE_ENCRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
				    aes_key, aes_key_size,
				    params[3].memref.buffer, &write_bytes);
	if (tee_rv != TEE_SUCCESS)
		goto out;

	/* Reduce the ouput buffer size, because we just wrote the key into output buffer */
	params[3].memref.size -= write_bytes;

	/* Encrypt the plain data with newly created key */
	tee_rv = wrap_aes_operation(new_file_key, TEE_MODE_ENCRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
				    params[2].memref.buffer, params[2].memref.size,
			(uint8_t *)params[3].memref.buffer + write_bytes,
			(uint32_t *)&params[3].memref.size);

	/* Output buffer size is holding the "encrypted" plain data size, but this buffer is
	 * containing the file key at the beginning of file and therefore we are adding also
	 * encrypted key size into this */
	params[3].memref.size += write_bytes;
out:
	/* TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(new_file_key);
	return tee_rv;
}

/*!
 * \brief do_crypto_decrypt_file
 * Reading AES key from the beginning of file and using it for decrypting the file.
 * \param dir_key
 * \param params
 * \return
 */
static TEE_Result do_crypto_decrypt_file(TEE_ObjectHandle dir_key, /* Opaque handle */
					 TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	uint32_t aes_key_size = OMS_AES_SIZE;
	uint8_t aes_key[OMS_AES_SIZE];
	TEE_ObjectHandle file_key = NULL;
	TEE_Attribute tee_aes_attr = {0}; /* TEE_Attribute: TEE Core API p-92 */
	TEE_Result tee_rv; /* Return values: TEE Core API p-31 */

	/* Zero is not a valid input size */
	if (params[2].memref.size == 0) {
		OT_LOG(LOG_ERR, "Input buffer too short");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* If output buffer is big enough. If not, return TEE_ERROR_SHORT_BUFFER and required size*/
	if (params[2].memref.size - aes_key_size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size + params[2].memref.size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Decrypt file key with directory key */
	tee_rv = wrap_aes_operation(dir_key, TEE_MODE_DECRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
				    params[2].memref.buffer, OMS_AES_SIZE,
				    aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* We need to use fresly decrypted key and therefore we are needing a object handle, which
	 * can be populated with decrypted key.
	 * TEE_AllocateTransientObject: TEE Core API p-102 */
	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, BYTES2BITS(OMS_AES_SIZE), &file_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		return tee_rv;
	}

	/* Initing a TEE attribute. TEE_InitRefAttribute: TEE Core API p-111 */
	TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	/* Populating allocated object. TEE_PopulateTransientObject: TEE Core API p-107 */
	tee_rv = TEE_PopulateTransientObject(file_key, &tee_aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		goto out;
	}

	/* Decrypting the file */
	tee_rv = wrap_aes_operation(file_key, TEE_MODE_DECRYPT, oms_aes_iv, OMS_AES_IV_SIZE,
				    (uint8_t *)params[2].memref.buffer + OMS_AES_SIZE,
			params[2].memref.size - OMS_AES_SIZE,
			params[3].memref.buffer, (uint32_t *)&params[3].memref.size);

out:
	/* TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(file_key);
	return tee_rv;
}

/*!
 * \brief do_crypto
 * Omnishare crypto operations. Function is containg a common functionality of crypto operations
 * and crypto operation parser, which will be calling spesific crypto operation.
 * Note: Crypto operations are not saving anything into secure storage.
 * \param paramTypes
 * \param params
 * \return GP return values.
 */
static TEE_Result do_crypto(uint32_t paramTypes,
			    TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	TEE_ObjectHandle dir_key = NULL; /* Opaque handle */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* ParamTypes parameter is used for checking parameters type.
	 * It just agreed between CA and TA. */

	/* Crypto operation have commons following parameters. Checking parameters one by one
	 * for purpose of printing debug message
	 *
	 * TEE_PARAM_TYPE_GET: TEE Core API p-48
	 * TEE_PARAM_TYPE_XXX: TEE Core API p-37*/
	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 1: expexted value input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((params[1].value.a == OM_OP_ENCRYPT_FILE ||
	     params[1].value.a == OM_OP_DECRYPT_FILE) &&
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 2: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 3: expexted memref output");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Get the current directory key */
	tee_rv = get_dir_key(paramTypes, params, &dir_key);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Do spesific crypto operation. Operation type is at index 1 and it is in value A member */
	switch (params[1].value.a) {
	case OM_OP_CREATE_DIRECTORY_KEY:
		tee_rv = do_crypto_create_dir_key(dir_key, params);
		break;

	case OM_OP_ENCRYPT_FILE:
		tee_rv = do_crypto_encrypt_file(dir_key, params);
		break;

	case OM_OP_DECRYPT_FILE:
		tee_rv = do_crypto_decrypt_file(dir_key, params);
		break;
	default:
		OT_LOG(LOG_ERR, "Unknown crypto command ID");
		tee_rv = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	/* TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(dir_key);
	return tee_rv;
}

/*!
 * \brief create_root_key
 * Creates an AES key. This key will be the first key of key chains. It will be encrypted with
 * omnishare spesific RSA key.
 * \param paramTypes
 * \param params
 * \return GP return values
 */
static TEE_Result create_root_key(uint32_t paramTypes,
				  TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	uint32_t aes_key_size = OMS_AES_SIZE;
	uint8_t aes_key[OMS_AES_SIZE];
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* ParamTypes parameter is used for checking parameters type.
	 * It just agreed between CA and TA. */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memref output");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if the output buffer at index zero is big enough.
	 * If is not big enough, return TEE_ERROR_SHORT_BUFFER error code and required size */
	if (OMS_RSA_MODULO_SIZE > params[0].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer is too short");
		params[0].memref.size = OMS_RSA_MODULO_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Create AES key */
	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, NULL);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Encrypt fresly created AES key with RSA key and place result into output buffer */
	return wrap_oms_RSA_operation(TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				      params[0].memref.buffer, (uint32_t *)&params[0].memref.size);
}

/*!
 * \brief set_oms_aes_key
 * Function is using omnishare spesific RSA key for decrypting the data blob. Data blob is
 * containing AES key (the first key of the key chains == root key)
 * \param params
 * \return GP return values
 */
static TEE_Result set_oms_aes_key(TEE_Param *params) /* TEE_Param: TEE Core API p-36 */
{
	uint32_t aes_key_size = OMS_RSA_MODULO_SIZE;
	uint8_t aes_key[OMS_RSA_MODULO_SIZE];
	TEE_Attribute tee_aes_attr = {0}; /* TEE_Attribute: TEE Core API p-92 */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* Expected input buffer should be at least as big as omnishare RSA modulo.
	 * Input buffer is at index zero */
	if (OMS_RSA_MODULO_SIZE > params[0].memref.size) {
		OT_LOG(LOG_ERR, "RSA decrypted AES key is wrong sized");
		return TEE_ERROR_GENERIC;
	}

	/* Decrypt input buffer with omnishare RSA key */
	tee_rv = wrap_oms_RSA_operation(TEE_MODE_DECRYPT, params[0].memref.buffer,
			params[0].memref.size, aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Decrypted result should be omnishare used AES key size */
	if (aes_key_size != OMS_AES_SIZE) {
		OT_LOG(LOG_ERR, "RSA decrypted AES key is wrong sized");
		return TEE_ERROR_GENERIC;
	}

	/* Next we are initing the first key of keychain. It is previously decrypted AES key */

	/* TEE_AllocateTransientObject: TEE Core API p-102 */
	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES,
					     BYTES2BITS(OMS_AES_SIZE), &oms_AES_key_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		return tee_rv;
	}

	/* Initing a TEE attribute. TEE_InitRefAttribute: TEE Core API p-111 */
	TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	/* Populating allocated object. TEE_PopulateTransientObject: TEE Core API p-107 */
	tee_rv = TEE_PopulateTransientObject(oms_AES_key_object, &tee_aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		/* TEE_FreeTransientObject: TEE Core API p-105 */
		TEE_FreeTransientObject(oms_AES_key_object);
	}

	/* If everything went fine, now we have open to global object handle for ready to use.
	 * One is a RSA key and one is AES key */

	return tee_rv;
}






/*
 *
 * TEE Core API defined five entry point functions
 *
 */

/* TA_CreateEntryPoint: TEE Core API p-43 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	char oms_rsa_keypair_id[] = "oms_rsa_keypair_object_id";
	TEE_ObjectHandle rsa_keypair = NULL; /* Opaque handle */
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */

	/* Create entry point is trying to find the omnishare spesific RSA key and open it. If
	 * key is not found, the key is created and saved into secure storage */

	/* Using open persisten object for determing if RSA key exist. We also could be using
	 * persistent storage enumerator for this task.
	 * TEE_OpenPersistentObject: TEE Core API p-117 */
	tee_rv = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					  oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
					  0, &oms_RSA_keypair_object);
	if (tee_rv == TEE_SUCCESS) {
		/* RSA key exist. No action needed. Note: Leaving handle open. */
		return tee_rv;
	} else if (tee_rv == TEE_ERROR_ITEM_NOT_FOUND) {
		/* OK: It just is that the object is not found and therefore it need to be created*/
	} else {
		OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", tee_rv);
		return tee_rv;
	}

	/* If we end up here, the key did not exist in secure storage. */

	/* Creating a transient object for the new RSA key. Transient object is needed, because
	 * generate key is accepting only transient objects
	 * TEE_AllocateTransientObject: TEE Core API p-102 */
	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					     BYTES2BITS(OMS_RSA_MODULO_SIZE), &rsa_keypair);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto out;
	}

	/* Generating the key.
	 * TEE_GenerateKey: TEE Core API p-114 */
	tee_rv = TEE_GenerateKey(rsa_keypair, BYTES2BITS(OMS_RSA_MODULO_SIZE), NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_GenerateKey failed: 0x%x", tee_rv);
		goto out;
	}

	/* Saving key into secure storage and leaving the handle open
	 * TEE_CreatePersistentObject: TEE Core API p-119 */
	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					    oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
					    0, rsa_keypair, NULL, 0, &oms_RSA_keypair_object);
	if (tee_rv != TEE_SUCCESS)
		OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", tee_rv);

out:
	/* Transient object is not any more needed. Lets free it and not leak the memory
	 * TEE_FreeTransientObject: TEE Core API p-105 */
	TEE_FreeTransientObject(rsa_keypair);
	return tee_rv;
}

/* TA_DestroyEntryPoint: TEE Core API p-43 */
void TA_EXPORT TA_DestroyEntryPoint(void)
{
	/* TA is going to be destroyed. It is a good practice close all our resources eg.
	 * persistent object. We have oms_RSA_keypair_object open and it need to be closed
	 * TEE_CloseObject: TEE Core API p-101 */
	TEE_CloseObject(oms_RSA_keypair_object);
}

/* TA_OpenSessionEntryPoint: TEE Core API p-44 */
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], /* TEE_Param: TEE Core API p-36*/
                                              void **sessionContext)
{
	TEE_Result tee_rv = TEE_SUCCESS; /* Return values: TEE Core API p-31 */
	struct session_ctx *new_session_ctx = NULL;

	/* Session context is controlled by TEE framework. It will be passed as a function
	 * parameter in invokeCMD and closeSession functions. Omnishare is using this parameter
	 * for determing, which session is invoking command or closing session. */
	new_session_ctx = TEE_Malloc(sizeof(struct session_ctx), 0);
	if (new_session_ctx == NULL) {
		OT_LOG(LOG_ERR, "Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Using paramTypes for determing the open session type (create root key or crypto
	 * operation). This is one way of doing this, because in this case we have only two
	 * possible options. Another way is just use one of the parameters for determining
	 * open session type eg paramType 3 is value parameter */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 2) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 3) == TEE_PARAM_TYPE_NONE) {
		new_session_ctx->session_type = OMS_CTX_TYPE_CREATE_ROOT_DIR;
		tee_rv = TEE_SUCCESS;

	} else if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT &&
		   TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 2) == TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 3) == TEE_PARAM_TYPE_NONE) {
		new_session_ctx->session_type = OMS_CTX_TYPE_DO_CRYPTO;
		tee_rv = set_oms_aes_key(params);

	} else {
		OT_LOG(LOG_ERR, "Bad parameter at params: not know combination : 0x%x", paramTypes);
		tee_rv = TEE_ERROR_BAD_PARAMETERS;
	}

	/* Session is not opened if return value going to be something else than TEE_SUCCESS and
	 * in that case we need all memory that we are allocated in Open Session function */
	if (tee_rv != TEE_SUCCESS)
		 /* TEE_Free: TEE Core API p-86 */
		TEE_Free(new_session_ctx);
	else
		*sessionContext = new_session_ctx;

	return tee_rv;
}

/* TA_InvokeCommandEntryPoint: TEE Core API p-46 */
void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	struct session_ctx *session_ctx = sessionContext;

	/* Free oms_AES_key_object if session type is OMS_CTX_TYPE_DO_CRYPTO */
	if (session_ctx->session_type == OMS_CTX_TYPE_DO_CRYPTO)
		/* TEE_FreeTransientObject: TEE Core API p-105 */
		TEE_FreeTransientObject(oms_AES_key_object);

	/* Session context need to be freed, because this session is not any more are contacting
	 * TEE. Because destroy entrypoint is Void function, this is a last place where session
	 * context can be freed or else we would leak a memory
	 * TEE_Free: TEE Core API p-86 */
	TEE_Free(session_ctx);
}

/* TA_InvokeCommandEntryPoint: TEE Core API p-47 */
TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])/*TEE_Param: TEE Core API p-36*/
{
	sessionContext = sessionContext; /* Not used */

	/* Invoke CMD is just a commandID parse. */
	switch (commandID) {
	case CMD_CREATE_ROOT_KEY:
		return create_root_key(paramTypes, params);

	case CMD_DO_CRYPTO:
		return do_crypto(paramTypes, params);

	default:
		OT_LOG(LOG_ERR, "Unknown command ID");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
