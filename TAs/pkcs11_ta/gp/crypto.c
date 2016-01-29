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

#include "commands.h"
#include "crypto.h"
#include "object.h"
#include "pkcs11_session.h"
#include "slot_token.h"
#include "tee_internal_api.h"
#include "token_conf.h"
#include "utils.h"

#define BIGGEST_RSA_KEY_IN_BYTES	256
#define BIGGEST_HASH_OUTUPUT_IN_BYTES	64
#define TEE_RSA_PRIVATE_KEY		0x5A
#define TEE_RSA_PUBLIC_KEY		0x5B
#define BITS_TO_BYTES(bits) (bits / 8)
#define BYTES_TO_BITS(bytes) (bytes * 8)

/* For readibility sake, parameters are collected into struct */
struct init_crypto_op {
	CK_MECHANISM mech_attr;
	CK_OBJECT_HANDLE key;
	TEE_ObjectHandle key_object;
	uint32_t crypto_type;
	struct pkcs11_session *session;
};

struct crypto_op {
	struct pkcs11_session *session;
	uint32_t crypto_type;
	void *src;
	uint32_t src_len;
	void *dst;
	uint32_t dst_len;
};


static uint32_t hash_output_length(CK_MECHANISM_TYPE hash)
{
	switch (hash) {
	case CKM_MD5:
	case CKM_MD5_RSA_PKCS:
	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
		return 16;

	case CKM_SHA_1:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
		return 20;

	case CKM_SHA256:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		return 32;

	case CKM_SHA384:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
		return 48;

	case CKM_SHA512:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		return 64;

	default:
		return 0;
	}
}

static void map_tee_buf_attr2ck_attr(obj_func_atribute tee_attr_id,
				     TEE_Attribute *tee_attr,
				     CK_ATTRIBUTE *ck_attr)
{
	tee_attr->attributeID = tee_attr_id;
	tee_attr->content.ref.buffer = ck_attr->pValue;
	tee_attr->content.ref.length = ck_attr->ulValueLen;
}

static void free_tee_attrs(TEE_Attribute *tee_attrs,
			   uint32_t tee_attrs_count)
{
	uint32_t i;

	for (i = 0; i < tee_attrs_count; i++)
		TEE_Free(tee_attrs[i].content.ref.buffer);

	TEE_Free(tee_attrs);
}

/* This function is written for AES key only. With small efforts this could be
 * modified as a general symmetric key object creation function */
static CK_RV map_sym_secret_key_object(struct init_crypto_op *crypto_op,
				       TEE_Attribute **tee_attrs,
				       uint32_t *tee_attrs_count,
				       uint32_t *key_size)
{
	CK_ATTRIBUTE ck_attr = {0};
	CK_RV ck_rv = CKR_OK;

	/* Malloc space for TEE_Attribute */
	*tee_attrs_count = 1;
	*tee_attrs = TEE_Malloc(sizeof(TEE_Attribute), 0);
	if (*tee_attrs == NULL)
		return CKR_GENERAL_ERROR;

	/* Must contain CKA_VALUE attribute */
	ck_rv = get_attr_from_object(crypto_op->key_object, CKA_VALUE, &ck_attr);
	if (ck_rv != CKR_OK)
		goto err;

	map_tee_buf_attr2ck_attr(TEE_ATTR_SECRET_VALUE, *tee_attrs, &ck_attr);

	/* Key size */
	*key_size = BYTES_TO_BITS(ck_attr.ulValueLen);

	return ck_rv;

err:
	free_tee_attrs(*tee_attrs, *tee_attrs_count);
	return ck_rv;
}

/* This function is written for AES key only. With small efforts this could be
 * modified as a general symmetric key object creation function */
static CK_RV map_AES_secret_key_object(struct init_crypto_op *crypto_op,
				       TEE_Attribute **tee_attrs,
				       uint32_t *tee_attrs_count,
				       object_type *tee_object_type,
				       uint32_t *key_size)
{
	*tee_object_type = TEE_TYPE_AES;
	return map_sym_secret_key_object(crypto_op, tee_attrs, tee_attrs_count, key_size);
}

static CK_RV map_HMAC_secret_key_object(struct init_crypto_op *crypto_op,
				       TEE_Attribute **tee_attrs,
				       uint32_t *tee_attrs_count,
				       object_type *tee_object_type,
				       uint32_t *key_size)
{
	switch (crypto_op->mech_attr.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
		*tee_object_type = TEE_TYPE_HMAC_MD5;
		break;

	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
		*tee_object_type = TEE_TYPE_HMAC_SHA1;
		break;

	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		*tee_object_type = TEE_TYPE_HMAC_SHA256;
		break;

	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
		*tee_object_type = TEE_TYPE_HMAC_SHA384;
		break;

	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		*tee_object_type = TEE_TYPE_HMAC_SHA512;
		break;

	default:
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return map_sym_secret_key_object(crypto_op, tee_attrs, tee_attrs_count, key_size);
}

static CK_RV map_RSA_key_object(struct init_crypto_op *crypto_op,
				TEE_Attribute **tee_attrs,
				uint32_t *tee_attrs_count,
				object_type *tee_object_type,
				uint32_t *key_size,
				uint8_t rsa_type)
{
	CK_ATTRIBUTE ck_attr = {0};
	TEE_Attribute *attrs;
	CK_RV ck_rv = CKR_OK;

	/* Malloc space for TEE_Attribute */
	*tee_attrs_count = rsa_type == TEE_RSA_PRIVATE_KEY ? 3 : 2;
	attrs = TEE_Malloc(*tee_attrs_count * sizeof(TEE_Attribute), 0);
	if (attrs == NULL)
		return CKR_GENERAL_ERROR;

	/* Must contain CKA_MODULUS attribute */
	TEE_MemFill(&ck_attr, 0, sizeof(CK_ATTRIBUTE));
	ck_rv = get_attr_from_object(crypto_op->key_object, CKA_MODULUS, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	map_tee_buf_attr2ck_attr(TEE_ATTR_RSA_MODULUS, &attrs[0], &ck_attr);
	*key_size = BYTES_TO_BITS(ck_attr.ulValueLen); /* GP size */

	/* Private rsa object public exponent is optional attribute in PKCS11. In the other
	 * hand in GP it is a mandatory parameter. If template/object is not providing
	 * public exponent, add default 65537! */

	TEE_MemFill(&ck_attr, 0, sizeof(CK_ATTRIBUTE));
	ck_rv = get_attr_from_object(crypto_op->key_object, CKA_PUBLIC_EXPONENT, &ck_attr);
	if (ck_rv == CKR_OK) {

		map_tee_buf_attr2ck_attr(TEE_ATTR_RSA_PUBLIC_EXPONENT, &attrs[1], &ck_attr);

	} else if (ck_rv == CKR_ATTRIBUTE_TYPE_INVALID) {

		attrs[1].content.ref.buffer = TEE_Malloc(sizeof(uint32_t), 0);
		if (tee_attrs[1]->content.ref.buffer == NULL)
			goto err;

		/* Use default value */
		attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
		*((uint32_t *)attrs[1].content.ref.buffer) = 65537;
		attrs[1].content.ref.length = sizeof(uint32_t);

	} else {
		goto err;
	}

	if (rsa_type == TEE_RSA_PRIVATE_KEY) {

		/* Must contain CKA_PRIVATE_EXPONENT1 attribute */
		TEE_MemFill(&ck_attr, 0, sizeof(CK_ATTRIBUTE));
		ck_rv = get_attr_from_object(crypto_op->key_object, CKA_PRIVATE_EXPONENT, &ck_attr);
		if (ck_rv != CKR_OK)
			return ck_rv;

		map_tee_buf_attr2ck_attr(TEE_ATTR_RSA_PRIVATE_EXPONENT, &attrs[2], &ck_attr);
	}

	*tee_object_type = rsa_type == TEE_RSA_PRIVATE_KEY ?
				   TEE_TYPE_RSA_KEYPAIR : TEE_TYPE_RSA_PUBLIC_KEY;
	*tee_attrs = attrs;

	return ck_rv;

err:
	free_tee_attrs(*tee_attrs, *tee_attrs_count);
	return ck_rv;
}

static CK_RV gen_gp_key_object(struct init_crypto_op *crypto_op)
{
	struct object_header obj_header;
	TEE_Attribute *tee_attrs;
	uint32_t tee_key_size = 0, tee_attrs_count;
	TEE_ObjectHandle gen_key_object;
	CK_ATTRIBUTE_TYPE ck_attr_type;
	object_type tee_obj_type = TEE_TYPE_GENERIC_SECRET;
	CK_ATTRIBUTE ck_attr = {0};
	CK_RV ck_rv = CKR_OK;
	TEE_Result tee_rv;

	/* Get object header */
	ck_rv = get_object_header(crypto_op->key_object, CKR_OBJECT_HANDLE_INVALID, &obj_header);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Get object key class */
	ck_attr.pValue = &ck_attr_type;
	ck_attr.ulValueLen = sizeof(CK_ATTRIBUTE_TYPE);
	ck_rv = get_attr_from_object(crypto_op->key_object, CKA_KEY_TYPE, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Map our pkcs11 object to GP key object */
	if (obj_header.obj_class == CKO_PUBLIC_KEY) {

		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_RSA)
			ck_rv = map_RSA_key_object(crypto_op, &tee_attrs, &tee_attrs_count,
						   &tee_obj_type, &tee_key_size,
						   TEE_RSA_PUBLIC_KEY);
		else
			ck_rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else if (obj_header.obj_class == CKO_PRIVATE_KEY) {

		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_RSA)
			ck_rv = map_RSA_key_object(crypto_op, &tee_attrs, &tee_attrs_count,
						   &tee_obj_type, &tee_key_size,
						   TEE_RSA_PRIVATE_KEY);
		else
			ck_rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else if (obj_header.obj_class == CKO_SECRET_KEY) {

		/* For now, only supported secret object type is AES and HMAC */
		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_AES)
			ck_rv = map_AES_secret_key_object(crypto_op, &tee_attrs, &tee_attrs_count,
							  &tee_obj_type, &tee_key_size);

		else if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_GENERIC_SECRET)
			ck_rv = map_HMAC_secret_key_object(crypto_op, &tee_attrs, &tee_attrs_count,
							   &tee_obj_type, &tee_key_size);

		else
			return CKR_FUNCTION_NOT_SUPPORTED;

	} else {
		return CKR_GENERAL_ERROR;
	}

	/* Allocate transient object */
	tee_rv = TEE_AllocateTransientObject(tee_obj_type, tee_key_size, &gen_key_object);
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	/* Populate object with key components */
	tee_rv = TEE_PopulateTransientObject(gen_key_object, tee_attrs, tee_attrs_count);
	if (tee_rv != TEE_SUCCESS) {
		TEE_FreeTransientObject(gen_key_object);
		return map_teec2ck(tee_rv);
	}

	/* TEE attributes not needed any more. */
	free_tee_attrs(tee_attrs, tee_attrs_count);

	/* GP key object is ready for use. We can close our pkcs11 object, because all necesary
	 * information is read from that. Crypto operation can now one use transient object. */
	TEE_CloseObject(crypto_op->key_object);
	crypto_op->key_object = gen_key_object;
	crypto_op->session->crypto_op.key_size = tee_key_size;

	return ck_rv;
}

static CK_RV init_sym_crypto(struct init_crypto_op *crypto_op)
{
	/* AES operation is needing 16-byte IV vector */
	if (crypto_op->mech_attr.ulParameterLen != 16)
		return CKR_MECHANISM_PARAM_INVALID;

	TEE_CipherInit(crypto_op->session->crypto_op.operation,
		       crypto_op->mech_attr.pParameter,
		       crypto_op->mech_attr.ulParameterLen);

	return CKR_OK;
}

static CK_RV init_mac_crypto(struct init_crypto_op *crypto_op)
{
	uint32_t hash_output = hash_output_length(crypto_op->mech_attr.mechanism);

	/* Take general mechanism output size, if it is general mode */
	switch (crypto_op->mech_attr.mechanism) {
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
		crypto_op->session->crypto_op.hmac_general_output =
				*(CK_MAC_GENERAL_PARAMS *)crypto_op->mech_attr.pParameter;

		/* Check that the provided output is legal. Note: Zero is legal size */
		if (crypto_op->session->crypto_op.hmac_general_output > hash_output)
			return CKR_MECHANISM_PARAM_INVALID;

		break;

	default:
		crypto_op->session->crypto_op.hmac_general_output = 0;
		break;
	}

	TEE_MACInit(crypto_op->session->crypto_op.operation, NULL, 0);
	return CKR_OK;
}

static CK_RV init_asym_sign_verify_crypto(struct init_crypto_op *crypto_op)
{
	uint32_t tee_hash_alg, hash_len;
	TEE_Result tee_ret;

	/* Note: Only supported asymetric crypto is sign/verify. */

	/* Map pkcs11 hash algortihm to GP */
	switch (crypto_op->session->crypto_op.mechanism) {
	case CKM_MD5_RSA_PKCS:
		tee_hash_alg = TEE_ALG_MD5;
		break;

	case CKM_SHA1_RSA_PKCS:
		tee_hash_alg = TEE_ALG_SHA1;
		break;

	case CKM_SHA256_RSA_PKCS:
		tee_hash_alg = TEE_ALG_SHA256;
		break;

	case CKM_SHA384_RSA_PKCS:
		tee_hash_alg = TEE_ALG_SHA384;
		break;

	case CKM_SHA512_RSA_PKCS:
		tee_hash_alg = TEE_ALG_SHA512;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	/* Get hash output length for cheking if hash can be used with that RSA key */
	hash_len = hash_output_length(crypto_op->session->crypto_op.mechanism);

	/* Can we use the RSA key for siging or verify that data length */
	if(hash_len > (BITS_TO_BYTES(crypto_op->session->crypto_op.key_size) - 11))
		return  CKR_KEY_SIZE_RANGE;

	tee_ret = TEE_AllocateOperation(&crypto_op->session->crypto_op.operation_2,
					tee_hash_alg, TEE_MODE_DIGEST, 0);
	if (tee_ret != TEE_SUCCESS)
		return map_teec2ck(tee_ret);

	return CKR_OK;
}

static CK_RV do_digest_crypto(struct crypto_op *crypto_op)
{
	CK_ULONG digest_len = hash_output_length(crypto_op->session->crypto_op.mechanism);

	/* Check digest output buffer size
	 * Note: No ouput from digest update */
	if (crypto_op->crypto_type != TEE_DIGEST_UPDATE && digest_len > crypto_op->dst_len) {
		crypto_op->dst_len = digest_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	/* Do digest operation */
	if (crypto_op->crypto_type == TEE_DIGEST_UPDATE) {

		TEE_DigestUpdate(crypto_op->session->crypto_op.operation,
				 crypto_op->src, crypto_op->src_len);

	} else if (crypto_op->crypto_type == TEE_DIGEST) {

		return map_teec2ck(TEE_DigestDoFinal(crypto_op->session->crypto_op.operation,
						     crypto_op->src, crypto_op->src_len,
						     crypto_op->dst, &crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_DIGEST_FINAL) {

		return map_teec2ck(TEE_DigestDoFinal(crypto_op->session->crypto_op.operation,
						     NULL, 0, crypto_op->dst, &crypto_op->dst_len));

	} else {
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

static CK_RV do_sym_crypto(struct crypto_op *crypto_op)
{
	/* NOTE: Only supported symmetric alogirth is CKM_AES_CBC and
	 * buffer checks is written that algortihm only */

	/* Input is multiple of block size */
	if (crypto_op->src_len % BITS_TO_BYTES(crypto_op->session->crypto_op.key_size))
		return CKR_DATA_LEN_RANGE;

	/* Output is at least input size */
	if (crypto_op->src_len > crypto_op->dst_len) {
		crypto_op->dst_len = crypto_op->src_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	/* Do symmetric operation */
	if (crypto_op->crypto_type == TEE_ENCRYPT ||
	    crypto_op->crypto_type == TEE_DECRYPT) {

		return map_teec2ck(TEE_CipherDoFinal(crypto_op->session->crypto_op.operation,
						     crypto_op->src, crypto_op->src_len,
						     crypto_op->dst, &crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_ENCRYPT_UPDATE ||
		   crypto_op->crypto_type == TEE_DECRYPT_UPDATE) {

		return map_teec2ck(TEE_CipherUpdate(crypto_op->session->crypto_op.operation,
						    crypto_op->src, crypto_op->src_len,
						    crypto_op->dst, &crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_ENCRYPT_FINAL ||
		   crypto_op->crypto_type == TEE_DECRYPT_FINAL) {

		return map_teec2ck(TEE_CipherDoFinal(crypto_op->session->crypto_op.operation,
						     NULL, 0, crypto_op->dst, &crypto_op->dst_len));

	} else {
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

static CK_RV do_asym_sign_verify(struct crypto_op *crypto_op)
{
	uint32_t hash_len = BIGGEST_HASH_OUTUPUT_IN_BYTES;
	char hash[hash_len]; /* Reserved for the most biggest hash, sha512 */
	CK_RV ck_rv = CKR_OK;
	TEE_Result tee_rv = TEE_SUCCESS;

	/* Output is produced on in following cases */
	if (crypto_op->crypto_type == TEE_SIGN || crypto_op->crypto_type == TEE_SIGN_FINAL) {

		/* Check output buffer size. RSA output is modulus sizes */
		if (BITS_TO_BYTES(crypto_op->session->crypto_op.key_size) > crypto_op->dst_len) {
			crypto_op->dst_len = BITS_TO_BYTES(crypto_op->session->crypto_op.key_size);
			return CKR_BUFFER_TOO_SMALL;
		}
	}

	/* Verification: Can be used only for RSA signature verification */
	if (crypto_op->crypto_type == TEE_VERIFY || crypto_op->crypto_type == TEE_VERIFY_FINAL) {

		/* Signature should be RSA key size */
		if (crypto_op->src == NULL ||
		    crypto_op->src_len != BITS_TO_BYTES(crypto_op->session->crypto_op.key_size))
			return CKR_ARGUMENTS_BAD;
	}

	/* Calculate hash, if needed. */
	if (crypto_op->crypto_type == TEE_SIGN ||
	    crypto_op->crypto_type == TEE_VERIFY) {

		tee_rv = TEE_DigestDoFinal(crypto_op->session->crypto_op.operation_2,
					   crypto_op->src, crypto_op->src_len,
					   hash, &hash_len);

		TEE_FreeOperation(crypto_op->session->crypto_op.operation_2);

	} else if (crypto_op->crypto_type == TEE_SIGN_FINAL ||
		   crypto_op->crypto_type == TEE_VERIFY_FINAL) {

		tee_rv = TEE_DigestDoFinal(crypto_op->session->crypto_op.operation_2,
					   NULL, 0, hash, &hash_len);

		TEE_FreeOperation(crypto_op->session->crypto_op.operation_2);

	} else if (crypto_op->crypto_type == TEE_VERIFY_UPDATE ||
		   crypto_op->crypto_type == TEE_SIGN_UPDATE) {

		TEE_DigestUpdate(crypto_op->session->crypto_op.operation_2,
				 crypto_op->src, crypto_op->src_len);

	}

	ck_rv = map_teec2ck(tee_rv);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Calculate actual signature/verification following cases */
	if (crypto_op->crypto_type == TEE_SIGN || crypto_op->crypto_type == TEE_SIGN_FINAL) {

		ck_rv = map_teec2ck(TEE_AsymmetricSignDigest(crypto_op->session->crypto_op.operation,
							     NULL, 0, hash, hash_len,
							     crypto_op->dst, &crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_VERIFY) {

		ck_rv = map_teec2ck(TEE_AsymmetricVerifyDigest(crypto_op->session->crypto_op.operation,
							       NULL, 0, hash, hash_len,
							       crypto_op->dst, crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_VERIFY_FINAL) {

		ck_rv = map_teec2ck(TEE_AsymmetricVerifyDigest(crypto_op->session->crypto_op.operation,
							       NULL, 0, hash, hash_len,
							       crypto_op->src, crypto_op->src_len));
	}

	return ck_rv;
}

static CK_RV do_mac_crypto(struct crypto_op *crypto_op)
{
	uint32_t hash_len = BIGGEST_HASH_OUTUPUT_IN_BYTES, operation_output;
	char hash[hash_len]; /* Reserved for the most biggest hash, sha512 */
	CK_RV ck_rv = CKR_OK;

	/* Calculate actual signature/verification following cases */
	if (crypto_op->crypto_type == TEE_VERIFY || crypto_op->crypto_type == TEE_VERIFY_FINAL) {

		ck_rv = map_teec2ck(TEE_MACCompareFinal(crypto_op->session->crypto_op.operation,
							crypto_op->src, crypto_op->src_len,
							crypto_op->dst, crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_VERIFY_UPDATE ||
		   crypto_op->crypto_type == TEE_SIGN_UPDATE) {

		TEE_MACUpdate(crypto_op->session->crypto_op.operation,
			      crypto_op->src, crypto_op->src_len);

	} else if (crypto_op->crypto_type == TEE_SIGN || crypto_op->crypto_type == TEE_SIGN_FINAL) {

		/* Output is generated only compute final function */
		switch (crypto_op->session->crypto_op.mechanism) {
		case CKM_MD5_HMAC_GENERAL:
		case CKM_SHA_1_HMAC_GENERAL:
		case CKM_SHA256_HMAC_GENERAL:
		case CKM_SHA384_HMAC_GENERAL:
		case CKM_SHA512_HMAC_GENERAL:
			operation_output = crypto_op->session->crypto_op.hmac_general_output;
			break;
		default:
			operation_output = hash_output_length(crypto_op->session->crypto_op.mechanism);
			break;
		}

		/* Check output buffer size. RSA output is modulus sizes */
		if (operation_output > crypto_op->dst_len) {
			crypto_op->dst_len = operation_output;
			return CKR_BUFFER_TOO_SMALL;
		}

		ck_rv = map_teec2ck(TEE_MACComputeFinal(crypto_op->session->crypto_op.operation,
							crypto_op->src, crypto_op->src_len,
							hash, &hash_len));

		TEE_MemMove(crypto_op->dst, hash, operation_output);
	}

	return ck_rv;
}

static CK_RV do_asym_enc_dec_crypto(struct crypto_op *crypto_op)
{
	uint32_t decryption_buf_len = BIGGEST_RSA_KEY_IN_BYTES; /* Biggest possbile RSA key */
	char decryption_buf[decryption_buf_len];
	CK_RV ck_rv = CKR_OK;

	/* Only supported algortihm is CKM_RSA_PKCS and that is single stage operation */
	if (crypto_op->crypto_type == TEE_ENCRYPT) {

		/* Can we use the RSA key for that data lenght */
		if(crypto_op->src_len >
		   (BITS_TO_BYTES(crypto_op->session->crypto_op.key_size) - 11))
			return  CKR_KEY_SIZE_RANGE;

		/* Check output buffer size. RSA output is modulus sizes */
		if (BITS_TO_BYTES(crypto_op->session->crypto_op.key_size) > crypto_op->dst_len) {
			crypto_op->dst_len = BITS_TO_BYTES(crypto_op->session->crypto_op.key_size);
			return CKR_BUFFER_TOO_SMALL;
		}

		ck_rv = map_teec2ck(TEE_AsymmetricEncrypt(crypto_op->session->crypto_op.operation,
							  NULL, 0,
							  crypto_op->src, crypto_op->src_len,
							  crypto_op->dst, &crypto_op->dst_len));

	} else if (crypto_op->crypto_type == TEE_DECRYPT) {

		/* Decrypted should be modulo size */
		if(crypto_op->src_len != (BITS_TO_BYTES(crypto_op->session->crypto_op.key_size)))
			return   CKR_ENCRYPTED_DATA_INVALID;

		ck_rv = map_teec2ck(TEE_AsymmetricDecrypt(crypto_op->session->crypto_op.operation,
							  NULL, 0,
							  crypto_op->src, crypto_op->src_len,
							  decryption_buf, &decryption_buf_len));

		/* Unfortunately we can't know output size. We must decrypt it to tempoarary
		 * buffer and copy it to a real output buffer. */
		if (decryption_buf_len > crypto_op->dst_len) {
			crypto_op->dst_len = decryption_buf_len;
			ck_rv = CKR_BUFFER_TOO_SMALL;
		} else {
			TEE_MemMove(crypto_op->dst, decryption_buf, decryption_buf_len);
			crypto_op->dst_len = decryption_buf_len;
		}

	} else {
		return CKR_FUNCTION_FAILED;
	}

	return ck_rv;
}

static CK_RV read_params_into_crypto_op(struct init_crypto_op *crypto_op,
					struct application *app,
					TEE_Param *params)
{
	uint32_t pos = 0;

	TEE_MemFill(crypto_op, 0, sizeof(struct init_crypto_op));

	/* Mechanism */
	TEE_MemMove(&crypto_op->mech_attr.mechanism, params[0].memref.buffer,
		    sizeof(crypto_op->mech_attr.mechanism));
	pos += sizeof(crypto_op->mech_attr.mechanism);

	/* ulParameterLen */
	TEE_MemMove(&crypto_op->mech_attr.ulParameterLen,
		    (uint8_t *)params[0].memref.buffer + pos,
			sizeof(crypto_op->mech_attr.ulParameterLen));
	pos += sizeof(crypto_op->mech_attr.ulParameterLen);

	/* pParameter */
	crypto_op->mech_attr.pParameter = (uint8_t *)params[0].memref.buffer + pos;

	/* Key */
	crypto_op->key = params[1].value.b;

	/* Crypto type */
	crypto_op->crypto_type = params[1].value.a;

	/* Get session from application */
	return app_get_session(app, params[3].value.a, &crypto_op->session);
}

static CK_RV can_mechanism_use_key(CK_MECHANISM_TYPE mechanism,
				   CK_ATTRIBUTE *allowed_mech_attr)
{
	uint32_t i;

	if (!allowed_mech_attr || !allowed_mech_attr->pValue)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < allowed_mech_attr->ulValueLen / sizeof(allowed_mech_attr->type); i++) {

		if (TEE_MemCompare((uint8_t *)allowed_mech_attr->pValue +
				   (i * sizeof(allowed_mech_attr->type)),
				   &mechanism, sizeof(allowed_mech_attr->type)) == 0)
			return CKR_OK;
	}

	return CKR_KEY_FUNCTION_NOT_PERMITTED;
}

static CK_RV check_object_for_crypto_op(struct init_crypto_op *crypto_op)
{
	CK_ATTRIBUTE ck_attr = {0};
	CK_KEY_TYPE keyType;
	CK_RV ck_rv = CKR_OK;
	CK_BBOOL ck_bool;

	/* can session use the key. Digest operation is not using key -> no object needed */
	if (crypto_op->crypto_type == TEE_DIGEST_INIT)
		return CKR_OK;

	/* Get object */
	ck_rv = get_object(crypto_op->session, crypto_op->key, &crypto_op->key_object, 0);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Can mechanism use key? If object is not defining CKA_ALLOWED_MECHANISMS, default
	 * action is allow, because this attribute is optional. If attribute is present,
	 * attribute is used for determing if mechanism can use this object */
	if (get_attr_from_object(crypto_op->key_object,
				 CKA_ALLOWED_MECHANISMS, &ck_attr) == CKR_OK) {

		ck_rv = can_mechanism_use_key(crypto_op->mech_attr.mechanism, &ck_attr);
		TEE_Free(ck_attr.pValue);
		ck_attr.pValue = 0;

		if (ck_rv != CKR_OK)
			goto err;
	}

	/* Is object key object? */
	ck_attr.pValue = &keyType;
	ck_attr.ulValueLen = sizeof(CK_KEY_TYPE);
	ck_rv = get_attr_from_object(crypto_op->key_object, CKA_KEY_TYPE, &ck_attr);
	if (ck_rv != CKR_OK)
		goto err;

	/* Object is key object -> Is correct key type  */
	switch (crypto_op->mech_attr.mechanism) {
	case CKM_AES_CBC:

		if (*((CK_KEY_TYPE *)ck_attr.pValue) != CKK_AES) {
			ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
			goto err;
		}

		break;

	case CKM_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:

		if (*((CK_KEY_TYPE *)ck_attr.pValue) != CKK_RSA) {
			ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
			goto err;
		}

		break;

	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:

		if (*((CK_KEY_TYPE *)ck_attr.pValue) != CKK_GENERIC_SECRET) {
			ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
			goto err;
		}

		break;

	default:
		ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto err;
	}

	/* key can be used for crypto */
	ck_attr.pValue = &ck_bool;
	ck_attr.ulValueLen = sizeof(CK_BBOOL);
	switch (crypto_op->crypto_type) {
	case TEE_DIGEST_INIT:
		break;

	case TEE_ENCRYPT_INIT:
		ck_rv = get_attr_from_object(crypto_op->key_object, CKA_ENCRYPT, &ck_attr);
		break;

	case TEE_DECRYPT_INIT:
		ck_rv = get_attr_from_object(crypto_op->key_object, CKA_DECRYPT, &ck_attr);
		break;

	case TEE_SIGN_INIT:
		ck_rv = get_attr_from_object(crypto_op->key_object, CKA_SIGN, &ck_attr);
		break;

	case TEE_VERIFY_INIT:
		ck_rv = get_attr_from_object(crypto_op->key_object, CKA_VERIFY, &ck_attr);
		break;

	default:
		return CKR_GENERAL_ERROR;
	}

	if (ck_rv != CKR_OK) {
		ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto err;
	}

	/* Attribute is found and the value should be TRUE */
	if (ck_attr.ulValueLen != sizeof(CK_BBOOL) || *((CK_BBOOL *)ck_attr.pValue) != CK_TRUE) {
		ck_rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
		goto err;
	}

	return ck_rv;

err:
	TEE_CloseObject(crypto_op->key_object);
	return ck_rv;
}

static void map_op_ck2tee(struct init_crypto_op *crypto_op,
			  algorithm_Identifier *tee_alg,
			  TEE_OperationMode *tee_mode)
{
	/* TEE Mode */
	switch (crypto_op->crypto_type) {
	case TEE_DIGEST:
	case TEE_DIGEST_FINAL:
	case TEE_DIGEST_UPDATE:
	case TEE_DIGEST_INIT:
		*tee_mode = TEE_MODE_DIGEST;
		break;

	case TEE_ENCRYPT:
	case TEE_ENCRYPT_FINAL:
	case TEE_ENCRYPT_UPDATE:
	case TEE_ENCRYPT_INIT:
		*tee_mode = TEE_MODE_ENCRYPT;
		break;

	case TEE_DECRYPT:
	case TEE_DECRYPT_FINAL:
	case TEE_DECRYPT_UPDATE:
	case TEE_DECRYPT_INIT:
		*tee_mode = TEE_MODE_DECRYPT;
		break;

	case TEE_SIGN:
	case TEE_SIGN_FINAL:
	case TEE_SIGN_UPDATE:
	case TEE_SIGN_INIT:
		*tee_mode = TEE_MODE_SIGN;
		break;

	case TEE_VERIFY:
	case TEE_VERIFY_FINAL:
	case TEE_VERIFY_UPDATE:
	case TEE_VERIFY_INIT:
		*tee_mode = TEE_MODE_VERIFY;
		break;
	default:
		/* Should never end up here */
		break;
	}

	/* Algortihm */
	switch (crypto_op->mech_attr.mechanism) {
	case CKM_AES_CBC:
		*tee_alg = TEE_ALG_AES_CBC_NOPAD;
		break;

	case CKM_MD5_RSA_PKCS:
		*tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_MD5;
		break;

	case CKM_SHA1_RSA_PKCS:
		*tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		break;

	case CKM_SHA256_RSA_PKCS:
		*tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		break;

	case CKM_SHA384_RSA_PKCS:
		*tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		break;

	case CKM_SHA512_RSA_PKCS:
		*tee_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		break;

	case CKM_MD5:
		*tee_alg = TEE_ALG_MD5;
		break;

	case CKM_SHA_1:
		*tee_alg = TEE_ALG_SHA1;
		break;

	case CKM_SHA256:
		*tee_alg = TEE_ALG_SHA256;
		break;

	case CKM_SHA384:
		*tee_alg = TEE_ALG_SHA384;
		break;

	case CKM_SHA512:
		*tee_alg = TEE_ALG_SHA512;
		break;

	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
		/* In PKCS11 MAC is same as Sign/Verify functions. In GP MAC != Verify != Sign.
		 * They have different modes and therefore mode is changed here to MAC */
		*tee_mode = TEE_MODE_MAC;
		*tee_alg = TEE_ALG_HMAC_MD5;
		break;

	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
		*tee_mode = TEE_MODE_MAC;
		*tee_alg = TEE_ALG_HMAC_SHA1;
		break;

	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		*tee_mode = TEE_MODE_MAC;
		*tee_alg = TEE_ALG_HMAC_SHA256;
		break;

	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
		*tee_mode = TEE_MODE_MAC;
		*tee_alg = TEE_ALG_HMAC_SHA384;
		break;

	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		*tee_mode = TEE_MODE_MAC;
		*tee_alg = TEE_ALG_HMAC_SHA512;
		break;

	case CKM_RSA_PKCS:
		*tee_alg = TEE_ALG_RSAES_PKCS1_V1_5;
		break;

	default:
		/* Should never end up here */
		break;
	}
}

TEE_Result crypto_init(struct application *app, uint32_t paramTypes, TEE_Param *params)
{
	struct init_crypto_op crypto_op;
	algorithm_Identifier tee_alg = 0;
	TEE_OperationMode tee_mode = 0;
	TEE_Result tee_ret;
	CK_RV ck_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Deserialize params into crypto operation struct */
	ck_rv = read_params_into_crypto_op(&crypto_op, app, params);
	if (ck_rv != CKR_OK)
		goto err_before_key_gen_1;

	/* Function will open an object and check if it is suitable for requested crypto op */
	ck_rv = check_object_for_crypto_op(&crypto_op);
	if (ck_rv != CKR_OK)
		goto err_before_key_gen_1;

	/* Set a key to operation. Digest is not needing a key */
	if (crypto_op.crypto_type != TEE_DIGEST_INIT) {

		/* Generate GP key object from pcks11 object */
		ck_rv = gen_gp_key_object(&crypto_op);
		if (ck_rv != CKR_OK)
			goto err_before_key_gen_2;
	}

	/* Key is ok. Map algortihm, mode and key size */
	map_op_ck2tee(&crypto_op, &tee_alg, &tee_mode);

	/* Re-check if mechanism is supported */
	ck_rv = mechanism_supported(crypto_op.mech_attr.mechanism,
				    crypto_op.session->crypto_op.key_size, tee_mode);
	if (ck_rv != CKR_OK)
		goto err_after_key_gen_1;

	/* GP Call: Let initialize operation */
	tee_ret = TEE_AllocateOperation(&crypto_op.session->crypto_op.operation,
					tee_alg, tee_mode, crypto_op.session->crypto_op.key_size);
	if (tee_ret != TEE_SUCCESS) {
		ck_rv = map_teec2ck(tee_ret);
		goto err_after_key_gen_1;
	}

	/* Set a key to operation. Digest is not needing a key */
	if (crypto_op.crypto_type != TEE_DIGEST_INIT) {

		/* GP Call: */
		tee_ret = TEE_SetOperationKey(crypto_op.session->crypto_op.operation,
					      crypto_op.key_object);
		if (tee_ret != TEE_SUCCESS) {
			ck_rv = map_teec2ck(tee_ret);
			goto err_after_key_gen_2;
		}
	}

	/* Init operation might need to know what mechanism is inited */
	crypto_op.session->crypto_op.mechanism = crypto_op.mech_attr.mechanism;

	/* Initialize crypto operation */
	switch (crypto_op.mech_attr.mechanism) {
	case CKM_AES_CBC:
		ck_rv = init_sym_crypto(&crypto_op);
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		ck_rv = init_asym_sign_verify_crypto(&crypto_op);
		break;

	case CKM_MD5:
	case CKM_SHA_1:
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		/* No init needed */
		break;

	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		ck_rv = init_mac_crypto(&crypto_op);
		break;

	case CKM_RSA_PKCS:
		/* No init needed */
		break;

	default:
		ck_rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	}

	if (ck_rv != CKR_OK)
		goto err_after_key_gen_2;

	/* Everything went fine */
	TEE_FreeTransientObject(crypto_op.key_object);
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;

err_before_key_gen_2:
	TEE_CloseObject(crypto_op.key_object);
err_before_key_gen_1:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;


err_after_key_gen_2:
	TEE_FreeOperation(crypto_op.session->crypto_op.operation);
	crypto_op.session->crypto_op.operation = NULL;
err_after_key_gen_1:
	TEE_FreeTransientObject(crypto_op.key_object);
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}

TEE_Result crypto(struct application *app, uint32_t paramTypes, TEE_Param *params)
{
	struct crypto_op crypto_op = {0};
	CK_RV ck_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INOUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[2].value.a > 0 && params[2].value.b == 0) {

		if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
			return TEE_ERROR_BAD_PARAMETERS;

	} else if (params[2].value.a == 0 && params[2].value.b > 0) {

		if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
			return TEE_ERROR_BAD_PARAMETERS;

	} else if (params[2].value.a > 0 && params[2].value.b > 0) {

		if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
			return TEE_ERROR_BAD_PARAMETERS;
	} else {
		if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Get session */
	ck_rv = app_get_session(app, params[3].value.a, &crypto_op.session);
	if (ck_rv != CKR_OK)
		goto out;

	/* Crypto operation is initialized */
	if (crypto_op.session->crypto_op.operation == NULL) {
		ck_rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/* Initialize crypto_op sturct */
	crypto_op.src = params[0].memref.buffer;
	crypto_op.src_len = params[2].value.a;
	crypto_op.dst_len = params[2].value.b;

	/* Userspace is providing only one buffer, which will be used for in/out. Some operation
	 * is needing two buffer in so that they operation can't operate if src == dst */
	crypto_op.dst = TEE_Malloc(crypto_op.dst_len, 0);
	if (crypto_op.dst == NULL) {
		ck_rv = CKR_DEVICE_MEMORY;
		goto out;
	}

	/* Crypto type (TEE_DIGEST, TEE_ENCRYPT...)*/
	crypto_op.crypto_type = params[1].value.a;

	switch (crypto_op.session->crypto_op.mechanism) {
	case CKM_AES_CBC:
		ck_rv = do_sym_crypto(&crypto_op);
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		ck_rv = do_asym_sign_verify(&crypto_op);
		break;

	case CKM_MD5:
	case CKM_SHA_1:
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		ck_rv = do_digest_crypto(&crypto_op);
		break;

	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		ck_rv = do_mac_crypto(&crypto_op);
		break;

	case CKM_RSA_PKCS:
		ck_rv = do_asym_enc_dec_crypto(&crypto_op);
		break;

	default:
		ck_rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	}

	if (ck_rv != CKR_BUFFER_TOO_SMALL &&
	    (crypto_op.crypto_type == TEE_CRYPTO || crypto_op.crypto_type == TEE_CRYPTO_FINAL)) {
		/* Operation is terminated, application must call init function */
		TEE_FreeOperation(crypto_op.session->crypto_op.operation);
		crypto_op.session->crypto_op.operation = NULL;
	}

	/* Lets check if user was quering buffer size or just buffer is too small. */
	if (ck_rv == CKR_BUFFER_TOO_SMALL && params[2].value.b == 0)
		ck_rv = CKR_OK;

	/* Replace in-buffer with handled data */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT)
		TEE_MemMove(params[0].memref.buffer, crypto_op.dst, crypto_op.dst_len);
	params[2].value.b = crypto_op.dst_len;
	TEE_Free(crypto_op.dst);
out:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}

TEE_Result crypto_verify(struct application *app, uint32_t paramTypes, TEE_Param *params)
{
	struct crypto_op crypto_op = {0};
	CK_RV ck_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get session */
	ck_rv = app_get_session(app, params[3].value.a, &crypto_op.session);
	if (ck_rv != CKR_OK)
		goto out;

	/* Crypto operation is initialized */
	if (crypto_op.session->crypto_op.operation == NULL) {
		ck_rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/* Userspace is providing only one buffer, which will be used for in/out. Some operation
	 * is needing two buffer in so that they operation can't operate if src == dst */
	crypto_op.dst = TEE_Malloc(params[2].value.b, 0);
	if (crypto_op.dst == NULL) {
		ck_rv = CKR_DEVICE_MEMORY;
		goto out;
	}

	/* Sign buffers */
	crypto_op.src = params[0].memref.buffer;
	TEE_MemMove(crypto_op.dst, params[1].memref.buffer, params[2].value.b);
	crypto_op.src_len = params[2].value.a;
	crypto_op.dst_len = params[2].value.b;

	/* Crypto type */
	crypto_op.crypto_type = TEE_VERIFY;

	/* Following verify algorithm are supported */
	switch (crypto_op.session->crypto_op.mechanism) {
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		ck_rv = do_asym_sign_verify(&crypto_op);
		break;

	case CKM_MD5_HMAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		ck_rv = do_mac_crypto(&crypto_op);
		break;

	default:
		ck_rv = CKR_GENERAL_ERROR;
		break;
	}

	/* Clean up after operation */
	TEE_FreeOperation(crypto_op.session->crypto_op.operation);
	crypto_op.session->crypto_op.operation = NULL;
	TEE_Free(crypto_op.dst);
out:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}

TEE_Result crypto_generate_random(struct application *app, uint32_t paramTypes, TEE_Param *params)
{
	app = app;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_GenerateRandom(params[0].memref.buffer, params[2].value.a);
	return TEE_SUCCESS;
}
