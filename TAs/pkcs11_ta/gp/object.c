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

#include "utils.h"
#include "object.h"
#include "tee_internal_api.h"
#include "pkcs11_session.h"
#include "pkcs11_application.h"
#include "stdbool.h"
#include "compat.h"
#include "cryptoki.h"
#include <string.h>

#define OBJ_ID_LEN CK_OBJECT_HANDLE
#define GENERATED_BY_TEE	0xFA
#define SET_TEMPLATE		0xFB
#define CREATE_TEMPLATE		0xFC

static char CPY_SET_OBJ_ID[] = "set_object_cpy_id";

struct pTemplate {
	void *buffer; /* Pointing to first attribute */
	CK_ULONG attr_count; /* Attributes count in pTemplate */
	size_t buffer_size; /* Buffer size in bytes */
	uint8_t generated_by_who; /* Who is generated template. TEE or recv from usr */
	uint8_t template_for; /* set/get/create template */
};

static CK_RV get_next_free_object_id(CK_OBJECT_HANDLE *next_id)
{
	/* For simplicity sake of POC: just get next..
	 * TODO: Check if next ID is not in use! */

	CK_OBJECT_HANDLE previous_object_id = 1;
	TEE_ObjectHandle id_object = NULL;
	/* Zero ID is reserved for our implementation. And PKCS11 is
	 * defining that zero is not valid object ID */
	CK_OBJECT_HANDLE id_object_id = 0;
	TEE_Result tee_rv = TEE_SUCCESS;
	size_t read_bytes;

	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id_object_id, sizeof(OBJ_ID_LEN),
					    TEE_DATA_FLAG_ACCESS_WRITE, NULL,
					    &previous_object_id, sizeof(CK_OBJECT_HANDLE), NULL);
	if (tee_rv == TEE_SUCCESS) {
		/* Special case: First object ID is previous ID */
		*next_id = previous_object_id;

	} else if (tee_rv == TEE_ERROR_ACCESS_CONFLICT) {

		/* Read previously signed ID */
		tee_rv = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id_object_id,
						  sizeof(CK_OBJECT_HANDLE),
						  (TEE_DATA_FLAG_ACCESS_WRITE |
						   TEE_DATA_FLAG_ACCESS_READ), &id_object);

		if (tee_rv != TEE_SUCCESS)
			goto out;

		tee_rv = TEE_ReadObjectData(id_object, &previous_object_id,
					    sizeof(CK_OBJECT_HANDLE), &read_bytes);
		if (tee_rv != TEE_SUCCESS || sizeof(CK_OBJECT_HANDLE) != read_bytes)
			goto out;

		/* Object ID is transfered in uint32_t -> value should fit into 32bit */
		if (previous_object_id > UINT32_MAX)
			previous_object_id = 0; /* Reset ID counter. TODO: check if not used */

		/* Increase counter */
		*next_id = ++previous_object_id;

		/* Write increased ID to storage */
		tee_rv = TEE_SeekObjectData(id_object, 0, TEE_DATA_SEEK_SET);
		if (tee_rv != TEE_SUCCESS)
			goto out;

		tee_rv = TEE_WriteObjectData(id_object, &previous_object_id,
					     sizeof(CK_OBJECT_HANDLE));
	} else {
		/* Something went wrong */
		*next_id = 0;
		tee_rv = TEEC_ERROR_GENERIC;
	}

out:
	TEE_CloseObject(id_object);
	return map_teec2ck(tee_rv);
}

static void release_object_id(CK_ULONG released_id)
{
	/* Placeholder, if something fancier needed */

	released_id = released_id;
}

static void get_next_attr_from_template(struct pTemplate *ptemplate,
					uint32_t *pos,
					CK_ATTRIBUTE *attr)
{
	/* Attribute type */
	TEE_MemMove(&attr->type, (uint8_t *)ptemplate->buffer + *pos, sizeof(CK_ATTRIBUTE_TYPE));
	*pos += sizeof(CK_ATTRIBUTE_TYPE);

	/* ulValueLen */
	TEE_MemMove(&attr->ulValueLen, (uint8_t *)ptemplate->buffer + *pos, sizeof(CK_ULONG));
	*pos += sizeof(CK_ULONG);

	/* pValue */
	attr->pValue = (uint8_t *)ptemplate->buffer + *pos;
	*pos += attr->ulValueLen;
}

static CK_RV get_attr_from_template(struct pTemplate *ptemplate,
				    CK_ATTRIBUTE_TYPE type,
				    CK_ATTRIBUTE *ret_attr)
{
	uint32_t pos = 0, i = 0;
	CK_ATTRIBUTE local_attr;

	for (i = 0; i < ptemplate->attr_count; i++) {

		get_next_attr_from_template(ptemplate, &pos, &local_attr);

		if (local_attr.type == type) {

			if (ret_attr)
				TEE_MemMove(ret_attr, &local_attr, sizeof(CK_ATTRIBUTE));

			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}

static CK_RV cpy_attr2buf(CK_ATTRIBUTE *ck_attr,
			  void *buf,
			  uint32_t buf_len)
{
	/* Zero size is not correct! */
	if (buf_len < ck_attr->ulValueLen || !ck_attr->ulValueLen)
		return CKR_GENERAL_ERROR;

	TEE_MemMove(buf, ck_attr->pValue, ck_attr->ulValueLen);

	return CKR_OK;
}

static CK_RV is_attr_type_valid(CK_ATTRIBUTE_TYPE type)
{
	/* Note: For now CKA_ALWAYS_AUTHENTICATE not supported */

	/* Attributes supported from subsections:
	 *	-Common attributes
	 *	-Key objects
	 *	-Public key objects
	 *	-Secret key objects
	 *	-AES secret key objects
	 *	-RSA public key objects
	 *	-RSA private key objects */

	switch (type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_ID:
	case CKA_START_DATE:
	case CKA_END_DATE:
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_ALLOWED_MECHANISMS:
	case CKA_SUBJECT:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_TRUSTED:
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_CHECK_VALUE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	case CKA_MODULUS_BITS:
	case CKA_VALUE:
	case CKA_VALUE_LEN:
	case CKA_LABEL:
	case CKA_TOKEN:
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

static CK_RV template_contain_correct_types(struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE template_attr;
	uint32_t i, pos = 0;
	CK_RV ck_rv;

	for (i = 0; i < ptemplate->attr_count; ++i) {

		/* Get next attr from search template */
		get_next_attr_from_template(ptemplate, &pos, &template_attr);

		ck_rv = is_attr_type_valid(template_attr.type);
		if (ck_rv != CKR_OK)
			return ck_rv;
	}

	return CKR_OK;
}

/*!
 * \brief write_obj_template_to_object
 * Write object template into object/SS.
 * \param obj_template
 * \param addidional_info Accept NULL parameter -> no addional info written
 * \param addidional_info_len
 * \param object
 * \return
 */
static CK_RV write_obj_template_to_object(struct pTemplate *ptemplate,
					  struct object_header *obj_header,
					  TEE_ObjectHandle object,
					  CK_RV (*callback)(TEE_ObjectHandle,
							    struct pTemplate *))
{
	CK_RV ck_rv = CKR_OK;
	TEE_Result tee_rv;

	/* How object is stored:
	 * |---------------------------------------------------------------------|
	 * | Object header,	  | callback template attrs 	 | Template	 |
	 * | struct object_header | callback len		 | template len	 |
	 * |---------------------------------------------------------------------|
	 */

	/* Put the object header into place */
	tee_rv = TEE_WriteObjectData(object, obj_header, sizeof(struct object_header));
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	/* Callback can be used for writting extra attributes */
	if (callback) {
		ck_rv = callback(object, ptemplate);
		if (ck_rv != CKR_OK)
			return ck_rv;
	}

	/* Write usr template */
	tee_rv = TEE_WriteObjectData(object, ptemplate->buffer, ptemplate->buffer_size);
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	return ck_rv;
}

static CK_RV write_attr2object(CK_ATTRIBUTE *ck_attr, TEE_ObjectHandle object)
{
	TEE_Result tee_rv;

	/* Template write format is documented in hal_gp.c serialize_template_into_shm() */
	tee_rv = TEE_WriteObjectData(object, &ck_attr->type, sizeof(CK_ATTRIBUTE_TYPE));
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	tee_rv = TEE_WriteObjectData(object, &ck_attr->ulValueLen, sizeof(CK_ULONG));
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	tee_rv = TEE_WriteObjectData(object, ck_attr->pValue, ck_attr->ulValueLen);
	if (tee_rv != TEE_SUCCESS)
		return map_teec2ck(tee_rv);

	return CKR_OK;
}

static CK_RV write_key_pkcs11_ctl_attrs(TEE_ObjectHandle object,
					struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE write_attr, template_attr;
	CK_ATTRIBUTE_TYPE pkcs11_always_attrs[2] = {CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE};
	CK_ATTRIBUTE_TYPE template_always_attr[2] = {CKA_SENSITIVE, CKA_EXTRACTABLE};
	CK_BBOOL ck_bool;
	CK_RV ck_rv;
	uint8_t i;

	/* Sign bool value to pValue, which will be used for attr writing */
	write_attr.pValue = &ck_bool;
	write_attr.ulValueLen = sizeof(CK_BBOOL);

	/* CKA_TOKEN: This attribute is kept at object header, but this need to be written
	 * to object as a proper attribute. This is written for eg. wrap key function. Then
	 * all attributes are in object data section */
	 if (ptemplate->template_for == CREATE_TEMPLATE) {

		 write_attr.type = CKA_TOKEN;
		if (CKR_OK != get_attr_from_template(ptemplate, CKA_TOKEN, &write_attr))
			*((CK_BBOOL *)write_attr.pValue) = CK_FALSE;

		ck_rv = write_attr2object(&write_attr, object);
		if (ck_rv != CKR_OK)
			return ck_rv;
	}

	/* CKA_LOCAL */
	write_attr.type = CKA_LOCAL;
	if (ptemplate->template_for == SET_TEMPLATE) {

		ck_rv = get_attr_from_object(object, CKA_LOCAL, &write_attr);
		if (ck_rv != CKR_OK)
			return ck_rv; /* CKA_LOCAL should be in key object! */

	} else if (ptemplate->template_for == CREATE_TEMPLATE) {

		if (ptemplate->generated_by_who == GENERATED_BY_TEE)
			*((CK_BBOOL *)write_attr.pValue) = CK_TRUE;
		else
			*((CK_BBOOL *)write_attr.pValue) = CK_FALSE;
	}

	ck_rv = write_attr2object(&write_attr, object);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* i < 2 == how many attributes are in pkcs11_always_attrs and template_always_attr table */
	for (i = 0; i < 2; i++) {

		write_attr.type = pkcs11_always_attrs[i];
		if (ptemplate->template_for == SET_TEMPLATE) {

			/* Key object has been created -> get attribute value from object */
			ck_rv = get_attr_from_object(object, pkcs11_always_attrs[i], &write_attr);
			if (ck_rv != CKR_OK)
				return ck_rv; /* Should be in key object! */

			/* Attribute can change only once and it has changed */
			if (*((CK_BBOOL *)write_attr.pValue) == CK_FALSE) {

				ck_rv = write_attr2object(&write_attr, object);
				if (ck_rv != CKR_OK)
					return ck_rv;

				continue;
			}
		}

		if (get_attr_from_template(ptemplate,
				     template_always_attr[i], &template_attr) == CKR_OK) {

			if (*((CK_BBOOL *)template_attr.pValue) == CK_TRUE)
				*((CK_BBOOL *)write_attr.pValue) = CK_FALSE;

		} else {
			*((CK_BBOOL *)write_attr.pValue) = CK_TRUE;
		}

		ck_rv = write_attr2object(&write_attr, object);
		if (ck_rv != CKR_OK)
			return ck_rv;
	}

	return CKR_OK;
}

/* This function is written for AES and HMAC keys only. With small efforts this could be
 * modified as a general symmetric key object creation function */
static CK_RV create_sym_secrect_key_object(struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE ck_attr = {0};
	CK_RV ck_rv = CKR_OK;

	/* AES secret object must NOT contain CKA_VALUE_LEN attribute, if tempalte recv from usr */
	if (ptemplate->generated_by_who != GENERATED_BY_TEE &&
	    get_attr_from_template(ptemplate, CKA_VALUE_LEN, NULL) == CKR_OK)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/* Must contain CKA_VALUE attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_VALUE, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	return ck_rv;
}

static CK_RV create_RSA_public_key_object(struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE ck_attr = {0};
	CK_RV ck_rv;

	/* Must contain NOT CKA_MODULUS_BITS attribute if used c_createobject() */
	if (ptemplate->generated_by_who != GENERATED_BY_TEE &&
	    get_attr_from_template(ptemplate, CKA_MODULUS_BITS, NULL) == CKR_OK)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/* Must contain CKA_MODULUS attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_MODULUS, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Must contain CKA_PUBLIC_EXPONENT attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_PUBLIC_EXPONENT, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	return ck_rv;
}

static CK_RV create_RSA_private_key_object(struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE ck_attr = {0};
	CK_RV ck_rv = CKR_OK;

	/* Must contain CKA_MODULUS attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_MODULUS, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Must contain CKA_PRIVATE_EXPONENT1 attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_PRIVATE_EXPONENT, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	return ck_rv;
}

static CK_RV create_key_object(struct pTemplate *ptemplate,
			       struct object_header *obj_header,
			       CK_OBJECT_HANDLE *new_obj_id)
{
	/* For now, three is max number of key components. This also could be TODO */
	TEE_ObjectHandle pers_object = NULL;
	CK_ATTRIBUTE ck_attr = {0};
	TEE_Result tee_rv;
	CK_RV ck_rv = CKR_OK;

	/* Before creating a key object, they have a few common checks */

	/* Must NOT contain CKA_LOCAL attribute */
	if (get_attr_from_template(ptemplate, CKA_LOCAL, NULL) == CKR_OK)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/* Must NOT contain CKA_KEY_GEN_MECHANISM attribute */
	if (get_attr_from_template(ptemplate, CKA_KEY_GEN_MECHANISM, NULL) == CKR_OK)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	/* Must contain CKA_KEY_TYPE attribute */
	ck_rv = get_attr_from_template(ptemplate, CKA_KEY_TYPE, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Provided template was valid */

	/* TODO: Do not allow create random key sizes a la AES123 */

	if (obj_header->obj_class == CKO_PUBLIC_KEY) {

		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_RSA)
			ck_rv = create_RSA_public_key_object(ptemplate);
		else
			ck_rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else if (obj_header->obj_class == CKO_PRIVATE_KEY) {

		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_RSA)
			ck_rv = create_RSA_private_key_object(ptemplate);
		else
			ck_rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else if (obj_header->obj_class == CKO_SECRET_KEY) {

		/* For now, only supported secret object type is AES */
		if (*((CK_KEY_TYPE *)ck_attr.pValue) == CKK_AES ||
		    *((CK_KEY_TYPE *)ck_attr.pValue) == CKK_GENERIC_SECRET)
			ck_rv = create_sym_secrect_key_object(ptemplate);
		else
			ck_rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else {
		ck_rv = CKR_GENERAL_ERROR;
	}

	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Template is OK, write it to object */
	if (get_next_free_object_id((CK_OBJECT_HANDLE *)new_obj_id) != CKR_OK)
		return CKR_GENERAL_ERROR;

	/* Create object and store it to secure storage.
	 * Note: Object is created and closed
	 * Note: Full template is saved and therefore we have some reduntance information. This
	 * need to be done if we would like to support warp/unwrap key functions! */
	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, new_obj_id,
					    sizeof(CK_OBJECT_HANDLE),
					    TEE_DATA_FLAG_ACCESS_READ |
					    TEE_DATA_FLAG_ACCESS_WRITE |
					    TEE_DATA_FLAG_ACCESS_WRITE_META,
					    NULL, NULL, 0, &pers_object);
	if (tee_rv != TEE_SUCCESS) {
		ck_rv = map_teec2ck(tee_rv);
		goto err_1;
	}

	/* write_key_pkcs11_ctl_attrs() is writing 4 attribute, which is controlled by
	 * pkcs11 implementation. Header need to be updated */
	obj_header->attr_count += 4 + ptemplate->attr_count;

	ck_rv = write_obj_template_to_object(ptemplate, obj_header,
					     pers_object, write_key_pkcs11_ctl_attrs);
	if (ck_rv != CKR_OK)
		goto err_2;

	TEE_CloseObject(pers_object);

	return ck_rv;

err_2:
	TEE_CloseAndDeletePersistentObject1(pers_object);
err_1:
	release_object_id(*new_obj_id);
	*new_obj_id = CKR_OBJECT_HANDLE_INVALID;
	return ck_rv;
}

static int is_public_object(CK_OBJECT_CLASS obj_class)
{
	/* NOTE!: only key object check -> everything else fails */
	switch (obj_class) {
	case CKO_PUBLIC_KEY:
		return 0;

	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		return 1;

	default:
		/* Other class checks are not yet implemented. Just to be sure! */
		return -1;
	}
}

static CK_RV can_session_create_object(struct object_header *obj_header,
				       struct pkcs11_session *session)
{
	CK_RV ck_rv = CKR_OK;
	int is_pub_obj;

	/* Read only session can not create Token object */
	if (obj_header->cka_token == CK_TRUE
	    && (session->sessionInfo.state == CKS_RO_PUBLIC_SESSION ||
		session->sessionInfo.state == CKS_RO_USER_FUNCTIONS))
		return CKR_SESSION_READ_ONLY;

	/* Public session can only create public object */
	is_pub_obj = is_public_object(obj_header->obj_class);
	if (is_pub_obj == -1) {
		return CKR_GENERAL_ERROR;

	} else if (is_pub_obj == 1) {

		if (session->sessionInfo.state == CKS_RO_PUBLIC_SESSION ||
		    session->sessionInfo.state == CKS_RW_PUBLIC_SESSION)
			return CKR_SESSION_READ_ONLY;
	}

	return ck_rv;
}

static void init_pTemplate_struct(struct pTemplate *pTemplate,
				  void *recv_template,
				  uint32_t recv_template_size)
{
	TEE_MemFill(pTemplate, 0, sizeof(struct pTemplate));

	/* Fill in template attribute count. It is first eight bytes */
	TEE_MemMove(&pTemplate->attr_count, recv_template, sizeof(CK_ULONG));

	/* Move to point the first attribute */
	pTemplate->buffer = (uint8_t *)recv_template + sizeof(CK_ULONG);
	pTemplate->buffer_size = recv_template_size - sizeof(CK_ULONG);
}

static CK_RV read_usr_send_template(struct pTemplate *pTemplate,
				    struct object_header *obj_header,
				    void *recv_template,
				    uint32_t recv_template_size)
{
	CK_ATTRIBUTE ck_attr;
	CK_RV ck_rv = CKR_OK;

	/* pTemplate struct. Template format is documented in libtee_pkcs11 hal_gp.c file. */
	init_pTemplate_struct(pTemplate, recv_template, recv_template_size);

	/* Object header */
	TEE_MemFill(obj_header, 0, sizeof(struct object_header));

	/* Must contain CKA_CLASS attribute */
	ck_rv = get_attr_from_template(pTemplate, CKA_CLASS, &ck_attr);
	if (ck_rv != CKR_OK)
		return ck_rv;

	ck_rv = cpy_attr2buf(&ck_attr, &obj_header->obj_class, sizeof(obj_header->obj_class));
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Trying to read CKA_TOKEN attribute */
	if (get_attr_from_template(pTemplate, CKA_TOKEN, &ck_attr) == CKR_OK) {

		/* Token attribute is found */
		ck_rv = cpy_attr2buf(&ck_attr, &obj_header->cka_token,
				     sizeof(obj_header->cka_token));
		if (ck_rv != CKR_OK)
			return ck_rv;
	} else {
		obj_header->cka_token = CK_FALSE;
	}

	return CKR_OK;
}

CK_RV get_object_header(TEE_ObjectHandle object,
			CK_OBJECT_HANDLE obj_id,
			struct object_header *obj_header)
{
	bool obj_was_open = object == NULL ? false : true;
	TEE_Result tee_ret;
	size_t read_bytes;

	if (!obj_was_open) {

		/* Object is not opened */
		tee_ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &obj_id,
						   sizeof(CK_OBJECT_HANDLE),
						   TEE_DATA_FLAG_ACCESS_READ, &object);
		if (tee_ret != TEE_SUCCESS)
			return map_teec2ck(tee_ret);

	} else {

		/* Object is open, but its position is unknow */
		tee_ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
		if (tee_ret != TEE_SUCCESS)
			return map_teec2ck(tee_ret);
	}

	/* Object header is beginning of object */
	tee_ret = TEE_ReadObjectData(object, obj_header,
				     sizeof(struct object_header), &read_bytes);

	/* Object is closed */
	if (!obj_was_open)
		TEE_CloseObject(object);

	if (tee_ret != TEE_SUCCESS || read_bytes != sizeof(struct object_header))
		return map_teec2ck(tee_ret);

	return CKR_OK;
}

static CK_RV can_attr_revealed(TEE_ObjectHandle object,
			       CK_ATTRIBUTE *attr)
{
	CK_ATTRIBUTE obj_attr = {0};
	CK_BBOOL ck_bool;
	CK_RV ck_rv;

	switch (attr->type) {
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	case CKA_VALUE:

		obj_attr.pValue = &ck_bool;
		obj_attr.ulValueLen = sizeof(CK_BBOOL);
		ck_rv = get_attr_from_object(object, CKA_SENSITIVE, &obj_attr);
		if (ck_rv == CKR_OK && *((CK_BBOOL *)obj_attr.pValue) == CK_TRUE)
			return CKR_ATTRIBUTE_SENSITIVE;

		ck_rv = get_attr_from_object(object, CKA_EXTRACTABLE, &obj_attr);
		if (ck_rv == CKR_OK && *((CK_BBOOL *)obj_attr.pValue) == CK_FALSE)
			return CKR_ATTRIBUTE_SENSITIVE;

		break;
	default:
		/* If everything fine, switchs case drop down here */
		ck_rv = CKR_OK;
		break;
	}

	return ck_rv;
}

static void write_attr2buffer(uint8_t *buffer,
			      uint32_t *pos,
			      CK_ATTRIBUTE *attr)
{
	/* Function will write serialized manner attirbute into buffer. It will update position
	 * according to write == how many bytes is written */

	/* Attribute type */
	TEE_MemMove(buffer + *pos, &attr->type, sizeof(CK_ATTRIBUTE_TYPE));
	*pos += sizeof(CK_ATTRIBUTE_TYPE);

	/* ulValueLen */
	TEE_MemMove(buffer + *pos, &attr->ulValueLen, sizeof(CK_ULONG));
	*pos += sizeof(CK_ULONG);

	/* pValue
	 * If ulValueLen is -1, pValue can't return eg. sensitive */
	if (attr->pValue && (CK_LONG)attr->ulValueLen != -1) {
		TEE_MemMove(buffer + *pos, attr->pValue, attr->ulValueLen);
		*pos += attr->ulValueLen;
	}
}


static CK_RV is_attr_modifiable(CK_ATTRIBUTE_TYPE type)
{
	/* Attributes supported from subsections:
	 *	-Common attributes
	 *	-Key objects
	 *	-Public key objects
	 *	-Secret key objects
	 *	-AES secret key objects
	 *	-RSA public key objects
	 *	-RSA private key objects */

	switch (type) {
	case CKA_ID:
	case CKA_START_DATE:
	case CKA_END_DATE:
	case CKA_DERIVE:
	case CKA_SUBJECT:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

static CK_RV can_attr_modified(struct pTemplate *ptemplate)
{
	CK_ATTRIBUTE template_attr;
	uint32_t i, pos = 0;
	CK_RV ck_rv;

	for (i = 0; i < ptemplate->attr_count; ++i) {

		/* Get next attr from search template */
		get_next_attr_from_template(ptemplate, &pos, &template_attr);

		ck_rv = is_attr_modifiable(template_attr.type);
		if (ck_rv != CKR_OK)
			return ck_rv;
	}

	return CKR_OK;
}

static CK_RV init_next_attr_from_object(TEE_ObjectHandle object)
{
	/* Set to point first attribute */

	return map_teec2ck(TEE_SeekObjectData(object,
					      sizeof(struct object_header), TEE_DATA_SEEK_SET));
}

static CK_RV get_next_attr_from_object(TEE_ObjectHandle object,
				       CK_ATTRIBUTE *ck_attr)
{
	TEE_Result tee_ret;
	size_t read_bytes;

	/* Attribute type */
	tee_ret = TEE_ReadObjectData(object, &ck_attr->type, sizeof(ck_attr->type), &read_bytes);
	if (tee_ret != TEE_SUCCESS || sizeof(ck_attr->type) != read_bytes)
		return map_teec2ck(tee_ret);

	/* ulValueLen */
	tee_ret = TEE_ReadObjectData(object, &ck_attr->ulValueLen,
				     sizeof(ck_attr->ulValueLen), &read_bytes);
	if (tee_ret != TEE_SUCCESS || sizeof(ck_attr->ulValueLen) != read_bytes)
		return map_teec2ck(tee_ret);

	/* pValue */
	ck_attr->pValue = TEE_Malloc(ck_attr->ulValueLen, 0);
	if (ck_attr->pValue == NULL)
		return CKR_DEVICE_MEMORY;

	tee_ret = TEE_ReadObjectData(object, ck_attr->pValue, ck_attr->ulValueLen, &read_bytes);
	if (tee_ret != TEE_SUCCESS || ck_attr->ulValueLen != read_bytes) {
		TEE_Free(ck_attr->pValue);
		return map_teec2ck(tee_ret);
	}

	return CKR_OK;
}

CK_RV get_object(struct pkcs11_session *session,
		 CK_OBJECT_HANDLE obj_id,
		 TEE_ObjectHandle *object,
		 uint32_t addidional_flags)
{
	struct object_header obj_header;
	int public_object;
	uint32_t flags = 0;
	TEE_Result tee_ret;
	CK_RV ck_rv;

	/* Get object header */
	ck_rv = get_object_header(NULL, obj_id, &obj_header);
	if (ck_rv != CKR_OK)
		return ck_rv;

	/* Is object this session object */
	if (obj_header.cka_token != CK_TRUE && this_session_object(session, obj_id) != CKR_OK)
		return CKR_GENERAL_ERROR;

	/* Which flag should be used for object opening */

	/* Determine if object is public or private */
	public_object = is_public_object(obj_header.obj_class);
	if (public_object == -1)
		return CKR_GENERAL_ERROR;

	/* PKCS11 2.20 table 6, Access to Different Types Objects by Different Types of Sessions */
	if (session->sessionInfo.state == CKS_RW_SO_FUNCTIONS ||
	    session->sessionInfo.state == CKS_RW_PUBLIC_SESSION) {

		if (public_object == 0)
			flags = TEE_DATA_FLAG_ACCESS_WRITE |
				TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
		else
			return CKR_SESSION_READ_ONLY;

	} else if (session->sessionInfo.state == CKS_RW_USER_FUNCTIONS) {
		flags = TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;

	} else if (session->sessionInfo.state == CKS_RO_USER_FUNCTIONS) {

		if (obj_header.cka_token == CK_TRUE)
			flags = TEE_DATA_FLAG_ACCESS_WRITE |
				TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
		else
			flags = TEE_DATA_FLAG_ACCESS_READ;

	} else if (session->sessionInfo.state == CKS_RO_PUBLIC_SESSION) {

		if (public_object == 0 && obj_header.cka_token == CK_FALSE)
			flags = TEE_DATA_FLAG_ACCESS_WRITE |
				TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
		else if (public_object == 0 && obj_header.cka_token == CK_TRUE)
			flags = TEE_DATA_FLAG_ACCESS_READ;
		else
			return CKR_SESSION_READ_ONLY;

	} else {
		/* Access denied */
		return CKR_SESSION_READ_ONLY;
	}

	tee_ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					   &obj_id, sizeof(OBJ_ID_LEN),
					   flags | addidional_flags, object);
	if (tee_ret != TEE_SUCCESS)
		return map_teec2ck(tee_ret);

	return CKR_OK;
}

CK_RV get_attr_from_object(TEE_ObjectHandle object,
			   CK_ATTRIBUTE_TYPE type,
			   CK_ATTRIBUTE *ck_attr)
{
	struct object_header obj_header;
	TEE_ObjectInfo object_info;
	CK_ATTRIBUTE iter_attr;
	size_t i, read_bytes;
	TEE_Result tee_ret;
	CK_RV ck_rv;

	/* Function is saving data position and setting it back before exiting */
	TEE_GetObjectInfo1(object, &object_info);

	/* Needing a object header. Object header is storing template attribute count */
	ck_rv = get_object_header(object, 0, &obj_header);
	if (ck_rv != CKR_OK)
		goto out;

	/* Iterate through template */
	for (i = 0; i < obj_header.attr_count; ++i) {

		/* Attribute type */
		tee_ret = TEE_ReadObjectData(object, &iter_attr.type,
					     sizeof(iter_attr.type), &read_bytes);
		if (tee_ret != TEE_SUCCESS || sizeof(iter_attr.type) != read_bytes) {
			ck_rv = map_teec2ck(tee_ret);
			goto out;
		}

		/* ulValueLen */
		tee_ret = TEE_ReadObjectData(object, &iter_attr.ulValueLen,
					     sizeof(iter_attr.ulValueLen), &read_bytes);
		if (tee_ret != TEE_SUCCESS || sizeof(iter_attr.ulValueLen) != read_bytes) {
			ck_rv = map_teec2ck(tee_ret);
			goto out;
		}

		/* If attribute is not queried attribute, skip pvalue */
		if (type != iter_attr.type) {

			tee_ret = TEE_SeekObjectData(object,
						     iter_attr.ulValueLen, TEE_DATA_SEEK_CUR);
			if (tee_ret != TEE_SUCCESS) {
				ck_rv = map_teec2ck(tee_ret);
				goto out;
			}

			continue;
		}

		/* Function is providing attribute checout functionality if object contain
		 * certain attribute */
		if (ck_attr == NULL) {
			ck_rv = CKR_OK;
			goto out;
		}

		/* If ck_attribute is providing a buffer, copy attribute pValue to buffer.
		 * If attribute is not providing a buffer, must use malloc! */

		/* pValue */
		/* If buffer provided and large enough. If buffer is not large enough,
		 * function will return general error, because then it is not mixed with a real
		 * buffer too small error code and this value could be passed back to user space */
		if (ck_attr->pValue != NULL) {

			if (iter_attr.ulValueLen > ck_attr->ulValueLen) {
				ck_rv = CKR_GENERAL_ERROR;
				goto out;
			}

			ck_attr->ulValueLen = iter_attr.ulValueLen;
			tee_ret = TEE_ReadObjectData(object, ck_attr->pValue,
						     ck_attr->ulValueLen, &read_bytes);
			if (tee_ret != TEE_SUCCESS || ck_attr->ulValueLen != read_bytes) {
				ck_rv = map_teec2ck(tee_ret);
				goto out;
			}

		} else {

			ck_attr->ulValueLen = iter_attr.ulValueLen;
			ck_attr->pValue = TEE_Malloc(iter_attr.ulValueLen, 0);
			if (ck_attr->pValue == NULL) {
				ck_rv = CKR_DEVICE_MEMORY;
				goto out;
			}

			tee_ret = TEE_ReadObjectData(object, ck_attr->pValue,
						     ck_attr->ulValueLen, &read_bytes);
			if (tee_ret != TEE_SUCCESS || ck_attr->ulValueLen != read_bytes) {
				TEE_Free(ck_attr->pValue);
				ck_attr->pValue = NULL;
				ck_rv = map_teec2ck(tee_ret);
				goto out;
			}
		}

		/* Copy attribute values from iteration attribute. */
		ck_attr->type = iter_attr.type;

		ck_rv = CKR_OK;
		goto out;
	}

	ck_rv = CKR_ATTRIBUTE_TYPE_INVALID;

out:
	tee_ret = TEE_SeekObjectData(object, object_info.dataPosition, TEE_DATA_SEEK_SET);
	if (tee_ret != TEE_SUCCESS)
		ck_rv = map_teec2ck(tee_ret);

	return ck_rv;
}

TEE_Result create_object(struct application *app,
			 uint32_t paramTypes,
			 TEE_Param *params)
{
	CK_OBJECT_HANDLE new_obj_id = CKR_OBJECT_HANDLE_INVALID;
	struct pkcs11_session *session;
	struct object_header obj_header;
	struct pTemplate ptemplate;
	CK_RV ck_rv = CKR_OK;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_OUTPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Session is needed for checking session permissions and adding objects */
	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto end;

	/* Read received template info */
	ck_rv = read_usr_send_template(&ptemplate, &obj_header,
				       params[0].memref.buffer, params[2].value.a);
	if (ck_rv != CKR_OK)
		goto end;

	/* Template is not generated by TEE -> obj_template.generated_by_who is set to zero
	 * to indicate that it is recv from usr */
	ptemplate.template_for = CREATE_TEMPLATE;
	ptemplate.generated_by_who = 0;

	/* Generic checks which are valid for all objects */
	ck_rv = can_session_create_object(&obj_header, session);
	if (ck_rv != CKR_OK)
		goto end;

	/* Check user provided template that the attribute types are supported */
	ck_rv = template_contain_correct_types(&ptemplate);
	if (ck_rv != CKR_OK)
		goto end;

	/* Which object will be created */
	switch (obj_header.obj_class) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		ck_rv = create_key_object(&ptemplate, &obj_header, &new_obj_id);
		break;

	default:
		/* Object class is not supported / not yet implemented */
		ck_rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto end;
	}

	/* Object creation failed for some reson and we are not storing it
	 * Token object does not need to store, it is going to secure storage.
	 * If it is session object, it needs to add application context */
	if (ck_rv == CKR_OK && obj_header.cka_token != CK_TRUE) {

		ck_rv = add_session_object(session, new_obj_id);
		if (ck_rv != CKR_OK) {
			delete_object(new_obj_id);
			new_obj_id = CKR_OBJECT_HANDLE_INVALID;
		}
	}

end:
	params[1].value.b = ck_rv;
	params[1].value.a = new_obj_id;
	return TEE_SUCCESS;
}

TEE_Result object_get_attr_value(struct application *app,
				 uint32_t paramTypes,
				 TEE_Param *params)
{
	CK_ATTRIBUTE template_attr = {0}, obj_attr = {0};
	struct pTemplate ptemplate;
	TEE_ObjectHandle object = NULL;
	struct pkcs11_session *session;
	CK_RV ck_rv = CKR_OK;
	uint32_t i, template_pos = 0, out_buf_pos = 0;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* User space send template */
	init_pTemplate_struct(&ptemplate, params[0].memref.buffer, params[2].value.a);

	/* Get session */
	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto err;

	/* Note: Function will only return object if session can view the object ! */
	ck_rv = get_object(session, params[1].value.a, &object, 0);
	if (ck_rv != CKR_OK)
		goto err;

	/* Initialize output buffer. Because we are using same IN buffer as OUT buffer,
	 * it is containing attribute count at the beginning of buffer */
	out_buf_pos += sizeof(CK_ULONG);

	/* If all attributes are find, return value is CKR_OK */
	params[3].value.a = CKR_OK;

	/* Proceed template attributes */
	for (i = 0; i < ptemplate.attr_count; i++) {

		/* Get attribute from template */
		get_next_attr_from_template(&ptemplate, &template_pos, &template_attr);

		/* Dirty if comparision, but there is no better way */

		/* Object can reveal queried attribute */
		ck_rv = can_attr_revealed(object, &obj_attr);
		if (ck_rv == CKR_OK) {

			/* Does object contain queried attribute */
			TEE_MemFill(&obj_attr, 0, sizeof(CK_ATTRIBUTE));
			ck_rv = get_attr_from_object(object, template_attr.type, &obj_attr);
			if (ck_rv == CKR_OK) {

				/* Attribute fit into out buffer. If uValueLen is zero,
				 * user is quering pValue length */
				if (template_attr.ulValueLen != 0 &&
				    obj_attr.ulValueLen > template_attr.ulValueLen)
					ck_rv = CKR_BUFFER_TOO_SMALL;
			}
		}

		/* Check return values of previous functions */
		if (ck_rv == CKR_ATTRIBUTE_SENSITIVE ||
		    ck_rv == CKR_ATTRIBUTE_TYPE_INVALID ||
		    ck_rv == CKR_BUFFER_TOO_SMALL) {
			obj_attr.ulValueLen = -1;
			params[3].value.a = ck_rv; /* Last error message is returned */

		} else if (ck_rv == CKR_OK) {
			/* OK, CKR_OK is set before loop. */
		} else {
			/* Something went wrong */
			goto err;
		}

		/* Prepare attribute for write. There is a special case. If uValueLen is zero,
		 * user quering pValue length. Attribute write buffer function know this by
		 * pValue. If pValue is NULL, it is not writing pValue */
		if (template_attr.ulValueLen == 0) {
			TEE_Free(obj_attr.pValue);
			obj_attr.pValue = NULL;
		}

		/* Write result to out buffer */
		write_attr2buffer(params[0].memref.buffer, &out_buf_pos, &obj_attr);

		/* get_attr_from_object function malloc space for pValue */
		TEE_Free(obj_attr.pValue);
		obj_attr.pValue = NULL;
	}

	TEE_CloseObject(object);

	return TEE_SUCCESS;

err:
	/* Something went wrong, zero out out buffer and return */
	TEE_MemFill(params[0].memref.buffer, 0, params[2].value.a);
	TEE_Free(obj_attr.pValue);
	params[3].value.a = ck_rv;
	TEE_CloseObject(object);
	return TEE_SUCCESS;
}

void delete_object(CK_ULONG obj_id)
{
	TEE_ObjectHandle del_obj;

	release_object_id(obj_id);

	if (TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &obj_id, sizeof(CK_ULONG),
				     TEE_DATA_FLAG_ACCESS_WRITE_META, &del_obj) != TEE_SUCCESS)
		return;

	TEE_CloseAndDeletePersistentObject1(del_obj);
}

TEE_Result find_objects_init(struct application *app,
			     uint32_t paramTypes,
			     TEE_Param *params)
{
	struct pkcs11_session *session;
	CK_RV ck_rv = CKR_OK;
	TEE_Result tee_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto err_1;

	/* Only one find operation can be active */
	if (session->find_op.ss_enumerator != NULL) {
		ck_rv = CKR_OPERATION_ACTIVE;
		goto err_1;
	}

	/* Template is containing template attribute count as a first parameter */
	session->find_op.pTemplate = TEE_Malloc(params[2].value.a, 0);
	if (session->find_op.pTemplate == NULL) {
		ck_rv = CKR_DEVICE_MEMORY;
		goto err_1;
	}

	/* Allov SS enumerator */
	tee_rv = TEE_AllocatePersistentObjectEnumerator(&session->find_op.ss_enumerator);
	if (tee_rv != TEE_SUCCESS) {
		ck_rv = map_teec2ck(tee_rv);
		goto err_2;
	}

	tee_rv = TEE_StartPersistentObjectEnumerator(session->find_op.ss_enumerator,
						     TEE_STORAGE_PRIVATE);
	if (tee_rv != TEE_SUCCESS) {
		ck_rv = map_teec2ck(tee_rv);
		goto err_3;
	}

	/* Copy template into place */
	TEE_MemMove(session->find_op.pTemplate, params[0].memref.buffer, params[2].value.a);

	params[3].value.a = ck_rv;
	return TEE_SUCCESS;

err_3:
	TEE_FreePersistentObjectEnumerator(session->find_op.ss_enumerator);
err_2:
	TEE_Free(session->find_op.pTemplate);
err_1:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}

static CK_RV mechanism_are_listed(CK_ATTRIBUTE *queried_mechs,
				  CK_ATTRIBUTE *object_mechs)
{
	CK_BBOOL mech_found;
	uint32_t i, j;

	/* Function is checking that queried mechanism are found from object mechanism. */

	if (queried_mechs->type != CKA_ALLOWED_MECHANISMS ||
	    object_mechs->type != CKA_ALLOWED_MECHANISMS)
		return CKR_GENERAL_ERROR;

	/* Loop queried mechanism and see if they are found from object */
	for (i = 0; i < queried_mechs->ulValueLen / sizeof(queried_mechs->type); i++) {

		/* Reset value for next run */
		mech_found = CK_FALSE;

		for (j = 0; j < object_mechs->ulValueLen / sizeof(object_mechs->type); j++) {

			if (TEE_MemCompare((uint8_t *)queried_mechs->pValue +
					   (i * sizeof(queried_mechs->type)),
					   (uint8_t *)object_mechs->pValue +
					   (j * sizeof(object_mechs->type)),
					   sizeof(queried_mechs->type)) == 0) {
				mech_found = CK_TRUE;
				break;
			}
		}

		if (mech_found == CK_FALSE)
			return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

TEE_Result find_objects(struct application *app,
		       uint32_t paramTypes,
		       TEE_Param *params)
{
	uint32_t j, template_pos = 0, buffer_pos = 0;
	CK_ATTRIBUTE template_attr = {0}, object_attr = {0};
	char temp_object_id[TEE_OBJECT_ID_MAX_LEN] = {0};
	CK_OBJECT_HANDLE object_id;
	size_t object_id_len = sizeof(CK_OBJECT_HANDLE);
	struct pTemplate ptemplate;
	struct pkcs11_session *session;
	TEE_ObjectHandle object;
	CK_RV ck_rv = CKR_OK;
	CK_ULONG i = 0;
	CK_BBOOL object_match;
	TEE_Result tee_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INOUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto out;

	/* Is find operation active */
	if (session->find_op.ss_enumerator == NULL) {
		ck_rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/* pTemplate struct. Template format is documented in libtee_pkcs11 hal_gp.c file. */
	init_pTemplate_struct(&ptemplate, session->find_op.pTemplate, 0);

	/* Find operation.
	 * Inout memory size is telling how many object handle can be returned. Memory size is in
	 * bytes. */
	for (i = 0; i < params[2].value.a / sizeof(CK_OBJECT_HANDLE); ) {

		/* Set object match. If object is not matches, for-loop will change this value */
		object_match = CK_TRUE;
		ck_rv = CKR_OK;
                object_id_len = TEE_OBJECT_ID_MAX_LEN;

		/* Get next object ID */
		tee_rv = TEE_GetNextPersistentObject(session->find_op.ss_enumerator, NULL,
                                                     temp_object_id, &object_id_len);
		if (tee_rv == TEE_ERROR_ITEM_NOT_FOUND) {
                        goto out;
                } else if (tee_rv == TEE_SUCCESS) {
                    if (object_id_len != sizeof(CK_OBJECT_HANDLE)) {
                            continue;
                    } else {
                            memcpy(&object_id, temp_object_id, sizeof(CK_OBJECT_HANDLE));
                    }
		} else {
			goto err;
		}

		/* TODO: reserved IDs ! Eg TOKEN_STORE. Next patchs */

		/* Get object, if session can see the object */
		ck_rv = get_object(session, object_id, &object, 0);
		if (ck_rv != CKR_OK)
			continue;

		/* Object have template specified attributes */
		template_pos = 0;
		for (j = 0; j < ptemplate.attr_count; ++j) {

			/* Reset object attribute */
			TEE_MemFill(&object_attr, 0, sizeof(CK_ATTRIBUTE));

			/* Get next attr from search template */
			get_next_attr_from_template(&ptemplate, &template_pos, &template_attr);

			/* Check if object contain attribute */
			ck_rv = get_attr_from_object(object, template_attr.type, &object_attr);
			if (ck_rv != CKR_OK) {
				object_match = CK_FALSE;
				break;
			}

			/* CKA_ALLOWED_MECHANISMS is special case. Attribute is containing a list
			 * of allowed mechanism types. */
			if (template_attr.type == CKA_ALLOWED_MECHANISMS) {

				ck_rv = mechanism_are_listed(&template_attr, &object_attr);
				if (ck_rv != CKR_OK)
					object_match = CK_FALSE;

			} else {

				/* Attribute is found. Lets compare if it a match to queried template */
				if (template_attr.ulValueLen != object_attr.ulValueLen ||
				    TEE_MemCompare(object_attr.pValue,
						   template_attr.pValue, object_attr.ulValueLen))
					object_match = CK_FALSE;
			}

			/* End of loop. Attribute is found and it is correct. Free pValue and cont*/
			TEE_Free(object_attr.pValue);

			if (object_match == CK_FALSE)
				break;
		}

		/* Close opened object */
		TEE_CloseObject(object);

		/* If object is match, save it to OUT buffer. Else check next object */
		if (object_match == CK_FALSE)
			continue;

		/* Object is matchs */
		TEE_MemMove((uint8_t *)params[0].memref.buffer + buffer_pos,
				&object_id, sizeof(CK_OBJECT_HANDLE));
		buffer_pos += sizeof(CK_OBJECT_HANDLE);
		i++;
	}

out:
	params[3].value.a = ck_rv;
	params[2].value.a = i;
	return TEE_SUCCESS;

err:
	/* Zero all and return CK error code */
	params[3].value.a = ck_rv;
	params[2].value.a = 0;
	TEE_MemFill(params[0].memref.buffer, 0, params[2].value.a);
	return TEE_SUCCESS;
}

TEE_Result find_objects_final(struct application *app,
			     uint32_t paramTypes,
			     TEE_Param *params)
{
	struct pkcs11_session *session;
	CK_RV ck_rv = CKR_OK;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto out;

	if (session->find_op.ss_enumerator == NULL) {
		ck_rv = CKR_OPERATION_NOT_INITIALIZED;
		goto out;
	}

	/* Free resources */
	TEE_Free(session->find_op.pTemplate);
	TEE_FreePersistentObjectEnumerator(session->find_op.ss_enumerator);
	session->find_op.ss_enumerator = NULL;

out:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}

TEE_Result object_set_attr_value(struct application *app,
				 uint32_t paramTypes,
				 TEE_Param *params)
{
	TEE_ObjectHandle set_object = NULL, cpy_set_object = NULL;
	CK_ATTRIBUTE template_attr = {0}, obj_attr = {0};
	struct object_header set_obj_header;
	struct pkcs11_session *session;
	struct pTemplate ptemplate;
	CK_ULONG set_obj_attr_count;
	uint32_t i, template_pos = 0;
	CK_RV ck_rv = CKR_OK;
	TEE_Result tee_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Fillin object template manually */
	init_pTemplate_struct(&ptemplate, params[0].memref.buffer, params[2].value.a);
	ptemplate.template_for = SET_TEMPLATE;

	/* Does template contains attributes that can be modified */
	ck_rv = can_attr_modified(&ptemplate);
	if (ck_rv != CKR_OK)
		goto err_1;

	/* Get session */
	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto err_1;

	/* Note: Function will only return object if session can view the object ! */
	ck_rv = get_object(session, params[1].value.a,
			&set_object, TEE_DATA_FLAG_ACCESS_WRITE_META);
	if (ck_rv != CKR_OK)
		goto err_1;

	/* Object header of targer object. Object header is containing attr count */
	ck_rv = get_object_header(set_object, CKR_OBJECT_HANDLE_INVALID, &set_obj_header);
	if (ck_rv != CKR_OK)
		goto err_1;

	/* Store set object attribute count. This is used for copying original attrs to new obj */
	set_obj_attr_count = set_obj_header.attr_count;

	/* Object header is containing information about visibility (token/session object) */
	ck_rv = get_attr_from_template(&ptemplate, CKA_TOKEN, &template_attr);
	if (ck_rv == CKR_OK)
		set_obj_header.cka_token = *(CK_ATTRIBUTE_TYPE *)template_attr.pValue;

	/* Note: All attributes must be modified succesfully or nothing is changed */

	/* Create new object, with temprary ID. Set new attribute values to new object and
	 * copy rest from original object. If everything is success, delete original object and
	 * rename temporary object. This is done, if some set attr might fail then object
	 * is not left corrupted state */

	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &CPY_SET_OBJ_ID,
					    sizeof(CPY_SET_OBJ_ID),
					    TEE_DATA_FLAG_OVERWRITE |
					    TEE_DATA_FLAG_ACCESS_READ |
					    TEE_DATA_FLAG_ACCESS_WRITE |
					    TEE_DATA_FLAG_ACCESS_WRITE_META, NULL,
					    NULL, 0, &cpy_set_object);
	if (tee_rv != TEE_SUCCESS) {
		ck_rv = map_teec2ck(tee_rv);
		goto err_1;
	}

	/* Calculate new attribute count. New count is new attributes + existing attributes. */
	for (i = 0; i < ptemplate.attr_count; i++) {

		/* Get attribute from template */
		get_next_attr_from_template(&ptemplate, &template_pos, &template_attr);
		ck_rv = get_attr_from_object(set_object, template_attr.type, NULL);
		if (ck_rv == CKR_OK)
			continue; /* Existing attribute */
		else if (ck_rv == CKR_ATTRIBUTE_TYPE_INVALID)
			set_obj_header.attr_count += 1; /* New attribute */
		else
			goto err_2;
	}

	/* Start writing objects */

	/* Write new attrs to temporary object */
	switch (set_obj_header.obj_class) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:

		ck_rv = write_obj_template_to_object(&ptemplate, &set_obj_header,
						     cpy_set_object, write_key_pkcs11_ctl_attrs);
		if (ck_rv != CKR_OK)
			goto err_2;
		break;

	default:
		/* Storage object is needed special handling */
		goto err_2;
	}

	/* Write rest of object attributes expect template defined attrs */
	ck_rv = init_next_attr_from_object(set_object);
	if (ck_rv != CKR_OK)
		goto err_2;

	for (i = 0; i < set_obj_attr_count; i++) {

		/* get_next_attr_from_object() is mallocing space for pValue */
		TEE_Free(obj_attr.pValue);
		obj_attr.pValue = NULL;

		/* Get from object */
		ck_rv = get_next_attr_from_object(set_object, &obj_attr);
		if (ck_rv != CKR_OK)
			goto err_2;

		/* We can not use get_attribute_from_object function because object is not yet
		 * ready. All attributes are not written. Threfore we must have function, which
		 * will be keeping track of ALL pkcs11 implementation controlled attributes! */
		if (obj_attr.type == CKA_LOCAL || obj_attr.type == CKA_ALWAYS_SENSITIVE ||
		    obj_attr.type == CKA_NEVER_EXTRACTABLE)
			continue;

		/* Attribute is already written */
		if (get_attr_from_template(&ptemplate, obj_attr.type, NULL) == CKR_OK)
			continue;

		ck_rv = write_attr2object(&obj_attr, cpy_set_object);
		if (ck_rv != CKR_OK)
			goto err_3;
	}

	/* Attribute might be alloced in last loop and it is not get freed. If it is not alloced,
	 * pValue is NULL pointer and no double-free call */
	TEE_Free(obj_attr.pValue);
	obj_attr.pValue = NULL;

	/* Remove original object and rename temporary object and close object.
	 * Note: Object might be lost (original) if temporary object renaming failing or
	 * if can't add object to session */
	TEE_CloseAndDeletePersistentObject1(set_object);
	set_object = NULL;

	tee_rv = TEE_RenamePersistentObject(cpy_set_object,
					    &params[1].value.a, sizeof(CK_OBJECT_HANDLE));
	if (tee_rv != CKR_OK)
		goto err_4;

	TEE_CloseObject(cpy_set_object);
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;

err_4:
	release_object_id(params[1].value.a);
	rm_session_object(session, params[1].value.a);
err_3:
	TEE_Free(obj_attr.pValue);
err_2:
	TEE_CloseAndDeletePersistentObject1(cpy_set_object);
err_1:
	/* Something went wrong, zero out out buffer and return */
	TEE_MemFill(params[0].memref.buffer, 0, params[2].value.a);
	params[3].value.a = ck_rv;
	TEE_CloseObject(set_object);
	return TEE_SUCCESS;
}

TEE_Result destroy_object(struct application *app,
			  uint32_t paramTypes,
			  TEE_Param *params)
{
	struct pkcs11_session *session;
	TEE_ObjectHandle object = NULL;
	CK_RV ck_rv;

	/* Expected parameters */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get session */
	ck_rv = app_get_session(app, params[3].value.a, &session);
	if (ck_rv != CKR_OK)
		goto out;

	/* Note: Function will only return object if session can view the object ! */
	ck_rv = get_object(session, params[0].value.a, &object, 0);
	if (ck_rv != CKR_OK)
		goto out;

	/* Close object and use delete object function. Delete function is opening object for
	 * deletetion and therefore it will only work with closed object */
	TEE_CloseObject(object);
	delete_object(params[0].value.a);
	rm_session_object(session, params[0].value.a);
out:
	params[3].value.a = ck_rv;
	return TEE_SUCCESS;
}
