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

#ifndef __OBJECT_H__
#define __OBJECT_H__

#include "tee_internal_api.h"
#include "tee_list.h"
#include "cryptoki.h"

struct application;
struct pkcs11_session;

struct session_object {
	struct list_head list;
	CK_OBJECT_HANDLE ID;
};

struct pkcs11_object_find {
	TEE_ObjectEnumHandle ss_enumerator;
	void *pTemplate; /* Raw template == as received from user space */
};

/* Frequently needed information about object and . Struct is placed at the beginning of object,
 * when object is stored into secure storage */
struct object_header {
	CK_OBJECT_CLASS obj_class;
	CK_BBOOL cka_token;
	CK_ULONG attr_count;
};

/*!
 * \brief create_object
 * Creates object. Function conducts parameter check and then creates object.
 * \param paramTypes Format of the data sent from the userspace
 * \param params The in/out buffers to hold the object template
 * \return TEE_ERROR_BAD_PARAMETERS if paramTypes are not correct. Else it will return TEE_SUCCESS.
 * Note: Object creation return value is mapped into params
 */
TEE_Result create_object(struct application *app,
			 uint32_t paramTypes,
			 TEE_Param *params);

/*!
 * \brief object_get_attr_value
 * C_GetAttributeValue
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result object_get_attr_value(struct application *app,
				 uint32_t paramTypes,
				 TEE_Param *params);

/*!
 * \brief find_objects_init
 * C_FindObjectsInit
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result find_objects_init(struct application *app,
			    uint32_t paramTypes,
			    TEE_Param *params);

/*!
 * \brief find_objects
 * C_FindObjects
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result find_objects(struct application *app,
		       uint32_t paramTypes,
		       TEE_Param *params);

/*!
 * \brief find_objects_final
 * C_FindObjectsFinal
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result find_objects_final(struct application *app,
			     uint32_t paramTypes,
			     TEE_Param *params);

/*!
 * \brief get_object
 * Opens object, if session is allowed to use the object
 * \param session
 * \param obj_id
 * \param object
 * \return
 */
CK_RV get_object(struct pkcs11_session *session,
		 CK_OBJECT_HANDLE obj_id,
		 TEE_ObjectHandle *object,
		 uint32_t addidional_flags);

/*!
 * \brief get_attr_from_object
 * Return an attribute from object if it is found.
 * Note. Object must be opened for read or read/write.
 * Note Note: Free attribute pValue!!
 * \param object
 * \param type
 * \param ck_attr
 * \return
 */
CK_RV get_attr_from_object(TEE_ObjectHandle object,
			   CK_ATTRIBUTE_TYPE type,
			   CK_ATTRIBUTE *ck_attr);

/*!
 * \brief delete_object
 * Delete an obhect based on its storage ID
 * \param obj_id The ID to remove
 */
void delete_object(CK_ULONG obj_id);

/*!
 * \brief get_object_header
 * Returning object header from SS object.
 * \param object If object is opened for read, object is read and left open
 * \param obj_id If != CKR_OBJECT_HANDLE_INVALID, object will be opened, read and closed
 * \param obj_header return value
 * \return 0 on success
 */
CK_RV get_object_header(TEE_ObjectHandle object,
			CK_OBJECT_HANDLE obj_id,
			struct object_header *obj_header);

/*!
 * \brief object_set_attr_value
 * C_SetAttributeValue
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result object_set_attr_value(struct application *app,
				 uint32_t paramTypes,
				 TEE_Param *params);

/*!
 * \brief destroy_object
 * C_DestroyObject
 * \param app
 * \param paramTypes
 * \param params
 * \return
 */
TEE_Result destroy_object(struct application *app,
			  uint32_t paramTypes,
			  TEE_Param *params);

#endif /* __OBJECT_H__ */
