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

#include "pkcs11_session.h"
#include "pkcs11_application.h"
#include "tee_internal_api.h"
#include "tee_list.h"
#include "object.h"
#include "compat.h"
#include "slot_token.h"

#include <stdlib.h>

void clean_session(struct pkcs11_session *session)
{
	struct session_object *ses_obj = NULL;
	struct list_head *pos, *la;

	if (session == NULL)
		return;

	if (session->is_initialized == false)
		return; /* nothing to do */

	if (!list_is_empty(&session->list)) {

		LIST_FOR_EACH_SAFE(pos, la, &session->list) {
			ses_obj = LIST_ENTRY(pos, struct session_object, list);
			list_unlink(&ses_obj->list);
			delete_object(ses_obj->ID);
			TEE_Free(ses_obj);
		}
	}

	TEE_MemFill(session, 0, sizeof(struct pkcs11_session));
}

CK_RV create_new_session(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	CK_RV ret;
	struct pkcs11_session *session;
	CK_FLAGS flags;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_OUTPUT) {
		return CKR_ARGUMENTS_BAD;
	}

	flags = params[0].value.a;

	ret = create_session_handle(app, flags, &session);
	if (ret != 0)
		return ret;

	params[1].value.a = session->session_id;

	return 0;
}

CK_RV close_session(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	struct pkcs11_session *session;
	CK_RV ret;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT)
		return CKR_ARGUMENTS_BAD;

	ret = app_get_session(app, params[0].value.a, &session);
	if (ret != 0)
		return ret;

	clean_session(session);

	app_check_login_status(app);
	return CKR_OK;
}

CK_RV close_all_sessions(struct application *app)
{
	foreach_session(app, clean_session);
	app_check_login_status(app);

	return CKR_OK;
}

CK_RV get_session_info(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	struct pkcs11_session *session;
	CK_RV ret;

	if (!(TEE_PARAM_TYPE_GET(paramTypes, 0) & TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) {
		return CKR_ARGUMENTS_BAD;
	}

	ret = app_get_session(app, params[1].value.a, &session);
	if (ret != 0)
		return ret;

	TEE_MemMove(params[0].memref.buffer, &session->sessionInfo, sizeof(CK_SESSION_INFO));

	return 0;
}

CK_RV add_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id)
{
	struct session_object *object;

	object = TEE_Malloc(sizeof(struct session_object), 0);
	if (object == NULL)
		return CKR_DEVICE_MEMORY;

	object->ID = object_id;
	INIT_LIST(&object->list);

	list_add_before(&object->list, &session->list);

	return CKR_OK;
}

void rm_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id)
{
	struct session_object *ses_obj = NULL;
	struct list_head *pos, *la;

	if (list_is_empty(&session->list))
		return;

	LIST_FOR_EACH_SAFE(pos, la, &session->list) {
		ses_obj = LIST_ENTRY(pos, struct session_object, list);
		if (ses_obj->ID != object_id)
			continue;

		list_unlink(&ses_obj->list);
		TEE_Free(ses_obj);
		return;
	}
}

CK_RV app_login_session(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	CK_RV ret;
	CK_USER_TYPE user_type;
	uint32_t pin_len;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)
		return CKR_ARGUMENTS_BAD;

	user_type = params[2].value.b;
	pin_len = params[2].value.a;

	ret = check_password(user_type, params[0].memref.buffer, pin_len);
	if (ret != 0)
		return ret;

	/* If we have made it here we have correctly validated the pin */

	return application_set_logged_in(app, user_type);
}

CK_RV app_logout_session(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_OUTPUT)
		return CKR_ARGUMENTS_BAD;

	params[3].value.a  = is_session_logged_in(app, params[0].value.a);
	if (params[3].value.a  != CKR_OK)
		return TEE_SUCCESS;

	application_set_logout(app);
	return TEE_SUCCESS;
}

CK_RV session_init_pin(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	CK_RV ret;
	struct pkcs11_session *session;
	uint32_t pin_len;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT) {
		return CKR_ARGUMENTS_BAD;
	}

	ret = app_get_session(app, params[3].value.a, &session);
	if (ret != 0)
		return ret;

	if (session->sessionInfo.state != CKS_RW_SO_FUNCTIONS)
		return CKR_USER_NOT_LOGGED_IN;

	pin_len = params[1].value.a;

	if (pin_len == 0)
		return CKR_ARGUMENTS_BAD; /* we do not currently support Trusted UI */

	return set_password(CKU_USER, params[0].memref.buffer, pin_len);
}

CK_RV session_set_pin(struct application *app, uint32_t paramTypes, TEE_Param params[4])
{
	CK_RV ret;
	struct pkcs11_session *session;
	CK_USER_TYPE user_type;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT) {
		return CKR_ARGUMENTS_BAD;
	}

	ret = app_get_session(app, params[3].value.a, &session);
	if (ret != 0)
		return ret;

	if (!(session->sessionInfo.state == CKS_RW_PUBLIC_SESSION ||
	    session->sessionInfo.state == CKS_RW_USER_FUNCTIONS ||
	    session->sessionInfo.state == CKS_RW_SO_FUNCTIONS))
		return CKR_SESSION_READ_ONLY;

	if (params[2].value.a == 0 || params[2].value.b == 0)
		return CKR_ARGUMENTS_BAD; /* we do not currently support Trusted UI */

	user_type = (session->sessionInfo.state == CKS_RW_SO_FUNCTIONS) ? CKU_SO : CKU_USER;

	/* check the old password is valid before replacing it */
	ret = check_password(user_type, params[0].memref.buffer, params[2].value.a);
	if (ret != 0)
		return ret;

	return set_password(user_type, params[1].memref.buffer, params[2].value.b);
}

CK_RV this_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id)
{
	struct session_object *ses_obj = NULL;
	struct list_head *pos;

	if (session == NULL || session->is_initialized == false)
		return CKR_GENERAL_ERROR;

	if (list_is_empty(&session->list))
		return CKR_GENERAL_ERROR;

	LIST_FOR_EACH(pos, &session->list) {
		ses_obj = LIST_ENTRY(pos, struct session_object, list);
		if (object_id == ses_obj->ID)
			return CKR_OK;
	}

	return CKR_GENERAL_ERROR;
}
