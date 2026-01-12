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
#include "pkcs11_application.h"
#include "pkcs11_session.h"
#include "slot_token.h"
#include "tee_internal_api.h"

#include "tee_logging.h"

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	TEE_Result ret;

	ret = initialize_token(false, 0, NULL);
	if (ret != 0)
		return ret;

	return initialize_apps();
}

void TA_EXPORT TA_DestroyEntryPoint(void) {}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
					      void **sessionContext)
{
	TEE_Result ret;
	uint64_t nonce;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT)
		return CKR_ARGUMENTS_BAD;

	ret = allocate_application((struct application **)sessionContext, &nonce);
	if (ret != 0)
		return ret;

	params[0].value.a = nonce >> 32;
	params[0].value.b = nonce & 0xFFFFFFFF;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	delete_application((struct application *)sessionContext);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	TEE_Result ret = TEE_SUCCESS;
	struct application *app = (struct application *)sessionContext;

	switch (commandID) {
	case TEE_GET_TOKEN_INFO:
		ret = get_token_info(paramTypes, params);
		goto out;
	case TEE_INIT_TOKEN:
		ret = initialize_token(true, paramTypes, params);
		goto out;
	case TEE_GET_MECHANISM_LIST:
		ret = get_mechanism_list(paramTypes, params);
		goto out;
	}

	/* App based session related info below */
	if (app == NULL)
		return CKR_ARGUMENTS_BAD;

	switch (commandID) {
	case TEE_CREATE_PKCS11_SESSION:
		ret = create_new_session(app, paramTypes, params);
		goto out;
	case TEE_CLOSE_PKCS11_SESSION:
		ret = close_session(app, paramTypes, params);
		goto out;
	case TEE_CLOSE_ALL_PKCS11_SESSION:
		ret = close_all_sessions(app);
		goto out;
	case TEE_GET_SESSION_INFO:
		ret = get_session_info(app, paramTypes, params);
		goto out;
	case TEE_CREATE_OBJECT:
		ret = create_object(app, paramTypes, params);
		goto out;
	case TEE_CRYPTO_INIT:
		ret = crypto_init(app, paramTypes, params);
		goto out;
	case TEE_CRYPTO:
		ret = crypto(app, paramTypes, params);
		goto out;
	case TEE_VERIFY:
		ret = crypto_verify(app, paramTypes, params);
		goto out;
	case TEE_LOGIN_SESSION:
		ret = app_login_session(app, paramTypes, params);
		goto out;
	case TEE_LOGOUT_SESSION:
		ret = app_logout_session(app, paramTypes, params);
		goto out;
	case TEE_INIT_PIN:
		ret = session_init_pin(app, paramTypes, params);
		goto out;
	case TEE_SET_PIN:
		ret = session_set_pin(app, paramTypes, params);
		goto out;
	case TEE_GENERATE_RANDOM:
		ret = crypto_generate_random(app, paramTypes, params);
		goto out;
	case TEE_GET_ATTR_VALUE:
		ret = object_get_attr_value(app, paramTypes, params);
		goto out;
	case TEE_FIND_OBJECTS_INIT:
		ret = find_objects_init(app, paramTypes, params);
		goto out;
	case TEE_FIND_OBJECTS:
		ret = find_objects(app, paramTypes, params);
		goto out;
	case TEE_FIND_OBJECTS_FINAL:
		ret = find_objects_final(app, paramTypes, params);
		goto out;
	case TEE_SET_ATTR_VALUE:
		ret = object_set_attr_value(app, paramTypes, params);
		goto out;
	case TEE_DESTROY_OBJECT:
		ret = destroy_object(app, paramTypes, params);
		goto out;
	default:
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

out:
	return ret;
}
