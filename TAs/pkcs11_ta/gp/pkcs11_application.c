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

#include "pkcs11_application.h"
#include "token_conf.h"
#include "compat.h"
#include "pkcs11_session.h"
#include "slot_token.h"
#include "tee_list.h"
#include "cryptoki.h"

#include <stdlib.h>
#include <stdbool.h>

#define PUBLIC_USER 0xFF

struct application {
	uint64_t nonce;
	CK_USER_TYPE user;
	struct pkcs11_session sessions[MAX_SESSIONS];
	bool is_initialized;
};

/* start by avoiding malloc by using a static allocation of applications */
static struct application app_pool[MAX_APPS];

/*!
 * \brief calculate_state
 * determine the state of a session based on the logged in status and requested flags
 * \param user The currently logged in user
 * \param flags The flags of the session (RW or RO)
 * \return
 */
static CK_STATE calculate_state(CK_USER_TYPE user, CK_FLAGS flags)
{
	if (flags & CKF_RW_SESSION) {
		if (user == CKU_SO)
			return CKS_RW_SO_FUNCTIONS;
		else if (user == CKU_USER)
			return CKS_RW_USER_FUNCTIONS;
		else
			return CKS_RW_PUBLIC_SESSION;
	} else {
		if (user == CKU_USER)
			return CKS_RO_USER_FUNCTIONS;
		else
			return CKS_RO_PUBLIC_SESSION;
	}
}

CK_RV initialize_apps()
{
	/* TODO  place holder if we need some setup */
	return 0;
}

CK_RV allocate_application(struct application **new_app, uint64_t *nonce)
{
	int i;
	/* this is a filthy hack should be replaced with a proper nonce generation routine */
	static uint64_t base_nonce = 11223344556677;

	if (new_app == NULL || nonce == NULL)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < MAX_APPS; i++) {
		if (app_pool[i].is_initialized == false) {
			TEE_MemFill(&app_pool[i], 0, sizeof(struct application));
			app_pool[i].nonce = base_nonce++;
			app_pool[i].is_initialized = true;
			app_pool[i].user = PUBLIC_USER; /* no one is logged in */
			*nonce = app_pool[i].nonce;
			*new_app = &app_pool[i];
			return 0;
		}
	}

	/* we do not have a free slot, so OUT of memory */
	return CKR_DEVICE_MEMORY;
}

void delete_application(struct application *old_app)
{
	int i;

	if (old_app == NULL)
		return;

	for (i = 0; i < MAX_SESSIONS; i++)
		clean_session(&old_app->sessions[i]);

	TEE_MemFill(old_app, 0, sizeof(struct application));
}

CK_RV create_session_handle(struct application *app, CK_FLAGS flags,
			    struct pkcs11_session **session)
{
	int i;

	if (app == NULL || session == NULL)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (app->sessions[i].is_initialized == false) {
			/* can not log in a RO session when there is already a SO
			 * session logged in */
			if (app->user == CKU_SO && !(flags & CKF_RW_SESSION))
				return CKR_SESSION_READ_WRITE_SO_EXISTS;

			/* can only open RO sessions when the token is write protected */
			if (is_token_write_protected() && ((flags & CKF_RW_SESSION)))
				return CKR_TOKEN_WRITE_PROTECTED;

			INIT_LIST(&app->sessions[i].list);
			app->sessions[i].is_initialized = true;
			app->sessions[i].session_id = ~i; /* standard disallows 0 as session id */
			app->sessions[i].sessionInfo.flags = flags;
			app->sessions[i].sessionInfo.state = calculate_state(app->user, flags);
			*session = &app->sessions[i];
			return 0;
		}
	}

	/* No available sessions left */
	return CKR_SESSION_COUNT;
}

CK_RV app_get_session(struct application *app, uint32_t session_id, struct pkcs11_session **session)
{
	uint32_t actual_session_id = ~session_id; /*convert back to real session ID */

	if (app == NULL || session == NULL)
		return CKR_ARGUMENTS_BAD;

	if (actual_session_id >= MAX_SESSIONS ||
	    app->sessions[actual_session_id].is_initialized == false)
		return CKR_SESSION_HANDLE_INVALID;

	*session = &app->sessions[actual_session_id];
	return 0;
}

void app_check_login_status(struct application *app)
{
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		/* if there is even 1 initialized session we do not change the state */
		if (app->sessions[i].is_initialized == true)
			return;
	}

	/* If we get here then there are currently no open sessions so we fallback to public mode */
	app->user = PUBLIC_USER;
}

CK_RV foreach_session(struct application *app, foreach_session_cb_t cb)
{
	int i;

	if (app == NULL || cb == NULL)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < MAX_SESSIONS; i++)
		cb(&app->sessions[i]);

	return 0;
}

CK_RV application_set_logged_in(struct application *app, CK_USER_TYPE user_type)
{
	int i;

	if (app == NULL)
		return CKR_ARGUMENTS_BAD;

	/* TODO check all the possible configurations for logging, what SO and USER combinations
	 * are allowed
	 */
	app->user = user_type;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (app->sessions[i].is_initialized == true) {
			app->sessions[i].sessionInfo.state =
					calculate_state(user_type,
							app->sessions[i].sessionInfo.flags);
		}
	}

	return 0;
}

void application_set_logout(struct application *app)
{
	uint32_t i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (app->sessions[i].is_initialized != true)
			continue;

		if (app->sessions[i].sessionInfo.state == CKS_RW_SO_FUNCTIONS ||
		    app->sessions[i].sessionInfo.state == CKS_RW_USER_FUNCTIONS)
			app->sessions[i].sessionInfo.state = CKS_RW_PUBLIC_SESSION;

		else if (app->sessions[i].sessionInfo.state == CKS_RO_USER_FUNCTIONS)
			app->sessions[i].sessionInfo.state = CKS_RO_PUBLIC_SESSION;
	}
}

CK_RV is_session_logged_in(struct application *app,
			   uint32_t session_id)
{
	struct pkcs11_session *session;
	CK_RV ck_rv;

	ck_rv = app_get_session(app, session_id, &session);
	if (ck_rv != CKR_OK)
		return ck_rv;

	if (!(session->sessionInfo.state != CKS_RW_USER_FUNCTIONS ||
	      session->sessionInfo.state != CKS_RO_USER_FUNCTIONS))
		return CKR_USER_NOT_LOGGED_IN;

	return CKR_OK;
}
