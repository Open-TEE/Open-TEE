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

#ifndef __PKCS11_SESSION_H__
#define __PKCS11_SESSION_H__

#include "crypto.h"
#include "cryptoki.h"
#include "object.h"
#include "tee_internal_api.h"
#include "tee_list.h"

#include <stdbool.h>

struct application;

struct pkcs11_session {
	struct pkcs11_crypto_op crypto_op;
	struct pkcs11_object_find find_op;
	struct list_head list;
	CK_SESSION_INFO sessionInfo;
	uint32_t session_id;
	bool is_initialized;
};

/*!
 * \brief free_session
 * Cleanup any resources used by a session (does NOT try to call free() on the session)
 * \param session The session to be cleaned
 */
void clean_session(struct pkcs11_session *session);

/*!
 * \brief create_new_session
 * Create a new pkcs11 session
 * \param app The associated application
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV create_new_session(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief close_session
 * Close a session to the token and clean up any items that it has
 * \param app The application that owns the session
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV close_session(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief close_all_sessions
 * Close all of the sessions associated with an application
 * \param app The application
 * \return 0 on success
 */
CK_RV close_all_sessions(struct application *app);

/*!
 * \brief get_session_info
 * Get the information for a specific slot
 * \param app The application that owns the session
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV get_session_info(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief add_session_object
 * Function is adding object ID to session. (function is not generating an object)
 * \param session The session to be object added
 * \param object_id
 * \return on success CKR_OK
 */
CK_RV add_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id);

/*!
 * \brief rm_session_object
 * Remove session object ID from session. (just removing ID, not the object)
 * \param  session The session to be object ID removed
 * \param object_id
 */
void rm_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id);

/*!
 * \brief app_login_session
 * Login to the token
 * \param app The application that owns the session
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV app_login_session(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief app_logout_session
 * Logout of a session
 * \param app The application that owns the session
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV app_logout_session(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief session_init_pin
 * Initialize the normal users pin
 * \param app The application to which the session is connected
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV session_init_pin(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief session_set_pin
 * Modify the pin of the logged in user or if not logged in then the CKU_USER pin is changed
 * \param app The application that owns the session
 * \param paramTypes The type of the data sent from the user space
 * \param params The actual data that is sent
 * \return 0 on success
 */
CK_RV session_set_pin(struct application *app, uint32_t paramTypes, TEE_Param params[4]);

/*!
 * \brief this_session_object
 * Is object belonging to queried session.
 * \param session Session
 * \param object_id Tested object ID
 * \return CKR_OK if it is queried session object.
 */
CK_RV this_session_object(struct pkcs11_session *session, CK_OBJECT_HANDLE object_id);


#endif // PKCS11_SESSION_H
