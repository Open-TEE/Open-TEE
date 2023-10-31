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

#ifndef __PKCS11_APPLICATION_H__
#define __PKCS11_APPLICATION_H__

#include "token_conf.h"
#include "cryptoki.h"

#include <stdint.h>

struct pkcs11_session;
struct application;

/*!
 * Declare a function callback that can be used in the foreach_session function
 */
typedef void (*foreach_session_cb_t)(struct pkcs11_session *session);

/*!
 * \brief initialize_apps
 * Initialize the applications structure
 * \return 0 on success
 */
CK_RV initialize_apps();

/*!
 * \brief allocate_application
 * Add a new application to the list of applications
 * \param new_app Return a pointer to the application struct on success
 * \param nonce Unique number to track the app id
 * \return 0 on success
 */
CK_RV allocate_application(struct application **new_app, uint64_t *nonce);

/*!
 * \brief delete_application
 * An application has closed its control socket and this means that it has disconnected so
 * free up any remaining resources.
 * \param nonce The applications ID
 */
void delete_application(struct application *old_app);

/*!
 * \brief create_session_handle
 * Retrieve a pointer to an uninitialized session structure
 * \param app The application to which the session will be attached
 * \param flags These help to determine the state of hte session
 * \param session The new session that is connected to the application
 * \return 0 on success
 */
CK_RV create_session_handle(struct application *app,
			    CK_FLAGS flags,
			    struct pkcs11_session **session);

/*!
 * \brief get_session
 * Find a session associated with an application
 * \param app The application context
 * \param sessionID The ID of the session to retrieve
 * \param session a pointer to the session if it exists
 * \return 0 on success
 */
CK_RV app_get_session(struct application *app,
		      uint32_t session_id,
		      struct pkcs11_session **session);

/*!
 * \brief app_check_login_status
 * Determine if all sessions are closed for this application.  If they are then the application
 * is logged out page 119 of the spec
 * \sa C_CloseSession
 * \param app The application for which the status should be ckecked
 */
void app_check_login_status(struct application *app);

/*!
 * \brief foreach_session
 * Iterate over all the sessions associated with an application and perform the callback on each
 * \param app The application the sessions are associated with
 * \param cb The callback function to call
 * \return 0 on success
 */
CK_RV foreach_session(struct application *app, foreach_session_cb_t cb);

/*!
 * \brief application_set_logged_in
 * Set the application state to logged in and set the state of each session accordingly
 * \param app The application the sessions are associated with
 * \param user_type The type of login that we have
 * \return 0 on success
 */
CK_RV application_set_logged_in(struct application *app, CK_USER_TYPE user_type);

/*!
 * \brief application_set_logout
 * Logout all application sessions.
 * \param app
 */
void application_set_logout(struct application *app);

/*!
 * \brief is_session_logged_in
 * \param app The application the sessions are associated with
 * \param session_id id of queried session
 * \return CKR_OK in case of logged in. CKR_USER_NOT_LOGGED_IN if not logged in.
 */
CK_RV is_session_logged_in(struct application *app,
			   uint32_t session_id);

#endif // __PKCS11_APPLICATION_H__
