/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

#ifndef __MUTEX_MANAGER_H_
#define __MUTEX_MANAGER_H_

#include "cryptoki.h"

/*!
 * \brief init_mutex_callbacks
 * If the calling application wishes to register it's own callbacks we must
 * register and store them
 * \param create [IN] The callback to create a mutex
 * \param destroy [IN] The callback to destroy a mutex
 * \param lock [IN] The callback to aquire the mutex
 * \param unlock [IN] The callback to release the mutex
 */
void init_mutex_callbacks(CK_CREATEMUTEX create, CK_DESTROYMUTEX destroy, CK_LOCKMUTEX lock,
			  CK_UNLOCKMUTEX unlock);

/*!
 * \brief create_mutex
 * Create a mutex and return the handle to the caller
 * \param mutex [OUT] The mutex to be populated
 * \return 0 on success
 */
int create_mutex(void **mutex);

/*!
 * \brief destroy_mutex
 * Free up a mutex that is no longer required
 * \param mutex [IN] The mutex to free
 * \return 0 on success
 */
int destroy_mutex(void *mutex);

/*!
 * \brief lock_mutex
 * Aquire the mutex, or block until the mutex can be aquired
 * \param mutex [IN] The mutex to aquire
 * \return 0 on success
 */
int lock_mutex(void *mutex);

/*!
 * \brief unlock_mutex
 * Release a mutex that is no longer required
 * \param mutex [IN] The mutex to release
 * \return 0 on success
 */
int unlock_mutex(void *mutex);

#endif /* __MUTEX_MANAGER_H_ */
