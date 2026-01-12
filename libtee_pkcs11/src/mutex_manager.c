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

#include "mutex_manager.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

static CK_CREATEMUTEX g_create;
static CK_DESTROYMUTEX g_destroy;
static CK_LOCKMUTEX g_lock;
static CK_UNLOCKMUTEX g_unlock;

void init_mutex_callbacks(CK_CREATEMUTEX create, CK_DESTROYMUTEX destroy, CK_LOCKMUTEX lock,
			  CK_UNLOCKMUTEX unlock)
{
	g_create = create;
	g_destroy = destroy;
	g_lock = lock;
	g_unlock = unlock;
}

int create_mutex(void **mutex)
{
	pthread_mutex_t *m_lock = NULL;

	if (g_create) {
		return g_create(mutex);
	} else {
		m_lock = calloc(1, sizeof(pthread_mutex_t));
		if (!m_lock)
			return CKR_HOST_MEMORY;

		if (pthread_mutex_init(m_lock, NULL) != 0) {
			free(m_lock);
			return CKR_GENERAL_ERROR;
		}

		*mutex = m_lock;
		return 0;
	}
}

int destroy_mutex(void *mutex)
{
	int ret;

	if (g_destroy) {
		return g_destroy(mutex);
	} else {
		do {
			ret = pthread_mutex_destroy((pthread_mutex_t *)mutex);
			/* pthread_mutex_destroy may return EBUSY, which means that another
			 * thread is holding a lock with this mutex. So loop until we complete
			 * successfully ot another error occurs.
			 */
			if (ret != EBUSY)
				break;
		} while (1);

		free(mutex);
		return (ret == 0) ? 0 : CKR_GENERAL_ERROR;
	}
}

int lock_mutex(void *mutex)
{
	if (g_lock)
		return g_lock(mutex);
	else
		return pthread_mutex_lock((pthread_mutex_t *)mutex);
}

int unlock_mutex(void *mutex)
{
	if (g_unlock)
		return g_unlock(mutex);
	else
		return pthread_mutex_unlock((pthread_mutex_t *)mutex);
}
