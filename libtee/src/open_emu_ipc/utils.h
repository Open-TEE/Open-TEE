/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#ifndef __TEE_OPEN_EMU_UTILS_H__
#define __TEE_OPEN_EMU_UTILS_H__

#include <inttypes.h>

/*!
 * \brief generate_random_path Generate a path, that can be used for a shared memory path
 * Memory for the path will be allocated in this function but it is the callers responsibility
 * to free the memory when finished.
 * \param path [OUT] the path that is created by this function
 * \return 0 on success, -1 if no memory available
 */
int generate_random_path(char *path);

#endif
