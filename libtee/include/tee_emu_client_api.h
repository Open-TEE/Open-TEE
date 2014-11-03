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

#ifndef __TEE_EMU_CLIENT_API_H__
#define __TEE_EMU_CLIENT_API_H__

#include <inttypes.h>
#include <pthread.h>

#define INITIALIZED 0xca

/*!
 * \brief TEEC_Context Logical container linking the Client Application to a particular TEE
 */
typedef struct {
	pthread_mutex_t mutex;
	int sockfd;
	uint8_t init;
} TEEC_Context;

/*!
 * \brief TEEC_Session Container linking a Client Application to a particular Trusted Application
 */
typedef struct {
	pthread_mutex_t mutex;
	int sockfd;
	uint8_t init;
} TEEC_Session;

enum mem_type { REGISTERED = 0, ALLOCATED = 0xa110ca7e };

/*!
  * \brief TEEC_SharedMemory A shared memory block that has been registered or allocated
  */
typedef struct {
	void *buffer;   /*!< pointer to a memory buffer that is shared with TEE */
	size_t size;    /*!< The size of the memory buffer in bytes */
	uint32_t flags; /*!< bit vector that can contain TEEC_MEM_INPUT or TEEC_MEM_OUTPUT */
	/* TODO what should be done about the opaque type <implementation defined> section */
	TEEC_Context *parent_ctx; /*!< Pointer to the context that owns this shared memory */
	char *shm_uuid;		  /*!< Pointer to the shared memory object that has been created */
	void *reg_address;	/*!< store the mmap address that is used for registered mem */
	enum mem_type type;       /*!< The type of the memory, i.e. allocated or registered */
	uint8_t init;
} TEEC_SharedMemory;

#endif
