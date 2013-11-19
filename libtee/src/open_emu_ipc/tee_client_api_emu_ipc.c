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

#include "tee_client_api.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "utils.h"

typedef struct context_t {
	int sockfd;
	uint32_t initialized;
} TEEC_Context;

/*!
 * \brief TEEC_Session Container linking a Client Application to a particular Trusted Application
 */
typedef struct session_t {
	uint32_t session;
} TEEC_Session;

enum mem_type {
	REGISTERED = 0,
	ALLOCATED = 0xa110ca7e
};

struct shared_mem_internal {
	TEEC_Context *parent_ctx; /*!< Pointer to the context that owns this shared memory */
	char *shm_uuid;           /*!< Pointer to the shared memory object that has been created */
	void *reg_address;	  /*!< store the mmap address that is used for registered mem */
	enum mem_type type;       /*!< The type of the memory, i.e. allocated or registered */
};

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

/*!
 * \brief create_shared_mem_internal
 * Create a memory mapped shared memory object that can be used to transfer data between the TEE
 * and the Client application
 * \param context The context to which we are registering the memory
 * \param sharedMem Shared memory object that contains the definition of the region we are creating
 * \param type The type of memory allocation \sa enum mem_type
 * \return TEEC_SUCCESS on success, other error on failure
 */
static TEEC_Result create_shared_mem_internal(TEEC_Context *context, TEEC_SharedMemory *sharedMem,
					      enum mem_type type)
{
	int flag = 0;
	int fd;
	void *address = NULL;
	TEEC_Result ret = TEEC_SUCCESS;
	struct shared_mem_internal *imp;

	if (!context || !sharedMem || sharedMem->flags == 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	imp = (struct shared_mem_internal *)malloc(sizeof(struct shared_mem_internal));
	if (!imp)
		return TEEC_ERROR_OUT_OF_MEMORY;

	memset(imp, 0, sizeof(struct shared_mem_internal));

	/* The name of the shm object files should be in the format "/somename\0"
	 * so we will generate a random name that matches this format based of of
	 * a UUID
	 */
	if (generate_random_path(imp->shm_uuid) == -1) {
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto errorExit;
	}

	if ((sharedMem->flags & TEEC_MEM_OUTPUT) && !(sharedMem->flags & TEEC_MEM_INPUT))
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(imp->shm_uuid, (flag | O_CREAT | O_EXCL),
		      (S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP));
	if (fd == -1) {
		ret = TEEC_ERROR_GENERIC;
		goto errorExit;
	}

	if (ftruncate(fd, sharedMem->size) == -1) {
		ret = TEEC_ERROR_GENERIC;
		goto errorTruncate;
	}

	address = mmap(NULL, sharedMem->size,
		       ((flag == O_RDONLY) ? PROT_READ : (PROT_WRITE | PROT_READ)),
		       MAP_SHARED, fd, 0);
	if (address == MAP_FAILED) {
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto errorTruncate;
	}

	/* If we are allocating memory the buffer is the new mmap'd region, where as if we are
	 * only registering memory the buffer has already been alocated locally, so the mmap'd
	 * region is where we will copy the data just before we call a command in the TEE, so it
	 * must be stored seperatly in the "implementation deined section"
	 */
	if (type == ALLOCATED)
		sharedMem->buffer = address;
	else if (type == REGISTERED)
		imp->reg_address = address;

	//TODO we must register the shared memory with the context
	imp->parent_ctx = context;
	imp->type = type;

	/* Store the shared memory object name so that the emulator can open the correct region */
	sharedMem->imp = (void *)imp;

	return TEEC_SUCCESS;

errorTruncate:
	shm_unlink(imp->shm_uuid);

errorExit:
	free(imp->shm_uuid);
	free(imp);
	return ret;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int sockfd;
	struct sockaddr_un sock_addr;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || context->initialized == 0xca11ab1e)
		return TEEC_ERROR_BAD_PARAMETERS;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return TEEC_ERROR_COMMUNICATION;

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		close(sockfd);
		return TEEC_ERROR_COMMUNICATION;
	}

	context->sockfd = sockfd;
	context->initialized = 0xca11ab1e;
	return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	if (!context || context->initialized != 0xca11ab1e)
		return;

	//TODO should check that we do not have any open sessions first
	close(context->sockfd);
	context->initialized = 0xdeadbeef;
	return;
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
	if (!context || !sharedMem || !sharedMem->buffer)
		return TEEC_ERROR_BAD_PARAMETERS;

	return create_shared_mem_internal(context, sharedMem, REGISTERED);
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
	return create_shared_mem_internal(context, sharedMem, ALLOCATED);
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem)
{
	void *address;
	struct shared_mem_internal *imp;

	if (!sharedMem)
		return;

	imp = (struct shared_mem_internal *)sharedMem->imp;

	/* If we allocated the memory free the buffer, other wise if it is just registered
	 * the buffer belongs to the Client Application, so we should not free it, instead
	 * we should free the mmap'd region that was mapped to support it
	 */
	if (imp->type == ALLOCATED)
		address = sharedMem->buffer;
	else
		address = imp->reg_address;

	/* Remove the memory mapped region and the shared memory */
	munmap(address, sharedMem->size);
	shm_unlink(imp->shm_uuid);

	/* Free the memory that has been allocated for the internal implementation */
	free(imp->shm_uuid);
	free(imp);
	sharedMem->imp = NULL;

	//TODO we must unregister the shared memory from the Context

	return;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connectionMethod,
			     void *connectionData, TEEC_Operation *operation,
			     uint32_t *returnOrigin)
{
	return TEEC_SUCCESS;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	if (!session)
		return;

	return;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
			       TEEC_Operation *operation, uint32_t *returnOrigin)
{
	return TEEC_SUCCESS;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	if (!operation)
		return;

	return;
}
