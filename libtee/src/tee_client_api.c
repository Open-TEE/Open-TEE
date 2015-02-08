/*****************************************************************************
** Copyright (C) 2014 Intel Corporation.                                    **
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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "com_protocol.h"
#include "tee_client_api.h"
#include "tee_logging.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

/* Mutex is used when write function occur to FD which is connected to TEE */
pthread_mutex_t fd_write_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Operation is started when message is send out and stopped when response message is received */
#define TEE_OPERATION_STARTED		0x38fa84fb

enum mem_type {
	REGISTERED = 0,
	ALLOCATED = 0xa110ca7e
};

/*!
 * \brief The context_internal struct
 * The implementation defined part of the TEEC_Context
 */
struct context_internal {
	uint64_t operation_id; /*!< Unique indefier between difrent CAs */
	pthread_mutex_t mutex;
	uint32_t ctx_status;
	int sockfd;
} ctx_internal;

/* Only one connection to TEE is allowed! Therefore only one context internal can be init */
#define CTX_INTERNAL_INIT		0xFB83DA36

struct shared_mem_internal {
	char shm_uuid[SHM_MEM_NAME_LEN];  /*!< the shared memory object that has been created */
	void *reg_address;	/*!< store the mmap address that is used for registered mem */
	size_t org_size;	/*!< initial size, needed for unmapping */
	enum mem_type type;       /*!< the type of the memory, i.e. allocated or registered */
};


/*!
 * \brief The session_internal struct
 * The implementation defined part of the TEEC_Session
 */
struct session_internal {
	pthread_mutex_t mutex;
	uint64_t sess_id;
	int sockfd;
	uint8_t init;
};

#define FOR_EACH_TEMP_SHM(i) for (i = 0; i < 4; ++i)

/*!
 *  \brief Iterate over parameters
 *  \param i interger
 */
#define FOR_EACH_PARAM(i) for (i = 0; i < 4; ++i)

static bool get_return_vals_from_err_msg(void *msg, TEE_Result *err_name, uint32_t *err_origin)
{
	uint8_t msg_name;

	if (!msg) {
		OT_LOG(LOG_ERR, "msg NULL");
		return false;
	}

	if (com_get_msg_name(msg, &msg_name)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name");
		return false;
	}

	if (msg_name != COM_MSG_NAME_ERROR) {
		OT_LOG(LOG_ERR, "Not an error message");
		return false;
	}

	if (err_name)
		*err_name = ((struct com_msg_error *) msg)->ret;

	if (err_origin)
		*err_origin = ((struct com_msg_error *) msg)->ret_origin;

	return true;
}

static bool verify_msg_name_and_type(void *msg, uint8_t expected_name, uint8_t expected_type)
{
	uint8_t msg_name, msg_type;

	if (!msg) {
		OT_LOG(LOG_ERR, "msg NULL");
		return false;
	}

	if (com_get_msg_name(msg, &msg_name) || com_get_msg_type(msg, &msg_type)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name and type");
		return false;
	}

	if (msg_name != expected_name)
		return false;

	if (msg_type != expected_type)
		return false;

	return true;
}

static int send_msg(int fd, void *msg, int msg_len, pthread_mutex_t mutex)
{
	int ret;

	if (pthread_mutex_lock(&mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		return -1;
	}

	ret = com_send_msg(fd, msg, msg_len);

	if (pthread_mutex_unlock(&mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

	return ret;
}

static void free_shm_and_from_manager(struct shared_mem_internal *shm_internal)
{
	struct com_msg_unlink_shm_region unlink_msg;

	if (shm_internal->org_size == 0)
		return;

	unlink_msg.msg_hdr.msg_name = COM_MSG_NAME_UNLINK_SHM_REGION;
	unlink_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	unlink_msg.msg_hdr.sess_id = 0;
	memcpy(unlink_msg.name, shm_internal->shm_uuid, SHM_MEM_NAME_LEN);

	/* Message filled. Send message */
	if (send_msg(ctx_internal.sockfd,
		     &unlink_msg, sizeof(struct com_msg_unlink_shm_region),
		     fd_write_mutex) != sizeof(struct com_msg_unlink_shm_region))
		OT_LOG(LOG_ERR, "Failed to send message TEE");

	/* Remove the memory mapped region and the shared memory */
	munmap(shm_internal->reg_address, shm_internal->org_size);
	shm_unlink(shm_internal->shm_uuid);
}

/*!
 * \brief get_shm_from_manager_and_map_region
 * Create a memory mapped shared memory object that can be used to transfer data between the TEE
 * and the Client application
 * \param shm_internal Shared memory object that contains the
 * definition of the region we are creating
 * \return TEEC_SUCCESS on success, other error on failure
 */
static TEEC_Result get_shm_from_manager_and_map_region(struct shared_mem_internal *shm_internal)
{
	struct com_msg_open_shm_region *recv_msg = NULL;
	struct com_msg_open_shm_region open_shm;
	TEEC_Result result = TEEC_SUCCESS;
	int fd, com_ret;

	/* Zero size is special case */
	if (!shm_internal->org_size)
		return TEE_SUCCESS;

	/* Fill message */
	open_shm.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SHM_REGION;
	open_shm.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_shm.msg_hdr.sess_id = 0; /* Not used here */
	open_shm.size = shm_internal->org_size;

	/* Message filled. Send message */
	if (pthread_mutex_lock(&ctx_internal.mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (send_msg(ctx_internal.sockfd, &open_shm, sizeof(struct com_msg_open_shm_region),
		     fd_write_mutex) != sizeof(struct com_msg_open_shm_region)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		return TEEC_ERROR_COMMUNICATION;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(ctx_internal.sockfd, (void **)(&recv_msg), NULL);

	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error")
		return TEEC_ERROR_COMMUNICATION;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding")
		return TEEC_ERROR_COMMUNICATION;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_OPEN_SHM_REGION, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv_msg, &result, NULL)) {
			OT_LOG(LOG_ERR, "Received unknow message")
			result = TEEC_ERROR_COMMUNICATION;
			goto err_ret;
		}

		/* Received error message */
		goto err_ret;
	}

	result = recv_msg->return_code;
	if (result != TEE_SUCCESS)
		goto err_ret;

	memcpy(shm_internal->shm_uuid, recv_msg->name, SHM_MEM_NAME_LEN);

	fd = shm_open(shm_internal->shm_uuid, (O_RDWR | O_RDONLY), 0);
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory area");
		result = TEEC_ERROR_GENERIC;
		goto release_shm_1;
	}

	/* mmap does not allow for the size to be zero, however the TEEC API allows it, so map a
	 * size of 1 byte, though it will probably be mapped to a page */
	shm_internal->reg_address = mmap(NULL, shm_internal->org_size,
					 (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
	if (shm_internal->reg_address == MAP_FAILED) {
		OT_LOG(LOG_ERR, "Failed to MMAP");
		result = TEEC_ERROR_OUT_OF_MEMORY;
		goto release_shm_2;
	}

	/* We have finished with the file handle as it has been mapped so don't leak it */
	close(fd);

	return result;

release_shm_2:
	close(fd);

release_shm_1:
	free_shm_and_from_manager(shm_internal);

err_ret:
	free(recv_msg);
	return result;
}

static TEEC_Result create_shared_mem(TEEC_Context *context, TEEC_SharedMemory *shared_mem,
				     enum mem_type type)
{
	struct shared_mem_internal *shm_internal = NULL;
	TEEC_Result ret;

	if (!context || ctx_internal.ctx_status != CTX_INTERNAL_INIT) {
		OT_LOG(LOG_ERR, "Context NULL or Initialize context before reg/alloc memory")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (!shared_mem) {
		OT_LOG(LOG_ERR, "Shared memory NULL")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Three: useful debug print to syslog */
	if (type == REGISTERED && shared_mem->buffer && !shared_mem->size)
		OT_LOG(LOG_ERR, "Warning: Registering a buffer, but size-parameter is zero");

	if (type == REGISTERED && shared_mem->size && !shared_mem->buffer)
		OT_LOG(LOG_ERR, "Warning: Registering a buffer, but buffer-parameter is NULL");

	if (type == ALLOCATED && !shared_mem->size)
		OT_LOG(LOG_ERR, "Warning: Allocating a buffer, but size-parameter is zero");

	shm_internal = (struct shared_mem_internal *)calloc(1, sizeof(struct shared_mem_internal));
	if (!shm_internal) {
		OT_LOG(LOG_ERR, "Failed to allocate memory for Shared memory");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* Get_shm_from_manager_and_map_refion() is needing shm size! */
	shm_internal->org_size = shared_mem->size;
	shm_internal->type = type;

	ret = get_shm_from_manager_and_map_region(shm_internal);
	if (ret != TEEC_SUCCESS) {
		free(shm_internal);
		shared_mem->imp = NULL;
		return ret;
	}

	/* If we are allocating memory the buffer is the new mmap'd region, where as if we are
	 * only registering memory the buffer has already been alocated locally, so the mmap'd
	 * region is where we will copy the data just before we call a command in the TEE, so it
	 * must be stored seperatly in the "implementation deined section" */
	if (type == ALLOCATED)
		shared_mem->buffer = shm_internal->reg_address;

	shared_mem->imp = shm_internal;
	return ret;
}

/*!
 * \brief copy_tee_operation_to_internal
 * Convert the TEE operation into a generic format do that it can be sent to the TA
 * \param operation The TEE operation format
 * \param internal_op the communication protocol format
 * \return 0 on success
 */
static void copy_tee_operation_to_internal(TEEC_Operation *operation,
					   struct com_msg_operation *internal_op)
{
	struct shared_mem_internal *internal_imp;
	TEEC_SharedMemory *mem_source;
	int i;

	memset(internal_op, 0, sizeof(struct com_msg_operation));

	internal_op->paramTypes = operation->paramTypes;

	FOR_EACH_PARAM(i) {

		if (TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_NONE) {
			continue;

		} else if (TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_VALUE_INPUT ||
			   TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_VALUE_INOUT) {

			memcpy(&internal_op->params[i].param.value,
			       &operation->params[i].value, sizeof(TEEC_Value));
			continue;

		} else if (TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_MEMREF_PARTIAL_INPUT ||
			   TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_MEMREF_PARTIAL_INOUT ||
			   TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_MEMREF_PARTIAL_OUTPUT) {
			OT_LOG(LOG_ERR, "WARNING: MEMREF partial is not implemented")
			continue;
		}

		/* TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INPUT,
		 * TEEC_MEMREF_TEMP_INOUT and TEEC_MEMREF_TEMP_OUTPUT */

		if (!(mem_source = operation->params[i].memref.parent))
			continue; /* Buffer is NULL == user error? */

		/* Flags is used for separating MEMREF_WHOLE type (read or write) */
		internal_op->params[i].flags = mem_source->flags;

		/* We have some shared memory area */
		internal_imp = (struct shared_mem_internal *)mem_source->imp;

		if (internal_imp->org_size == 0)
			continue;

		if (internal_imp->type == REGISTERED) {

			/* Copy the data from the buffer registered by the user
			 * to the address of the shared memory region */
			if (!mem_source->buffer || !(internal_imp->reg_address)) {
				OT_LOG(LOG_ERR, "Invalid Buffer ??");
				continue;
			}

			memcpy(internal_imp->reg_address, mem_source->buffer, mem_source->size);
		}

		/* assign the name of the shared memory and its size area to
				 * the operation that is being passed.  This will allow us
				 * to open the same segment in the TA side
				 */
		strncpy(internal_op->params[i].param.memref.shm_area,
			internal_imp->shm_uuid, SHM_MEM_NAME_LEN);

		internal_op->params[i].param.memref.size = mem_source->size;
	}
}

/*!
 * \brief copy_internal_to_tee_operation
 * When the response message comes from the TA we must copy the data back into the user defined
 * operation
 * \param operation The users operation
 * \param internal_op The internal transport format
 */
static void copy_internal_to_tee_operation(TEEC_Operation *operation,
					   struct com_msg_operation *internal_op)
{
	struct shared_mem_internal *internal_imp;
	TEEC_SharedMemory *mem_source;
	int i;

	FOR_EACH_PARAM(i) {

		if (TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_NONE) {
			continue;

		} else if (TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_OUTPUT ||
			   TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_VALUE_INOUT) {

			memcpy(&operation->params[i].value,
			       &internal_op->params[i].param.value, sizeof(TEEC_Value));
			continue;

		} else if (TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_INPUT ||
			   TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_INOUT ||
			   TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_PARTIAL_OUTPUT) {
			OT_LOG(LOG_ERR, "WARNING: MEMREF partial is not implemented")
			continue;
		}

		/* TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INPUT,
		 * TEEC_MEMREF_TEMP_INOUT and TEEC_MEMREF_TEMP_OUTPUT */

		if (!(mem_source = operation->params[i].memref.parent))
			continue;

		/* Update size to operation */
		mem_source->size = internal_op->params[i].param.memref.size;

		/* We have some shared memory area */
		internal_imp = (struct shared_mem_internal *)mem_source->imp;

		if (internal_imp->org_size == 0)
			continue;

		if (internal_imp->type == REGISTERED) {

			/* Copy the data from the shared memory region back into
			 * the buffer registered by the user */
			if (!mem_source->buffer || !(internal_imp->reg_address)) {
				OT_LOG(LOG_ERR, "Invalid Buffer ??");
				continue;
			}

			memcpy(mem_source->buffer, internal_imp->reg_address, mem_source->size);
		}
	}
}

/*!
 * \brief wait_socket_close
 * This function is not interested any data that is comming from socket.
 * It only breaks it while loop, when error occured.
 * \param fd
 */
static void wait_socket_close(int fd)
{
	const int tmp_len = 8;
	char tmp[tmp_len];
	int read_bytes;

	while (1) {
		read_bytes = read(fd, &tmp, tmp_len);
		if (read_bytes == -1) {

			if (errno == EINTR)
				continue;

			break;

		} else if (read_bytes == 0) {
			/* If socket other end is closed before this function read is called,
			 * read returns zero */
			break;

		} else {
			continue;
		}
	}
}

static void unregister_temp_refs(TEEC_Operation *operation, TEEC_SharedMemory *temp_shm)
{
	int i;

	if (!operation)
		return;

	FOR_EACH_TEMP_SHM(i) {

		if (TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INPUT ||
		    TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_OUTPUT ||
		    TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INOUT) {

			operation->params[i].tmpref.buffer = temp_shm[i].buffer;
			operation->params[i].tmpref.size = temp_shm[i].size;
			TEEC_ReleaseSharedMemory(&temp_shm[i]);
		}
	}
}

static TEEC_Result register_temp_refs(TEEC_Operation *operation, TEEC_SharedMemory *temp_shm)
{
	TEEC_Result ret = TEEC_SUCCESS;
	TEEC_Context *ctx;
	int i;

	if (!operation)
		return TEEC_SUCCESS; /* It is not an error if operation NULL */

	/* Context is not used. We have only on context, which is initialized during the
	 * TEEC_InitializeContext() function. Therefore we can have a context here
	 *
	 * Note: This need to be changed, if we are allowing to have more than one opentee-process*/
	ctx = (TEEC_Context *)&ctx_internal;

	FOR_EACH_TEMP_SHM(i) {

		if (TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INPUT ||
		    TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_OUTPUT ||
		    TEEC_PARAM_TYPE_GET(operation->paramTypes, i) == TEEC_MEMREF_TEMP_INOUT) {

			temp_shm[i].buffer = operation->params[i].tmpref.buffer;
			temp_shm[i].size = operation->params[i].tmpref.size;
			operation->params[i].memref.parent = &temp_shm[i];

			ret = create_shared_mem(ctx, &temp_shm[i], REGISTERED);
			if (ret != TEEC_SUCCESS)
				goto err;

		}
	}

	return ret;

err:
	unregister_temp_refs(operation, temp_shm);
	return ret;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int com_ret;
	TEE_Result ret = TEEC_SUCCESS;
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn init_msg;
	struct com_msg_ca_init_tee_conn *recv_msg = NULL;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || ctx_internal.ctx_status == CTX_INTERNAL_INIT) {
		OT_LOG(LOG_ERR, "Contex NULL or initialized")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Reset context */
	memset(&ctx_internal, 0, sizeof(struct context_internal));

	/* Init context mutex */
	if (pthread_mutex_init(&ctx_internal.mutex, NULL)) {
		OT_LOG(LOG_ERR, "Failed to init mutex")
		ret = TEEC_ERROR_GENERIC;
		goto err_1;
	}

	ctx_internal.sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctx_internal.sockfd == -1) {
		OT_LOG(LOG_ERR, "Socket creation failed")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(ctx_internal.sockfd,
		    (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Failed to connect to TEE")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_3;
	}

	/* Fill init message */
	init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	init_msg.msg_hdr.sess_id = 0;     /* ignored */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&ctx_internal.mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err_3;
	}

	/* Send init message to TEE */
	if (send_msg(ctx_internal.sockfd, &init_msg, sizeof(struct com_msg_ca_init_tee_conn),
		     fd_write_mutex) != sizeof(struct com_msg_ca_init_tee_conn)) {
		OT_LOG(LOG_ERR, "Failed to send context initialization msg");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_4;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(ctx_internal.sockfd, (void **)(&recv_msg), NULL);

	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* If else is only for correct log message */
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_3;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_3;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_CA_INIT_CONTEXT, COM_TYPE_RESPONSE)) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_3;
	}

	ctx_internal.operation_id = ((struct com_msg_ca_init_tee_conn *)recv_msg)->operation_id;
	ctx_internal.ctx_status = CTX_INTERNAL_INIT;
	ret = recv_msg->ret;
	free(recv_msg);

	return ret;

err_4:
	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */
err_3:
	close(ctx_internal.sockfd);
err_2:
	pthread_mutex_destroy(&ctx_internal.mutex);
err_1:
	free(recv_msg);
	return ret;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	struct com_msg_ca_finalize_constex fin_con_msg;

	if (!context || ctx_internal.ctx_status != CTX_INTERNAL_INIT)
		return;

	fin_con_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_FINALIZ_CONTEXT;
	fin_con_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	fin_con_msg.msg_hdr.sess_id = 0;     /* ignored */

	if (pthread_mutex_lock(&ctx_internal.mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (send_msg(ctx_internal.sockfd, &fin_con_msg,
		     sizeof(struct com_msg_ca_finalize_constex), fd_write_mutex) !=
	    sizeof(struct com_msg_ca_finalize_constex)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto unlock;
	}

	/* We are not actually receiving any data from TEE. This call is here for blocking
	 * purpose. It is preventing closing this side socket before TEE closes connection. With
	 * this it is easier segregate expected disconnection and not expected disconnection.
	 * This blocking will end when TEE closes its side socket. */
	wait_socket_close(ctx_internal.sockfd);

unlock:
	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

err:
	while (pthread_mutex_destroy(&ctx_internal.mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex");
			break;
		}
		/* Busy loop */
	}

	memset(&ctx_internal, 0, sizeof(struct context_internal));
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	return create_shared_mem(context, shared_mem, REGISTERED);
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	return create_shared_mem(context, shared_mem, ALLOCATED);
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shared_mem)
{
	if (!shared_mem || !shared_mem->imp)
		return;

	free_shm_and_from_manager(shared_mem->imp);

	free(shared_mem->imp);
	shared_mem->imp = NULL;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connection_method,
			     void *connection_data, TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	struct session_internal *session_internal = NULL;
	struct com_msg_open_session *recv_msg = NULL;
	struct com_msg_open_session open_msg;
	TEEC_Result result = TEEC_SUCCESS;
	TEEC_SharedMemory temp_shm[4];
	int com_ret = 0;

	if (return_origin)
		*return_origin = TEE_ORIGIN_API;

	if (!context || !session || ctx_internal.ctx_status != CTX_INTERNAL_INIT) {
		OT_LOG(LOG_ERR, "Context or session NULL or in improper state");
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (operation && operation->started) {
		OT_LOG(LOG_ERR, "Invalid operation state. Operation started. It should be zero")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (operation)
		operation->imp = operation;

	if (connection_method != TEEC_LOGIN_PUBLIC) {
		OT_LOG(LOG_ERR, "Only public login method supported");
		connection_data = connection_data; /* Not used */
		return TEEC_ERROR_NOT_SUPPORTED;
	}

	session_internal = (struct session_internal *)calloc(1, sizeof(struct session_internal));
	if (!session_internal) {
		OT_LOG(LOG_ERR, "Failed to create memory for session");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* Fill open msg */

	/* Header section */
	open_msg.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg.msg_hdr.sess_id = 0; /* manager will generate */

	/* UUID */
	memcpy(&open_msg.uuid, destination, sizeof(TEEC_UUID));

	com_ret = register_temp_refs(operation, temp_shm);
	if (com_ret != TEEC_SUCCESS) {
		free(session_internal);
		return com_ret;
	}

	if (operation)
		copy_tee_operation_to_internal(operation, &open_msg.operation);
	else
		open_msg.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
								 TEEC_NONE, TEEC_NONE);

	open_msg.operation.operation_id = ctx_internal.operation_id;

	if (pthread_mutex_lock(&ctx_internal.mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		result = TEEC_ERROR_GENERIC;
		goto mutex_fail;
	}

	/* Check can if operation may be canceled */
	if (operation && !operation->imp)
		goto op_cancel;

	/* Message filled. Send message */
	if (send_msg(ctx_internal.sockfd, &open_msg, sizeof(struct com_msg_open_session),
		     fd_write_mutex) != sizeof(struct com_msg_open_session)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto err_com_1;
	}

	/* Operation send to TA -> operation started */
	if (operation)
		operation->started = TEE_OPERATION_STARTED;

	/* Wait for answer */
	com_ret = com_recv_msg(ctx_internal.sockfd, (void **)(&recv_msg), NULL);

	/* Received message -> operation returned from TEE */
	if (operation)
		operation->started = 0;

	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		goto err_com_2;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
		goto err_com_2;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_OPEN_SESSION, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv_msg, &result, return_origin)) {
			OT_LOG(LOG_ERR, "Received unknow message")
			goto err_com_2;
		}

		goto err_msg;
	}

	/* Message received succesfully */
	if (return_origin)
		*return_origin = recv_msg->return_origin;
	result = recv_msg->return_code_open_session;

	/* copy back the response data contained in the operation */
	if (operation)
		copy_internal_to_tee_operation(operation, &recv_msg->operation);

	unregister_temp_refs(operation, temp_shm);

	if (result != TEE_SUCCESS)
		goto err_ret;

	session_internal->sockfd = ctx_internal.sockfd;
	session_internal->mutex = ctx_internal.mutex;
	session_internal->sess_id = recv_msg->msg_hdr.sess_id;
	session->imp = session_internal;
	free(recv_msg);
	return result;


err_com_1:
	if (operation)
		operation->started = 0;

	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

err_com_2:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;

err_ret:
err_msg:
mutex_fail:
	unregister_temp_refs(operation, temp_shm);
	free(recv_msg);
	free(session_internal);
	session->imp = NULL;
	return result;

op_cancel:
	unregister_temp_refs(operation, temp_shm);
	if (pthread_mutex_unlock(&ctx_internal.mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

	free(session_internal);
	session->imp = NULL;
	return TEEC_ERROR_CANCEL;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	struct com_msg_close_session close_msg;
	struct session_internal *internal_imp = NULL;

	if (!session) {
		OT_LOG(LOG_ERR, "Session NULL or not initialized");
		return;
	}

	internal_imp = (struct session_internal *)session->imp;
	if (!internal_imp)
		return;

	close_msg.msg_hdr.msg_name = COM_MSG_NAME_CLOSE_SESSION;
	close_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	close_msg.msg_hdr.sess_id = internal_imp->sess_id;

	/* Message filled. Send message */
	if (pthread_mutex_lock(&internal_imp->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (send_msg(internal_imp->sockfd, &close_msg, sizeof(struct com_msg_close_session),
		     fd_write_mutex) != sizeof(struct com_msg_close_session))
		OT_LOG(LOG_ERR, "Failed to send message TEE");

	if (pthread_mutex_unlock(&internal_imp->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	free(internal_imp);
	session->imp = NULL;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command_id,
			       TEEC_Operation *operation, uint32_t *return_origin)
{
	struct com_msg_invoke_cmd *recv_msg = NULL;
	struct com_msg_invoke_cmd invoke_msg;
	struct session_internal *session_internal;
	TEEC_Result result = TEEC_SUCCESS;
	TEEC_SharedMemory temp_shm[4];
	int com_ret = 0;

	if (return_origin)
		*return_origin = TEE_ORIGIN_API;

	if (!session) {
		OT_LOG(LOG_ERR, "session NULL")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (operation && operation->started) {
		OT_LOG(LOG_ERR, "Invalid operation state. Operation started. It should be zero")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (operation)
		operation->imp = operation;

	session_internal = (struct session_internal *)session->imp;
	if (!session_internal) {
		OT_LOG(LOG_ERR, "session not initialized")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Fill message */
	invoke_msg.msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg.msg_hdr.sess_id = session_internal->sess_id;
	invoke_msg.cmd_id = command_id;

	com_ret = register_temp_refs(operation, temp_shm);
	if (com_ret != TEEC_SUCCESS)
		return com_ret;

	if (operation)
		copy_tee_operation_to_internal(operation, &invoke_msg.operation);
	else
		invoke_msg.operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
								   TEEC_NONE, TEEC_NONE);

	invoke_msg.operation.operation_id = ctx_internal.operation_id;

	/* Message filled. Send message */
	if (pthread_mutex_lock(&session_internal->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		return TEEC_ERROR_GENERIC;
	}

	/* Check can if operation may be canceled */
	if (operation && !operation->imp)
		goto op_cancel;

	/* Message filled. Send message */
	if (send_msg(session_internal->sockfd, &invoke_msg,
		     sizeof(struct com_msg_invoke_cmd), fd_write_mutex) !=
	    sizeof(struct com_msg_invoke_cmd)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE")
		goto err_com_2;
	}

	/* Operation send to TA -> operation started */
	if (operation)
		operation->started = TEE_OPERATION_STARTED;

	/* Wait for answer */
	com_ret = com_recv_msg(session_internal->sockfd, (void **)(&recv_msg), NULL);

	/* Received message -> operation returned from TEE */
	if (operation)
		operation->started = 0;

	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error")
		goto err_com_1;
	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding")
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to invoke cmd message. Worst case situation is
		 * that task is complited, but message delivery only failed. For now, just report
		 * communication error and dump problem "upper layer". */
		goto err_com_1;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_INVOKE_CMD, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv_msg, &result, return_origin)) {
			OT_LOG(LOG_ERR, "Received unknow message")
			goto err_com_2;
		}

		goto err_msg;
	}

	/* Success. Let see result */
	result = recv_msg->return_code;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* copy back the response data contained in the operation */
	if (operation)
		copy_internal_to_tee_operation(operation, &recv_msg->operation);

	unregister_temp_refs(operation, temp_shm);
	free(recv_msg);
	return result;

err_com_2:
	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

	if (operation)
		operation->started = 0;

err_com_1:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;

err_msg:
	unregister_temp_refs(operation, temp_shm);
	free(recv_msg);
	return result;

op_cancel:
	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");
	unregister_temp_refs(operation, temp_shm);
	return TEEC_ERROR_CANCEL;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	struct com_msg_request_cancellation cancel_msg;

	if (!operation) {
		OT_LOG(LOG_ERR, "Cancel not send, because opearion NULL")
		return;
	}

	/* Set operation to be canceled. What is signaling operation cancelation is opeartion
	 * imp-member. If imp NULL, operation is cancelled. */
	operation->imp = NULL;

	/* Operation may have send already to TEE. If started member NULL, operation is not send
	 * to TEE and is queued in CA */
	if (!operation->started) {
		OT_LOG(LOG_ERR, "Cancel not send, because operation not yet started")
		return;
	}

	cancel_msg.msg_hdr.msg_name = COM_MSG_NAME_REQUEST_CANCEL;
	cancel_msg.msg_hdr.msg_type = COM_TYPE_QUERY;

	send_msg(ctx_internal.sockfd, &cancel_msg,
		 sizeof(struct com_msg_request_cancellation), fd_write_mutex);
}
