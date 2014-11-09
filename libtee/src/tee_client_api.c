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
#include "utils.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

/* Mutex is used when write function occur to FD which is connected to TEE */
pthread_mutex_t fd_write_mutex = PTHREAD_MUTEX_INITIALIZER;

/* tee_conn_ctx_state -variable is used for limiting one connection to TEE */
static int tee_conn_ctx_state;
#define TEE_CONN_CTX_INIT	1
#define TEE_CONN_CTX_NOT_INIT	0

enum mem_type {
	REGISTERED = 0,
	ALLOCATED = 0xa110ca7e
};

struct shared_mem_internal {
	char *shm_uuid;		  /*!< Pointer to the shared memory object that has been created */
	void *reg_address;	/*!< store the mmap address that is used for registered mem */
	enum mem_type type;       /*!< The type of the memory, i.e. allocated or registered */
};

/*!
 * \brief The context_internal struct
 * The implementation defined part of the TEEC_Context
 */
struct context_internal {
	pthread_mutex_t mutex;
	int sockfd;
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

/*!
 * \brief create_shared_mem_internal
 * Create a memory mapped shared memory object that can be used to transfer data between the TEE
 * and the Client application
 * \param context The context to which we are registering the memory
 * \param shared_mem Shared memory object that contains the definition of the region we are creating
 * \param type The type of memory allocation \sa enum mem_type
 * \return TEEC_SUCCESS on success, other error on failure
 */
static TEEC_Result create_shared_mem_internal(TEEC_Context *context, TEEC_SharedMemory *shared_mem,
					      enum mem_type type)
{
	int flag = 0;
	int fd;
	void *address = NULL;
	TEEC_Result ret = TEEC_SUCCESS;
	struct shared_mem_internal *internal_imp;

	if (!context || !shared_mem)
		return TEEC_ERROR_BAD_PARAMETERS;

	internal_imp = (struct shared_mem_internal *)calloc(1, sizeof(struct shared_mem_internal));
	if (!internal_imp) {
		OT_LOG(LOG_ERR, "Failed to allocate memory for Shared memory");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* The name of the shm object files should be in the format "/somename\0"
	 * so we will generate a random name that matches this format based of of
	 * a UUID
	 */
	if (generate_random_path(&internal_imp->shm_uuid) == -1) {
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto errorExit;
	}

	if ((shared_mem->flags & TEEC_MEM_OUTPUT) && !(shared_mem->flags & TEEC_MEM_INPUT))
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(internal_imp->shm_uuid, (flag | O_CREAT | O_EXCL),
		      (S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP));
	if (fd == -1) {
		OT_LOG(LOG_ERR, "Failed to open the shared memory");
		ret = TEEC_ERROR_GENERIC;
		goto errorExit;
	}

	/* if ftruncate 0 is used this will result in no file being created, mmap will fail below */
	if (ftruncate(fd, shared_mem->size != 0 ? shared_mem->size : 1) == -1) {
		ret = TEEC_ERROR_GENERIC;
		OT_LOG(LOG_ERR, "Failed to truncate");
		goto errorTruncate;
	}

	/* mmap does not allow for the size to be zero, however the TEEC API allows it, so map a
	 * size of 1 byte, though it will probably be mapped to a page
	 */
	address =
	    mmap(NULL, shared_mem->size != 0 ? shared_mem->size : 1,
		 ((flag == O_RDONLY) ? PROT_READ : (PROT_WRITE | PROT_READ)), MAP_SHARED, fd, 0);
	if (address == MAP_FAILED) {
		OT_LOG(LOG_ERR, "Failed to MMAP");
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto errorTruncate;
	}

	/* We have finished with the file handle as it has been mapped so don't leak it */
	close(fd);

	/* If we are allocating memory the buffer is the new mmap'd region, where as if we are
	 * only registering memory the buffer has already been alocated locally, so the mmap'd
	 * region is where we will copy the data just before we call a command in the TEE, so it
	 * must be stored seperatly in the "implementation deined section"
	 */
	if (type == ALLOCATED)
		shared_mem->buffer = address;
	else if (type == REGISTERED)
		internal_imp->reg_address = address;

	internal_imp->type = type;
	shared_mem->imp = internal_imp;

	return TEEC_SUCCESS;

errorTruncate:
	shm_unlink(internal_imp->shm_uuid);
	close(fd);

errorExit:
	free(internal_imp->shm_uuid);
	free(internal_imp);
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
	int i;
	uint32_t param_types = operation->paramTypes;
	TEEC_SharedMemory *mem_source;
	struct shared_mem_internal *internal_imp;

	memset(internal_op, 0, sizeof(struct com_msg_operation));

	internal_op->paramTypes = operation->paramTypes;

	for (i = 0; i < 4; i++) {
		if (TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_NONE) {
			continue;
		} else if (TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INPUT ||
			   TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_VALUE_INOUT) {

			memcpy(&internal_op->params[i].value,
			       &operation->params[i].value, sizeof(TEEC_Value));

		} else if (TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_TEMP_INPUT ||
			   TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_TEMP_INOUT ||
			   TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_TEMP_OUTPUT) {
			/* TODO: this needs to be registered as shared memory and
			 * the data copied there*/
		} else if (TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_WHOLE ||
			   TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_INPUT ||
			   TEEC_PARAM_TYPE_GET(param_types, i) == TEEC_MEMREF_PARTIAL_INOUT) {

			if ((mem_source = operation->params[i].memref.parent)) {

				/* We have some shared memory area */
				internal_imp = (struct shared_mem_internal *)mem_source->imp;
				if (internal_imp->type == REGISTERED) {

					/* Copy the data from the buffer registered by the user
					 * to the address of the shared memory region
					 */
					if (!mem_source->buffer || !(internal_imp->reg_address)) {
						OT_LOG(LOG_ERR, "Invalid Buffer ??");
						continue;
					}

					memcpy(internal_imp->reg_address,
					       mem_source->buffer,
					       mem_source->size);
				}

				/* assign the name of the shared memory and its size area to
				 * the operation that is being passed.  This will allow us
				 * to open the same segment in the TA side
				 */
				strncpy(internal_op->params[i].memref.shm_area,
					internal_imp->shm_uuid, SHM_MEM_NAME_LEN);

				internal_op->params[i].memref.size = mem_source->size;
			}
		}
	}
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

	if (msg_name != expected_name) {
		OT_LOG(LOG_ERR, "Not expexted name of the message");
		return false;
	}

	if (msg_type != expected_type) {
		OT_LOG(LOG_ERR, "Not expexted type of the message");
		return false;
	}

	return true;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int com_ret;
	TEE_Result ret = TEEC_SUCCESS;
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn init_msg;
	struct com_msg_ca_init_tee_conn *recv_msg = NULL;
	struct context_internal *inter_imp = NULL;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || tee_conn_ctx_state == TEE_CONN_CTX_INIT) {
		OT_LOG(LOG_ERR, "Contex NULL or initialized")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	inter_imp = (struct context_internal *)calloc(1, sizeof(struct context_internal));
	if (!inter_imp) {
		OT_LOG(LOG_ERR, "Failed to create space for context");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}


	/* Init context mutex */
	if (pthread_mutex_init(&inter_imp->mutex, NULL)) {
		OT_LOG(LOG_ERR, "Failed to init mutex")
		return TEEC_ERROR_GENERIC;
	}

	inter_imp->sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (inter_imp->sockfd == -1) {
		OT_LOG(LOG_ERR, "Socket creation failed")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(inter_imp->sockfd,
		    (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Failed to connect to TEE")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Fill init message */
	init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	init_msg.msg_hdr.sess_id = 0;     /* ignored */

	/* Send init message to TEE */
	if (send_msg(inter_imp->sockfd, &init_msg, sizeof(struct com_msg_ca_init_tee_conn),
		     fd_write_mutex) != sizeof(struct com_msg_ca_init_tee_conn)) {
		OT_LOG(LOG_ERR, "Failed to send context initialization msg");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(inter_imp->sockfd, (void **)(&recv_msg), NULL);

	/* If else is only for correct log message */
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_CA_INIT_CONTEXT, COM_TYPE_RESPONSE)) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	tee_conn_ctx_state = TEE_CONN_CTX_INIT;
	ret = recv_msg->ret;
	free(recv_msg);

	context->imp = inter_imp;

	return ret;

err_2:
	close(inter_imp->sockfd);
err_1:
	pthread_mutex_destroy(&inter_imp->mutex);
	free(recv_msg);
	free(inter_imp);

	context->imp = NULL;
	tee_conn_ctx_state = TEE_CONN_CTX_NOT_INIT;
	return ret;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	struct com_msg_ca_finalize_constex fin_con_msg;
	struct context_internal *inter_imp;

	if (!context || tee_conn_ctx_state != TEE_CONN_CTX_INIT)
		return;

	inter_imp = (struct context_internal *)context->imp;
	if (!inter_imp)
		return;

	fin_con_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_FINALIZ_CONTEXT;
	fin_con_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	fin_con_msg.msg_hdr.sess_id = 0;     /* ignored */

	if (pthread_mutex_lock(&inter_imp->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (send_msg(inter_imp->sockfd, &fin_con_msg,
			 sizeof(struct com_msg_ca_finalize_constex), fd_write_mutex) !=
	    sizeof(struct com_msg_ca_finalize_constex)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto unlock;
	}

	/* We are not actually receiving any data from TEE. This call is here for blocking
	 * purpose. It is preventing closing this side socket before TEE closes connection. With
	 * this it is easier segregate expected disconnection and not expected disconnection.
	 * This blocking will end when TEE closes its side socket. */
	wait_socket_close(inter_imp->sockfd);

unlock:
	if (pthread_mutex_unlock(&inter_imp->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	tee_conn_ctx_state = TEE_CONN_CTX_NOT_INIT;
	close(inter_imp->sockfd);

	while (pthread_mutex_destroy(&inter_imp->mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex")
			break;
		}
		/* Busy loop */
	}

	free(inter_imp);
	context->imp = NULL;
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	if (!context || !shared_mem)
		return TEEC_ERROR_BAD_PARAMETERS;

	return create_shared_mem_internal(context, shared_mem, REGISTERED);
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	return create_shared_mem_internal(context, shared_mem, ALLOCATED);
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shared_mem)
{
	void *address;
	struct shared_mem_internal *internal_imp = NULL;

	if (!shared_mem)
		return;

	internal_imp = (struct shared_mem_internal *)shared_mem->imp;
	if (!internal_imp)
		return;

	/* If we allocated the memory free the buffer, other wise if it is just registered
	 * the buffer belongs to the Client Application, so we should not free it, instead
	 * we should free the mmap'd region that was mapped to support it
	 */
	if (internal_imp->type == ALLOCATED)
		address = shared_mem->buffer;
	else
		address = internal_imp->reg_address;

	/* Remove the memory mapped region and the shared memory */
	munmap(address, shared_mem->size);
	shm_unlink(internal_imp->shm_uuid);
	free(internal_imp->shm_uuid);
	free(internal_imp);
	shared_mem->imp = NULL;

	return;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connection_method,
			     void *connection_data, TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	struct com_msg_open_session open_msg;
	struct com_msg_open_session *recv_msg = NULL;
	int com_ret = 0;
	TEEC_Result result = TEEC_SUCCESS;
	struct context_internal *context_internal = NULL;
	struct session_internal *session_internal = NULL;

	/* Not used on purpose. Reminding about implement memory stuff. (only UUID is handeled) */
	connection_method = connection_method;
	connection_data = connection_data;

	if (!context || !session || tee_conn_ctx_state != TEE_CONN_CTX_INIT) {
		OT_LOG(LOG_ERR, "Context or session NULL or in improper state");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	context_internal = (struct context_internal *)context->imp;

	session_internal = (struct session_internal *)calloc(1, sizeof(struct session_internal));
	if (!session_internal) {
		OT_LOG(LOG_ERR, "Failed to create memory for session");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* Fill open msg */

	/* Header section */
	open_msg.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg.msg_hdr.sess_id = 0; /* manager will generate */

	/* UUID */
	memcpy(&open_msg.uuid, destination, sizeof(TEEC_UUID));

	if (operation)
		copy_tee_operation_to_internal(operation, &open_msg.operation);

	if (pthread_mutex_lock(&context_internal->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (send_msg(context_internal->sockfd, &open_msg, sizeof(struct com_msg_open_session),
		     fd_write_mutex) != sizeof(struct com_msg_open_session)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto err_com;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(context_internal->sockfd, (void **)(&recv_msg), NULL);
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		goto err_com;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
		goto err_com;
	}

	if (pthread_mutex_unlock(&context_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_OPEN_SESSION, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv, &result, return_origin))
			goto err_com;

		goto err_msg;
	}

	/* Message received succesfully */
	result = recv_msg->return_code_open_session;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	session_internal->sockfd = context_internal->sockfd;
	session_internal->mutex = context_internal->mutex;
	session_internal->sess_id = recv_msg->msg_hdr.sess_id;
	session->imp = session_internal;
	free(recv_msg);
	return result;

err_com:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;

err_msg:
	if (pthread_mutex_unlock(&context_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

	free(recv_msg);
	free(session_internal);
	session->imp = NULL;
	return result;
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
	struct com_msg_invoke_cmd invoke_msg;
	struct com_msg_invoke_cmd *recv_msg = NULL;
	int com_ret = 0;
	TEEC_Result result = TEEC_SUCCESS;
	struct session_internal *session_internal;

	command_id = command_id; /* Not used on purpose. Reminding about implement memory stuff */

	if (!session || !operation) {
		OT_LOG(LOG_ERR, "session or operation NULL or session not initialized")
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	session_internal = (struct session_internal *)session->imp;
	if (!session_internal)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* Fill message */
	invoke_msg.msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg.msg_hdr.sess_id = session_internal->sess_id;

	if (operation)
		copy_tee_operation_to_internal(operation, &invoke_msg.operation);

	/* Message filled. Send message */
	if (pthread_mutex_lock(&session_internal->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (send_msg(session_internal->sockfd, &invoke_msg,
		     sizeof(struct com_msg_invoke_cmd), fd_write_mutex) !=
	    sizeof(struct com_msg_invoke_cmd)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE")
		goto err_com_1;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(session_internal->sockfd, (void **)(&recv_msg), NULL);
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

	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_INVOKE_CMD, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv, &result, return_origin))
			goto err_com_2;

		goto err_msg;
	}

	/* Success. Let see result */
	result = recv_msg->return_code;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	free(recv_msg);
	return result;

err_com_1:
	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");
err_com_2:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;
err_msg:
	free(recv_msg);
	return result;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	/* PLACEHOLDER */

	operation = operation;
}
