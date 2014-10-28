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

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "com_protocol.h"
#include "tee_client_api.h"
#include "tee_logging.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int sockfd, recv_bytes;
	TEE_Result ret = TEEC_SUCCESS;
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn init_msg;
	struct com_msg_ca_init_tee_conn *recv_msg = NULL;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || context->init == INITIALIZED) {
		OT_LOG(LOG_ERR, "Contex NULL or initialized")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Init context mutex */
	if (pthread_mutex_init(&context->mutex, NULL)) {
		OT_LOG(LOG_ERR, "Failed to init mutex")
		return TEEC_ERROR_GENERIC;
	}

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		OT_LOG(LOG_ERR, "Socket creation failed")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Failed to connect to TEE")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Fill init message */
	init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	init_msg.msg_hdr.sess_id = 0; /* ignored */
	init_msg.msg_hdr.sender_type = 0; /* ignored */

	/* Send init message to TEE */
	if (com_send_msg(sockfd, &init_msg, sizeof(struct com_msg_ca_init_tee_conn)) !=
			sizeof(struct com_msg_ca_init_tee_conn)) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Wait for answer */
	if (com_recv_msg(sockfd, (void **)(&recv_msg), &recv_bytes) == -1) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Check message */
	if (recv_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
			recv_msg->msg_hdr.msg_type != COM_TYPE_RESPONSE) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	context->init = INITIALIZED;
	context->sockfd  = sockfd;
	free(recv_msg);

	return ret;

err_2:
	close(sockfd);
err_1:
	pthread_mutex_destroy(&context->mutex);
	free(recv_msg);
	return ret;
}


void TEEC_FinalizeContext(TEEC_Context *context)
{
	struct com_msg_ca_finalize_constex fin_con_msg;

	if (!context || context->init != INITIALIZED)
		return;

	fin_con_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_FINALIZ_CONTEXT;
	fin_con_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	fin_con_msg.msg_hdr.sess_id = 0; /* ignored */
	fin_con_msg.msg_hdr.sender_type = 0; /* ignored */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&context->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	com_send_msg(context->sockfd, &fin_con_msg, sizeof(struct com_msg_ca_finalize_constex));

	if (pthread_mutex_unlock(&context->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	context->init = 0;
	close(context->sockfd);
	while (pthread_mutex_destroy(&context->mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex")
			break;
		}
		/* Busy loop */
	}
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connection_method,
			     void *connection_data, TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	context = context; session = session; destination = destination;
	connection_method = connection_method; connection_data = connection_data;
	operation = operation; return_origin = return_origin;

	return TEEC_SUCCESS;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	if (!session)
		return;

	return;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command_id,
			       TEEC_Operation *operation, uint32_t *return_origin)
{
	session = session; command_id = command_id;
	operation = operation; return_origin = return_origin;
	return TEEC_SUCCESS;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	if (!operation)
		return;

	return;
}
