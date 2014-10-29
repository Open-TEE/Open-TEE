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
#include "socket_help.h"
#include "tee_client_api.h"
#include "tee_logging.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int sockfd, recv_bytes;
	TEE_Result ret = TEEC_SUCCESS;
	uint8_t msg_name, msg_type;
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

	/* Check received message */
	if (com_get_msg_name(recv_msg, &msg_name) || com_get_msg_type(recv_msg, &msg_type)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name and type");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	if (msg_name != COM_MSG_NAME_CA_INIT_CONTEXT || msg_type != COM_TYPE_RESPONSE) {
		OT_LOG(LOG_ERR, "Received wrong message, discarding");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	context->init = INITIALIZED;
	context->sockfd  = sockfd;
	ret = recv_msg->ret;
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
	struct com_msg_open_session open_msg;
	struct com_msg_open_session *recv_msg = NULL;
	int recv_bytes, ret = 0;
	uint8_t msg_name, msg_type;
	TEEC_Result result = TEEC_SUCCESS;

	/* Not used on purpose. Reminding about implement memory stuff. (only UUID is handeled) */
	connection_method = connection_method;
	connection_data = connection_data;
	operation = operation;

	if (!context || context->init != INITIALIZED || !session || session->init == INITIALIZED) {
		OT_LOG(LOG_ERR, "Context or session NULL or in improper state");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Init context mutex */
	if (pthread_mutex_init(&session->mutex, NULL)) {
		OT_LOG(LOG_ERR, "Failed to init mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Fill open msg */

	/* Header section */
	open_msg.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg.msg_hdr.sess_id = 0; /* manager filled */
	open_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* UUID */
	memcpy(&open_msg.uuid, destination, sizeof(TEEC_UUID));

	/* ## TODO: Operation parameters and rest params ## */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&context->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (com_send_msg(context->sockfd, &open_msg, sizeof(struct com_msg_open_session)) !=
	    sizeof(struct com_msg_open_session)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto err_com;
	}

	/* Wait for answer */
	ret = com_recv_msg(context->sockfd, (void **)(&recv_msg), &recv_bytes);
	if (ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		goto err_com;

	} else if (ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
		goto err_com;
	}

	/* Check received message */
	if (com_get_msg_name(recv_msg, &msg_name) || com_get_msg_type(recv_msg, &msg_type)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name and type");
		goto err_com;
	}

	if (msg_name != COM_MSG_NAME_OPEN_SESSION || msg_type != COM_TYPE_RESPONSE) {
		OT_LOG(LOG_ERR, "Received wrong message, discarding");
		goto err_com;
	}

	if (recv_msg->return_code_open_session == TEEC_SUCCESS) {
		/* Session opened succesfully. Manager is sending now session socket */

		if (recv_fd(context->sockfd, &session->sockfd) == -1) {
			OT_LOG(LOG_ERR, "Failed to receive socket");
			goto err_com;
		}
	}

	if (pthread_mutex_unlock(&context->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Success. Let see result */
	result = recv_msg->return_code_open_session;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	session->init = INITIALIZED;
	free(recv_msg);
	return result;

err_com:
	pthread_mutex_destroy(&session->mutex);
	if (pthread_mutex_unlock(&context->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	free(recv_msg);
	return TEEC_ERROR_COMMUNICATION;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	struct com_msg_close_session close_msg;

	if (!session || session->init != INITIALIZED) {
		OT_LOG(LOG_ERR, "Session NULL or not initialized");
		return;
	}

	close_msg.msg_hdr.msg_name = COM_MSG_NAME_CLOSE_SESSION;
	close_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	close_msg.msg_hdr.sess_id = 0; /* manager filled */
	close_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&session->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (com_send_msg(session->sockfd, &close_msg, sizeof(struct com_msg_close_session)) !=
	    sizeof(struct com_msg_close_session))
		OT_LOG(LOG_ERR, "Failed to send message TEE");

	if (pthread_mutex_unlock(&session->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	close(session->sockfd);
	session->init = 0;
	while (pthread_mutex_destroy(&session->mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex")
			break;
		}
		/* Busy loop */
	}
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command_id,
			       TEEC_Operation *operation, uint32_t *return_origin)
{
	struct com_msg_invoke_cmd invoke_msg;
	struct com_msg_invoke_cmd *recv_msg = NULL;
	int ret = 0, recv_bytes;
	TEEC_Result result = TEEC_SUCCESS;
	uint8_t msg_name, msg_type;

	command_id = command_id; /* Not used on purpose. Reminding about implement memory stuff */

	if (!session || !operation || session->init != INITIALIZED) {
		OT_LOG(LOG_ERR, "session or operation NULL or session not initialized")
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/* Fill message */
	invoke_msg.msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg.msg_hdr.sess_id = 0; /* manager filled */
	invoke_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* ## TODO/NOTE: Map operation to message! ## */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&session->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (com_send_msg(session->sockfd, &invoke_msg, sizeof(struct com_msg_invoke_cmd)) !=
			sizeof(struct com_msg_invoke_cmd)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE")
		goto err_com_1;
	}

	/* Wait for answer */
	ret = com_recv_msg(session->sockfd, (void **)(&recv_msg), &recv_bytes);
	if (ret == -1) {
		OT_LOG(LOG_ERR, "Socket error")
		goto err_com_1;
	} else if (ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding")
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to invoke cmd message. Worst case situation is
		 * that task is complited, but message delivery only failed. For now, just report
		 * communication error and dump problem "upper layer". */
		goto err_com_1;
	}

	if (pthread_mutex_unlock(&session->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex") /* No action */

	/* Check received message */
	if (com_get_msg_name(recv_msg, &msg_name) || com_get_msg_type(recv_msg, &msg_type)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name and type");
		goto err_com_2;
	}

	if (msg_name != COM_MSG_NAME_INVOKE_CMD || msg_type != COM_TYPE_RESPONSE) {
		OT_LOG(LOG_ERR, "Received wrong message, discarding");
		goto err_com_2;
	}

	/* Success. Let see result */
	result = recv_msg->return_code;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	free(recv_msg);
	return result;

err_com_1:
	if (pthread_mutex_unlock(&session->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");
err_com_2:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	free(recv_msg);
	return TEEC_ERROR_COMMUNICATION;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	if (!operation)
		return;

	return;
}
