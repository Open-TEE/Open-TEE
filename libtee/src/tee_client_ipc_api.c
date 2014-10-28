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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "tee_client_api.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int sockfd;
	struct sockaddr_un sock_addr;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || context->init == INITIALIZED)
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
	context->init = INITIALIZED;

	return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	if (!context || context->init != INITIALIZED)
		return;

	//TODO should check that we do not have any open sessions first
	close(context->sockfd);
	context->init = 0xFF;
	return;
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
