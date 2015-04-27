/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
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
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <zlib.h>

#include <sys/types.h>
#include <sys/socket.h>

struct control_fd {
	struct cmsghdr header;
	int fd[4];
};


#include "com_protocol.h"
#include "tee_logging.h"

static const uint32_t COM_MSG_START = 0xABCDEF12;
#define TRY_READ_FD_COUNT 5
#define ELEMENTS_IN_MESSAGE 2

/* Transport information */
struct com_transport_info {
	uint64_t checksum;
	uint32_t start;
	uint32_t data_len; /* data_len: user message length */
} __attribute__((aligned));


int send_fd(int sockfd, int *fd_table_to_send, int fd_count, struct iovec *aiov, int aiovlen)
{
	struct msghdr msg_head;
	struct iovec iov;
	struct control_fd anc_load;
	char dummy = 'T';

	memset(&msg_head, 0, sizeof(struct msghdr));

	if (aiov == NULL) {
		iov.iov_base = &dummy;
		iov.iov_len = sizeof(char);

		/* add 1 iov buffer to the header */
		msg_head.msg_iov = &iov;
		msg_head.msg_iovlen = 1;
	} else {
		msg_head.msg_iov = aiov;
		msg_head.msg_iovlen = aiovlen;
	}

	if (fd_count > 0) {
		anc_load.header.cmsg_type = SCM_RIGHTS;
		anc_load.header.cmsg_len = CMSG_LEN(sizeof(int)*fd_count);
		anc_load.header.cmsg_level = SOL_SOCKET;

		msg_head.msg_control = &anc_load;
		msg_head.msg_controllen = CMSG_SPACE(sizeof(int)*fd_count);
		memcpy(CMSG_DATA(CMSG_FIRSTHDR(&msg_head)),
		       fd_table_to_send, sizeof(int)*fd_count);
	}

	return sendmsg(sockfd, &msg_head, 0);
}

int recv_fd(int sockfd, int *recv_fd_table, int *fd_count, struct iovec *aiov, int aiovlen)
{
	struct msghdr msg_head = {0};
	struct iovec iov;
	struct control_fd anc_load;
	char dummy;
	int ret = 0, count;
	struct cmsghdr *recv_cont;

	memset(&anc_load, 0, sizeof(anc_load));

	if (aiov == NULL) {
		iov.iov_base = &dummy;
		iov.iov_len = sizeof(char);

		/* add 1 iov buffer to the header */
		msg_head.msg_iov = &iov;
		msg_head.msg_iovlen = 1;
	} else {
		msg_head.msg_iov = aiov;
		msg_head.msg_iovlen = aiovlen;
	}


	msg_head.msg_name = NULL;
	msg_head.msg_namelen = 0;
	msg_head.msg_control = &anc_load;
	msg_head.msg_controllen = CMSG_SPACE(sizeof(int)*4);

	ret = recvmsg(sockfd, &msg_head, 0);
	if (ret == -1)
		return -1;

	if (anc_load.header.cmsg_type == SCM_RIGHTS && recv_fd_table) {

		recv_cont = CMSG_FIRSTHDR(&msg_head);
		if (recv_cont == NULL)
			return -1;

		count = (recv_cont->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		if (count <= 0)
			return -1;

		memcpy(recv_fd_table, CMSG_DATA(recv_cont), sizeof(int)*count);
		if (fd_count)
			*fd_count = count;
	}
	return ret;
}


static int read_iov_element(int fd, struct iovec *iov, int *temp_fd, int *temp_fd_count)
{
	int read_bytes = 0;

	while (1) {

		if (temp_fd)
			read_bytes = recv_fd(fd, temp_fd, temp_fd_count, iov, 1);
		else
			read_bytes = readv(fd, iov, 1);

		if (read_bytes == -1) {

			if (errno == EINTR)
				continue;

			OT_LOG(LOG_ERR, "read error");
			return -1;

		} else if (read_bytes == 0) {
			OT_LOG(LOG_ERR, "read error");
			errno = EPIPE;
			return -1;
		}

		break;
	}

	return read_bytes;
}

static int wind_fd_next_start(int fd)
{
	/* TODO: This function only emtying socket and due that message can be lost!!
	 *
	 * Use IOCTL call to find out data in socket, then peek and find next starting point */

	static const int BUF_LEN = 256;
	char tmp[BUF_LEN];
	int read_bytes;

	while (1) {
		read_bytes = read(fd, &tmp, BUF_LEN);
		if (read_bytes == -1) {
			if (errno == EINTR)
				continue;
			OT_LOG(LOG_ERR, "read error");
			return -1;
		} else if (read_bytes == 0) {
			OT_LOG(LOG_ERR, "read error");
			errno = EPIPE;
			return -1;
		}

		if (read_bytes == BUF_LEN)
			continue;
		else
			break;
	}

	return 1; /* This function should only call in com_recv_msg function */
}

int com_recv_msg(int sockfd, void **msg, int *msg_len, int *shareable_fd, int *shareable_fd_count)
{
	struct iovec iov[ELEMENTS_IN_MESSAGE];
	int ret;
	struct com_transport_info com_recv_trans_info;

	if (!msg) {
		OT_LOG(LOG_ERR, "msg null");
		return 1;
	}

	/* Set NULL, because then can use ERR-goto and not refering unmalloced memory */
	*msg = NULL;

	/*Transport capsule */
	iov[0].iov_base = &com_recv_trans_info;
	iov[0].iov_len = sizeof(struct com_transport_info);

	/* Read transport capsule */
	if (read_iov_element(sockfd, &iov[0], shareable_fd, shareable_fd_count) == -1) {
		OT_LOG(LOG_ERR, "Problem with reading transport capsule");
		ret = -1;
		goto err;
	}

	/* Transport information read. Verify bit sequence */
	if (com_recv_trans_info.start != COM_MSG_START) {
		OT_LOG(LOG_ERR, "Read data is not beginning correctly");
		ret = wind_fd_next_start(sockfd);
		goto err;
	}

	/* Malloc space for incomming message and read message */
	*msg = calloc(1, com_recv_trans_info.data_len);
	if (!*msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		ret = 1;
		goto err;
	}

	iov[1].iov_base = *msg;
	iov[1].iov_len = com_recv_trans_info.data_len;

	if (read_iov_element(sockfd, &iov[1], NULL, NULL) == -1) {
		OT_LOG(LOG_ERR, "Problem with reading msg");
		ret = -1;
		goto err;
	}

	/* Calculate and verify checksum */
	if (com_recv_trans_info.checksum != crc32(0, *msg, com_recv_trans_info.data_len)) {
		OT_LOG(LOG_ERR, "Message checksum is not matching, discard msg");
		ret = 1;
		goto err;
	}

	if (msg_len)
		*msg_len = com_recv_trans_info.data_len;

	return 0;

err:
	free(*msg); /* Discardin msg */
	if (msg_len)
		*msg_len = 0;
	*msg = NULL;
	return ret;
}

int com_send_msg(int sockfd, void *msg, int msg_len,
		 int *shareable_fd, int shareable_fd_count)
{
	struct iovec iov[ELEMENTS_IN_MESSAGE] = { {0} };
	int bytes_write;
	struct com_transport_info com_trans_info = {0};

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	/* Fill and calculate transport information */
	com_trans_info.start = COM_MSG_START;
	com_trans_info.data_len = msg_len;
	com_trans_info.checksum = crc32(0, msg, msg_len);

	iov[0].iov_base = &com_trans_info;
	iov[0].iov_len = sizeof(struct com_transport_info);

	iov[1].iov_base = msg;
	iov[1].iov_len = msg_len;

	/* Send message */
	while (1) {

		bytes_write = send_fd(sockfd, shareable_fd, shareable_fd_count,
				      iov, ELEMENTS_IN_MESSAGE);

		if (bytes_write == -1) {
			if (errno == EINTR)
				continue;

			OT_LOG(LOG_ERR, "send error: %s", strerror(errno));
			return -1;
		}

		break;
	}

	return bytes_write - sizeof(struct com_transport_info);
}

int com_get_msg_name(void *msg, uint8_t *msg_name)
{
	/* Not the most optimized operation, but I do not know a better way than
	 * a "hardcoded" solution. */

	struct com_msg_hdr msg_hdr;

	if (!msg || !msg_name) {
		OT_LOG(LOG_ERR, "message null");
		return 1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	*msg_name = msg_hdr.msg_name;
	return 0;
}

int com_get_msg_type(void *msg, uint8_t *msg_type)
{
	struct com_msg_hdr msg_hdr;

	if (!msg || !msg_type) {
		OT_LOG(LOG_ERR, "message null");
		return 1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	*msg_type = msg_hdr.msg_type;
	return 0;
}

int com_get_msg_sess_id(void *msg, uint64_t *sess_id)
{
	struct com_msg_hdr msg_hdr;

	if (!msg || !sess_id) {
		OT_LOG(LOG_ERR, "message null");
		return 1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	*sess_id = msg_hdr.sess_id;
	return 0;
}
