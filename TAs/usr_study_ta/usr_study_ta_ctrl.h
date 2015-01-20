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

#ifndef __USR_STUDY_TA_CTRL__
#define __USR_STUDY_TA_CTRL__

struct account {
	uint32_t owner_id;
	uint32_t balance;
	uint32_t transaction_count;
};

struct transaction {
	uint32_t msg_len;
	uint32_t amount;
};

/* Commands */
#define	USR_AC_CMD_RESERVED		0x00000000
#define USR_AC_CMD_WITHDRAW		0x00000001
#define USR_AC_CMD_DEPOSIT		0x00000002
#define USR_AC_CMD_GET_ACCOUNT		0x00000003
#define USR_AC_CMD_GET_TRANSACTION	0x00000004
#define USR_AC_CMD_SELF_CHECK		0x00000005
#define USR_AC_CMD_RESET		0x00000006

#endif /* __USR_STUDY_TA_CTRL__ */
