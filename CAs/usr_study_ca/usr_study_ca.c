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

/* NOTE!!
 *
 * This is implemented for user study. It is serving the purpose of user study!
 * Therefore it might not have the most perfect design choices and implementation.
 *
 * NOTE!!
 */

#include "tee_client_api.h"
#include "usr_study_ta_ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
	0x12345678, 0x8765, 0x4321, { 'U', 'S', 'R', 'S', 'T', 'U', 'D', 'Y'}
};

#define MAX_MSG_SIZE		200

#define DEPOSIT_MSG_1		"Winnings"
#define DEPOSIT_AMOUNT_1	2000
#define DEPOSIT_MSG_2		"Salary"
#define DEPOSIT_AMOUNT_2	500
#define DEPOSIT_MSG_3		"Sell old stuff"
#define DEPOSIT_AMOUNT_3	300
#define WITHDRAW_MSG_1		"Rent"
#define WITHDRAW_AMOUNT_1	1500
#define WITHDRAW_MSG_2		"Gas"
#define WITHDRAW_AMOUNT_2	50
#define WITHDRAW_MSG_3		"New TV from store"
#define WITHDRAW_AMOUNT_3	550
#define WITHDRAW_MSG_4		"New phone from friends store"
#define WITHDRAW_AMOUNT_4	200

#define OWNER_ID		0xf3da12cc
#define BALANCE			500
#define	TRANSACTION_COUNT	7

#define P_STR(str) printf("failed: %s\n", str);

static void p_failed(TEE_Result ret)
{
	switch (ret) {
	case TEE_ERROR_GENERIC:
		P_STR("TEE_ERROR_GENERIC")
		return;
	case TEE_ERROR_ACCESS_DENIED:
		P_STR("TEE_ERROR_ACCESS_DENIED")
		return;
	case TEE_ERROR_CANCEL:
		P_STR("TEE_ERROR_CANCEL")
		return;
	case TEE_ERROR_ACCESS_CONFLICT:
		P_STR("TEE_ERROR_ACCESS_CONFLICT")
		return;
	case TEE_ERROR_EXCESS_DATA:
		P_STR("TEE_ERROR_EXCESS_DATA")
		return;
	case TEE_ERROR_BAD_FORMAT:
		P_STR("TEE_ERROR_BAD_FORMAT")
		return;
	case TEE_ERROR_BAD_PARAMETERS:
		P_STR("TEE_ERROR_BAD_PARAMETERS")
		return;
	case TEE_ERROR_BAD_STATE:
		P_STR("TEE_ERROR_BAD_STATE")
		return;
	case TEE_ERROR_ITEM_NOT_FOUND:
		P_STR("TEE_ERROR_ITEM_NOT_FOUND")
		return;
	case TEE_ERROR_NOT_IMPLEMENTED:
		P_STR("TEE_ERROR_NOT_IMPLEMENTED")
		return;
	case TEE_ERROR_NOT_SUPPORTED:
		P_STR("TEE_ERROR_NOT_SUPPORTED")
		return;
	case TEE_ERROR_NO_DATA:
		P_STR("TEE_ERROR_NO_DATA")
		return;
	case TEE_ERROR_OUT_OF_MEMORY:
		P_STR("TEE_ERROR_OUT_OF_MEMORY")
		return;
	case TEE_ERROR_BUSY:
		P_STR("TEE_ERROR_BUSY")
		return;
	case TEE_ERROR_COMMUNICATION:
		P_STR("TEE_ERROR_COMMUNICATION")
		return;
	case TEE_ERROR_SECURITY:
		P_STR("TEE_ERROR_SECURITY")
		return;
	case TEE_ERROR_SHORT_BUFFER:
		P_STR("TEE_ERROR_SHORT_BUFFER")
		return;
	case TEE_PENDING:
		P_STR("TEE_PENDING")
		return;
	case TEE_ERROR_TIMEOUT:
		P_STR("TEE_ERROR_TIMEOUT")
		return;
	case TEE_ERROR_OVERFLOW:
		P_STR("TEE_ERROR_OVERFLOW")
		return;
	case TEE_ERROR_TARGET_DEAD:
		P_STR("TEE_ERROR_TARGET_DEAD")
		return;
	case TEE_ERROR_STORAGE_NO_SPACE:
		P_STR("TEE_ERROR_STORAGE_NO_SPACE")
		return;
	case TEE_ERROR_MAC_INVALID:
		P_STR("TEE_ERROR_MAC_INVALID")
		return;
	case TEE_ERROR_SIGNATURE_INVALID:
		P_STR("TEE_ERROR_SIGNATURE_INVALID")
		return;
	case TEE_ERROR_TIME_NOT_SET:
		P_STR("TEE_ERROR_TIME_NOT_SET")
		return;
	case TEE_ERROR_TIME_NEEDS_RESET:
		P_STR("TEE_ERROR_TIME_NEEDS_RESET")
		return;
	default:
		break;
	}
}

static TEEC_Result open_session(TEEC_Context *context, TEEC_Session *session,
				uint32_t account_interest)
{
	TEEC_Operation operation;
	uint32_t conn_method = TEEC_LOGIN_PUBLIC;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Open session is expection account currency */
	operation.params[0].value.a = account_interest;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Open session with TA */
	return TEEC_OpenSession(context, session, &uuid, conn_method, NULL, &operation, NULL);
}

static TEEC_Result exec_transaction(TEEC_Session *session, TEEC_SharedMemory *shm_inout,
				    uint32_t transaction_type, uint32_t amount,
				    char *msg, uint32_t msg_len)
{
	TEEC_Operation operation;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Set amount to operation */
	operation.params[0].value.a = amount;

	/* Copy message to shm and assign to operation */
	memcpy(shm_inout->buffer, msg, msg_len);
	shm_inout->size = MAX_MSG_SIZE;
	operation.params[1].memref.parent = shm_inout;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
						TEEC_NONE, TEEC_NONE);

	/* Execute transaction*/
	if (transaction_type == USR_AC_CMD_DEPOSIT)
		return TEEC_InvokeCommand(session, USR_AC_CMD_DEPOSIT, &operation, NULL);
	else
		return TEEC_InvokeCommand(session, USR_AC_CMD_WITHDRAW, &operation, NULL);
}

static TEEC_Result do_dummy_transactions(TEEC_Session *session, TEEC_SharedMemory *shm_inout)
{
	TEE_Result ret = TEE_SUCCESS;

	printf("Making transactions: ");

	/* Transaction: 1 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_DEPOSIT,
			       DEPOSIT_AMOUNT_1, DEPOSIT_MSG_1, sizeof(DEPOSIT_MSG_1));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 2 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_DEPOSIT,
			       DEPOSIT_AMOUNT_2, DEPOSIT_MSG_2, sizeof(DEPOSIT_MSG_2));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 3 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_WITHDRAW,
			       WITHDRAW_AMOUNT_1, WITHDRAW_MSG_1, sizeof(WITHDRAW_MSG_1));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 4 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_WITHDRAW,
			       WITHDRAW_AMOUNT_2, WITHDRAW_MSG_2, sizeof(WITHDRAW_MSG_2));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 5 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_WITHDRAW,
			       WITHDRAW_AMOUNT_3, WITHDRAW_MSG_3, sizeof(WITHDRAW_MSG_3));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 6 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_DEPOSIT,
			       DEPOSIT_AMOUNT_3, DEPOSIT_MSG_3, sizeof(DEPOSIT_MSG_3));
	if (ret != TEEC_SUCCESS)
		goto end;

	/* Transaction: 7 */
	ret = exec_transaction(session, shm_inout, USR_AC_CMD_WITHDRAW,
			       WITHDRAW_AMOUNT_4, WITHDRAW_MSG_4, sizeof(WITHDRAW_MSG_4));
	if (ret != TEEC_SUCCESS)
		goto end;

end:
	if (ret != TEEC_SUCCESS)
		p_failed(ret);
	else
		printf("Ok\n");

	return ret;
}

static TEE_Result get_account(TEEC_Session *session, TEEC_SharedMemory *shm_inout)
{
	struct account *usr_ac;
	TEEC_Operation operation;
	TEE_Result ret = TEE_SUCCESS;

	printf("Querying account: ");

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	operation.params[0].memref.parent = shm_inout;
	shm_inout->size = MAX_MSG_SIZE;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	ret = TEEC_InvokeCommand(session, USR_AC_CMD_GET_ACCOUNT, &operation, NULL);

	if (ret != TEE_SUCCESS) {
		p_failed(ret);
		return ret;
	}

	usr_ac = shm_inout->buffer;

	if (usr_ac->balance != BALANCE ||
	    usr_ac->transaction_count != TRANSACTION_COUNT ||
	    usr_ac->owner_id != OWNER_ID) {
		printf("Something is wrong: 0x%x\n", ret);
		return TEE_ERROR_GENERIC;
	}

	printf("Ok\n");
	return ret;
}

static TEE_Result get_transactions(TEEC_Session *session, TEEC_SharedMemory *shm_inout)
{
	TEEC_Operation operation;
	TEE_Result ret = TEE_SUCCESS;
	struct transaction *trans;

	printf("Getting random transactions: ");


	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Getting random transaction */
	operation.params[0].value.a = 6;

	shm_inout->size = MAX_MSG_SIZE;
	operation.params[1].memref.parent = shm_inout;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
						TEEC_NONE, TEEC_NONE);

	ret = TEEC_InvokeCommand(session, USR_AC_CMD_GET_TRANSACTION, &operation, NULL);

	if (ret != TEE_SUCCESS) {
		p_failed(ret);
		return ret;
	}

	trans = shm_inout->buffer;

	if (trans->amount != DEPOSIT_AMOUNT_3) {
		printf("Something is wrong");
		return TEE_ERROR_GENERIC;
	}

	printf("Ok\n");
	return ret;
}

static TEE_Result exec_ta_self_check(TEEC_Session *session)
{
	TEE_Result ret = TEE_SUCCESS;

	printf("Executing TA self checking: ");

	ret = TEEC_InvokeCommand(session, USR_AC_CMD_SELF_CHECK, NULL, NULL);

	if (ret != TEE_SUCCESS) {
		p_failed(ret);
		return ret;
	}

	printf("Ok\n");
	return ret;
}

static TEE_Result reset_account(TEEC_Session *session)
{
	TEE_Result ret = TEE_SUCCESS;

	printf("Resetting account: ");

	ret = TEEC_InvokeCommand(session, USR_AC_CMD_RESET, NULL, NULL);

	if (ret != TEE_SUCCESS) {
		p_failed(ret);
		return ret;
	}

	printf("Ok\n");
	return ret;
}

static TEE_Result unknow_cmd(TEEC_Session *session)
{
	TEE_Result ret = TEE_SUCCESS;

	printf("Testing unknown cmd: ");

	ret = TEEC_InvokeCommand(session, USR_AC_CMD_RESERVED, NULL, NULL);

	if (ret != TEE_SUCCESS) {
		p_failed(ret);
		return ret;
	}

	printf("Ok\n");
	return ret;
}

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_SharedMemory shm_inout;
	TEEC_Result ret;


	printf("\nSTART: usr study app\n");

	printf("Initializing: ");

	/* Initialize context */
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_1;
	}

	/* Alloc used shared memory */
	shm_inout.size = MAX_MSG_SIZE;
	shm_inout.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_AllocateSharedMemory(&context, &shm_inout);
	if (ret != TEE_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_2;
	}

	ret = open_session(&context, &session, OWNER_ID);
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_3;
	}

	printf("Ok\n");

	printf("----Begin-with-test-cases----\n");

	ret = do_dummy_transactions(&session, &shm_inout);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = get_account(&session, &shm_inout);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = get_transactions(&session, &shm_inout);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = exec_ta_self_check(&session);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = reset_account(&session);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = unknow_cmd(&session);
	if (ret != TEE_SUCCESS)
		goto end_4;

	ret = exec_ta_self_check(&session);
	if (ret != TEE_SUCCESS)
		goto end_4;

	/* Cleanup used connection/resources */
end_4:
	TEEC_CloseSession(&session);
end_3:
	TEEC_ReleaseSharedMemory(&shm_inout);
end_2:
	TEEC_FinalizeContext(&context);

end_1:
	printf("-------------------------\n");

	if (ret == TEE_SUCCESS)
		printf("Run summary: PASS\n");
	else
		printf("Run summary: FAILED\n");

	printf("-------------------------\n");

	printf("END: usr study app\n\n");
	exit(ret);
}
