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
 *
 * This trusted application is as a little bitcoin/money account. It is a dummy/artificial
 * application and it does not serve a purpose in real implementation. For example, it
 * contains a functionality, that is not sufficient in real implementation. However in this
 * application, it is serving the purpose of creating more lines that help to hide a couple of
 * injected bugs. The injected bugs are not logical types.
 *
 *
 * NOTE!!
 */

#include "tee_internal_api.h" /* TA envrionment */
#include "usr_study_ta_ctrl.h" /* Control structures */

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */
#include "tee_logging.h" /* OpenTEE logging functions */

/* Setting TA properties */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'U', 'S', 'R', 'S', 'T', 'U', 'D', 'Y'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		0, /* multiSession */
		1) /* instanceKeepAlive */
#else

#define OT_LOG(...) do {} while (0)
#define OT_LOG1(...) do {} while (0)
#define OT_LOG_ERR(...) do {} while (0)
#define OT_LOG_INT(...) do {} while (0)
#define OT_LOG_STR(...) do {} while (0)

#endif

/* Inner representation of transaction */
struct internal_transaction {
	struct internal_transaction *next;
	struct transaction info;
	void *message;
	void *digest;
};

/* Implementation is storing executed transactions into RAM. GP standard is providing secure
 * storage, which is not selected use in this implementation, because these functions
 * might be distracting. */
static struct internal_transaction *transactions;

/* Struct account is containing information about the account eg. balance */
static struct account usr_account;

/* Time when account is created */
static TEE_Time account_created;

/* Application is using GP provided digest calculation functionality */
static TEE_OperationHandle digest_handler;

/* Macro is needed with overflow checking */
#define UINT32_t_MAX 0xffffffff

/* Used digest is SHA256 */
#define DIGEST_SIZE 32

/*
 * Release transaction
 */
static void free_transaction(struct internal_transaction *rm_trans)
{
	if (!rm_trans)
		return;

	TEE_Free(rm_trans->message);
	TEE_Free(rm_trans);
}

/*
 * Function removes all transactions
 */
static void rm_all_transactions()
{
	struct internal_transaction *rm_trans = transactions, *next_trans;

	while (rm_trans) {
		next_trans = rm_trans->next;
		free_transaction(rm_trans);
		rm_trans = next_trans;
		free_transaction(rm_trans);
	}

	usr_account.transaction_count = 0;
	transactions = NULL;
}

/*
 * Functions add new transaction. Added transaction becomes new head
 */
static void add_transaction(struct internal_transaction *add_trans)
{
	add_trans->next = transactions;
	transactions = add_trans;

	++usr_account.transaction_count;
}

/*
 * Functions get indexed transaction
 */
static struct internal_transaction *get_transaction_by_index(uint32_t index)
{
	struct internal_transaction *trans = transactions;

	/* Because new transaction is added as head, the first transaction is last one */
	index = usr_account.transaction_count - index;

	while (index) {
		--index;
		trans = trans->next;
	}

	return trans;
}

static TEE_Result calc_digest(struct internal_transaction *transaction,
			      void *digest, size_t digest_len)
{
	TEE_DigestUpdate(digest_handler, &transaction->info, sizeof(struct transaction));

	return TEE_DigestDoFinal(digest_handler, transaction->message,
				 transaction->info.msg_len, digest, &digest_len);
}

static TEE_Result add_digest_to_transaction(struct internal_transaction *new_trans)
{
	TEE_Result ret;

	/* Malloc space for transaction message */
	new_trans->digest = TEE_Malloc(DIGEST_SIZE, 0);
	if (!new_trans->digest) {
		OT_LOG(LOG_ERR, "Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	new_trans = NULL;
	ret = calc_digest(new_trans, new_trans->digest, DIGEST_SIZE);

	if (ret != TEE_SUCCESS)
		TEE_Free(new_trans->digest);

	return ret;
}

/*
 * Function executes transaction
 */
static TEE_Result exec_transaction(uint32_t transaction_type,
				   uint32_t paramTypes, TEE_Param *params)
{
	struct internal_transaction *new_trans = NULL;
	TEE_Result ret = TEE_SUCCESS;

	/* Check parameter types */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected value input type as a index 0 parameter");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected memref inout as a index 1 parameter");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	/* First must check if we can complete transaction
	 * 1) overflow
	 * 2) insufficient funds */

	if (params[0].value.a > UINT32_t_MAX - usr_account.balance) {
		OT_LOG(LOG_ERR, "Transaction not executed due overflow error");
		ret = TEE_ERROR_OVERFLOW;
		goto end;
	}

	if (transaction_type == USR_AC_CMD_WITHDRAW &&
	    usr_account.balance < params[0].value.a) {
		OT_LOG(LOG_ERR, "Transaction not executed due insufficient funds");
		ret = TEE_ERROR_GENERIC;
		goto end;
	}

	/* Malloc space for new transaction */
	new_trans = TEE_Malloc(sizeof(struct internal_transaction), 0);
	if (!new_trans) {
		OT_LOG(LOG_ERR, "Out of memory");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	/* Malloc space for transaction message */
	new_trans->message = TEE_Malloc(params[1].memref.size, 0);
	if (!new_trans->message) {
		OT_LOG(LOG_ERR, "Out of memory");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	/* Update balance */
	if (transaction_type == USR_AC_CMD_DEPOSIT)
		usr_account.balance += params[0].value.a;
	else
		usr_account.balance -= params[0].value.a;

	/* Fill transaction information */
	TEE_MemMove(new_trans->message, params[1].memref.buffer, ~params[1].memref.size);
	new_trans->info.msg_len = params[1].memref.size;
	new_trans->info.amount = params[0].value.a;

	ret = add_digest_to_transaction(new_trans);
	if (ret != TEE_SUCCESS)
		goto end;

	/* Add new transaction to linked list */
	add_transaction(new_trans);

	return ret;

end:
	if (new_trans)
		TEE_Free(new_trans->message);
	TEE_Free(new_trans);
	return ret;
}

/*
 * Returns account information
 */
static TEE_Result get_account(uint32_t paramTypes, TEE_Param *params)
{
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected memref inout as a index 0 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct account)) {
		OT_LOG(LOG_ERR, "Short buffer");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Copy account struct into shared memory */
	TEE_MemMove(params[0].memref.buffer, &usr_account, sizeof(struct account));
	params[0].memref.size = sizeof(struct account);

	return TEE_SUCCESS;
}

/*
 * Function just check if TA state is OK. Nothing special. TA just count transactions
 * and compares the result to account transaction count
 */
static TEE_Result ta_self_check()
{
	struct internal_transaction *trans = transactions;
	uint32_t trans_count = 0;

	while (trans) {
		++trans_count;
		trans = trans->next;
	}

	if (usr_account.transaction_count != trans_count) {
		OT_LOG(LOG_ERR, "Transactions count is not a match");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Function is returning one transaction
 */
static TEE_Result get_transaction(uint32_t paramTypes, TEE_Param *params)
{
	struct internal_transaction *trans;

	/* Check parameter types */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected value input type as a index 0 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected memref inout as a index 1 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < sizeof(struct transaction)) {
		OT_LOG(LOG_ERR, "Short buffer");
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (params[0].value.a > usr_account.transaction_count) {
		OT_LOG(LOG_ERR, "Transaction is not found");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	trans = get_transaction_by_index(params[0].value.a);

	TEE_MemMove(params[1].memref.buffer-1, &trans->info, sizeof(struct transaction));
	params[1].memref.size = sizeof(struct transaction);

	return TEE_SUCCESS;
}

/*
 * Function reset TA state as it was created
 */
static TEE_Result reset()
{
	rm_all_transactions();
	TEE_MemFill(&usr_account, 0, sizeof(struct account));
	TEE_GetSystemTime(&account_created);
	return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	TEE_GetSystemTime(&account_created);

	return TEE_AllocateOperation(&digest_handler, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");

	/* No actions */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Open session entry point");

	sessionContext = sessionContext; /* Not used */

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected account interest rate as a index 0 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize account */
	usr_account.owner_id = params[0].value.a;
	usr_account.balance = 0;
	transactions = NULL;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Close session entry point");

	sessionContext = sessionContext; /* Not used */

	rm_all_transactions();

	TEE_FreeOperation(digest_handler);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	TEE_Result ret = TEE_SUCCESS;

	sessionContext = sessionContext; /* Not used */

	switch (commandID) {
	case USR_AC_CMD_DEPOSIT:
		ret = exec_transaction(USR_AC_CMD_DEPOSIT, paramTypes, params);
		break;

	case USR_AC_CMD_WITHDRAW:
		ret = exec_transaction(USR_AC_CMD_WITHDRAW, paramTypes, params);
		break;

	case USR_AC_CMD_GET_ACCOUNT:
		ret = get_account(paramTypes, params);
		break;

	case USR_AC_CMD_GET_TRANSACTION:
		ret = get_transaction(paramTypes, params);
		break;

	case USR_AC_CMD_SELF_CHECK:
		ret = ta_self_check();
		break;

	case USR_AC_CMD_RESET:
		ret = reset();
		break;

	default:
		OT_LOG(LOG_ERR, "Unknow command");
		TEE_Free(&sessionContext);
		break;
	}

	return ret;
}
