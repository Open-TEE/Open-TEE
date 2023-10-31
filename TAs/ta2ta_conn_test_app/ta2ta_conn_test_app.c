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

#include "tee_internal_api.h"
#include "tee_logging.h"
#include "ta2ta_conn_test_app_ctrl.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'T', 'A', '2', 'T', 'A', '0', '0', '0'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		0) /* instanceKeepAlive */
#endif

static uint32_t create_entry_counter = 0;

static TEE_Result has_create_entry_called_once()
{
	if (create_entry_counter == 1) {
		return TEE_SUCCESS;
	}

	return TEE_ERROR_GENERIC;
}

static TEE_Result invoke_params_test(uint32_t paramTypes,
				     TEE_Param params[4])
{
	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_MEMREF_INPUT, 1)) {
		OT_LOG_ERR("Not expected param type at 1");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_MEMREF_OUTPUT, 2)) {
		OT_LOG_ERR("Not expected param type at 2");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_VALUE_INPUT, 3)) {
		OT_LOG_ERR("Not expected param type at 3");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_VALUE_OUTPUT, 4)) {
		OT_LOG_ERR("Not expected param type at 4");
		return TEE_ERROR_GENERIC;
	}

	if (params[0].memref.size != INVOKE_DATA_IN_LEN) {
		OT_LOG(LOG_ERR, "Not expected lenght");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_MemCompare(params[0].memref.buffer, invoke_data_in, INVOKE_DATA_IN_LEN)) {
		OT_LOG(LOG_ERR, "Not expected buffer content");
		return TEE_ERROR_GENERIC;
	}

	if (params[1].memref.size != INVOKE_DATA_OUT_RESERVED_LEN) {
		OT_LOG(LOG_ERR, "Not expected lenght");
		return TEE_ERROR_GENERIC;
	}

	if (params[2].value.a != 0) {
		OT_LOG(LOG_ERR, "NOT expected value in a");
		return TEE_ERROR_GENERIC;
	}

	if (params[2].value.b != invoke_value_b_in) {
		OT_LOG(LOG_ERR, "NOT expected value in b");
		return TEE_ERROR_GENERIC;
	}

	if (params[3].value.a != 0) {
		OT_LOG(LOG_ERR, "NOT expected value in a");
		return TEE_ERROR_GENERIC;
	}

	if (params[3].value.b != 0) {
		OT_LOG(LOG_ERR, "NOT expected value in b");
		return TEE_ERROR_GENERIC;
	}

	//Fill Response
	TEE_MemMove(params[1].memref.buffer, invoke_data_out, INVOKE_DATA_OUT_LEN);
	params[1].memref.size = INVOKE_DATA_OUT_LEN;

	params[3].value.b = invoke_value_b_out;

	return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the create entry point");

	create_entry_counter += 1;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the Destroy entry point");
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
					      void **sessionContext)
{
	sessionContext = sessionContext;

	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_MEMREF_INOUT, 1)) {
		OT_LOG_ERR("Not expected param type at 1");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_VALUE_INOUT, 2)) {
		OT_LOG_ERR("Not expected param type at 2");
		return TEE_ERROR_GENERIC;
	}

	if (params[0].memref.size != OPEN_DATA_IN_LEN) {
		OT_LOG_ERR("Not expected lenght");
		return TEE_ERROR_GENERIC;
	}

	if (TEE_MemCompare(params[0].memref.buffer, open_data_in, OPEN_DATA_IN_LEN)) {
		OT_LOG_ERR("Not expected buffer content");
		return TEE_ERROR_GENERIC;
	}

	if (params[1].value.a != open_value_a_in) {
		OT_LOG_ERR("NOT expected value in a");
		return TEE_ERROR_GENERIC;
	}

	if (params[1].value.b != 0) {
		OT_LOG_ERR("NOT expected value in b");
		return TEE_ERROR_GENERIC;
	}

	TEE_MemMove(params[0].memref.buffer, open_data_out, OPEN_DATA_OUT_LEN);
	params[0].memref.size = OPEN_DATA_OUT_LEN;
	params[1].value.a = open_value_a_out;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	OT_LOG(LOG_INFO, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	sessionContext = sessionContext;

	OT_LOG(LOG_INFO, "Calling the Invoke command entry point");

	switch (commandID) {
	case CMD_HAS_CREATE_ENTRY_CALLED_ONCE:
		return has_create_entry_called_once();
	case CMD_INVOKE_PARAMS_TEST:
		return invoke_params_test(paramTypes, params);
	default:
		OT_LOG(LOG_ERR, "Not supported command id -> Panicking");
	}

	TEE_Panic(TEE_ERROR_GENERIC);
	return TEE_ERROR_GENERIC;
}
