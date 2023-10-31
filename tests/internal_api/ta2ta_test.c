/*****************************************************************************
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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
#include "ta2ta_conn_test_app_ctrl.h"
#include "print_functions.h"

static uint32_t basic_ta2ta_connection()
{
	TEE_Result gp_rv, fn_rv = 1;
	uint32_t paramTypes, retOrigin;
	TEE_TASessionHandle session;
	TEE_Param params[4] = {0};
	uint8_t open_buf_in[OPEN_DATA_IN_LEN] = {0};
	uint8_t invoke_buf_in[INVOKE_DATA_IN_LEN] = {0},
		invoke_buf_out[INVOKE_DATA_OUT_RESERVED_LEN] = {0};

	paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_VALUE_INOUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	TEE_MemMove(open_buf_in, (void *)open_data_in, OPEN_DATA_IN_LEN);
	params[0].memref.buffer = open_buf_in;
	params[0].memref.size = OPEN_DATA_IN_LEN;

	params[1].value.a = open_value_a_in;
	params[1].value.b = 0;

	gp_rv = TEE_OpenTASession((TEE_UUID *)&ta2ta_uuid,
				  TEE_TIMEOUT_INFINITE,
				  paramTypes, params,
				  &session, &retOrigin);
	if (gp_rv != TEE_SUCCESS) {
		PRI_FAIL("Opensession failed : 0x%x", gp_rv);
		goto err_1;
	}

	//Check params open session return params
	if (params[0].memref.size != OPEN_DATA_OUT_LEN) {
		PRI_FAIL("Not expected lenght");
		goto err_2;
	}

	if (TEE_MemCompare(params[0].memref.buffer, (void *)open_data_out, OPEN_DATA_OUT_LEN)) {
		PRI_FAIL("Not expected buffer content");
		goto err_2;
	}

	if (params[1].value.a != open_value_a_out) {
		PRI_FAIL("NOT expected value in a");
		goto err_2;
	}

	if (params[1].value.b != 0) {
		PRI_FAIL("NOT expected value in b");
		goto err_2;
	}

	//Initialize invoke params
	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);

	paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT);

	TEE_MemMove(invoke_buf_in, (void *)invoke_data_in, INVOKE_DATA_IN_LEN);
	params[0].memref.buffer = invoke_buf_in;
	params[0].memref.size = INVOKE_DATA_IN_LEN;

	params[1].memref.buffer = invoke_buf_out;
	params[1].memref.size = INVOKE_DATA_OUT_RESERVED_LEN;

	params[2].value.a = 0;
	params[2].value.b = invoke_value_b_in;

	params[3].value.a = 123123; //Discarded
	params[3].value.b = 565656; //Discarded

	gp_rv = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
				    CMD_INVOKE_PARAMS_TEST,
				    paramTypes, params,
				    &retOrigin);
	if (gp_rv != TEE_SUCCESS) {
		PRI_FAIL("Invoke cmd failed : 0x%x", gp_rv);
		goto err_2;
	}

	if (params[1].memref.size != INVOKE_DATA_OUT_LEN) {
		PRI_FAIL("Not expected lenght");
		goto err_2;
	}

	if (TEE_MemCompare(params[1].memref.buffer, (void *)invoke_data_out, INVOKE_DATA_OUT_LEN)) {
		PRI_FAIL("Not expected buffer content");
		goto err_2;
	}

	if (params[3].value.a != 0) {
		PRI_FAIL("NOT expected value in a");
		goto err_2;
	}

	if (params[3].value.b != invoke_value_b_out) {
		PRI_FAIL("NOT expected value in b");
		goto err_2;
	}

	fn_rv = 0;

 err_2:
	TEE_CloseTASession(session);
 err_1:

	if (fn_rv == 0)
		PRI_OK("-");

	return fn_rv;
}

uint32_t ta2ta_test(uint32_t loop_count)
{
	uint32_t i, test_have_fail = 0;

	PRI_STR("START: ta2ta tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {

		if (basic_ta2ta_connection()) {
			test_have_fail = 1;
			break;
		}

	}

	PRI_STR("----Test-has-reached-end----\n");

	PRI_STR("END: ta2ta tests");

	return test_have_fail ? 1 : 0;
}
