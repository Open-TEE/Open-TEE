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

/* Simple application for testing entry point functions calling.
 * Application will be updated as manager process development goes forward */

#include "conn_test_ctl.h"
#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*********************************************************************
 *
 * START: CONFIGURE SECTION
 *
 * This is only setting the amounts of stress tests eg how many loops
 *********************************************************************/
static uint32_t full_treatment_loop_count = 5;
#define PRI(str, ...) printf(str, ##__VA_ARGS__);
#define PRIn(str, ...) printf(str "\n", ##__VA_ARGS__);
static const TEEC_UUID uuid = {0x12345678, 0x8765, 0x4321, {'T','A','C','O','N','N','T','E'}};

/* Dirty, but cleanest and fastest for now */
static uint8_t in_vector[] = IN_KNOWN_VECTOR;
static uint8_t out_vector[] = OUT_KNOWN_VECTOR;
static uint8_t reg_buffer[SIZE_OF_VEC(IN_KNOWN_VECTOR)];
static uint8_t rand_buffer[RAND_BUFFER_SIZE];

/*********************************************************************
 *
 * END: CONFIGURE SECTION
 *
 *********************************************************************/

static void reverse_buffer(uint8_t *buffer,
			   uint32_t buffer_length,
			   size_t *reversed_size)
{
	uint32_t i, j;
	uint8_t tmp;

	for (i = 0, j = buffer_length - 1; i < j; i++, j--) {
		tmp = buffer[i];
		buffer[i] = buffer[j];
		buffer[j] = tmp;
	}

	if (reversed_size)
		*reversed_size = REVERSED_SIZE(buffer_length);
}

static int seed_random()
{
	uint32_t seed;
	FILE* urandom;

	urandom = fopen("/dev/urandom", "r");
	if (urandom == NULL)
		return 1;

	if (fread(&seed, sizeof(int), 1, urandom) != 1)
		return 1;

	fclose(urandom);
	srand(seed);
	return 0;
}

static void fill_buffer_with_random(uint8_t *buffer,
				    uint32_t buffer_length)
{
	uint32_t i;

	for (i = 0; i < buffer_length; i++)
		buffer[i] = rand();
}

static void fill_operation_params(TEEC_Operation *operation,
				  TEEC_SharedMemory *reg_inout_mem,
				  TEEC_SharedMemory *alloc_inout_mem)
{
	operation->paramTypes =	TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
						 TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INOUT);

	/* Value parameter */
	operation->params[0].value.a  = IN_VALUE_A;
	operation->params[0].value.b  = IN_VALUE_B;

	/* Register memory */
	reg_inout_mem->size = SIZE_OF_VEC(in_vector);
	memcpy(reg_inout_mem->buffer, in_vector, SIZE_OF_VEC(in_vector));
	operation->params[1].memref.parent = reg_inout_mem;

	/* Alloc memory */
	alloc_inout_mem->size = SIZE_OF_VEC(in_vector);
	memcpy(alloc_inout_mem->buffer, in_vector, SIZE_OF_VEC(in_vector));
	operation->params[2].memref.parent = alloc_inout_mem;

	/* Temp parameter */
	fill_buffer_with_random(rand_buffer, RAND_BUFFER_SIZE);
	operation->params[3].tmpref.buffer = rand_buffer;
	operation->params[3].tmpref.size = RAND_BUFFER_SIZE;
}

static int check_operation_params(TEEC_Operation *operation)
{
	uint32_t i;

	if (operation->paramTypes != TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
						      TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INOUT)) {
		PRIn("Not expected paramTypes");
		return 1;
	}

	if (operation->params[0].value.a != OUT_VALUE_A) {
		PRIn("Parameter at 0 is not expected (value a)");
		return 1;
	}

	if (operation->params[0].value.b != OUT_VALUE_B) {
		PRIn("Parameter at 0 is not expected (value B)");
		return 1;
	}

	for (i = 1; i < 3; i++) {
		if (operation->params[i].memref.size != SIZE_OF_VEC(out_vector)) {
			PRI("Parameter at %u is not expected (wrong size)", i);
			return 1;
		}

		if (memcmp(operation->params[i].memref.parent->buffer,
			   out_vector, SIZE_OF_VEC(out_vector))) {
		    PRIn("Parameter at %u is not expected (wrong data)", i);
		    return 1;
		}
	}

	if (operation->params[3].tmpref.size != REVERSED_SIZE(RAND_BUFFER_SIZE)) {
		PRIn("Parameter at 3 is not expected (wrong size)");
		return 1;
	}

	reverse_buffer(rand_buffer, RAND_BUFFER_SIZE, NULL);

	if (memcmp(operation->params[3].tmpref.buffer,
		   rand_buffer, REVERSED_SIZE(RAND_BUFFER_SIZE))) {
	    PRIn("Parameter at 3 is not expected (wrong data)");
	    return 1;
	}

	return 0;
}

static int reg_shared_memory(TEEC_Context *context,
			     TEEC_SharedMemory *reg_shm,
			     void *buffer,
			     uint32_t buffer_size,
			     uint32_t flags)
{
	TEEC_Result ret;

	PRI("Registering shared memory: ");
	reg_shm->buffer = buffer;
	reg_shm->size = buffer_size;
	reg_shm->flags = flags;
	ret = TEEC_RegisterSharedMemory(context, reg_shm);
	if (ret != TEE_SUCCESS) {
		PRIn("TEEC_RegisterSharedMemory failed: 0x%x", ret);
		return 1;
	}

	PRIn("registered");
	return 0;
}


static int alloc_shared_memory(TEEC_Context *context,
			       TEEC_SharedMemory *alloc_shm,
			       uint32_t buffer_size,
			       uint32_t flags)
{
	TEEC_Result ret;

	PRI("Allocating shared memory: ");
	alloc_shm->size = buffer_size;
	alloc_shm->flags = flags;
	ret = TEEC_AllocateSharedMemory(context, alloc_shm);
	if (ret != TEE_SUCCESS) {
		PRIn("TEEC_AllocateSharedMemory failed: 0x%x", ret);
		return 1;
	}

	PRIn("allocated");
	return 0;
}

static int call_invoke_cmd(TEEC_Session *session,
			   TEEC_SharedMemory *reg_shm,
			   TEEC_SharedMemory *alloc_shm,
			   uint32_t command_id)
{
	TEEC_Operation operation = {0};
	uint32_t return_origin;
	TEEC_Result ret;

	PRI("Invoking command 0x%x: ", command_id);
	fill_operation_params(&operation, reg_shm, alloc_shm);
	ret = TEEC_InvokeCommand(session, command_id, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		PRIn("TEEC_InvokeCommand failed: 0x%x\n", ret);
		return 1;
	}

	if (return_origin != TEEC_ORIGIN_TRUSTED_APP) {
		PRIn("Return origin is not from Trusted APP");
		return 1;
	}

	if (check_operation_params(&operation))
		return 1;

	PRIn("invoked");
	return 0;
}

static int full_treatment_test()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation = {0};
	TEEC_Result ret;
	TEEC_SharedMemory reg_inout_mem = {0}, alloc_inout_mem = {0};
	uint32_t return_origin;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;
	uint32_t fn_ret = 1; /* Default is error return */

	/* Initialize context */
	PRI("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		PRI("TEEC_InitializeContext failed: 0x%x", ret);
		goto end_1;
	} else {
		PRIn("initialized");
	}

	/*
	 * Aquire shared memorys. These memorys are sending know vectors, see beginning of file
	 */
	if (reg_shared_memory(&context, &reg_inout_mem, reg_buffer, SIZE_OF_VEC(in_vector),
			      TEEC_MEM_INPUT | TEEC_MEM_OUTPUT))
		goto end_2;

	if (alloc_shared_memory(&context, &alloc_inout_mem, SIZE_OF_VEC(in_vector),
				TEEC_MEM_INPUT | TEEC_MEM_OUTPUT))
		goto end_3;


	/* Open session */
	PRI("Openning session: ");
	fill_operation_params(&operation, &reg_inout_mem, &alloc_inout_mem);
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
			       NULL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		PRIn("TEEC_OpenSession failed: 0x%x", ret);
		goto end_4;
	} else {

		if (ret != TEEC_SUCCESS) {
			PRI("TEEC_InvokeCommand failed: 0x%x\n", ret);
			goto end_5; /* Session is open */
		}

		if (check_operation_params(&operation))
			goto end_5; /* Session is open */

		PRIn("opened");
	}

	/* Invoke: Crypto tests */
	if (call_invoke_cmd(&session, &reg_inout_mem, &alloc_inout_mem, INVOKE_CMD_ID_1))
		goto end_5;

	/* Invoke: Crypto tests */
	if (call_invoke_cmd(&session, &reg_inout_mem, &alloc_inout_mem, INVOKE_CMD_ID_1))
		goto end_5;

	fn_ret = 0; /* Success. If some void function fails, nothing to be done, here */

end_5:
	PRI("Closing session: ");
	TEEC_CloseSession(&session);
	PRIn("closed");
end_4:
	PRI("Releasing allocated memory: ");
	TEEC_ReleaseSharedMemory(&alloc_inout_mem);
	PRIn("released");
end_3:
	PRI("Releasing registered memory: ");
	TEEC_ReleaseSharedMemory(&reg_inout_mem);
	PRIn("released");
end_2:
	PRI("Finalizing ctx: ");
	TEEC_FinalizeContext(&context);
	PRIn("finalized");

end_1:
	PRIn("");
	return fn_ret;
}

int main()
{
	uint32_t i;

	PRIn("START: conn test app\n");

	if (seed_random()) {
		PRI("Error: Can't seed random");
		goto err;
	}

	for (i = 0; i < full_treatment_loop_count; i++) {
		if (full_treatment_test())
			goto err;
	}

	PRIn("END: conn test app\n");

	PRIn("\n");
	PRIn("!!! SUCCESS !!!");
	PRIn("Connection test app did not found any errors.");
	PRIn("^^^ SUCCESS ^^^");
	PRIn("\n");

	exit(0);

err:
	PRIn("\n");
	PRIn("### ERROR ###");
	PRIn("Connection test app did found some errors.");
	PRIn("See our consol output (a couple of last prints) and our machine log.");
	PRIn("For example you could try: $ tail -f /var/log/syslog");
	PRIn("^^^ ERROR ^^^");

	exit(1);
}
