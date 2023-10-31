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

#ifndef __TA2TA_CONN_TEST_APP_CTRL_H__
#define __TA2TA_CONN_TEST_APP_CTRL_H__

#include <stdint.h>

const TEEC_UUID ta2ta_uuid = {
	0x12345678, 0x8765, 0x4321, { 'T', 'A', '2', 'T', 'A', '0', '0', '0'}
};

#define CMD_HAS_CREATE_ENTRY_CALLED_ONCE 6532
#define CMD_INVOKE_PARAMS_TEST 6533

#define OPEN_DATA_IN_LEN 8
const uint8_t open_data_in[] = "testtest";
#define OPEN_DATA_OUT_LEN 8
const uint8_t open_data_out[] = "tsettset";
const uint32_t open_value_a_in = 12345;
const uint32_t open_value_a_out = 54321;

#define INVOKE_DATA_IN_LEN 10
const uint8_t invoke_data_in[] = "xxxxxxxxxxxxxx";
#define INVOKE_DATA_OUT_RESERVED_LEN 33
#define INVOKE_DATA_OUT_LEN 8
const uint8_t invoke_data_out[] = "yyyyyyyyyyyyy";
const uint32_t invoke_value_b_in = 5434532;
const uint32_t invoke_value_b_out = 578653;

#endif
