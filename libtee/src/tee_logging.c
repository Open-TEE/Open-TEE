/*****************************************************************************
** Copyright (C) 2015-2021 Tanel Dettenborn                                 **
** Copyright (C) 2015-2021 Brian McGillion                                  **
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


#if (defined TA_PLUGIN || defined OT_LOGGING)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "tee_logging.h"
#include "tee_storage_api.h"
#include "tee_crypto_api.h"

void pri_opm_info(const char *title, void *operationInfoMultiple)
{
	TEE_OperationInfoMultiple *info = operationInfoMultiple;
	uint32_t i = 0;
	
	if (info == NULL) {
		OT_LOG_ERR("pri_opm_info: NULL");
		return;
	}
	
	if (title != NULL) {
		OT_LOG_ERR("%s\n", title);
	}

	OT_LOG_ERR("algorithm        [%u]", info->algorithm);
	OT_LOG_ERR("operationClass   [%u]", info->operationClass);
	OT_LOG_ERR("mode             [%u]", info->mode);
	OT_LOG_ERR("digestLength     [%u]", info->digestLength);
	OT_LOG_ERR("handleState      [%u]", info->handleState);
	OT_LOG_ERR("maxKeySize       [%u]", info->maxKeySize);
	OT_LOG_ERR("operationState   [%u]", info->operationState);
	OT_LOG_ERR("numberOfKeys     [%u]", info->numberOfKeys);

	if (info->numberOfKeys == 0) {
		return;
	}
	
	for (i = 0; i < info->numberOfKeys; ++i) {
		OT_LOG_ERR("key             nr %d", i);
		OT_LOG_ERR("keySize          [%u]", info->keyInformation[i].keySize);
		OT_LOG_ERR("requiredKeyUsage [%u]", info->keyInformation[i].requiredKeyUsage);
	}	
}

void pri_op_info(const char *title, void *operationInfo)
{
	TEE_OperationInfo *info = operationInfo;

	if (info == NULL) {
		OT_LOG_ERR("pri_op_info: NULL");
		return;
	}
	
	if (title != NULL) {
		OT_LOG_ERR("%s\n", title);
	}

	OT_LOG_ERR("algorithm        [%u]", info->algorithm);
	OT_LOG_ERR("operationClass   [%u]", info->operationClass);
	OT_LOG_ERR("mode             [%u]", info->mode);
	OT_LOG_ERR("digestLength     [%u]", info->digestLength);
	OT_LOG_ERR("maxKeySize       [%u]", info->maxKeySize);
	OT_LOG_ERR("keySize          [%u]", info->keySize);
	OT_LOG_ERR("requiredKeyUsage [%u]", info->requiredKeyUsage);
	OT_LOG_ERR("handleState      [%u]", info->handleState);
}

void pri_obj_info(const char *title, void *objectInfo)
{
	TEE_ObjectInfo *info = objectInfo;
	
	if (info == NULL) {
		OT_LOG_ERR("pri_obj_info: NULL");
		return;
	}

	if (title != NULL) {
		OT_LOG_ERR("%s\n", title);
	}

	OT_LOG_ERR("dataPosition  [%u]", info->dataPosition);
	OT_LOG_ERR("dataSize      [%u]", info->dataSize);
	OT_LOG_ERR("handleFlags   [%u]", info->handleFlags);
	OT_LOG_ERR("keySize       [%u]", info->keySize);
	OT_LOG_ERR("maxObjectSize [%u]", info->maxObjectSize);
	OT_LOG_ERR("objectType    [%u]", info->objectType);
	OT_LOG_ERR("objectUsage   [%u]", info->objectUsage);
}

void pri_buf_hex_format(const char *title,
			const unsigned char *buf,
			int buf_len)
{
	int rowLen = 0, rowMaxLen = 16, i = 0;
	char hexstr[rowMaxLen*4+1];
        char hex[4];
	
	if (buf == NULL) {
		OT_LOG_ERR("pri_buf_hex_format: NULL");
		return;
	}
	
        memset(hexstr, 0, rowMaxLen);

	if (title != NULL) {
		OT_LOG_ERR("%s [%u]\n", title, buf_len);
	}
	
	for (i = 0; i < buf_len; ++i) {
		sprintf(hex, "%02X ", buf[i]);
		strncat(hexstr, hex, 4);
		rowLen++;
		if (rowLen == rowMaxLen) {
			strcat(hexstr, "\n");
			OT_LOG_ERR("%s", hexstr);
			memset(hexstr, 0, rowMaxLen);
			rowLen = 0;
		}
	}

	if ((buf_len % rowMaxLen) != 0) {
		strncat(hexstr, "\n", 2);
		OT_LOG_ERR("%s", hexstr);
	}
}

#endif
