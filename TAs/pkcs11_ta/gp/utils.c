/*****************************************************************************
** Copyright (C) 2016 Open-TEE project.                                     **
** Copyright (C) 2016 Atte Pellikka                                         **
** Copyright (C) 2016 Brian McGillion                                       **
** Copyright (C) 2016 Tanel Dettenborn                                      **
** Copyright (C) 2016 Ville Kankainen                                       **
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

#include "utils.h"
#include "cryptoki.h"
#include "tee_internal_api.h"

/* TODO: List is not complite!! */

CK_RV map_teec2ck(TEE_Result teec_result)
{
	switch (teec_result) {
	case TEE_ERROR_GENERIC:
	case TEE_ERROR_CANCEL:
	case TEE_ERROR_ACCESS_DENIED:
	case TEE_ERROR_ACCESS_CONFLICT:
	case TEE_ERROR_EXCESS_DATA:
	case TEE_ERROR_BAD_FORMAT:
	case TEE_ERROR_BAD_STATE:
	case TEE_ERROR_ITEM_NOT_FOUND:
	case TEE_ERROR_NOT_IMPLEMENTED:
	case TEE_ERROR_NOT_SUPPORTED:
	case TEE_ERROR_NO_DATA:
	case TEE_ERROR_BUSY:
	case TEE_ERROR_COMMUNICATION:
	case TEE_ERROR_SECURITY:
	case TEE_PENDING:
	case TEE_ERROR_TIMEOUT:
	case TEE_ERROR_OVERFLOW:
	case TEE_ERROR_TARGET_DEAD:
	case TEE_ERROR_TIME_NOT_SET:
	case TEE_ERROR_TIME_NEEDS_RESET:
		return CKR_GENERAL_ERROR;

	case TEE_ERROR_MAC_INVALID:
	case TEE_ERROR_SIGNATURE_INVALID:
		return CKR_SIGNATURE_INVALID;

	case TEE_ERROR_STORAGE_NO_SPACE:
	case TEE_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_BAD_PARAMETERS:
		return CKR_ATTRIBUTE_VALUE_INVALID;

	case TEE_SUCCESS:
		return CKR_OK;

	default:
		// Prevent accidental success return
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}
