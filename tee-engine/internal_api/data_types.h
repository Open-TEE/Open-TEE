/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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

#ifndef __TEE_INTERNAL_DATA_TYPES_H__
#define __TEE_INTERNAL_DATA_TYPES_H__

#include <stddef.h>
#include <stdint.h>

typedef uint32_t TEE_Result;

typedef TEE_Result TEEC_Result;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;

typedef TEE_UUID TEEC_UUID;

/* Compatibility with the Client API */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_GENERIC		0xFFFF0000
#define TEEC_ERROR_ACCESS_DENIED	0xFFFF0001
#define TEEC_ERROR_CANCEL		0xFFFF0002
#define TEEC_ERROR_ACCESS_CONFLICT	0xFFFF0003
#define TEEC_ERROR_EXCESS_DATA		0xFFFF0004
#define TEEC_ERROR_BAD_FORMAT		0xFFFF0005
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_BAD_STATE		0xFFFF0007
#define TEEC_ERROR_ITEM_NOT_FOUND	0xFFFF0008
#define TEEC_ERROR_NOT_IMPLEMENTED	0xFFFF0009
#define TEEC_ERROR_NOT_SUPPORTED	0xFFFF000A
#define TEEC_ERROR_NO_DATA		0xFFFF000B
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C
#define TEEC_ERROR_BUSY			0xFFFF000D
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_SECURITY		0xFFFF000F
#define TEEC_ERROR_SHORT_BUFFER		0xFFFF0010
#define TEEC_ERROR_TARGET_DEAD		0xFFFF3024


#define TEE_SUCCESS			TEEC_SUCCESS
#define TEE_ERROR_GENERIC		TEEC_ERROR_GENERIC
#define TEE_ERROR_ACCESS_DENIED		TEEC_ERROR_ACCESS_DENIED
#define TEE_ERROR_CANCEL		TEEC_ERROR_CANCEL
#define TEE_ERROR_ACCESS_CONFLICT	TEEC_ERROR_ACCESS_CONFLICT
#define TEE_ERROR_EXCESS_DATA		TEEC_ERROR_EXCESS_DATA
#define TEE_ERROR_BAD_FORMAT		TEEC_ERROR_BAD_FORMAT
#define TEE_ERROR_BAD_PARAMETERS	TEEC_ERROR_BAD_PARAMETERS
#define TEE_ERROR_BAD_STATE		TEEC_ERROR_BAD_STATE
#define TEE_ERROR_ITEM_NOT_FOUND	TEEC_ERROR_ITEM_NOT_FOUND
#define TEE_ERROR_NOT_IMPLEMENTED	TEEC_ERROR_NOT_IMPLEMENTED
#define TEE_ERROR_NOT_SUPPORTED		TEEC_ERROR_NOT_SUPPORTED
#define TEE_ERROR_NO_DATA		TEEC_ERROR_NO_DATA
#define TEE_ERROR_OUT_OF_MEMORY		TEEC_ERROR_OUT_OF_MEMORY
#define TEE_ERROR_BUSY			TEEC_ERROR_BUSY
#define TEE_ERROR_COMMUNICATION		TEEC_ERROR_COMMUNICATION
#define TEE_ERROR_SECURITY		TEEC_ERROR_SECURITY
#define TEE_ERROR_SHORT_BUFFER		TEEC_ERROR_SHORT_BUFFER
#define TEE_PENDING			0xFFFF2000
#define TEE_ERROR_TIMEOUT		0xFFFF3001
#define TEE_ERROR_OVERFLOW		0xFFFF300F
#define TEE_ERROR_TARGET_DEAD		TEEC_ERROR_TARGET_DEAD

#define TEE_ERROR_STORAGE_NO_SPACE	0xFFFF3041
#define TEE_ERROR_MAC_INVALID		0xFFFF3071
#define TEE_ERROR_SIGNATURE_INVALID	0xFFFF3072
#define TEE_ERROR_TIME_NOT_SET		0xFFFF5000
#define TEE_ERROR_TIME_NEEDS_RESET	0xFFFF5001

typedef struct {
	uint32_t login;
	TEE_UUID uuid;
} TEE_Identity;


typedef union {
	struct {
		void* buffer;
		size_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;


typedef struct __TEE_TASessionHandle* TEE_TASessionHandle;

typedef struct __TEE_PropSetHandle* TEE_PropSetHandle;


/* Paramater Types */
#define TEE_PARAM_TYPE_NONE		0x00000000
#define TEE_PARAM_TYPE_VALUE_INPUT	0x00000001
#define TEE_PARAM_TYPE_VALUE_OUTPUT	0x00000002
#define TEE_PARAM_TYPE_VALUE_INOUT	0x00000003
#define TEE_PARAM_TYPE_MEMREF_INPUT	0x00000005
#define TEE_PARAM_TYPE_MEMREF_OUTPUT	0x00000006
#define TEE_PARAM_TYPE_MEMREF_INOUT	0x00000007

/* Session Login Methods */
#define TEE_LOGIN_PUBLIC		0x00000000
#define TEE_LOGIN_USER			0x00000001
#define TEE_LOGIN_GROUP			0x00000002
#define TEE_LOGIN_APPLICATION		0x00000004
#define TEE_LOGIN_APPLICATION_USER	0x00000005
#define TEE_LOGIN_APPLICATION_GROUP	0x00000006
#define TEE_LOGIN_TRUSTED_APP		0xF0000000

/* Return Code Origins */
#define TEE_ORIGIN_API			0x00000001
#define TEE_ORIGIN_COMMS		0x00000002
#define TEE_ORIGIN_TEE			0x00000003
#define TEE_ORIGIN_TRUSTED_APP		0x00000004

/* Property Set Pseudo-Handle Constants */
#define TEE_PROPSET_CURRENT_TA		(TEE_PropSetHandle)0xFFFFFFFF
#define TEE_PROPSET_CURRENT_CLIENT	(TEE_PropSetHandle)0xFFFFFFFE
#define TEE_PROPSET_TEE_IMPLEMENTATION	(TEE_PropSetHandle)0xFFFFFFFD

#define TEE_ACCESS_READ			0x00000001
#define TEE_ACCESS_WRITE		0x00000002
#define TEE_ACCESS_ANY_OWNER		0x00000004

#define TEE_PARAM_TYPES(param0Type, param1Type, param2Type, param3Type) \
	((param0Type) | ((param1Type) << 4) | ((param2Type) << 8) | ((param3Type) << 12))

#define TEE_PARAM_TYPE_GET(paramsType, index) (((paramsType) >> (index * 4)) & 0xF)

#endif
