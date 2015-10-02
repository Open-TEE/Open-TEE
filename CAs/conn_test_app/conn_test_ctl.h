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

#include <stdint.h>
#include <stdlib.h>

/* TA valid commands */
#define INVOKE_CMD_ID_1		0xFB45A123
#define INVOKE_CMD_ID_2		0xFC45A123


/* Value parameter checking: Open session caller is sending IN-values */
#define IN_VALUE_A	56
#define IN_VALUE_B	23
#define OUT_VALUE_A	456
#define OUT_VALUE_B	123

/* REceiving a correct vector */
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)
#define IN_KNOWN_VECTOR "\xa8\xd6\x8a\xcd\x41\x3c\x5e\x19\x5d\x5e\xf0\x4e\x1b\x4f\xaa\xf2"	\
			"\x42\x36\x5c\xb4\x50\x19\x67\x55\xe9\x2e\x12\x15\xba\x59\x80\x2a"	\
			"\xaf\xba\xdb\xf2\x56\x4d\xd5\x50\x95\x6a\xbb\x54\xf8\xb1\xc9\x17"	\
			"\x84\x4e\x5f\x36\x19\x5d\x10\x88\xc6\x00\xe0\x7c\xad\xa5\xc0\x80"	\
			"\xed\xe6\x79\xf5\x0b\x3d\xe3\x2c\xf4\x02\x6e\x51\x45\x42\x49\x5c"	\
			"\x54\xb1\x90\x37\x68\x79\x1a\xae\x9e\x36\xf0\x82\xcd\x38\xe9\x41"	\
			"\xad\xa8\x9b\xae\xca\xda\x61\xab\x0d\xd3\x7a\xd5\x36\xbc\xb0\xa0"	\
			"\x94\x62\x71\x59\x48\x36\xe9\x2a\xb5\x51\x73\x01\xd4\x51\x76\xb5"

#define OUT_KNOWN_VECTOR "\x97\xd2\x9a\xc5\xed\xe9\x4c\x0a\x50\x71\xe0\x09\x5e\x61\x02\x12"	\
			 "\x3d\x17\x26\x13\x2f\x9d\xc1\x02\x67\x2a\xb8\x7b\x1c\xec\x18\xab"	\
			 "\xdb\x04\x09\x6c\x21\xd3\xfd\xb1\x29\x74\x2d\x25\x03\x89\x46\x0f"	\
			 "\xe6\x3b\x5f\x79\xc7\x7c\x2f\x91\x2a\x8f\x7d\x4f\x39\xcb\xd7\x58"	\
			 "\x13\x9c\x87\x23\x66\xca\xc3\x5a\x40\xfe\x24\x83\x22\x82\x5a\xdf"	\
			 "\x57\x48\x1d\x92\x83\x2e\x66\x05\x7f\x80\xe0\x89\x64\xbe\x99\x3d"

/* For esthetic reasons the full treatment functionality are collected into single sturct */
#define RAND_BUFFER_SIZE	59875 /* Totaly random size =) */
struct full_fn_params {
	uint8_t in_vector[SIZE_OF_VEC(IN_KNOWN_VECTOR)];
	uint8_t out_vector[SIZE_OF_VEC(OUT_KNOWN_VECTOR)];
	uint8_t rand_buffer[RAND_BUFFER_SIZE];
	uint32_t paramTypes;
};

/* Getting the reversed buffer size (see reverse_buffer -function) */
#define REVERSED_SIZE(non_reversed_size)    \
    ((non_reversed_size > 2) ? non_reversed_size - 2 : non_reversed_size)
