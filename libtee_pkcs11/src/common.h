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

#ifndef __COMMON_H_
#define __COMMON_H_

#include "cryptoki.h"

extern void *g_tee_context;

/* Following four macros are defined for function default parameter functionality. Idea is to
 * declare struct which will be containing default function parameters and have a middle function
 * which will be filling default values. See command.h file, how this should be used */
/* Defining a couple of constant for SHM functions */
#define	LINK_NAME_PREFIX(x) link_fn_##x
#define LINK_FN(name, args, ...) LINK_NAME_PREFIX(name)((LINK_NAME_PREFIX(args)) {__VA_ARGS__})
#define FN_SHM_HEAD(type, name, args) type LINK_NAME_PREFIX(name)(LINK_NAME_PREFIX(args) in)
#define FN_SHM_ARGS(name, ...) typedef struct { __VA_ARGS__ } LINK_NAME_PREFIX(name);
#define FN_SHM_ARG(name, value) name = in.name ? in.name : (value)
#define LINK_SHM_FN(type, fn, args)\
  FN_SHM_HEAD(type, fn, args) {\
  void *FN_SHM_ARG(ptr_1, NULL_PTR);\
  void *FN_SHM_ARG(ptr_2, NULL_PTR);\
  void *FN_SHM_ARG(ptr_3, NULL_PTR);\
  void *FN_SHM_ARG(ptr_4, NULL_PTR);\
  \
  return fn(ptr_1, ptr_2, ptr_3, ptr_4);\
  }
/* A couple of constant value */
#define SHM_PARAMS_NAME		shm_params
#define SHM_FN_RV_TYPE		CK_RV
#define SHM_LIB_REG_FN		lib_shm_register
#define SHM_LIB_FREE_FN		lib_shm_release
/* Parameters struct declaration and functions headers */
FN_SHM_ARGS(SHM_PARAMS_NAME, void *ptr_1; void *ptr_2; void *ptr_3; void *ptr_4;)
FN_SHM_HEAD(SHM_FN_RV_TYPE, SHM_LIB_REG_FN, SHM_PARAMS_NAME);
FN_SHM_HEAD(SHM_FN_RV_TYPE, SHM_LIB_FREE_FN, SHM_PARAMS_NAME);


/* Caller should use following macros */

/*!
  \def register_shm(...)
  This function will register up to four shared memory region. In parameters are pointers to
  TEEC_SharedMemory structs and function will return CK_RV value. Example:
  rv = register_shm(&shm_1);
  rv = register_shm(&shm_1, &shm_2);
*/
#define register_shm(...) LINK_FN(SHM_LIB_REG_FN, SHM_PARAMS_NAME, __VA_ARGS__)

/*!
  \def release_shm(...)
  See register_shm(...). This will do the same, but is releasing the registers
*/
#define release_shm(...) LINK_FN(SHM_LIB_FREE_FN, SHM_PARAMS_NAME, __VA_ARGS__)

#endif /* __COMMON_H_ */
