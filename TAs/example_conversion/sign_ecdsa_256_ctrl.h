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

#ifndef __SIGN_ECDSA_256_CTRL_H__
#define __SIGN_ECDSA_256_CTRL_H__

#include <stdint.h>

const TEEC_UUID uuid = {
     0x12345678, 0x8765, 0x4321, { 'S', 'I', 'G', 'N', 'S', 'I', 'G', 'N'}
};

#define SIGN_ECDSA_256_SIGN 1234

#endif
