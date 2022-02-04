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

#ifndef __PRINT_FUNCTIONS_H__
#define __PRINT_FUNCTIONS_H__

/* Start Open-TEE spesifics. NOT GP Compliant. For debugin sake */
#include "tee_logging.h"

#define PRI_STR(str)        OT_LOG1(LOG_DEBUG, str);
#define PRI(str, ...)       OT_LOG1(LOG_DEBUG, "%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    OT_LOG1(LOG_DEBUG, " [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   OT_LOG1(LOG_DEBUG, " YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  OT_LOG1(LOG_DEBUG, "FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) OT_LOG1(LOG_DEBUG, "ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);
/* End Open-TEE spesifics */

#endif
