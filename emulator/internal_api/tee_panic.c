/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
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

#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>


#include "tee_panic.h"
#include "tee_logging.h"

void TEE_Panic(TEE_Result panicCode)
{
	void* callstack[128];
	int i, frames = backtrace(callstack, 128);
	char** strs = backtrace_symbols(callstack, frames);

	printf("P A N I C !\n");

	OT_LOG_ERR("TEE_Panic: TA panicked with [%u] panicode\n", panicCode);
	OT_LOG_ERR("TEE_Panic: Stacktrace START\n");

	for (i = 0; i < frames; ++i) {
		OT_LOG_ERR("TEE_Panic: %s\n", strs[i]);
	}
	free(strs);

	OT_LOG_ERR("TEE_Panic: Stacktrace END\n");
	
	exit(panicCode);
}
