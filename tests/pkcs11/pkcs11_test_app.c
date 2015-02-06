/*****************************************************************************
** Copyright (C) 2015 Brian McGillion                                       **
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

#include <cryptoki.h>
#include <stdlib.h>
#include <stdio.h>

static CK_FUNCTION_LIST_PTR func_list;

int main()
{
	CK_RV ret;
	CK_INFO info;

	ret = C_GetFunctionList(&func_list);
	if (ret != CKR_OK || func_list == NULL) {
		printf("Failed to get function list: %d\n", ret);
		exit(1);
	}

	ret = func_list->C_Initialize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to initialize the library: %d\n", ret);
		exit(2);
	}

	ret = C_GetInfo(&info);
	if (ret != CKR_OK) {
		printf("Failed to get the library info: %d\n", ret);
		exit(3);
	}

	printf("Version : Major %d: Minor %d\n",
	       info.cryptokiVersion.major, info.cryptokiVersion.minor);

	ret = func_list->C_Finalize(NULL);
	if (ret != CKR_OK) {
		printf("Failed to Finalize the library: %d\n", ret);
		exit(4);
	}

	return 0;
}
