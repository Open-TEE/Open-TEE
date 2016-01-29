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

#include "compat.h"

int TEE_StrLen(const char *s)
{
	int i = 0;

	while (1) {
		if (*(s++) != '\0')
			i++;
		else
			break;
	}

	return i;
}
