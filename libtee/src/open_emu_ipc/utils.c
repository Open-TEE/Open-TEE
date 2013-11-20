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

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <crypt.h>
#include <uuid/uuid.h>
#include <string.h>

int generate_random_path(char **path)
{
	time_t time_val;
	const char *str_time;
	uuid_t uuid;
	char salt[20];
	char *raw_rand, *tmp;

	time_val = time(NULL);
	str_time = ctime(&time_val);
	uuid_generate(uuid);

	memcpy(salt, "$5$", 3);
	memcpy(salt + 3, uuid, sizeof(uuid));
	salt[19] = '$';

	raw_rand = strrchr(crypt(str_time, salt), '$');

	/* shm_open does not like to have path seperators '/' in teh name so remove them */
	tmp = raw_rand;
	while (*tmp) {
		if (*tmp == '/')
			*tmp = '_';
		tmp++;
	}

	*path = malloc(strlen(raw_rand) + 1);
	if (!*path)
		return -1;

	memcpy(*path, raw_rand, strlen(raw_rand) + 1);
	*(path[0]) = '/';

	return 0;
}
