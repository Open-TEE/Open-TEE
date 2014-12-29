/*****************************************************************************
** Copyright (C) 2014 Mika Tammi                                            **
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

#ifdef TA_PLUGIN

#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
	{ 0xC8316964, 0x986B, 0x837F, { 0xC3, 0x9A, 0xED, 0xF8, 0x2C, 0xD3, 0x9E, 0x63 } },
	  4096, /* dataSize */
	  512,  /* stackSize */
	  0,    /* singletonInstance */
	  0,    /* multiSession */
	  0)    /* instanceKeepAlive */

#endif
