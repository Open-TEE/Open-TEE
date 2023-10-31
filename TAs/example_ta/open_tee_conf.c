/*****************************************************************************
** Copyright (C) <YOUR OWN COPYRIGHT>                                       **
**                                                                          **
**  Apache and open source would be nice :)                                 **
*****************************************************************************/

#ifdef TA_PLUGIN

/* This is the required functionality to enable running the TA in OpenTee.  Make sure to update
   the UUID to your own unique ID. */
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
    { 0x01020304, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 } }, 512, 255, 1,
    1, 1)
#endif
