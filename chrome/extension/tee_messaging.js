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

function tee_parse_json(msg) {
  //check the mode we are on and do stuff based on that
  if (msg.text === "error") {
    console.log("there was an error");
    return;
  }

  console.log("parsing json");
  console.log(JSON.stringify(msg));

  //check if we are processing a request from extension
  if(g_reply)
  {
    console.log(msg.payload);
    var tmp = null;

    tmp = msg.payload;

    g_reply.postMessage({dataout:tmp});
    g_reply.disconnect();
    g_reply = null;
    g_replymode = null;
    return;
  }

  switch (g_mode) {
    case "NOT_CONNECTED":
      //do nothing
      break;
    case "CONNECTED":
      //do nothing
      break;
    case "DECRYPT":
      //update the output with payload
      displayResponse(window.atob(msg.payload));
      break;
    case "ENCRYPT":
      //update the output with payload
      displayResponse(msg.payload);
      break;
    case "TEST":
      //do nothing
      break;
    case "ADDKEY":
      //do noTYHINTHINTHgh
      break;
  }
}
