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

//WIP
//connects to tee and offers fancy services
var g_port = null;
//Connects to an application through the messaging service
//This requires the CA to be registered with chrome
function tee_connect(hostname) {
  g_port = chrome.runtime.connectNative(hostname);
  g_port.onDisconnect.addListener(onDisconnected);
  g_port.onMessage.addListener(onNativeMessage);

  if(g_port) {
    return true;
  }
  else {
    return false;
  }
}

function tee_status() {
  return g_port ? true : false;
}

//takes command and parameters to send to tee
//makes json and sends to port
function tee_send_msg(param) {

}

function tee_generate_keypair(param) {

}

function tee_encrypt(param) {
}

function tee_decrypt(param) {

}

function tee_save_public_key(param) {

}

function tee_get_public_key(param) {

}

function tee_disconnect(param) {

}
