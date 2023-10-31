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
//parses json received from CA

function onNativeMessage(msg) {
  appendMessage("Received message: " + JSON.stringify(msg));
  tee_parse_json(msg);
}

function onDisconnected() {
  appendMessage("Failed to connect: " + chrome.runtime.lastError.message);
  tee_disconnect();
  g_mode = "NOT_CONNECTED";
  updateUiState;
}

function onTestMode() {
  g_mode = "TEST";
  updateUiState();
}

function onDecryptMode() {
  g_mode = "DECRYPT";
  updateUiState();
}

function onEncryptMode() {
  g_mode = "ENCRYPT";
  updateUiState();
}

function onAddkeyMode() {
  g_mode = "ADDKEY";
  updateUiState();
}
