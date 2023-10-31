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

var g_port = null;
var g_mode = null;
var g_reply = null;
var g_replymode = null;

var mode_enum = Object.freeze( {
  "NOT_CONNECTED" : 0,
  "CONNECTED" : 1,
  "DECRYPT" : 2,
  "TEST" : 3,
  "ENCRYPT" : 4,
  "ADDKEY" : 5
})

function utf8_to_b64(str) {
    return window.btoa(unescape(encodeURIComponent(str)));
}

function b64_to_utf8(str) {
    return decodeURIComponent(escape(window.atob(str)));
}

function showMessage(text) {
  document.getElementById('mode-specific-msg').innerHTML = "<p>" + text + "</p>" + "<hr>";;
}

function appendMessage(text) {
  var responsebox = document.getElementById('responsebox');
  responsebox.innerHTML += text + "\n";
  responsebox.scrollTop = responsebox.scrollHeight;
}

function displayResponse(text) {
  document.getElementById('mode-specific-outputbox').innerHTML = text;
}

function updateUiState() {
  var HIDE = 'none';
  var SHOW = 'block';

  //variables to control the visibility of different elements
  var show_connect = HIDE;
  var show_button_send = HIDE;
  var show_button_decrypt = HIDE;
  var show_button_encrypt = HIDE;
  var show_button_addkey = HIDE;
  var show_button_test = HIDE;
  var show_response = HIDE;
  var show_mode_specific = SHOW;
  var show_mode_specific_input = HIDE;
  var show_mode_specific_inputbox = HIDE;
  var show_mode_specific_output = HIDE;

  switch (g_mode) {
    case "NOT_CONNECTED":
      show_connect = SHOW;
      show_button_send = HIDE;
      show_button_decrypt = HIDE;
      show_button_encrypt = HIDE;
      show_button_addkey = HIDE;
      show_button_test = HIDE;
      show_response = HIDE;
      show_mode_specific = SHOW;
      show_mode_specific_input = HIDE;
      show_mode_specific_inputbox = HIDE;
      show_mode_specific_output = HIDE;
      showMessage("Please connect to TEE");
      break;
    case "CONNECTED":
      show_connect = HIDE;
      show_button_send = HIDE;
      show_button_decrypt = SHOW;
      show_button_encrypt = SHOW;
      show_button_addkey = SHOW;
      show_button_test = SHOW;
      show_response = SHOW;
      show_mode_specific = SHOW;
      show_mode_specific_input = HIDE;
      show_mode_specific_inputbox = HIDE;
      show_mode_specific_output = HIDE;
      showMessage("You are connected, please select mode");
      break;
    case "DECRYPT":
      show_connect = HIDE;
      show_button_send = SHOW;
      show_button_decrypt = SHOW;
      show_button_encrypt = SHOW;
      show_button_addkey = SHOW;
      show_button_test = SHOW;
      show_response = SHOW;
      show_mode_specific = SHOW;
      show_mode_specific_input = SHOW;
      show_mode_specific_inputbox = SHOW;
      show_mode_specific_output = SHOW;
      showMessage("You are connected, DECRYPT mode");
      break;
    case "TEST":
      show_connect = HIDE;
      show_button_send = SHOW;
      show_button_decrypt = SHOW;
      show_button_encrypt = SHOW;
      show_button_addkey = SHOW;
      show_button_test = SHOW;
      show_response = SHOW;
      show_mode_specific = SHOW;
      show_mode_specific_input = SHOW;
      show_mode_specific_inputbox = HIDE;
      show_mode_specific_output = HIDE;
      showMessage("You are connected, TEST mode");
      break;
    case "ENCRYPT":
      show_connect = HIDE;
      show_button_send = SHOW;
      show_button_decrypt = SHOW;
      show_button_encrypt = SHOW;
      show_button_addkey = SHOW;
      show_button_test = SHOW;
      show_response = SHOW;
      show_mode_specific = SHOW;
      show_mode_specific_input = SHOW;
      show_mode_specific_inputbox = SHOW;
      show_mode_specific_output = SHOW;
      showMessage("You are connected, ENCRYPT mode");
      break;
    case "ADDKEY":
      show_connect = HIDE;
      show_button_send = SHOW;
      show_button_decrypt = SHOW;
      show_button_encrypt = SHOW;
      show_button_addkey = SHOW;
      show_button_test = SHOW;
      show_response = SHOW;
      show_mode_specific = SHOW;
      show_mode_specific_input = SHOW;
      show_mode_specific_inputbox = HIDE;
      show_mode_specific_output = HIDE;
      showMessage("You are connected, ADDKEY mode");
      break;
    default:
      console.log("something went boogers up");
      break;
  }

  document.getElementById('connect-button').style.display = show_connect;
  document.getElementById('send-message-button').style.display = show_button_send;
  document.getElementById('mode-select-decrypt').style.display = show_button_decrypt;
  document.getElementById('mode-select-test').style.display = show_button_test;
  document.getElementById('mode-select-encrypt').style.display = show_button_encrypt;
  document.getElementById('mode-select-addkey').style.display = show_button_addkey;
  document.getElementById('response').style.display = show_response;
  document.getElementById('mode-specific-msg').style.display = show_mode_specific;
  document.getElementById('mode-specific-input').style.display = show_mode_specific_input;
  document.getElementById('mode-specific-inputbox').style.display = show_mode_specific_inputbox;
  document.getElementById('mode-specific-output').style.display = show_mode_specific_output;
}

//this function passes the message to the parser which passes it to appropriate crypto function
//which in turn passes it to the CA
function sendNativeMessage(message) {
  //make this do the right stuff babes
  //TODO check that message is json object
  if (message !== null)
  {
      g_port.postMessage(message);
      appendMessage("Sent message: " + JSON.stringify(message));
  }
}

function nativeMessageSendHandler() {
  sendNativeMessage(nativeMessageConstructor());
}

function nativeMessageConstructor() {
  var json = null;
  //create the json to be sent and return that
  switch (g_mode) {
    case "NOT_CONNECTED":
      //error
      break;
    case "CONNECTED":
      //error
      //button should not be visible here
      break;
    case "DECRYPT":
      var payload = document.getElementById('mode-specific-inputbox').value;
      var key = document.getElementById('mode-specific-input').value;
      json = {"text":"decrypt", "key":key, "payload":payload};
      break;
    case "TEST":
      var input = document.getElementById('mode-specific-input').value;
      json = {"text":input};
      break;
    case "ENCRYPT":
      var payload = document.getElementById('mode-specific-inputbox').value;
      var key = document.getElementById('mode-specific-input').value;
      json = {"text":"encrypt", "key":key, "payload":utf8_to_b64(payload)};
      break;
    case "ADDKEY":
      var key = document.getElementById('mode-specific-input').value;
      json = {"text":"addkey", "key":key};
      break;
  }
  return json;
}

function connect() {
  var hostname = "com.intel.chrome.opentee.proxy";
  appendMessage("Connecting to native messaging host " + hostname);
  var ret = tee_connect(hostname);

  if (ret){
    g_mode = "CONNECTED";
    appendMessage("CONNECTED to native messaging host " + hostname);
  }
  updateUiState();
}

function loadScript(name) {
  var script = document.createElement('script');
  script.setAttribute("type","text/javascript");
  //script.setAttribute("src",name);
  script.src = chrome.extension.getURL(name);
  document.head.appendChild(script);
  //document.getElementsByTagName("head")[0].appendChild( script );
}

function content_decrypt(msg)
{
  var json = null;

  json = {"text":"decrypt", "key":"demo", "payload":msg};
  sendNativeMessage(json);
}

function content_encrypt(msg)
{
  var json = null;
  json = {"text":"encrypt", "key":"demo", "payload":msg};
  sendNativeMessage(json);
}

document.addEventListener('DOMContentLoaded', function () {
  //load libs
  //loadScript("tee_crypto.js");
  //loadScript("tee_eventhandler.js");
  //loadScript("tee_messaging.js");

  document.getElementById('connect-button').addEventListener(
    'click', connect);
  document.getElementById('send-message-button').addEventListener(
    'click', nativeMessageSendHandler);
  document.getElementById('mode-select-decrypt').addEventListener(
    'click', onDecryptMode);
  document.getElementById('mode-select-test').addEventListener(
    'click', onTestMode);
  document.getElementById('mode-select-encrypt').addEventListener(
    'click', onEncryptMode);
  document.getElementById('mode-select-addkey').addEventListener(
    'click', onAddkeyMode);

  g_mode = "NOT_CONNECTED";
  updateUiState();

  chrome.runtime.onConnectExternal.addListener( function(port) {
    console.assert(port.name == "opentee_dec");
    port.onMessage.addListener(function(request) {
      if (request.datain) {
        console.log(request.datain);
        if(!g_port)
        {
            //TODO: post a message
            return;
        }
        var data = request.datain;

        g_reply = port;
        g_replymode = "DECRYPT";
        content_decrypt(data);
      }
      if (request.datatocrypt) {
        console.log(request.datatocrypt);
        g_reply = port;
        g_replymode = "ENCRYPT";
        content_encrypt(request.datatocrypt);
      }
  });});
});
