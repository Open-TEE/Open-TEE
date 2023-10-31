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
function utf8_to_b64(str) {
    return window.btoa(unescape(encodeURIComponent(str)));
}

function b64_to_utf8(str) {
    return decodeURIComponent(escape(window.atob(str)));
}

function encrypt(id) {
  console.log('encrypting content(' + id + ')->');

  var element = document.getElementById(id);
  console.log(element.innerText);
  console.log(element.textContent);
  console.log(utf8_to_b64(element.textContent));

  var port = chrome.runtime.connect("knldjmfmopnpolahpmmgbagdohdnhkik",{name: "opentee_dec"});
  //TODO: base64 the message first
  port.postMessage({datatocrypt:window.btoa((element.innerText))});
  port.onMessage.addListener(function(response) {
    console.log('encrypting content(' + id + ')<-');
    if (response.dataout) {
      console.log(response.dataout);
      element.textContent="crypted_stuff " + response.dataout + "-";
      element.style.visibility = 'visible';
    }
  });
};

function decrypt(id) {
  console.log('showing content(' + id + ')->');

  var element = document.getElementById(id);
  //console.log(element.textContent);
  var datatodecrypt = element.textContent.split('-')[0];
  // Make a simple request:
  var port = chrome.runtime.connect("knldjmfmopnpolahpmmgbagdohdnhkik",{name: "opentee_dec"});
  port.postMessage({datain:datatodecrypt});
  port.onMessage.addListener(function(response) {
    console.log('showing content(' + id + ')<-');
    if (response.dataout) {
      console.log(response.dataout);
      element.innerText=window.atob(response.dataout);
      element.style.visibility = 'visible';
    }
  });
};
