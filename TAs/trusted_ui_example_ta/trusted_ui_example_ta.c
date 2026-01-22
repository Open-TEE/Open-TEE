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

#include "tee_internal_api.h"
#include "tee_tui_api.h"
#include "tee_logging.h"

#include <string.h>

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{

}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
					      void **sessionContext)
{
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	sessionContext = sessionContext;
	paramTypes = paramTypes;
	params = params;

	if (commandID == 1) {
		/* TODO: Use Trusted User Interface API to get input from user */
		uint32_t width;
		uint32_t height;
		uint32_t lastindex;

		TEE_TUIScreenOrientation orientation = TEE_TUI_PORTRAIT;
		TEE_TUIScreenInfo screenInfo;

		TEE_TUIScreenConfiguration screenConf;
		TEE_TUIEntryField entryfields[3];
		TEE_TUIButtonType button;

		char username_buffer[256];
		char password_buffer[256];
		char pincode_buffer[5] = {0, 0, 0, 0, 0};

		TEE_MemFill(&screenInfo, 0, sizeof(screenInfo));

		TEE_MemFill(&screenConf, 0, sizeof(screenConf));
		TEE_MemFill(entryfields, 0, sizeof(entryfields));

		screenConf.screenOrientation = orientation;
		screenConf.label.text = "Please login to ACME Bank";
		screenConf.label.textColor[0] = 255;
		screenConf.label.textColor[1] = 128;
		screenConf.label.textColor[2] = 0;
		screenConf.label.image.source = TEE_TUI_NO_SOURCE;
		screenConf.requestedButtons[TEE_TUI_OK] = true;
		screenConf.requestedButtons[TEE_TUI_CANCEL] = true;

		entryfields[0].label = "Username";
		entryfields[0].mode = TEE_TUI_CLEAR_MODE;
		entryfields[0].buffer = username_buffer;
		entryfields[0].bufferLength = sizeof(username_buffer);

		entryfields[1].label = "Password";
		entryfields[1].mode = TEE_TUI_HIDDEN_MODE;
		entryfields[1].buffer = password_buffer;
		entryfields[1].bufferLength = sizeof(password_buffer);

		entryfields[2].label = "PIN-code";
		entryfields[2].mode = TEE_TUI_TEMPORARY_CLEAR_MODE;
		entryfields[2].buffer = pincode_buffer;
		entryfields[2].bufferLength = sizeof(pincode_buffer);

		TEE_TUICheckTextFormat("hahaateksti", &width, &height, &lastindex);
		OT_LOG(LOG_ERR, "1");
		//TEE_TUIGetScreenInfo(orientation, 4, &screenInfo);
		TEE_TUIInitSession();
		OT_LOG(LOG_ERR, "2");
		TEE_TUIDisplayScreen(&screenConf, false, entryfields, 3, &button);
		OT_LOG(LOG_ERR, "3");
		TEE_TUICloseSession();
		OT_LOG(LOG_ERR, "4");

		OT_LOG(LOG_ERR, "%s", screenInfo.buttonInfo[0].buttonText);
		OT_LOG(LOG_ERR, "USER: %s", username_buffer);
		OT_LOG(LOG_ERR, "PASS: %s", password_buffer);
		pincode_buffer[4] = '\0';
		OT_LOG(LOG_ERR, "PIN:  %s", pincode_buffer);

		uint32_t username_length = strlen(username_buffer);
		uint32_t password_length = strlen(password_buffer);
		uint32_t pincode_length = strlen(pincode_buffer);
		uint32_t buf_size = sizeof(uint32_t) * 3 +
				    username_length +
				    password_length +
				    pincode_length;

		char *return_buf = TEE_Malloc(buf_size, 0);
		if (return_buf == NULL)
			return TEEC_ERROR_GENERIC;

		char *buf_acc = return_buf;

		TEE_MemMove(buf_acc, &username_length, sizeof(uint32_t));
		buf_acc += sizeof(uint32_t);

		TEE_MemMove(buf_acc, &password_length, sizeof(uint32_t));
		buf_acc += sizeof(uint32_t);

		TEE_MemMove(buf_acc, &pincode_length, sizeof(uint32_t));
		buf_acc += sizeof(uint32_t);

		TEE_MemMove(buf_acc, &username_buffer, username_length);
		buf_acc += username_length;

		TEE_MemMove(buf_acc, &password_buffer, password_length);
		buf_acc += password_length;

		TEE_MemMove(buf_acc, &pincode_buffer, pincode_length);
		buf_acc += pincode_length;

		TEE_MemMove(params[2].memref.buffer, return_buf, buf_size);
		params[2].memref.size = buf_size;

		return TEEC_SUCCESS;
	}

	return TEE_SUCCESS;
}
