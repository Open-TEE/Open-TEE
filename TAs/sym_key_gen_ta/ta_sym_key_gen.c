#include "tee_internal_api.h" /* TA envrionment */
#include "tee_logging.h" /* OpenTEE logging functions */
#include <string.h>

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'S', 'Y', 'M', 'K', 'E', 'Y', '0', '0'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */

#endif

// Command IDs
#define CMD_GENERATE_AES_KEY 0x00000001
#define CMD_RETRIEVE_AES_KEY 0x00000002
#define CMD_ENCRYPT_FILE 0x00000003
#define CMD_DECRYPT_FILE 0x00000004

// Function headers
TEE_Result generate_aes_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result store_aes_key(uint32_t unique_key_identifier, TEE_ObjectHandle key_handle, uint32_t key_size);
TEE_Result retrieve_aes_key(uint32_t unique_key_identifier, void* key_data, size_t* key_data_size);
TEE_Result encrypt_file(uint32_t param_types, TEE_Param params[4]);
TEE_Result decrypt_file(uint32_t param_types, TEE_Param params[4]);

#ifndef TEE_HANDLE_NULL
#define TEE_HANDLE_NULL 0
#endif


TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	/* No functionality */

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");

	/* No functionality */
}



TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sessionContext) 
{
	OT_LOG(LOG_ERR, "Calling the Open session entry point");

    return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Close session entry point");

	TEE_FreeOperation(sessionContext);
}




TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID, uint32_t param_types, TEE_Param params[4]) {
    switch (commandID) {
        case CMD_GENERATE_AES_KEY:
            return generate_aes_key(param_types, params);
        case CMD_RETRIEVE_AES_KEY:
            return retrieve_aes_key(params[0].value.a, params[1].memref.buffer, &params[1].memref.size);
        case CMD_ENCRYPT_FILE:
            return encrypt_file(param_types, params); 
        case CMD_DECRYPT_FILE:
            return decrypt_file(param_types, params); 
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}







TEE_Result generate_aes_key(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    uint32_t key_size;
    uint32_t unique_key_identifier;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_size = params[0].value.a; // Key size in bits (e.g., 128, 192, 256)
    unique_key_identifier = params[1].value.a; // Unique key identifier (e.g., 1234)

    if (key_size != 128 && key_size != 192 && key_size != 256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key_handle);
    if (res != TEE_SUCCESS) return res;

    res = TEE_GenerateKey(key_handle, key_size, NULL, 0);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(key_handle);
        return res;
    }

    // Send the key to the CA (unsecure - used for validation only)
    //res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_SECRET_VALUE, params[2].memref.buffer, &params[2].memref.size);

    // Call store_aes_key to store the key with the identifier
    if (res == TEE_SUCCESS) {
        //res = store_aes_key(unique_key_identifier, params[2].memref.buffer, params[2].memref.size); // Used when you want to send key to CA
        res = store_aes_key(unique_key_identifier, key_handle, key_size);
    }

    TEE_FreeTransientObject(key_handle);

    return res;
}




TEE_Result store_aes_key(uint32_t unique_key_identifier, TEE_ObjectHandle key_handle, uint32_t key_size) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    uint32_t object_id = unique_key_identifier; // Unique identifier for the key
    uint32_t storage_id = TEE_STORAGE_PRIVATE;
    uint8_t key_data[key_size]; 
    size_t key_data_size = sizeof(key_data);

    // Create or open a persistent object for the key
    res = TEE_CreatePersistentObject(storage_id, &object_id, sizeof(object_id),
                                     TEE_DATA_FLAG_ACCESS_WRITE,
                                     TEE_HANDLE_NULL, NULL, 0, &object);
    if (res != TEE_SUCCESS) return res;

    // Extract key data from key_handle
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_SECRET_VALUE, key_data, &key_data_size);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(key_handle);
        return res;
    }

    // Write the key data to the object
    res = TEE_WriteObjectData(object, key_data, key_data_size);

    TEE_CloseObject(object);
    return res;
}



// Function to retrieve the AES key 
TEE_Result retrieve_aes_key(uint32_t unique_key_identifier, void* key_data, size_t* key_data_size) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    uint32_t storage_id = TEE_STORAGE_PRIVATE;
    uint32_t object_id = unique_key_identifier;

    res = TEE_OpenPersistentObject(storage_id, &object_id, sizeof(object_id), TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) return res;

    /* 
        Read the content of the 'object' (the content is the key) into a buffer (key_data)   
    */
    res = TEE_ReadObjectData(object, key_data, *key_data_size, key_data_size);
    if (res != TEE_SUCCESS) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    TEE_CloseObject(object);
    return res;
}








TEE_Result encrypt_file(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    void* data = params[1].memref.buffer;
    size_t data_size = params[1].memref.size;
    void* encrypted_data = params[2].memref.buffer;
    size_t encrypted_data_size = params[2].memref.size;

    // Define buffer for AES key and size variable
    uint8_t key_data[32]; // Buffer for AES-256 key (256 bits = 32 bytes) --> this is 'hardcoded', there should be an option for other key sizes 
    size_t key_data_size = sizeof(key_data); // Size of the key buffer

    // Retrieve the AES key --> this gives the actual key 
    res = retrieve_aes_key(unique_key_identifier, &key_data, &key_data_size);
    if (res != TEE_SUCCESS) return res;

    // Create a transient object to hold the key
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_data_size * 8, &key_handle);
    if (res != TEE_SUCCESS) return res;

    // Load the key data into the transient object
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_data, key_data_size);
    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS) return res;

    // Prepare the operation
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, key_data_size * 8);
    if (res != TEE_SUCCESS) return res;

    // Set the operation key
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS) return res;

    uint8_t IV[16];
    size_t IV_len = 16;

    // IV
    // INitialized to 0 for simplicity, highly unsecure
    memset(&IV, 0, sizeof(IV));

    TEE_CipherInit(op, IV, IV_len);

    // Check buffer size and handle TEE_ERROR_SHORT_BUFFER if necessary
    res = TEE_CipherDoFinal(op, data, data_size, encrypted_data, &encrypted_data_size);
    if (res != TEE_SUCCESS) {
        if (res == TEE_ERROR_SHORT_BUFFER) {
            // Handle the case where the provided buffer is not large enough (I have not handled it)
        }
        return res;
    }

    TEE_FreeOperation(op);
    TEE_FreeTransientObject(key_handle);

    return res;
}




TEE_Result decrypt_file(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    void* data = params[1].memref.buffer;
    size_t data_size = params[1].memref.size;
    void* encrypted_data = params[2].memref.buffer;
    size_t encrypted_data_size = params[2].memref.size;

    // Define buffer for AES key and size variable
    uint8_t key_data[32]; // Buffer for AES-256 key (256 bits = 32 bytes)
    size_t key_data_size = sizeof(key_data); // Size of the key buffer

    // Retrieve the AES key
    res = retrieve_aes_key(unique_key_identifier, &key_data, &key_data_size);
    if (res != TEE_SUCCESS) return res;

    // Create a transient object to hold the key
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_data_size * 8, &key_handle);
    if (res != TEE_SUCCESS) return res;

    // Load the key data into the transient object
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_data, key_data_size);
    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS) return res;

    // Prepare the operation
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, key_data_size * 8);
    if (res != TEE_SUCCESS) return res;

    // Set the operation key
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS) return res;

    uint8_t IV[16];
    memset(&IV, 0, sizeof(IV));
    size_t IV_len = 16;

    TEE_CipherInit(op, IV, IV_len);

    // Check buffer size and handle TEE_ERROR_SHORT_BUFFER if necessary
    res = TEE_CipherDoFinal(op, data, data_size, encrypted_data, &encrypted_data_size);
    if (res != TEE_SUCCESS) {
        if (res == TEE_ERROR_SHORT_BUFFER) {
            // Handle the case where the provided buffer is not large enough (I have not handled it)
        }
        return res;
    }

    TEE_FreeOperation(op);
    TEE_FreeTransientObject(key_handle);

    return res;
}