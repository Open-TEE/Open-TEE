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
#define CMD_GENERATE_AES_KEY    0x00000001
#define CMD_RETRIEVE_AES_KEY    0x00000002
#define CMD_ENCRYPT_FILE        0x00000003
#define CMD_DECRYPT_FILE        0x00000004
#define CMD_ENCRYPT_HASH        0x00000005
#define CMD_DECRYPT_VERIFY      0x00000006
#define CMD_ENCRYPT_AES_GCM     0x00000007
#define CMD_DECRYPT_AES_GCM     0x00000008

// Function headers
TEE_Result generate_aes_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result store_aes_key(uint32_t unique_key_identifier, TEE_ObjectHandle key_handle, uint32_t key_size);
TEE_Result retrieve_aes_key(uint32_t unique_key_identifier, void* key_data, size_t* key_data_size);
TEE_Result encrypt_file(uint32_t param_types, TEE_Param params[4]);
TEE_Result decrypt_file(uint32_t param_types, TEE_Param params[4]);
TEE_Result encryption_with_hash(uint32_t param_types, TEE_Param params[4]);
TEE_Result decryption_with_verify(uint32_t param_types, TEE_Param params[4]);
TEE_Result encrypt_file_aes_gcm(uint32_t param_types, TEE_Param params[4]);
TEE_Result decrypt_file_aes_gcm(uint32_t param_types, TEE_Param params[4]);


#ifndef TEE_HANDLE_NULL
#define TEE_HANDLE_NULL 0
#endif

#define SHA256_HASH_SIZE 32


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
        case CMD_ENCRYPT_HASH:
            return encryption_with_hash(param_types, params);
        case CMD_DECRYPT_VERIFY:
            return decryption_with_verify(param_types, params);
        case CMD_ENCRYPT_AES_GCM:
            return encrypt_file_aes_gcm(param_types, params);
        case CMD_DECRYPT_AES_GCM:
            return decrypt_file_aes_gcm(param_types, params);
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

    // Retrieve the AES key --> this gives the actual key not object
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
    // Initialized to 0 for simplicity, highly unsecure
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




TEE_Result generate_hash(void* data, size_t data_size, void* hash, size_t* hash_size) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) return res;

    TEE_DigestUpdate(op, data, data_size);

    res = TEE_DigestDoFinal(op, NULL, 0, hash, hash_size);

    TEE_FreeOperation(op);
    return res;
}



TEE_Result verify_hash(void* data, size_t data_size, void* hash_to_verify, size_t hash_size) {
    TEE_Result res;
    uint8_t computed_hash[SHA256_HASH_SIZE];
    size_t computed_hash_size = SHA256_HASH_SIZE;

    res = generate_hash(data, data_size, computed_hash, &computed_hash_size);
    if (res != TEE_SUCCESS) return res;

    if (hash_size != computed_hash_size || memcmp(computed_hash, hash_to_verify, SHA256_HASH_SIZE) != 0) {
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}



TEE_Result encryption_with_hash(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    uint32_t second_unique_key_identifier = params[0].value.b;
    void* data = params[1].memref.buffer;
    size_t data_size = params[1].memref.size;
    void* enc_hash_enc = params[2].memref.buffer;
    size_t enc_hash_enc_data_size = params[2].memref.size;

    /* Generate hash of 'data' */
    uint8_t hash[SHA256_HASH_SIZE]; // hash array to store hash
    size_t hash_size = SHA256_HASH_SIZE;

    res = generate_hash(data, data_size, hash, &hash_size);
    if (res != TEE_SUCCESS) return res;



    /* Encrypt 'data' using encrypt_file function */

    // Buffer to store encrypted data (ensure it's large enough)
    size_t MAX_ENCRYPTED_DATA_SIZE = data_size;
    uint8_t encrypted_data[MAX_ENCRYPTED_DATA_SIZE]; 
    size_t encrypted_data_size = sizeof(encrypted_data);

    // Prepare parameters for encrypt_file function
    TEE_Param encrypt_params[4];
    encrypt_params[0].value.a = unique_key_identifier;
    encrypt_params[1].memref.buffer = data;
    encrypt_params[1].memref.size = data_size;
    encrypt_params[2].memref.buffer = encrypted_data;
    encrypt_params[2].memref.size = encrypted_data_size;

    // Call encrypt_file function
    res = encrypt_file(TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE),
                       encrypt_params);
    if (res != TEE_SUCCESS) return res;



    /* Append hash to encrypted_data (append to the end) */

    // Create a new buffer to hold both encrypted data and hash
    size_t total_size = encrypted_data_size + hash_size;
    uint8_t* combined_data = TEE_Malloc(total_size, 0);
    // Optional: Set the allocated memory to zero
    TEE_MemFill(combined_data, 0, total_size);
    if (!combined_data) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // Copy encrypted data to combined_data
    TEE_MemMove(combined_data, encrypted_data, encrypted_data_size);

    // Append hash to the end of combined_data
    TEE_MemMove(combined_data + encrypted_data_size, hash, hash_size); // combined_data + ecnrypted_data_size is the starting position after which the hash will be appended

    // Now, combined_data contains the encrypted data followed by the hash
    



    /* Encrypt combined_data using encrypt_file function */

    // Ensure the enc_hash_enc buffer is large enough
    if (total_size > enc_hash_enc_data_size) {
        TEE_Free(combined_data);
        return TEE_ERROR_SHORT_BUFFER;
    }
    

    // Reuse encrypt_params to encrypt combined_data
    encrypt_params[0].value.a = second_unique_key_identifier;
    encrypt_params[1].memref.buffer = combined_data;
    encrypt_params[1].memref.size = total_size;
    encrypt_params[2].memref.buffer = enc_hash_enc;  // Use the provided buffer for output
    encrypt_params[2].memref.size = enc_hash_enc_data_size;  // Use the size of the provided output buffer

    // Call encrypt_file function to encrypt combined_data
    res = encrypt_file(TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                    TEE_PARAM_TYPE_MEMREF_INPUT,
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                    TEE_PARAM_TYPE_NONE),
                    encrypt_params);
    if (res != TEE_SUCCESS) {
        TEE_Free(combined_data);
        return res;
    }

    // Clean up
    TEE_Free(combined_data);

    return TEE_SUCCESS;

}



TEE_Result decryption_with_verify(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    uint32_t second_unique_key_identifier = params[0].value.b;
    void* data = params[1].memref.buffer;
    size_t data_size = params[1].memref.size;
    void* output_data = params[2].memref.buffer;
    size_t output_data_size = params[2].memref.size;



    // Buffer to store first decrypted data
    size_t MAX_DECRYPTED_DATA_SIZE = data_size;
    uint8_t decrypted_data[MAX_DECRYPTED_DATA_SIZE];
    size_t decrypted_data_size = sizeof(decrypted_data);
    
    // Prepare parameters for decrypt_file function
    TEE_Param decrypt_params[4];
    decrypt_params[0].value.a = second_unique_key_identifier;
    decrypt_params[1].memref.buffer = data;
    decrypt_params[1].memref.size = data_size;
    decrypt_params[2].memref.buffer = decrypted_data;
    decrypt_params[2].memref.size = decrypted_data_size;
    
    /* First decryption with the second key */
    res = decrypt_file(TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE),
                      decrypt_params);
    if (res != TEE_SUCCESS) return res;
    



    /* Extract the hash from the end of the decrypted data */ 
    if (decrypted_data_size < SHA256_HASH_SIZE) {
        return TEE_ERROR_SECURITY;
    }
    uint8_t extracted_hash[SHA256_HASH_SIZE];
    TEE_MemMove(extracted_hash, decrypted_data + decrypted_data_size - SHA256_HASH_SIZE, SHA256_HASH_SIZE);



    
    /* Remove hash from decrypted data to get the original encrypted data (the ciphertext) */ 
    size_t original_encrypted_data_size = decrypted_data_size - SHA256_HASH_SIZE;
    uint8_t* original_encrypted_data = TEE_Malloc(original_encrypted_data_size, 0);
    if (!original_encrypted_data) {
        // Handle memory allocation error
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(original_encrypted_data, decrypted_data, original_encrypted_data_size);



    /* Second decryption with the first key to get the plaintext */
    decrypt_params[0].value.a = unique_key_identifier;
    decrypt_params[1].memref.buffer = original_encrypted_data;
    decrypt_params[1].memref.size = original_encrypted_data_size;
    decrypt_params[2].memref.buffer = output_data;  // Use the provided buffer for output
    decrypt_params[2].memref.size = output_data_size;  // Use the size of the provided output buffer
    res = decrypt_file(TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE),
                      decrypt_params);
    if (res != TEE_SUCCESS) {
        TEE_Free(original_encrypted_data);
        return res;
    }
    


    /* Verification */

    // Generate hash of the decrypted message
    uint8_t generated_hash[SHA256_HASH_SIZE];
    size_t generated_hash_size = SHA256_HASH_SIZE;
    res = generate_hash(output_data, output_data_size, generated_hash, &generated_hash_size);
    if (res != TEE_SUCCESS) {
        TEE_Free(original_encrypted_data);
        return res;
    }
    
    // Compare the extracted hash with the generated hash
    res = verify_hash(output_data, output_data_size, extracted_hash, SHA256_HASH_SIZE);
    if (res != TEE_SUCCESS) {
        // Hash verification failed
        TEE_Free(original_encrypted_data);
        return TEE_ERROR_SECURITY;
    }

    // Clean-up
    TEE_Free(original_encrypted_data);

    return TEE_SUCCESS;
}









TEE_Result encrypt_file_aes_gcm(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    void* data = params[1].memref.buffer;
    size_t data_size = params[1].memref.size;
    void* encrypted_data = params[2].memref.buffer;
    size_t encrypted_data_size = params[2].memref.size;
    uint32_t tag_len = 16; // Length of the GCM tag in bytes
    uint8_t tag[tag_len];

    // Define buffer for AES key and size variable
    uint8_t key_data[32]; // Buffer for AES-256 key
    size_t key_data_size = sizeof(key_data);

    // Retrieve the AES key
    res = retrieve_aes_key(unique_key_identifier, key_data, &key_data_size);
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

    // Prepare the operation for AES-GCM
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, key_data_size * 8);
    if (res != TEE_SUCCESS) return res;
    
    // Set the operation key
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS) return res;
    
    // Generate and set the IV/nonce
    uint8_t iv[12]; // 12 bytes IV for GCM
    TEE_GenerateRandom(iv, sizeof(iv)); // Randomly generate IV

    // Initialize the AE operation
    res = TEE_AEInit(op, iv, sizeof(iv), tag_len * 8, 0, data_size);
    if (res != TEE_SUCCESS) return res;
    
    // Update the AE operation with the data
    size_t processed_len = data_size;
    res = TEE_AEUpdate(op, data, data_size, encrypted_data, &processed_len);
    if (res != TEE_SUCCESS) return res;
    
    // Finalize the encryption and get the authentication tag
    res = TEE_AEEncryptFinal(op, NULL, 0, NULL, NULL, 
                             tag, &tag_len);
    if (res != TEE_SUCCESS) return res;
    
    // Append the tag to the output buffer (after the encrypted data)
    TEE_MemMove(encrypted_data + processed_len, tag, sizeof(tag));
    processed_len = processed_len + sizeof(tag);

    // Append the IV to the output buffer (after the encrypted data and tag)
    TEE_MemMove(encrypted_data + processed_len, iv, sizeof(iv));
    
    TEE_FreeTransientObject(key_handle);
    //TEE_FreeOperation(op);

    return res;
}



TEE_Result decrypt_file_aes_gcm(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t unique_key_identifier = params[0].value.a;
    void* encrypted_data = params[1].memref.buffer;
    size_t encrypted_data_size = params[1].memref.size;
    void* data = params[2].memref.buffer;
    size_t data_size = params[2].memref.size;

    size_t iv_size = 12; // Size of the IV
    size_t tag_len = 16; // Size of the GCM tag

    // Extract the IV from the end of the encrypted data
    uint8_t iv[iv_size];
    TEE_MemMove(iv, encrypted_data + encrypted_data_size - iv_size, iv_size);

    // Extract the tag from the encrypted data
    uint8_t tag[tag_len];
    TEE_MemMove(tag, encrypted_data + encrypted_data_size - iv_size - tag_len, tag_len);

    // Adjust the encrypted data size to exclude the tag and IV
    size_t actual_encrypted_data_size = encrypted_data_size - iv_size - tag_len;

    // Define buffer for AES key and size variable
    uint8_t key_data[32]; // Buffer for AES-256 key
    size_t key_data_size = sizeof(key_data);

    // Retrieve the AES key
    res = retrieve_aes_key(unique_key_identifier, key_data, &key_data_size);
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

    // Prepare the operation for AES-GCM decryption
    res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, key_data_size * 8);
    if (res != TEE_SUCCESS) return res;

    // Set the operation key
    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS) return res;

    // Initialize the AE decryption operation
    res = TEE_AEInit(op, iv, iv_size, tag_len * 8, 0, actual_encrypted_data_size);
    if (res != TEE_SUCCESS) return res;

    // Decrypt the data
    size_t processed_len = data_size;
    res = TEE_AEUpdate(op, encrypted_data, actual_encrypted_data_size, data, &processed_len);
    if (res != TEE_SUCCESS) return res;

    // Finalize the decryption and verify the tag
    res = TEE_AEDecryptFinal(op, NULL, 0, data + processed_len, &processed_len, tag, tag_len);
    if (res != TEE_SUCCESS) return res;

    TEE_FreeOperation(op);
    TEE_FreeTransientObject(key_handle);

    return res;
}
