#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>
# include <string.h>
#include <stddef.h>

// UUID of the Trusted Application
#define TA_AES_KEYGEN_UUID { 0x12345678, 0x8765, 0x4321, {'S', 'Y', 'M', 'K', 'E', 'Y', '0', '0'} }

// Command ID for generating an AES key
#define CMD_GENERATE_AES_KEY 0x00000001
#define CMD_RETRIEVE_AES_KEY 0x00000002
#define CMD_ENCRYPT_FILE 0x00000003
#define CMD_DECRYPT_FILE 0x00000004


// Function headers
void retrieve_and_check_key(uint32_t unique_key_identifier, TEEC_Session *sess);




// Error checking function
static void check_result(TEEC_Result res, const char* function, uint32_t err_origin) {
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "ERROR in %s; error code: 0x%x, origin: 0x%x\n", function, res, err_origin);
        exit(1);
    }
}



int main(int argc, char *argv[]) {

    uint32_t command;

    // Ensure correct number of arguments are passed
    if (argc < 3) { // there needs to be at least 3 arguments 
        fprintf(stderr, "Usage: %s <command> <key id>\n", argv[0]);
        exit(1);
    }

    // Determine operation based on command line arguments
    if (strcmp(argv[1], "generate") == 0) {
        command = CMD_GENERATE_AES_KEY;
    } else if (strcmp(argv[1], "retrieve") == 0) {
        command = CMD_RETRIEVE_AES_KEY;
    } else if (strcmp(argv[1], "encrypt") == 0) {
        command = CMD_ENCRYPT_FILE;
    } else if (strcmp(argv[1], "decrypt") == 0) {
        command = CMD_DECRYPT_FILE;
    } else {
        printf("Choose a valid command: generate, retrieve, encrypt, decrypt\n");
        exit(1);
    }

    uint32_t unique_key_identifier = atoi(argv[2]); 
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_AES_KEYGEN_UUID;
    uint32_t err_origin;
    uint8_t key[32]; // AES-256 key size in bytes

    // Zero out the structures
    memset(&ctx, 0, sizeof(ctx));
    memset(&sess, 0, sizeof(sess));
    memset(&op, 0, sizeof(op));
    memset(key, 0, sizeof(key));

    // Initialize a context connecting to the TEE
    res = TEEC_InitializeContext(NULL, &ctx);
    check_result(res, "TEEC_InitializeContext", err_origin);

    // Open a session with the TA
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    check_result(res, "TEEC_OpenSession", err_origin);

    if (command == CMD_GENERATE_AES_KEY) {

        // Prepare the operation for key generation
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        op.params[0].value.a = 256; // AES-256 key size in bits
        op.params[1].value.a = unique_key_identifier;
        /*
            The below two lines are commented out because they are not needed as the key will not be sent back to CA from TA
        */ 
        //op.params[2].tmpref.buffer = key;
        //op.params[2].tmpref.size = sizeof(key);

        /* 
            Register shared memory (not needed because we do not expect anything from TA) 
        */
        //res = TEEC_RegisterSharedMemory(&ctx, &op.params[2].memref);
        //check_result(res, "TEEC_RegisterSharedMemory", err_origin);

        // Invoke the command
        res = TEEC_InvokeCommand(&sess, command, &op, &err_origin);
        if (res != TEE_SUCCESS) {
            printf("Failed to generate key.\nCheck that this is the first time the uniuqe identifier is being used\nand no previous key has been generated with this identifier.\n\n");
        }
        check_result(res, "TEEC_InvokeCommand", err_origin);
        
        
        // Display success message
        /* 
            If the key was sent back from TA to CA, it would be inside 'key' buffer 
        */
        printf("Generated AES-256 Key with identifier: %d Successfuly.\n", unique_key_identifier);

    } else if (command == CMD_ENCRYPT_FILE || command == CMD_DECRYPT_FILE) {

        if (argc < 5) {
            fprintf(stderr, "Usage: %s [encrypt/decrypt] <key id> <input file> <output file>\n", argv[0]);
            exit(1);
        }

        // Get input and output file names
        char *input_file = argv[3];
        char *output_file = argv[4];
        
        // Read content of input file
        FILE *f = fopen(input_file, "rb");
        if (!f) {
            perror("Failed to open input file");
            exit(1);
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *input_data = malloc(fsize);
        fread(input_data, fsize, 1, f);
        fclose(f);

        // Prepare the operation
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        op.params[0].value.a = unique_key_identifier;
        op.params[1].tmpref.buffer = input_data;
        op.params[1].tmpref.size = fsize;
        
        // Assuming the output file size is same as input file size
        size_t required_size = fsize;

        // Allocate buffer to recieve output (cipher text) with required size
        uint8_t *output_data = malloc(required_size);
        if (!output_data) {
            perror("Failed to allocate memory for output data");
            free(input_data);
            exit(1);
        }
        
        // Prepare the operation again with the correct buffer size (to recieve the ciphertext)
        op.params[2].tmpref.buffer = output_data;
        op.params[2].tmpref.size = required_size;

        // Invoke the command 
        res = TEEC_InvokeCommand(&sess, command, &op, &err_origin);
        check_result(res, "TEEC_InvokeCommand", err_origin);


        // Write output file
        FILE *f_out = fopen(output_file, "wb");
        if (!f_out) {
            perror("Failed to open output file");
            free(input_data);
            free(output_data);
            exit(1);
        }
        fwrite(output_data, required_size, 1, f_out); 
        fclose(f_out);

        free(input_data);
        free(output_data);
        

        
    } else {
        /* 
        This is not secure because it will show the key in user-space. 
        The only reason this is here is because I wanted to validate keys are actaully being generatd and can be retrieved. 
        */

        // Prepare the operation for key retrieval
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].value.a = unique_key_identifier;
        op.params[1].tmpref.buffer = key;
        op.params[1].tmpref.size = sizeof(key);

        // Register shared memory
        res = TEEC_RegisterSharedMemory(&ctx, &op.params[1].memref);
        check_result(res, "TEEC_RegisterSharedMemory", err_origin);

        // Call retrieval function
        retrieve_and_check_key(unique_key_identifier, &sess);

    }


    // Close the session and release the context
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}



/*
Function to retrieve to user-space a key using the unique identifier of the key
This is VERY insecure and is just for validation purposes only as it sends the key to user-space
*/
void retrieve_and_check_key(uint32_t unique_key_identifier, TEEC_Session *sess) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    uint8_t retrieved_key_buffer[32]; // Buffer to store the retrieved key
    size_t key_size = sizeof(retrieved_key_buffer);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = unique_key_identifier;
    op.params[1].tmpref.buffer = retrieved_key_buffer;
    op.params[1].tmpref.size = key_size;

    res = TEEC_InvokeCommand(sess, CMD_RETRIEVE_AES_KEY, &op, &err_origin);
    if (res == TEEC_SUCCESS) {
        printf("Key retrieved successfully, size: %zu\n", op.params[1].tmpref.size);
        
        printf("Retrieved AES-256 Key with identifier: %d\n", unique_key_identifier);
        for (size_t i = 0; i < op.params[1].tmpref.size; i++) {
            printf("%02X", retrieved_key_buffer[i]);
            if ((i + 1) % 4 == 0) printf(" ");
        }
        printf("\n");
        
    } else {
        printf("Failed to retrieve key, error: 0x%x, origin: 0x%x\n", res, err_origin);
    }
}