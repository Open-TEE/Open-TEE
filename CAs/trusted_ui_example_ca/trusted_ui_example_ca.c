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

/* Example application for demonstration of Trusted User Interface API. */
/* Invokes Trusted Application to get user input via Trusted UI and
 * returns encrypted data via public key cryptography. */

#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define RSA_KEY_BITS 4096
#define AES_KEY_SIZE (256 / 8)
#define AES_IV_SIZE (256 / 8)

static const TEEC_UUID uuid = {
	0xC8316964, 0x986B, 0x837F, { 0xC3, 0x9A, 0xED, 0xF8, 0x2C, 0xD3, 0x9E, 0x63 }
};

struct rsa_key_modulus {
	char *modulus;
	size_t modulus_len;
};

struct ta_output {
	char *rsa_encrypted_aes_key;
	size_t rsa_encrypted_aes_key_len;

	char *aes_encrypted_user_data;
	size_t aes_encrypted_user_data_len;
};

struct trusted_input {
	char *username;
	char *password;
	char *pincode;
};

static int seed_random_generator()
{
	const ssize_t byte_read_count = RSA_KEY_BITS / 8;
	if (RAND_load_file("/dev/urandom", byte_read_count) != byte_read_count)
		return -1;

	return 0;
}

static int decrypt_aes_key(RSA *rsa,
			   const char *encrypted_key_buf,
			   char *aes_key,
			   char *aes_iv)
{
	unsigned char decrypted_buf[AES_KEY_SIZE + AES_IV_SIZE];

	if (RSA_private_decrypt(AES_KEY_SIZE + AES_IV_SIZE,
				(const unsigned char *)encrypted_key_buf,
				decrypted_buf,
				rsa,
				RSA_PKCS1_OAEP_PADDING) == -1)
		return -1;

	memcpy(aes_key, decrypted_buf, AES_KEY_SIZE);
	memcpy(aes_iv, decrypted_buf + AES_KEY_SIZE, AES_IV_SIZE);

	return 0;
}

static RSA *generate_rsa_key()
{
	RSA *rsa = NULL;
	BIGNUM *exponent = NULL;

	/* Seed OpenSSL random generator */
	if (seed_random_generator() != 0) {
		printf("Error seeding random generator\n");
		goto err;
	}

	rsa = RSA_new();
	exponent = BN_new();

	if (rsa == NULL ||
	    exponent == NULL ||

	    /* Set 65537 as exponent */
	    BN_hex2bn(&exponent, "010001") == 0 ||

	    /* Generate RSA private/public key pair */
	    RSA_generate_key_ex(rsa, RSA_KEY_BITS, exponent, NULL) == 0)
		goto err;

	BN_free(exponent);
	exponent = NULL;

	return rsa;
err:
	RSA_free(rsa);
	rsa = NULL;

	BN_free(exponent);
	exponent = NULL;

	return NULL;
}

static int invoke_ta_tui_cmd(struct ta_output *output,
			     struct rsa_key_modulus *pubkey,
			     TEEC_Context *context,
			     TEEC_Session *session)
{
	int ret = -1;
	uint32_t return_origin;
	TEEC_Operation op;
	TEEC_SharedMemory shmem_rsa_key_in;
	TEEC_SharedMemory shmem_rsa_encrypted_aes_key_out;
	TEEC_SharedMemory shmem_aes_encrypted_user_data;

	memset(&op, 0, sizeof(op));
	memset(&shmem_rsa_key_in, 0, sizeof(shmem_rsa_key_in));
	memset(&shmem_rsa_encrypted_aes_key_out, 0, sizeof(shmem_rsa_encrypted_aes_key_out));
	memset(&shmem_aes_encrypted_user_data, 0, sizeof(shmem_aes_encrypted_user_data));

	shmem_rsa_key_in.buffer = pubkey->modulus;
	shmem_rsa_key_in.size = pubkey->modulus_len;
	shmem_rsa_key_in.flags = TEEC_MEM_INPUT;

	shmem_rsa_encrypted_aes_key_out.buffer = output->rsa_encrypted_aes_key;
	shmem_rsa_encrypted_aes_key_out.size = output->rsa_encrypted_aes_key_len;
	shmem_rsa_encrypted_aes_key_out.flags = TEEC_MEM_OUTPUT;

	shmem_aes_encrypted_user_data.buffer = output->aes_encrypted_user_data;
	shmem_aes_encrypted_user_data.size = output->aes_encrypted_user_data_len;
	shmem_aes_encrypted_user_data.flags = TEEC_MEM_OUTPUT;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_OUTPUT);

	op.params[0].memref.parent = &shmem_rsa_key_in;
	op.params[1].memref.parent = &shmem_rsa_encrypted_aes_key_out;
	op.params[2].memref.parent = &shmem_aes_encrypted_user_data;

	if (TEEC_RegisterSharedMemory(context, &shmem_rsa_key_in) != TEEC_SUCCESS)
		goto err1;

	if (TEEC_RegisterSharedMemory(context, &shmem_rsa_encrypted_aes_key_out) !=
		TEEC_SUCCESS)
		goto err2;

	if (TEEC_RegisterSharedMemory(context, &shmem_aes_encrypted_user_data) !=
		TEEC_SUCCESS)
		goto err3;

	if (TEEC_InvokeCommand(session, 1, &op, &return_origin) != TEEC_SUCCESS) {
		printf("Error in TEEC_InvokeCommand\n");
		goto err4;
	}

	output->aes_encrypted_user_data_len = shmem_aes_encrypted_user_data.size;
	ret = 0;

err4:
	TEEC_ReleaseSharedMemory(&shmem_aes_encrypted_user_data);
err3:
	TEEC_ReleaseSharedMemory(&shmem_rsa_encrypted_aes_key_out);
err2:
	TEEC_ReleaseSharedMemory(&shmem_rsa_key_in);
err1:
	return ret;
}

static int invoke_ta(struct ta_output *output,
		     struct rsa_key_modulus *pubkey)
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	uint32_t return_origin;

	memset(&context, 0, sizeof(context));
	memset(&session, 0, sizeof(session));

	/* Initialize context */
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext error: 0x%08x\n", ret);
		return -1;
	}

	/* Open session */
	ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession error: 0x%08x\n", ret);
		return -2;
	}

	ret = invoke_ta_tui_cmd(output, pubkey, &context, &session);
	if (ret != 0)
		ret = -3;

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);

	return ret;
}

static int deserialize_data(struct trusted_input *dest, char *buf, size_t buf_len)
{
	uint32_t username_length;
	uint32_t password_length;
	uint32_t pincode_length;
	char *buf_ptr = buf + (3 * sizeof(uint32_t));

	/* Buffer size must be at least 3 times uint32_t */
	if (buf_len < 3 * sizeof(uint32_t)) {
		printf("Buffer size too small to contain header data\n");
		return -1;
	}

	memcpy(&username_length, buf, sizeof(uint32_t));
	memcpy(&password_length, buf + sizeof(uint32_t), sizeof(uint32_t));
	memcpy(&pincode_length, buf + (2 * sizeof(uint32_t)), sizeof(uint32_t));

	/* Check if buffer length matches the header */
	if (buf_len !=
	    (3 * sizeof(uint32_t) +
	     username_length + password_length + pincode_length)) {
		printf("Buffer length mismatch %zu != %zu\n",
		       buf_len,
		       (3 * sizeof(uint32_t) + username_length + password_length + pincode_length));
		//return -2;
	}

	dest->username = malloc(username_length + 1);
	dest->password = malloc(password_length + 1);
	dest->pincode = malloc(pincode_length + 1);

	if (dest->username == NULL ||
	    dest->password == NULL ||
	    dest->pincode == NULL) {
		free(dest->username);
		free(dest->password);
		free(dest->pincode);

		return -3;
	}

	memcpy(dest->username, buf_ptr, username_length);
	dest->username[username_length] = '\0';
	buf_ptr += username_length;

	memcpy(dest->password, buf_ptr, password_length);
	dest->password[password_length] = '\0';
	buf_ptr += password_length;

	memcpy(dest->pincode, buf_ptr, pincode_length);
	dest->pincode[pincode_length] = '\0';

	return 0;
}

static int extract_modulus_from_rsa(struct rsa_key_modulus *n, RSA *rsa)
{
	ssize_t modulus_len = BN_num_bytes(rsa->n);

	n->modulus = malloc(modulus_len);
	if (n->modulus == NULL)
		return -1;

	if (BN_bn2bin(rsa->n, (unsigned char *)n->modulus) != modulus_len) {
		free(n->modulus);
		n->modulus = NULL;
		return -2;
	}

	n->modulus_len = modulus_len;

	return 0;
}

static int decrypt_data_from_ta(struct trusted_input *user_input)
{
	int ret = -1;
	RSA *rsa;
	struct ta_output encrypted_data = { 0 };
	struct rsa_key_modulus pubkey = { 0 };
	char aes_key[AES_KEY_SIZE];
	char aes_iv[AES_IV_SIZE];
	char *serialized_user_data = NULL;
	size_t serialized_user_data_len = 0;

	/* Generate RSA key pair */
	/* NOTE: In real life situation the key would be generated on the
	 *       server of the bank and only public key would be submitted
	 *       to this application. Decryption would then happen on the
	 *       server of the bank. */
	rsa = generate_rsa_key();
	if (rsa == NULL)
		goto err;

	/* Extract RSA public key modulus from OpenSSL RSA struct */
	if (extract_modulus_from_rsa(&pubkey, rsa) != 0)
		goto err;

	/* Allocate buffers for data returned from TA */
	encrypted_data.rsa_encrypted_aes_key_len = RSA_size(rsa);
	encrypted_data.rsa_encrypted_aes_key =
		malloc(encrypted_data.rsa_encrypted_aes_key_len);
	if (encrypted_data.rsa_encrypted_aes_key == NULL)
		goto err;

	encrypted_data.aes_encrypted_user_data_len = 1024;
	encrypted_data.aes_encrypted_user_data =
		malloc(encrypted_data.aes_encrypted_user_data_len);
	if (encrypted_data.aes_encrypted_user_data == NULL)
		goto err;

	/* Invoke Trusted Application for Trusted User Interface input */
	if (invoke_ta(&encrypted_data, &pubkey) != 0)
		goto err;

	/* Decrypt AES key with RSA private key */
	//decrypt_aes_key(rsa, encrypted_data.rsa_encrypted_aes_key, aes_key, aes_iv);

	/* TODO: Forgot about AES Initialization Vector */
	/* TODO: Decrypt user data encrypted with AES */
	/* TODO: Deserialize user data */
	//deserialize_data(user_input, serialized_user_data, serialized_user_data_len);
	ret = deserialize_data(user_input,
			       encrypted_data.aes_encrypted_user_data,
			       encrypted_data.rsa_encrypted_aes_key_len);
	if (ret != 0)
		goto err;

	ret = 0;
err:
	free(serialized_user_data);
	free(encrypted_data.aes_encrypted_user_data);
	free(encrypted_data.rsa_encrypted_aes_key);
	free(pubkey.modulus);

	return ret;
}

static int get_input_from_ta_and_print()
{
	struct trusted_input user_input = {NULL, NULL, NULL};

	if (decrypt_data_from_ta(&user_input) != 0)
		return -1;

	printf("=== ACME BANK Login Information ===\n");
	printf("Username: %s\n", user_input.username);
	printf("Password: %s\n", user_input.password);
	printf("PIN-code: %s\n", user_input.pincode);

	/* Clean up */
	free(user_input.username);
	user_input.username = NULL;

	free(user_input.password);
	user_input.password = NULL;

	free(user_input.pincode);
	user_input.pincode = NULL;

	return 0;
}

int main()
{
	if (get_input_from_ta_and_print() != 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
