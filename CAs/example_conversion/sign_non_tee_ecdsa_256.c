/*****************************************************************************
** Copyright (C) 2022 Technology Innovation Institute (TII)                 **
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>

// Note: Please readme

void handle_mbedtls_error(int mbedtls_errno)
{
	size_t buf_len_err_mbedtls = 200;
	char buf_err_mbedtls[buf_len_err_mbedtls];

	mbedtls_strerror(mbedtls_errno, buf_err_mbedtls, buf_len_err_mbedtls);
	printf("MBEDTLS Error [%s]\n", buf_err_mbedtls);
}

int main()
{
	const char *pers = "personilization string";
	mbedtls_entropy_context mbedtls_entropy;
	mbedtls_ctr_drbg_context mbedtls_ctr_drbg;
	mbedtls_ecdsa_context ctx_sign;
	unsigned char hash[32];
	unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
	size_t sig_len;
	int rv;
	FILE *f;

	memset(hash, 0x23, 32);
	memset(sig, 0, MBEDTLS_ECDSA_MAX_LEN);

	// Initialize crypto lib
	mbedtls_ctr_drbg_init(&mbedtls_ctr_drbg);
	mbedtls_entropy_init(&mbedtls_entropy);

	if ((rv = mbedtls_ctr_drbg_seed(&mbedtls_ctr_drbg, mbedtls_entropy_func, &mbedtls_entropy,
					(const unsigned char *)pers, strlen(pers))) != 0) {
		handle_mbedtls_error(rv);
		goto err_1;
	}

	// Initialize crypto operation
	mbedtls_ecdsa_init(&ctx_sign);

	// Create key
	if ((rv = mbedtls_ecdsa_genkey(&ctx_sign, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random,
				       &mbedtls_ctr_drbg)) != 0) {
		handle_mbedtls_error(rv);
		goto err_2;
	}

	// Save key to disk
	f = fopen("ecdsa-key", "w+");
	if (f) {
		if ((rv = mbedtls_mpi_write_file("Qx: ", &ctx_sign.private_Q.private_X, 16, f)) !=
		    0) {
			handle_mbedtls_error(rv);
			goto err_3;
		}
		if ((rv = mbedtls_mpi_write_file("Qy: ", &ctx_sign.private_Q.private_Y, 16, f)) !=
		    0) {
			handle_mbedtls_error(rv);
			goto err_3;
		}
		if ((rv = mbedtls_mpi_write_file("Qz: ", &ctx_sign.private_Q.private_Z, 16, f)) !=
		    0) {
			handle_mbedtls_error(rv);
			goto err_3;
		}
		if ((rv = mbedtls_mpi_write_file("d: ", &ctx_sign.private_d, 16, f)) != 0) {
			handle_mbedtls_error(rv);
			goto err_3;
		}
	} else {
		goto err_2;
	}

	// Sign hash
	if ((rv = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256, hash, 32, sig,
						MBEDTLS_ECDSA_MAX_LEN, &sig_len,
						mbedtls_ctr_drbg_random, &mbedtls_ctr_drbg)) != 0) {
		handle_mbedtls_error(rv);
		goto err_2;
	}

err_3:
	fclose(f); // skipping error check
err_2:
	mbedtls_ecdsa_free(&ctx_sign);
err_1:
	mbedtls_ctr_drbg_free(&mbedtls_ctr_drbg);
	mbedtls_entropy_free(&mbedtls_entropy);

	exit(rv);
}
