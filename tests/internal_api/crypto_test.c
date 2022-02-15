/*****************************************************************************
** Copyright (C) 2013 Secure Systems Group.                                 **
** Copyright (C) 2015 Intel Corporation.				    **
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

/* Extreme simply smoke tests. */

#include "crypto_test.h"
#include "tee_internal_api.h"
#include "print_functions.h"

static const uint32_t SHA1_SIZE = 20;
static const uint32_t SHA224_SIZE = 28;
static const uint32_t SHA256_SIZE = 32;
static const uint32_t SHA384_SIZE = 48;
static const uint32_t SHA512_SIZE = 64;

#define NaN 34213456 //Not used in GP!
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)
#define MAX_HASH_OUTPUT_LENGTH 64 /* sha512 */

static uint32_t compare_opmultiple_info(TEE_OperationInfoMultiple *info,
					TEE_OperationInfoMultiple *e_info);


static uint8_t ecc_msg_p256[] = "\x59\x05\x23\x88\x77\xc7\x74\x21\xf7\x3e\x43\xee\x3d\xa6\xf2\xd9\xe2\xcc\xad\x5f\xc9\x42\xdc\xec\x0c\xbd\x25\x48\x29\x35\xfa\xaf\x41\x69\x83\xfe\x16\x5b\x1a\x04\x5e\xe2\xbc\xd2\xe6\xdc\xa3\xbd\xf4\x6c\x43\x10\xa7\x46\x1f\x9a\x37\x96\x0c\xa6\x72\xd3\xfe\xb5\x47\x3e\x25\x36\x05\xfb\x1d\xdf\xd2\x80\x65\xb5\x3c\xb5\x85\x8a\x8a\xd2\x81\x75\xbf\x9b\xd3\x86\xa5\xe4\x71\xea\x7a\x65\xc1\x7c\xc9\x34\xa9\xd7\x91\xe9\x14\x91\xeb\x37\x54\xd0\x37\x99\x79\x0f\xe2\xd3\x08\xd1\x61\x46\xd5\xc9\xb0\xd0\xde\xbd\x97\xd7\x9c\xe8";
static uint8_t ecc_d_p256[] = "\x51\x9b\x42\x3d\x71\x5f\x8b\x58\x1f\x4f\xa8\xee\x59\xf4\x77\x1a\x5b\x44\xc8\x13\x0b\x4e\x3e\xac\xca\x54\xa5\x6d\xda\x72\xb4\x64";
static uint8_t ecc_qx_p256[] = "\x1c\xcb\xe9\x1c\x07\x5f\xc7\xf4\xf0\x33\xbf\xa2\x48\xdb\x8f\xcc\xd3\x56\x5d\xe9\x4b\xbf\xb1\x2f\x3c\x59\xff\x46\xc2\x71\xbf\x83";
static uint8_t ecc_qy_p256[] = "\xce\x40\x14\xc6\x88\x11\xf9\xa2\x1a\x1f\xdb\x2c\x0e\x61\x13\xe0\x6d\xb7\xca\x93\xb7\x40\x4e\x78\xdc\x7c\xcd\x5c\xa8\x9a\x4c\xa9";
static uint8_t ecc_s_p256[] = "\x8b\xf7\x78\x19\xca\x05\xa6\xb2\x78\x6c\x76\x26\x2b\xf7\x37\x1c\xef\x97\xb2\x18\xe9\x6f\x17\x5a\x3c\xcd\xda\x2a\xcc\x05\x89\x03";

static char *ecc_rfc_msg_p256 = "sample";
static uint8_t ecc_rfc_d_p256[] = "\xC9\xAF\xA9\xD8\x45\xBA\x75\x16\x6B\x5C\x21\x57\x67\xB1\xD6\x93\x4E\x50\xC3\xDB\x36\xE8\x9B\x12\x7B\x8A\x62\x2B\x12\x0F\x67\x21";
static uint8_t ecc_rfc_qx_p256[] = "\x60\xFE\xD4\xBA\x25\x5A\x9D\x31\xC9\x61\xEB\x74\xC6\x35\x6D\x68\xC0\x49\xB8\x92\x3B\x61\xFA\x6C\xE6\x69\x62\x2E\x60\xF2\x9F\xB6";
static uint8_t ecc_rfc_qy_p256[] = "\x79\x03\xFE\x10\x08\xB8\xBC\x99\xA4\x1A\xE9\xE9\x56\x28\xBC\x64\xF2\xF1\xB2\x0C\x2D\x7E\x9F\x51\x77\xA3\xC2\x94\xD4\x46\x22\x99";
static uint8_t ecc_rfc_r_p256[] = "\xEF\xD4\x8B\x2A\xAC\xB6\xA8\xFD\x11\x40\xDD\x9C\xD4\x5E\x81\xD6\x9D\x2C\x87\x7B\x56\xAA\xF9\x91\xC3\x4D\x0E\xA8\x4E\xAF\x37\x16";
static uint8_t ecc_rfc_s_p256[] = "\xF7\xCB\x1C\x94\x2D\x65\x7C\x41\xD4\x36\xC7\xA1\xB6\xE2\x9F\x65\xF3\xE9\x00\xDB\xB9\xAF\xF4\x06\x4D\xC4\xAB\x2F\x84\x3A\xCD\xA8";

//aes gcm 256: encrypt
static uint8_t aes_gcm_enc_key_256[] = "\x36\xd5\x9c\x85\x72\x26\xd2\xcb\xc9\x4c\x70\x87\xbf\x89"
	"\x9b\xe6\x08\x74\x57\xcf\x7d\xe9\xd5\x26\xf1\x8c\x60\xc9\x92\x39\x09\xd4";
static uint8_t aes_gcm_enc_iv_256[] = "\x1a";
static uint8_t aes_gcm_enc_plain_256[] = "\x02\x6b\xf2\x25\xe7\xba\x1c\x68\x43\xc5\xd4\x57\xaa\x29\xfd\x3b";
static uint8_t aes_gcm_enc_aad_256[] = "\x29\x55\x1b\x35\x43\x53\xa5\xc8\x6a\x43\xd4\x72\xa0\x44\xaa\xcc"
	"\x62\xf2\x37\xe6\xa6\xa2\xf6\x7c\x3f\x09\x78\x22\xd6\x91\x43\xa5"
	"\xaf\x75\x3e\x01\x0b\x14\x9c\xc1\xe0\xb9\x8b\x2c\x6b\x19\x58\xa2"
	"\x64\xf2\x31\x10\xf4\xa4\xc7\x67\x79\x71\xf4\x46\x45\x08\xe7\xd8"
	"\x55\x8f\x24\xf5\x4a\x49\xaa\x66\xda\xd0\x6f\x08\x5f\x8b\x88\xa3"
	"\x12\x38\xbc\x5d\xe1\x75\x34\x21\xda\xe4";
static uint8_t aes_gcm_enc_cipher_256[] = "\xac\xb2\x08\xe4\x76\xeb\xd8\xaf\x21\xa2\x27\x33\x13\x25\x06\x5f";
static uint8_t aes_gcm_enc_tag_256[] = "\x07\x38\x2d\xf9\x7d\x7b\x87\x6e\x60\x88\x03\x6f\x6c\xaa\xda\x93";

//aes gcm 256: decrypt
static uint8_t aes_gcm_dec_key_256[] = "\x74\x58\xa2\x0f\x61\x08\x9b\x97\x18\x4b\xc6\xd5\xc2"
	"\x2a\x43\xa1\xc8\xf4\x93\x71\x10\x26\xf8\xdd\x49\xc3\xe0\xde\xfd\x33\x4e\x03";
static uint8_t aes_gcm_dec_iv_256[] = "\x68";
static uint8_t aes_gcm_dec_cipher_256[] = "\xc7\x1f\x63\xe0\x0b\x75\x65\x98\x5d\xf7\x11\x57\x61\xeb\x48"
	"\x96\x1e\x20\xeb\xd4\x85\x7d\xd1\x0c\x87\xf1\xf4\xfe\x36\x57\x82\x79\xd7\x58\x91\x63\x1b\xfe"
	"\xa1\xff\x71\xe5\xdf\xa5\x34\xa9\x22\xd0\x13\x38\x89";
static uint8_t aes_gcm_dec_aad_256[] = "\x68\x1f\xaa\x07\x7d\xd1\x70\xf7\x7b\x57\x3d\x41\x1d\x4d\xc3\x1a";
static uint8_t aes_gcm_dec_tag_256[] = "\xc5\xea\xb2\xf1\xb5\x2d\x40\xae\xdd\x50\xae\xef\xd9\xb5\x9a";
static uint8_t aes_gcm_dec_plain_256[] = "\xd4\xe4\xfb\x6f\x34\xdf\xc1\xd4\x69\x98\xc5\x98\x69\xbf\x4f\x3d"
	"\x92\x28\xa8\xba\x70\xba\x3a\x68\xac\xea\xc3\xc6\x45\xec\x64\x00\xd0\xb6"
	"\x12\x34\x15\x30\xa0\xf3\xcf\xc1\x8f\x7f\x49\x3b\x1d\x42\xa5\x97\x62";

//aes rfc3602
static uint8_t aes_cbc_key_128[] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
static uint8_t aes_cbc_iv_128[]  = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
static uint8_t aes_cbc_plain_128[] =  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	                       "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
static uint8_t aes_cbc_cipher_128[] = "\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a"
	                       "\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1";

//aes NIST: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
static uint8_t aes_ctr_key_256[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
	"\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
static uint8_t aes_ctr_ctr_256[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
static uint8_t aes_ctr_plain_256[] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
static uint8_t aes_ctr_cipher_256[] = "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28";

static uint8_t aes_ctr_key_192[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
static uint8_t aes_ctr_ctr_192[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
static uint8_t aes_ctr_plain_192[] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
static uint8_t aes_ctr_cipher_192[] = "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b";

//hmac NIST: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip
static uint8_t hmac_sha1_key[] = "\x59\x78\x59\x28\xd7\x25\x16\xe3\x12\x72";
static uint8_t hmac_sha1_msg[] = "\xa3\xce\x88\x99\xdf\x10\x22\xe8\xd2\xd5\x39\xb4\x7b\xf0"
	"\xe3\x09\xc6\x6f\x84\x09\x5e\x21\x43\x8e\xc3\x55\xbf\x11"
	"\x9c\xe5\xfd\xcb\x4e\x73\xa6\x19\xcd\xf3\x6f\x25\xb3\x69"
	"\xd8\xc3\x8f\xf4\x19\x99\x7f\x0c\x59\x83\x01\x08\x22\x36"
	"\x06\xe3\x12\x23\x48\x3f\xd3\x9e\xde\xaa\x4d\x3f\x0d\x21"
	"\x19\x88\x62\xd2\x39\xc9\xfd\x26\x07\x41\x30\xff\x6c\x86"
	"\x49\x3f\x52\x27\xab\x89\x5c\x8f\x24\x4b\xd4\x2c\x7a\xfc"
	"\xe5\xd1\x47\xa2\x0a\x59\x07\x98\xc6\x8e\x70\x8e\x96\x49"
	"\x02\xd1\x24\xda\xde\xcd\xbd\xa9\xdb\xd0\x05\x1e\xd7\x10"
	"\xe9\xbf";
static uint8_t hmac_sha1_mac[] = "\x3c\x81\x62\x58\x9a\xaf\xae\xe0\x24\xfc"
	"\x9a\x5c\xa5\x0d\xd2\x33\x6f\xe3\xeb\x28";


//Nist 
static uint8_t ecdh_256_qx[] = "\x70\x0c\x48\xf7\x7f\x56\x58\x4c\x5c\xc6\x32\xca\x65\x64\x0d\xb9\x1b\x6b\xac\xce\x3a\x4d\xf6\xb4\x2c\xe7\xcc\x83\x88\x33\xd2\x87";
static uint8_t ecdh_256_qy[] = "\xdb\x71\xe5\x09\xe3\xfd\x9b\x06\x0d\xdb\x20\xba\x5c\x51\xdc\xc5\x94\x8d\x46\xfb\xf6\x40\xdf\xe0\x44\x17\x82\xca\xb8\x5f\xa4\xac";
static uint8_t ecdh_256_d[] = "\x7d\x7d\xc5\xf7\x1e\xb2\x9d\xda\xf8\x0d\x62\x14\x63\x2e\xea\xe0\x3d\x90\x58\xaf\x1f\xb6\xd2\x2e\xd8\x0b\xad\xb6\x2b\xc1\xa5\x34";
static uint8_t ecdh_256_shared[] = "\x46\xfc\x62\x10\x64\x20\xff\x01\x2e\x54\xa4\x34\xfb\xdd\x2d\x25\xcc\xc5\x85\x20\x60\x56\x1e\x68\x04\x0d\xd7\x77\x89\x97\xbd\x7b";


// sha256 (NIST)
static uint8_t sha256msg[] = "\x45\x11\x01\x25\x0e\xc6\xf2\x66\x52\x24\x9d\x59\xdc\x97\x4b\x73"
		      "\x61\xd5\x71\xa8\x10\x1c\xdf\xd3\x6a\xba\x3b\x58\x54\xd3\xae\x08"
		      "\x6b\x5f\xdd\x45\x97\x72\x1b\x66\xe3\xc0\xdc\x5d\x8c\x60\x6d\x96"
		      "\x57\xd0\xe3\x23\x28\x3a\x52\x17\xd1\xf5\x3f\x2f\x28\x4f\x57\xb8"
		      "\x5c\x8a\x61\xac\x89\x24\x71\x1f\x89\x5c\x5e\xd9\x0e\xf1\x77\x45"
		      "\xed\x2d\x72\x8a\xbd\x22\xa5\xf7\xa1\x34\x79\xa4\x62\xd7\x1b\x56"
		      "\xc1\x9a\x74\xa4\x0b\x65\x5c\x58\xed\xfe\x0a\x18\x8a\xd2\xcf\x46"
		      "\xcb\xf3\x05\x24\xf6\x5d\x42\x3c\x83\x7d\xd1\xff\x2b\xf4\x62\xac"
		      "\x41\x98\x00\x73\x45\xbb\x44\xdb\xb7\xb1\xc8\x61\x29\x8c\xdf\x61"
		      "\x98\x2a\x83\x3a\xfc\x72\x8f\xae\x1e\xda\x2f\x87\xaa\x2c\x94\x80"
		      "\x85\x8b\xec";

static uint8_t sha256hash[] = "\x3c\x59\x3a\xa5\x39\xfd\xcd\xae\x51\x6c\xdf\x2f\x15\x00\x0f\x66"
		       "\x34\x18\x5c\x88\xf5\x05\xb3\x97\x75\xfb\x9a\xb1\x37\xa1\x0a\xa2";

//https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip
static uint8_t sha1msg[] = "\xc4\xa7\x56\xf6\x02\x4a\x9d\xce\xab\xf6\xe2\x64\xff\xff\xf9\xc7\x19\x21\x7f\xb4\x18\x14\x1a\xc5\x7d\x60\x02\xe5\xd4\x73\xc1\x07\x97\xf1\x37\x18\x4f\x4b\xe0\x31\xfc\x93\x5a\x12\xb7\x8f\x21\xcc\x96\x0c\x9e\xbd\xd0\x74\x60\xc1\x21\xa3\xa9\xa7\x70\xf7\x2c";
static uint8_t sha1hash[] = "\x36\xfd\x10\x1b\x7d\x07\x68\x5a\x3f\x8a\xaa\x04\x73\x7c\x95\x4d\x9a\xb7\xba\xa5";

// RSA (NIST)
//https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip
static uint8_t modulus[] = "\xa8\xd6\x8a\xcd\x41\x3c\x5e\x19\x5d\x5e\xf0\x4e\x1b\x4f\xaa\xf2"
		    "\x42\x36\x5c\xb4\x50\x19\x67\x55\xe9\x2e\x12\x15\xba\x59\x80\x2a"
		    "\xaf\xba\xdb\xf2\x56\x4d\xd5\x50\x95\x6a\xbb\x54\xf8\xb1\xc9\x17"
		    "\x84\x4e\x5f\x36\x19\x5d\x10\x88\xc6\x00\xe0\x7c\xad\xa5\xc0\x80"
		    "\xed\xe6\x79\xf5\x0b\x3d\xe3\x2c\xf4\x02\x6e\x51\x45\x42\x49\x5c"
		    "\x54\xb1\x90\x37\x68\x79\x1a\xae\x9e\x36\xf0\x82\xcd\x38\xe9\x41"
		    "\xad\xa8\x9b\xae\xca\xda\x61\xab\x0d\xd3\x7a\xd5\x36\xbc\xb0\xa0"
		    "\x94\x62\x71\x59\x48\x36\xe9\x2a\xb5\x51\x73\x01\xd4\x51\x76\xb5";

static uint8_t public_exp_4_bytes[] = "\x00\x00\x00\x03";

static uint8_t private_exp[] = "\x1c\x23\xc1\xcc\xe0\x34\xba\x59\x8f\x8f\xd2\xb7\xaf\x37\xf1\xd3"
			"\x0b\x09\x0f\x73\x62\xae\xe6\x8e\x51\x87\xad\xae\x49\xb9\x95\x5c"
			"\x72\x9f\x24\xa8\x63\xb7\xa3\x8d\x6e\x3c\x74\x8e\x29\x72\xf6\xd9"
			"\x40\xb7\xba\x89\x04\x3a\x2d\x6c\x21\x00\x25\x6a\x1c\xf0\xf5\x6a"
			"\x8c\xd3\x5f\xc6\xee\x20\x52\x44\x87\x66\x42\xf6\xf9\xc3\x82\x0a"
			"\x3d\x9d\x2c\x89\x21\xdf\x7d\x82\xaa\xad\xca\xf2\xd7\x33\x4d\x39"
			"\x89\x31\xdd\xbb\xa5\x53\x19\x0b\x3a\x41\x60\x99\xf3\xaa\x07\xfd"
			"\x5b\x26\x21\x46\x45\xa8\x28\x41\x9e\x12\x2c\xfb\x85\x7a\xd7\x3b";

static uint8_t rsa_msg[] = "\xd7\x38\x29\x49\x7c\xdd\xbe\x41\xb7\x05\xfa\xac\x50\xe7\x89\x9f"
		    "\xdb\x5a\x38\xbf\x3a\x45\x9e\x53\x63\x57\x02\x9e\x64\xf8\x79\x6b"
		    "\xa4\x7f\x4f\xe9\x6b\xa5\xa8\xb9\xa4\x39\x67\x46\xe2\x16\x4f\x55"
		    "\xa2\x53\x68\xdd\xd0\xb9\xa5\x18\x8c\x7a\xc3\xda\x2d\x1f\x74\x22"
		    "\x86\xc3\xbd\xee\x69\x7f\x9d\x54\x6a\x25\xef\xcf\xe5\x31\x91\xd7"
		    "\x43\xfc\xc6\xb4\x78\x33\xd9\x93\xd0\x88\x04\xda\xec\xa7\x8f\xb9"
		    "\x07\x6c\x3c\x01\x7f\x53\xe3\x3a\x90\x30\x5a\xf0\x62\x20\x97\x4d"
		    "\x46\xbf\x19\xed\x3c\x9b\x84\xed\xba\xe9\x8b\x45\xa8\x77\x12\x58";

static uint8_t rsa_sig[] = "\x17\x50\x15\xbd\xa5\x0a\xbe\x0f\xa7\xd3\x9a\x83\x53\x88\x5c\xa0"
		    "\x1b\xe3\xa7\xe7\xfc\xc5\x50\x45\x74\x41\x11\x36\x2e\xe1\x91\x44"
		    "\x73\xa4\x8d\xc5\x37\xd9\x56\x29\x4b\x9e\x20\xa1\xef\x66\x1d\x58"
		    "\x53\x7a\xcd\xc8\xde\x90\x8f\xa0\x50\x63\x0f\xcc\x27\x2e\x6d\x00"
		    "\x10\x45\xe6\xfd\xee\xd2\xd1\x05\x31\xc8\x60\x33\x34\xc2\xe8\xdb"
		    "\x39\xe7\x3e\x6d\x96\x65\xee\x13\x43\xf9\xe4\x19\x83\x02\xd2\x20"
		    "\x1b\x44\xe8\xe8\xd0\x6b\x3e\xf4\x9c\xee\x61\x97\x58\x21\x63\xa8"
		    "\x49\x00\x89\xca\x65\x4c\x00\x12\xfc\xe1\xba\x65\x11\x08\x97\x50";


static int calc_digest(algorithm_Identifier hash_alg,
		       void *msg, size_t msg_len,
		       void *hash, size_t *hash_len)
{
	TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
	TEE_Result ret;

	ret = TEE_AllocateOperation(&operation, hash_alg, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed allocate digest operation");
		return 1;
	}

	ret = TEE_DigestDoFinal(operation, msg, msg_len, hash, hash_len);
	TEE_FreeOperation(operation);

	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Final failed");
		return 1;
	}

	return 0;
}

static uint32_t sha256_digest()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle digest_handler = (TEE_OperationHandle)NULL;
	TEE_OperationHandle digest_handler_2 = (TEE_OperationHandle)NULL;
	void *rand_msg = NULL;
	void *rand_msg_2 = NULL;
	uint32_t op_alg = TEE_ALG_SHA256;
	uint32_t op_mode = TEE_MODE_DIGEST;
	uint32_t op_keysize = 0;
	uint32_t sha256Len = 32;
	uint32_t op_class = TEE_OPERATION_DIGEST;
	size_t operationSize;
	char hash[64] = {0};
	char hash_2[64] = {0};
	size_t rand_msg_len = 1000;
	size_t hash_len = 64;
	size_t hash_len_2 = 64;
	size_t fn_ret = 1; /* Initialized error return */
	TEE_OperationInfoMultiple info;
	
	TEE_OperationInfoMultiple expectInfoM;
	expectInfoM.algorithm = op_alg;
	expectInfoM.operationClass = op_class;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = sha256Len;
	expectInfoM.maxKeySize = 0;
	expectInfoM.handleState = (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 0;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	rand_msg = TEE_Malloc(rand_msg_len, 0);
	rand_msg_2 = TEE_Malloc(rand_msg_len, 0);
	if (rand_msg == NULL || rand_msg_2 == NULL) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_GenerateRandom(rand_msg, rand_msg_len);
	TEE_MemMove(rand_msg_2, rand_msg, rand_msg_len);

	ret = TEE_AllocateOperation(&digest_handler, op_alg, op_mode, op_keysize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	ret = TEE_AllocateOperation(&digest_handler_2, op_alg, op_mode, op_keysize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc second handler");
		goto err;
	}

	TEE_GetOperationInfoMultiple(digest_handler, &info, &operationSize);
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}
	
	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);
	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);

	TEE_DigestUpdate(digest_handler_2, rand_msg_2, rand_msg_len);
	TEE_DigestUpdate(digest_handler_2, rand_msg_2, rand_msg_len);

	TEE_GetOperationInfoMultiple(digest_handler, &info, &operationSize);
	expectInfoM.operationState = TEE_OPERATION_STATE_ACTIVE;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	ret = TEE_DigestDoFinal(digest_handler, NULL, 0, hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed final first");
		goto err;
	}

	ret = TEE_DigestDoFinal(digest_handler_2, NULL, 0, hash_2, &hash_len_2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed final second");
		goto err;
	}

	if (hash_len_2 != hash_len) {
		PRI_FAIL("Length bhould be same");
		goto err;
	}

	if (TEE_MemCompare(hash, hash_2, hash_len_2)) {
		PRI_FAIL("Hashes should be same");
		goto err;
	}

	TEE_GetOperationInfoMultiple(digest_handler, &info, &operationSize);
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}
	
	fn_ret = 0; /* OK */

err:
	TEE_FreeOperation(digest_handler);
	TEE_FreeOperation(digest_handler_2);
	TEE_Free(rand_msg);
	TEE_Free(rand_msg_2);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t compare_opmultiple_info(TEE_OperationInfoMultiple *info,
					TEE_OperationInfoMultiple *e_info)
{
	//NOTE: Pass "NaN" if not interested..

	if (info == NULL || e_info == NULL) {
		PRI_FAIL("info is NULL");
		return 1;
	}

	if (e_info->algorithm != NaN && e_info->algorithm != info->algorithm) {
		PRI_FAIL("algorithm mismatch (expected[%u]; fromInfo[%u])",
			 e_info->algorithm, info->algorithm);
		return 1;
	}

	if (e_info->operationClass != NaN && e_info->operationClass != info->operationClass) {
		PRI_FAIL("operationClass mismatch (expected[%u]; fromInfo[%u])",
			 e_info->operationClass, info->operationClass);
		return 1;
	}
	
	if (e_info->mode != NaN && e_info->mode != info->mode) {
		PRI_FAIL("mode mismatch (expected[%u]; fromInfo[%u])",
			 e_info->mode, info->mode);
		return 1;
	}

	if (e_info->digestLength != NaN && e_info->digestLength != info->digestLength) {
		PRI_FAIL("digestLength mismatch (expected[%u]; fromInfo[%u])",
			 e_info->digestLength, info->digestLength);
		return 1;
	}

	if (e_info->maxKeySize != NaN && e_info->maxKeySize != info->maxKeySize) {
		PRI_FAIL("maxKeySize mismatch (expected[%u]; fromInfo[%u])",
			 e_info->maxKeySize, info->maxKeySize);
		return 1;
	}

	if (e_info->handleState != NaN && e_info->handleState != info->handleState) {
		PRI_FAIL("handleState mismatch (expected[%u]; fromInfo[%u])",
			 e_info->handleState, info->handleState);
		return 1;
	}

	if (e_info->operationState != NaN && e_info->operationState != info->operationState) {
		PRI_FAIL("operationState mismatch (expected[%u]; fromInfo[%u])",
			 e_info->operationState, info->operationState);
		return 1;
	}

	if (e_info->numberOfKeys != NaN && e_info->numberOfKeys != info->numberOfKeys) {
		PRI_FAIL("numberOfKeys mismatch (expected[%u]; fromInfo[%u])",
			 e_info->numberOfKeys, info->numberOfKeys);
		return 1;
	}

	if (e_info->keyInformation[0].keySize != NaN &&
	    e_info->keyInformation[0].keySize != info->keyInformation[0].keySize) {
		PRI_FAIL("keySize mismatch (expected[%u]; fromInfo[%u])",
			 e_info->keyInformation[0].keySize, info->keyInformation[0].keySize);
		return 1;
	}

	if (e_info->keyInformation[0].requiredKeyUsage != NaN &&
	    e_info->keyInformation[0].requiredKeyUsage != info->keyInformation[0].requiredKeyUsage) {
		PRI_FAIL("requiredKeyUsage mismatch (expected[%u]; fromInfo[%u])",
			 e_info->keyInformation[0].requiredKeyUsage,
			 info->keyInformation[0].requiredKeyUsage);
		return 1;
	}

	return 0;
}

static uint32_t sha256_digest_nist()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle sha256_operation = (TEE_OperationHandle)NULL;
	TEE_OperationInfoMultiple info;
	uint32_t op_alg = TEE_ALG_SHA256;
	uint32_t op_mode = TEE_MODE_DIGEST;
	uint32_t op_class = TEE_OPERATION_DIGEST;
	uint32_t keySize = 0;
	uint32_t sha256Size = 32;
	size_t operationSize;
	char hash[64] = {0};
	size_t hash_len = MAX_HASH_OUTPUT_LENGTH;
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_OperationInfoMultiple expectInfoM;
	expectInfoM.algorithm = op_alg;
	expectInfoM.operationClass = op_class;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = sha256Size;
	expectInfoM.maxKeySize = 0;
	expectInfoM.handleState = (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 0;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	ret = TEE_AllocateOperation(&sha256_operation, op_alg, op_mode, keySize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc sha256 handler");
		goto err;
	}

	TEE_GetOperationInfoMultiple(sha256_operation, &info, &operationSize);
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}
	
	ret = TEE_DigestDoFinal(sha256_operation,
				sha256msg, SIZE_OF_VEC(sha256msg), hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Final failed");
		goto err;
	}

	if (hash_len != SIZE_OF_VEC(sha256hash)) {
		PRI_FAIL("Length bhould be same");
		goto err;
	}

	if (TEE_MemCompare(hash, sha256hash, hash_len)) {
		PRI_FAIL("Hashes should be same");
		goto err;
	}

	TEE_GetOperationInfoMultiple(sha256_operation, &info, &operationSize);
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	fn_ret = 0; /* OK */

err:
	TEE_FreeOperation(sha256_operation);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static int warp_sym_op(TEE_ObjectHandle key,
		       TEE_OperationMode mode,
		       void *IV,
		       size_t IV_len,
		       uint32_t alg,
		       void *in_chunk,
		       size_t in_chunk_len,
		       void *out_chunk,
		       size_t *out_chunk_len,
		       uint32_t test_maxKeySize,
		       uint32_t test_keySize)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle handle = NULL;
	size_t write_bytes = 0, total_write_bytes = 0;
	TEE_ObjectInfo info;
	TEE_OperationInfoMultiple infoM;
	TEE_OperationInfoMultiple expectInfoM;
	size_t operationSize;
	
	expectInfoM.algorithm = alg;
	expectInfoM.operationClass = TEE_OPERATION_CIPHER;
	expectInfoM.mode = mode;
	expectInfoM.digestLength = 0;
	expectInfoM.maxKeySize = test_maxKeySize;
	expectInfoM.handleState = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	TEE_GetObjectInfo1(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(handle, &infoM, &operationSize);
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}
	
	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(handle, &infoM, &operationSize);
	expectInfoM.maxKeySize = test_maxKeySize;
	expectInfoM.keyInformation[0].keySize = test_keySize;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	TEE_CipherInit(handle, IV, IV_len);

	TEE_GetOperationInfoMultiple(handle, &infoM, &operationSize);
	expectInfoM.handleState = (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
	expectInfoM.operationState = TEE_OPERATION_STATE_ACTIVE;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}

	write_bytes = 1;
	ret = TEE_CipherUpdate(handle, in_chunk, in_chunk_len, out_chunk, &write_bytes);
	if (ret != TEE_ERROR_SHORT_BUFFER) {
		PRI_FAIL("Updated failure (expected short buffer): 0x%x", ret);
		goto err;
	}
	

	write_bytes = *out_chunk_len;

	ret = TEE_CipherUpdate(handle, in_chunk, in_chunk_len, out_chunk, &write_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Updated failure : 0x%x", ret);
		goto err;
	}

	total_write_bytes += write_bytes;
	write_bytes = *out_chunk_len - total_write_bytes;
		
	ret = TEE_CipherDoFinal(handle, NULL, 0,
				(unsigned char *)out_chunk + total_write_bytes, &write_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Do final failure : 0x%x", ret);
		goto err;
	}

	*out_chunk_len = total_write_bytes + write_bytes;

	TEE_GetOperationInfoMultiple(handle, &infoM, &operationSize);
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (4)");
		goto err;
	}
	
	TEE_FreeOperation(handle);
	return 0;
err:
	TEE_FreeOperation(handle);
	return 1;
}

static uint32_t aes_256_cbc_enc_dec()
{
	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t plain_len = 32;
	size_t cipher_len = 32;
	size_t dec_plain_len = plain_len;
	size_t IVlen = 16;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}
	TEE_GenerateRandom(IV, IVlen);
	TEE_MemMove(plain, plain_msg, 5);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_sym_op(key, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len, key_size, key_size))
		goto err;

	if (warp_sym_op(key, TEE_MODE_DECRYPT, IV, IVlen, alg,
			cipher, cipher_len, dec_plain, &dec_plain_len, key_size, key_size))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, dec_plain_len)) {
		PRI_FAIL("Plain text is not matching");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);

	return fn_ret;
}

static uint32_t aes_128_cbc_enc_dec()
{
	TEE_Result ret = TEE_SUCCESS;
	size_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t plain_len = 32;
	size_t cipher_len = 32;
	size_t dec_plain_len = plain_len;
	size_t IVlen = 16;

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;
	void *IV = NULL;

	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!IV || !plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}
	TEE_GenerateRandom(IV, IVlen);
	TEE_MemMove(plain, plain_msg, 5);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_sym_op(key, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len, key_size, key_size))
		goto err;

	if (warp_sym_op(key, TEE_MODE_DECRYPT, IV, IVlen, alg,
			cipher, cipher_len, dec_plain, &dec_plain_len, key_size, key_size))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, dec_plain_len)) {
		PRI_FAIL("Plain text is not matching");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(dec_plain);
	return fn_ret;
}

static int warp_asym_op(TEE_ObjectHandle key,
			TEE_OperationMode mode,
			uint32_t alg,
			TEE_Attribute *params,
			uint32_t paramCount,
			void *in_chunk,
			size_t in_chunk_len,
			void *out_chunk,
			size_t *out_chunk_len)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle handle = (TEE_OperationHandle)NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo1(key, &info);

	ret = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(handle, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	if (mode == TEE_MODE_SIGN) {

		ret = TEE_AsymmetricSignDigest(handle, params, paramCount,
					       in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Sign failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_VERIFY) {

		ret = TEE_AsymmetricVerifyDigest(handle, params, paramCount,
						 in_chunk, in_chunk_len, out_chunk, *out_chunk_len);
		if (ret == TEE_SUCCESS) {
			/* Do nothing */
		} else if (ret == TEE_ERROR_SIGNATURE_INVALID) {
			PRI_FAIL("Signature invalid");
			goto err;
		} else {
			PRI_FAIL("Verify failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_ENCRYPT) {

		ret = TEE_AsymmetricEncrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Encrypt failed : 0x%x", ret);
			goto err;
		}

	} else if (mode == TEE_MODE_DECRYPT) {

		ret = TEE_AsymmetricDecrypt(handle, params, paramCount,
					    in_chunk, in_chunk_len, out_chunk, out_chunk_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Decrypt failed : 0x%x", ret);
			goto err;
		}

	} else {
		goto err;
	}

	TEE_FreeOperation(handle);
	return 0;

err:
	TEE_FreeOperation(handle);
	return 1;
}

static uint32_t do_rsa_sign_nist_sha1_pkcs(bool fromStorage)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectHandle nistKey = NULL, usedKey = NULL;
	TEE_ObjectHandle perObject = NULL;
	char hash[64] = {0}; //sha1
	char signature[256] = {0}; //1024
	size_t signature_len = 256, hash_len = 64;
	TEE_Attribute rsa_attrs[3];
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, fn_ret = 1; /* Init error return */;
	char objID[] = "2222222222222222222222222222223322226622222222222222222222222222";//64
	size_t objID_len = 45;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	
	/* Modulo */
	rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
	rsa_attrs[0].content.ref.buffer = modulus;
	rsa_attrs[0].content.ref.length = SIZE_OF_VEC(modulus);

	rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	rsa_attrs[1].content.ref.buffer = public_exp_4_bytes;
	rsa_attrs[1].content.ref.length = SIZE_OF_VEC(public_exp_4_bytes);

	/* Private exp */
	rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
	rsa_attrs[2].content.ref.buffer = private_exp;
	rsa_attrs[2].content.ref.length = SIZE_OF_VEC(private_exp);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 1024, &nistKey);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc object handler");
		goto err;
	}

	ret = TEE_PopulateTransientObject(nistKey, (TEE_Attribute *)&rsa_attrs, 3);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA key population failed");
		goto err;
	}

	
	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, nistKey, NULL, 0,
						 (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}

		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       (void *)objID, objID_len, flags, &perObject);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}

		usedKey = perObject;
	} else {
		usedKey = nistKey;
	}
	
	if (calc_digest(TEE_ALG_SHA1, rsa_msg, SIZE_OF_VEC(rsa_msg), hash, &hash_len))
		goto err;

	if (warp_asym_op(usedKey, TEE_MODE_SIGN, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (void *)hash, hash_len, (void *)signature, &signature_len))
		goto err;

	if (SIZE_OF_VEC(rsa_sig) != signature_len) {
		PRI_FAIL("Signature length invalid (expected[%lu]; calculated[%lu])",
			 SIZE_OF_VEC(rsa_sig), signature_len);
		goto err;
	}

	if (TEE_MemCompare(rsa_sig, signature, signature_len)) {
		PRI_FAIL("Signature invalid");
		goto err;
	}

	if (warp_asym_op(usedKey, TEE_MODE_VERIFY, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (void *)hash, hash_len, (void *)signature, &signature_len))
		goto err;

	fn_ret = 0; /* OK */

err:
	TEE_FreeTransientObject(nistKey);
	if (fromStorage) {
		TEE_CloseAndDeletePersistentObject1(perObject);
	} else {
		//Nothing due nistKey == usedKey
	}
	
	return fn_ret;
}

static uint32_t ECDSA_sig_and_ver(uint32_t curve, uint32_t keysize,
				  uint32_t alg, uint32_t hashlen)
{
	TEE_Result ret;
	TEE_ObjectHandle ecdsa_keypair = (TEE_ObjectHandle)NULL;
	TEE_Attribute ecdsa_attrs[1];
	size_t key_size = keysize;
	uint32_t ecdsa_alg = alg;
	char *dig_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t dig_len = hashlen;
	/* enough for a p521 sig */
	size_t sig_len = 160;

	void *dig = NULL;
	void *sig = NULL;

	dig = TEE_Malloc(dig_len, 0);
	sig = TEE_Malloc(sig_len, 0);
	if (!dig || !sig) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(dig, dig_msg, 5);

	/* Curve */
	ecdsa_attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
	ecdsa_attrs[0].content.value.a = curve;
	ecdsa_attrs[0].content.value.b = 0;

	ret = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_size, &ecdsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(ecdsa_keypair, key_size, ecdsa_attrs, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(ecdsa_keypair, TEE_MODE_SIGN, ecdsa_alg, ecdsa_attrs, 1,
			 dig, dig_len, sig, &sig_len))
		goto err;

	if (warp_asym_op(ecdsa_keypair, TEE_MODE_VERIFY, ecdsa_alg, ecdsa_attrs, 1,
			 dig, dig_len, sig, &sig_len))
		goto err;

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(ecdsa_keypair);
	TEE_Free(dig);
	TEE_Free(sig);

	if (fn_ret == 0)
		PRI_OK("- with key size %u", keysize);

	return fn_ret;
}

static uint32_t ECDSA_set_key_and_rm_and_do_crypto(uint32_t curve, uint32_t keysize,
						   uint32_t alg, uint32_t hashlen)
{
	TEE_Result ret;
	TEE_ObjectHandle ecdsa_keypair = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle sign_op = (TEE_OperationHandle)NULL,
			verify_op = (TEE_OperationHandle)NULL;
	TEE_Attribute ecdsa_attrs[1];
	size_t key_size = keysize;
	uint32_t ecdsa_alg = alg;
	char *dig_seed = "TEST";
	size_t dig_len = hashlen, sig_len = 160;
	char dig[MAX_HASH_OUTPUT_LENGTH] = {0}, sig[160] = {0};
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_MemMove(dig, dig_seed, 5);

	/* Curve */
	ecdsa_attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
	ecdsa_attrs[0].content.value.a = curve;
	ecdsa_attrs[0].content.value.b = 0;

	ret = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_size, &ecdsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(ecdsa_keypair, key_size, ecdsa_attrs, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&sign_op, ecdsa_alg, TEE_MODE_SIGN, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc sign operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&verify_op, ecdsa_alg, TEE_MODE_VERIFY, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc verify operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(sign_op, ecdsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set sign operation key : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(verify_op, ecdsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set verify operation key : 0x%x", ret);
		goto err;
	}

	TEE_FreeTransientObject(ecdsa_keypair);
	ecdsa_keypair = (TEE_ObjectHandle)NULL;

	ret = TEE_AsymmetricSignDigest(sign_op, (TEE_Attribute *)NULL, 0,
				       dig, dig_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(verify_op, (TEE_Attribute *)NULL, 0,
					 dig, dig_len, sig, sig_len);
	if (ret == TEE_SUCCESS) {
		/* Do nothing */
	} else if (ret == TEE_ERROR_SIGNATURE_INVALID) {
		PRI_FAIL("Signature invalid");
		goto err;
	} else {
		PRI_FAIL("Verify failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(ecdsa_keypair);
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(verify_op);

	if (fn_ret == 0)
		PRI_OK("- with key size: %u", keysize);

	return fn_ret;
}

static uint32_t nist_ecdsa_sign()
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	TEE_OperationHandle op_sign = NULL, op_verify = NULL;
	uint32_t key_size = 256;
	uint32_t key_type = TEE_TYPE_ECDSA_KEYPAIR;
	uint32_t op_alg = TEE_ALG_ECDSA_SHA256;
	uint32_t op_mode_sign = TEE_MODE_SIGN;
	uint32_t op_mode_verify = TEE_MODE_VERIFY;
	uint32_t op_max_size = 256;
	uint32_t param_count = 4, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params[4] = {0};
	char hash[MAX_HASH_OUTPUT_LENGTH];
	size_t hash_len = MAX_HASH_OUTPUT_LENGTH;
	char sig[200] = {0};
	size_t sig_len = 200;

	char msg[500] = {0};
	size_t msg_len = SIZE_OF_VEC(ecc_msg_p256);
	TEE_MemMove(msg, ecc_msg_p256, msg_len);

	// Qx
	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = ecc_qx_p256;
	params[0].content.ref.length = SIZE_OF_VEC(ecc_qx_p256);

	// Qy
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = ecc_qy_p256;
	params[1].content.ref.length = SIZE_OF_VEC(ecc_qy_p256);

	// R
	params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	params[2].content.ref.buffer = ecc_d_p256;
	params[2].content.ref.length = SIZE_OF_VEC(ecc_d_p256);
	
	// Curve
	params[3].attributeID = TEE_ATTR_ECC_CURVE;
	params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
	params[3].content.value.b = 0;

	if (calc_digest(TEE_ALG_SHA256, ecc_msg_p256, SIZE_OF_VEC(ecc_msg_p256), hash, &hash_len))
		goto err;
	
	ret = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("ECC key pair population failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&op_sign, op_alg, op_mode_sign, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(op_sign, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&op_verify, op_alg, op_mode_verify, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(op_verify, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0,
				       hash, hash_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(op_verify, NULL, 0,
				       hash, hash_len, sig, sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Verify failed : 0x%x", ret);
		goto err;
	}
	
	fn_ret = 0; // OK

err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(op_sign);
	TEE_FreeOperation(op_verify);
	return fn_ret;	
}

static uint32_t rfc_ecdsa_sign()
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	TEE_OperationHandle op_sign = NULL, op_verify = NULL;
	uint32_t key_size = 256;
	uint32_t key_type = TEE_TYPE_ECDSA_KEYPAIR;
	uint32_t op_alg = TEE_ALG_ECDSA_SHA256;
	uint32_t op_mode_sign = TEE_MODE_SIGN;
	uint32_t op_max_size = 256;
	uint32_t param_count = 4, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params[4] = {0};
	unsigned char hash[MAX_HASH_OUTPUT_LENGTH];
	size_t hash_len = MAX_HASH_OUTPUT_LENGTH;
	unsigned char sig[200] = {0};
	size_t sig_len = 200;

	// Qx
	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = ecc_rfc_qx_p256;
	params[0].content.ref.length = SIZE_OF_VEC(ecc_qx_p256);

	// Qy
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = ecc_rfc_qy_p256;
	params[1].content.ref.length = SIZE_OF_VEC(ecc_qy_p256);

	// R
	params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	params[2].content.ref.buffer = ecc_rfc_d_p256;
	params[2].content.ref.length = SIZE_OF_VEC(ecc_d_p256);
	
	// Curve
	params[3].attributeID = TEE_ATTR_ECC_CURVE;
	params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
	params[3].content.value.b = 0;

	if (calc_digest(TEE_ALG_SHA256, ecc_rfc_msg_p256, 6, hash, &hash_len))
		goto err;
	
	ret = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("ECC key pair population failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&op_sign, op_alg, op_mode_sign, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(op_sign, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0,
				       hash, hash_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	if (sig_len != 72) {
		PRI_FAIL("Not expected signature lenght");
		goto err;
	}

	if (TEE_MemCompare(sig + 5, ecc_rfc_r_p256, 32)) {
		PRI_FAIL("Not expected r-component");
		goto err;
	}

	if (TEE_MemCompare(sig + 40, ecc_rfc_s_p256, 32)) {
		PRI_FAIL("Not expected r-component");
		goto err;
	}
	fn_ret = 0; // OK

err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(op_sign);
	return fn_ret;	
}

static uint32_t basic_ecdsa_gen_sign_verify()
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	uint32_t obj_type = TEE_TYPE_ECDSA_KEYPAIR;
	uint32_t key_size = 256;
	uint32_t op_alg = TEE_ALG_ECDSA_SHA256;
	uint32_t op_mode_sign = TEE_MODE_SIGN;
	uint32_t op_mode_verify = TEE_MODE_VERIFY;
	uint32_t op_max_size = 256;
	TEE_OperationHandle op_sign = NULL, op_verify = NULL;
	uint32_t param_count = 1, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params = {0};
	char hash[MAX_HASH_OUTPUT_LENGTH];
	size_t hash_len = MAX_HASH_OUTPUT_LENGTH;
	char sig[200] = {0};
	size_t sig_len = 200;

	params.attributeID = TEE_ATTR_ECC_CURVE;
	params.content.value.a = TEE_ECC_CURVE_NIST_P256;
	
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, &params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Key generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&op_sign, op_alg, op_mode_sign, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(op_sign, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set sign key : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&op_verify, op_alg, op_mode_verify, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_SetOperationKey(op_verify, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set verify key : 0x%x", ret);
		goto err;
	}

	if (calc_digest(TEE_ALG_SHA256, ecc_msg_p256, SIZE_OF_VEC(ecc_msg_p256), hash, &hash_len))
		goto err;
		
	ret = TEE_AsymmetricSignDigest(op_sign, NULL, 0,
				       hash, hash_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(op_verify, NULL, 0,
				       hash, hash_len, sig, sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Verify failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; // OK

err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(op_sign);
	TEE_FreeOperation(op_verify);
	return fn_ret;	
}

static uint32_t run_ecdsa_tests()
{
	if (nist_ecdsa_sign()) {
		return 1;
	}

	if (rfc_ecdsa_sign()) {
		return 1;
	}

	if (basic_ecdsa_gen_sign_verify()) {
		return 1;
	}
	
	// run the tests for all the curves
	if (ECDSA_sig_and_ver(TEE_ECC_CURVE_NIST_P192, 192, TEE_ALG_ECDSA_SHA1, SHA1_SIZE) ||
	    ECDSA_sig_and_ver(TEE_ECC_CURVE_NIST_P224, 224, TEE_ALG_ECDSA_SHA224, SHA224_SIZE) ||
	    ECDSA_sig_and_ver(TEE_ECC_CURVE_NIST_P256, 256, TEE_ALG_ECDSA_SHA256, SHA256_SIZE) ||
	    ECDSA_sig_and_ver(TEE_ECC_CURVE_NIST_P384, 384, TEE_ALG_ECDSA_SHA384, SHA384_SIZE) ||
	    ECDSA_sig_and_ver(TEE_ECC_CURVE_NIST_P521, 521, TEE_ALG_ECDSA_SHA512, SHA512_SIZE) ||
	    ECDSA_set_key_and_rm_and_do_crypto(TEE_ECC_CURVE_NIST_P192, 192, TEE_ALG_ECDSA_SHA1, SHA1_SIZE) ||
	    ECDSA_set_key_and_rm_and_do_crypto(TEE_ECC_CURVE_NIST_P224, 224, TEE_ALG_ECDSA_SHA224, SHA224_SIZE) ||
	    ECDSA_set_key_and_rm_and_do_crypto(TEE_ECC_CURVE_NIST_P256, 256, TEE_ALG_ECDSA_SHA256, SHA256_SIZE) ||
	    ECDSA_set_key_and_rm_and_do_crypto(TEE_ECC_CURVE_NIST_P384, 384, TEE_ALG_ECDSA_SHA384, SHA384_SIZE) ||
	    ECDSA_set_key_and_rm_and_do_crypto(TEE_ECC_CURVE_NIST_P521, 521, TEE_ALG_ECDSA_SHA512, SHA512_SIZE))
		return 1;

	PRI_OK("-");
	return 0;	
}

static uint32_t RSA_sig_and_ver()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
	char *dig_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t dig_len = 20;
	size_t sig_len = 64;

	void *dig = NULL;
	void *sig = NULL;

	dig = TEE_Malloc(dig_len, 0);
	sig = TEE_Malloc(sig_len, 0);
	if (!dig || !sig) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(dig, dig_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(rsa_keypair, TEE_MODE_SIGN, rsa_alg, (TEE_Attribute *)NULL, 0,
			 dig, dig_len, sig, &sig_len))
		goto err;

	if (warp_asym_op(rsa_keypair, TEE_MODE_VERIFY, rsa_alg, (TEE_Attribute *)NULL, 0,
			 dig, dig_len, sig, &sig_len))
		goto err;

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(dig);
	TEE_Free(sig);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t HMAC_computation_basic()
{
	TEE_Result ret;
	TEE_ObjectHandle hmac_key = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle hmac_handle = (TEE_OperationHandle)NULL;
	TEE_OperationHandle hmac_handle2 = (TEE_OperationHandle)NULL;
	size_t key_size = 256;
	uint32_t alg = TEE_ALG_HMAC_SHA256;
	uint32_t alg2 = TEE_ALG_HMAC_SHA256;
	char *seed_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	size_t mac_len = 64;
	size_t msg_len = 100;

	void *mac = NULL;
	void *msg = NULL;

	mac = TEE_Malloc(mac_len, 0);
	msg = TEE_Malloc(msg_len, 0);
	if (!mac || !msg) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(msg, seed_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_size, &hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(hmac_key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle, alg, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	ret = TEE_AllocateOperation(&hmac_handle2, alg2, TEE_MODE_MAC, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc second handler");
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle, hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(hmac_handle2, hmac_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set second operation key : 0x%x", ret);
		goto err;
	}

	TEE_MACInit(hmac_handle, NULL, 0);

	TEE_MACUpdate(hmac_handle, msg, msg_len);

	ret = TEE_MACComputeFinal(hmac_handle, NULL, 0, mac, &mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("First final failed : 0x%x", ret);
		goto err;
	}

	TEE_MACInit(hmac_handle2, NULL, 0);

	ret = TEE_MACCompareFinal(hmac_handle2, msg, msg_len, mac, mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("MAC Invalid");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(hmac_key);
	TEE_FreeOperation(hmac_handle);
	TEE_FreeOperation(hmac_handle2);
	TEE_Free(mac);
	TEE_Free(msg);

	return fn_ret;
}

static uint32_t RSA_generate_keypair_enc_dec(size_t key_size, uint32_t rsa_alg, size_t plain_len, size_t cipher_len, size_t dec_plain_len)
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	char *plain_msg = "TEST";
	uint32_t fn_ret = 1; /* Initialized error return */

	void *plain = NULL;
	void *cipher = NULL;
	void *dec_plain = NULL;

	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	dec_plain = TEE_Malloc(dec_plain_len, 0);
	if (!plain || !cipher || !dec_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain, plain_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	if (warp_asym_op(rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, cipher, &cipher_len))
		goto err;
	
	if (warp_asym_op(rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (TEE_MemCompare(dec_plain, plain, plain_len)) {
		PRI_FAIL("Decrypted not matching to original\n");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_Free(plain);
	TEE_Free(dec_plain);
	TEE_Free(cipher);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t RSA_keypair_enc_dec()
{
	// run the tests for all the algorithms
	if (RSA_generate_keypair_enc_dec(512, TEE_ALG_RSAES_PKCS1_V1_5, 10, 64, 64) ||
	    RSA_generate_keypair_enc_dec(512, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, 10, 64, 64) ||
	    RSA_generate_keypair_enc_dec(2048, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224, 10, 256, 256) ||
	    RSA_generate_keypair_enc_dec(2048, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, 10, 256, 256) ||
	    RSA_generate_keypair_enc_dec(2048, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384, 10, 256, 256) ||
	    RSA_generate_keypair_enc_dec(2048, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512, 10, 256, 256))
		return 1;

	PRI_OK("-");
	return 0;
}

static uint32_t set_key_and_rm_and_do_crypto()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle sign_op = (TEE_OperationHandle)NULL,
			verify_op = (TEE_OperationHandle)NULL;
	size_t key_size = 512;
	uint32_t rsa_alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
	char *dig_seed = "TEST";
	size_t dig_len = 32, sig_len = 64;
	char dig[32] = {0}, sig[64] = {0};
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_MemMove(dig, dig_seed, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&sign_op, rsa_alg, TEE_MODE_SIGN, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc sign operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&verify_op, rsa_alg, TEE_MODE_VERIFY, key_size * 2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc verify operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(sign_op, rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set sign operation key : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(verify_op, rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set verify operation key : 0x%x", ret);
		goto err;
	}

	TEE_FreeTransientObject(rsa_keypair);
	rsa_keypair = (TEE_ObjectHandle)NULL;

	ret = TEE_AsymmetricSignDigest(sign_op, (TEE_Attribute *)NULL, 0,
				       dig, dig_len, sig, &sig_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Sign failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AsymmetricVerifyDigest(verify_op, (TEE_Attribute *)NULL, 0,
					 dig, dig_len, sig, sig_len);
	if (ret == TEE_SUCCESS) {
		/* Do nothing */
	} else if (ret == TEE_ERROR_SIGNATURE_INVALID) {
		PRI_FAIL("Signature invalid");
		goto err;
	} else {
		PRI_FAIL("Verify failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(verify_op);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t read_key_and_do_crypto()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_keypair = (TEE_ObjectHandle)NULL,
			persisten_rsa_keypair = (TEE_ObjectHandle)NULL;
	char objID[] = "56c5d1b260704de30fe99f67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	uint32_t objID_len = 45;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5, key_size = 512;
	char *plain_msg = "TEST";
	size_t plain_len = 10, cipher_len = 64, dec_plain_len = 64,
			per_cipher_len = 64, per_dec_plain_len = 64;
	char plain[10] = {0}, cipher[64] = {0}, dec_plain[64] = {0},
			per_cipher[64] = {0}, per_dec_plain[64] = {0};
	uint32_t fn_ret = 1; /* Initialized error return */

	TEE_MemMove(plain, plain_msg, 5);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(rsa_keypair, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Generate key failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 0, rsa_keypair, NULL, 0,
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &persisten_rsa_keypair);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	/* Transient object */
	if (warp_asym_op(rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, cipher, &cipher_len))
		goto err;

	if (warp_asym_op(rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)cipher, cipher_len, dec_plain, &dec_plain_len))
		goto err;

	if (dec_plain_len != plain_len || TEE_MemCompare(dec_plain, plain, plain_len)) {
		PRI_FAIL("Decrypted not matching to original");
		goto err;
	}

	/* Persistent object */
	if (warp_asym_op(persisten_rsa_keypair, TEE_MODE_ENCRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 plain, plain_len, per_cipher, &per_cipher_len))
		goto err;

	if (warp_asym_op(persisten_rsa_keypair, TEE_MODE_DECRYPT, rsa_alg, (TEE_Attribute *)NULL, 0,
			 (unsigned char *)per_cipher, per_cipher_len,
			 per_dec_plain, &per_dec_plain_len))
		goto err;

	if (per_dec_plain_len != plain_len ||
	    TEE_MemCompare(dec_plain, per_dec_plain, dec_plain_len)) {
		PRI_FAIL("Persisten decrypted not matching plain text");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(rsa_keypair);
	TEE_CloseAndDeletePersistentObject1(persisten_rsa_keypair);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}


static uint32_t aes_per()
{
	TEE_ObjectHandle perkey = NULL;
	TEE_ObjectHandle key = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t key_size = 128;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	uint32_t fn_ret = 1; // Initialized error return
	char objID[] = "1111111111111111111111111121111111111111111111111111111111111111";//64
	uint32_t objID_len = 64;
	TEE_Attribute aes_key = {0};
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	
	size_t plain_len = SIZE_OF_VEC(aes_cbc_plain_128);
	size_t cipher_len = 200; //Random lenght. Function will assign correct length
	size_t IVlen = SIZE_OF_VEC(aes_cbc_iv_128);
	size_t expect_cipher_len = SIZE_OF_VEC(aes_cbc_cipher_128);
		
	void *plain = NULL;
	void *cipher = NULL;
	void *IV = NULL;
	void *expect_cipher = NULL;

	//AES key
	aes_key.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key.content.ref.length = SIZE_OF_VEC(aes_cbc_key_128);
	aes_key.content.ref.buffer = aes_cbc_key_128;
	
	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	expect_cipher =  TEE_Malloc(expect_cipher_len, 0);
	if (!IV || !plain || !cipher || !expect_cipher) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain, aes_cbc_plain_128, plain_len);
	TEE_MemMove(IV, aes_cbc_iv_128, IVlen);
	TEE_MemMove(expect_cipher, aes_cbc_cipher_128, expect_cipher_len);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA key population failed");
		goto err;
	}
	
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 0, key, NULL, 0, (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &perkey);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	if (warp_sym_op(perkey, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len, key_size, key_size)) {
		goto err;
	}

	if (expect_cipher_len != cipher_len) {
		PRI_FAIL("Cipher text length is wrong (expectLen[%lu]; cipherLen[%lu])",
			 expect_cipher_len, cipher_len);
		goto err;
	}
	
	if (TEE_MemCompare(cipher, expect_cipher, expect_cipher_len)) {
		PRI_FAIL("Cipher text is wrong");
		goto err;
	}
	
	fn_ret = 0; //Ok
err:
	TEE_FreeTransientObject(key);
	TEE_CloseAndDeletePersistentObject1(perkey);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(expect_cipher);
	return fn_ret;	
}

static uint32_t sha1_digest_nist()
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle sha1_operation = (TEE_OperationHandle)NULL;
	char hash[MAX_HASH_OUTPUT_LENGTH] = {0};
	size_t hash_len = MAX_HASH_OUTPUT_LENGTH, fn_ret = 1; /* Initialized error return */

	ret = TEE_AllocateOperation(&sha1_operation, TEE_ALG_SHA1, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc sha256 handler");
		goto err;
	}

	ret = TEE_DigestDoFinal(sha1_operation,
				sha1msg, SIZE_OF_VEC(sha1msg), hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Digest failed : 0x%x", ret);
		goto err;
	}

	if (hash_len != SIZE_OF_VEC(sha1hash)) {
		PRI_FAIL("Sha1 hash lenght error (expected[%lu]; calculated[%lu])",
			 SIZE_OF_VEC(sha1hash), hash_len);
		goto err;
	}

	if (TEE_MemCompare(hash, sha1hash, hash_len)) {
		PRI_FAIL("SHA1 hash is not correct");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeOperation(sha1_operation);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t aes_256_ctr_nist()
{
	TEE_ObjectHandle key = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t alg = TEE_ALG_AES_CTR;
	uint32_t fn_ret = 1; // Initialized error return
	TEE_Attribute aes_key = {0};
	
	size_t plain_len = SIZE_OF_VEC(aes_ctr_plain_256);
	size_t cipher_len = 210; //Random lenght. Function will assign correct length
	size_t IVlen = SIZE_OF_VEC(aes_ctr_ctr_256);
	size_t expect_cipher_len = SIZE_OF_VEC(aes_ctr_cipher_256);
		
	void *plain = NULL;
	void *cipher = NULL;
	void *IV = NULL;
	void *expect_cipher = NULL;

	//AES key
	aes_key.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key.content.ref.length = SIZE_OF_VEC(aes_ctr_key_256);
	aes_key.content.ref.buffer = aes_ctr_key_256;
	
	IV = TEE_Malloc(IVlen, 0);
	plain = TEE_Malloc(plain_len, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	expect_cipher =  TEE_Malloc(expect_cipher_len, 0);
	if (!IV || !plain || !cipher || !expect_cipher) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain, aes_ctr_plain_256, plain_len);
	TEE_MemMove(IV, aes_ctr_ctr_256, IVlen);
	TEE_MemMove(expect_cipher, aes_ctr_cipher_256, expect_cipher_len);

	/* Alloc and gen keys */
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA key population failed");
		goto err;
	}

	if (warp_sym_op(key, TEE_MODE_ENCRYPT, IV, IVlen, alg,
			plain, plain_len, cipher, &cipher_len, key_size, key_size)) {
		goto err;
	}

	if (expect_cipher_len != cipher_len) {
		PRI_FAIL("Cipher text length is wrong (expectLen[%lu]; cipherLen[%lu])",
			 expect_cipher_len, cipher_len);
		goto err;
	}
	
	if (TEE_MemCompare(cipher, expect_cipher, expect_cipher_len)) {
		PRI_FAIL("Cipher text is wrong");
		goto err;
	}
	
	fn_ret = 0; //Ok
err:
	TEE_FreeTransientObject(key);
	TEE_Free(plain);
	TEE_Free(IV);
	TEE_Free(cipher);
	TEE_Free(expect_cipher);

	return fn_ret;	
}

static uint32_t hmac_sha1_nist(bool fromStorage)
{
	TEE_Result ret;
	TEE_ObjectHandle nistKey = NULL, usedKey = NULL, perObject = NULL;
	TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
	uint32_t key_type = TEE_TYPE_HMAC_SHA1;
	uint32_t key_size = SIZE_OF_VEC(hmac_sha1_key) * 8; // x * 8 = converts to bits
	uint32_t max_key_size = 504;
	uint32_t alg = TEE_ALG_HMAC_SHA1;
	uint32_t op_mode = TEE_MODE_MAC;
	uint32_t fn_ret = 1; /* Initialized error return */
	TEE_Attribute hmac_key;
	char objID[] = "2222222222222222212342222222222222222222222222222222222222222222";//64
	uint32_t objID_len = 45;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	
	size_t msg_len = SIZE_OF_VEC(hmac_sha1_msg);
	size_t mac_len = 189; //Random lenght. Function will assign correct length
	size_t expect_mac_len = SIZE_OF_VEC(hmac_sha1_mac);
	
	void *msg = NULL;
	void *mac = NULL;
	void *expect_mac = NULL;

	TEE_OperationInfoMultiple infoM;
	TEE_OperationInfoMultiple expectInfoM;
	size_t operationSize;
	
	expectInfoM.algorithm = alg;
	expectInfoM.operationClass = TEE_OPERATION_MAC;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = expect_mac_len;
	expectInfoM.maxKeySize = max_key_size;
	expectInfoM.handleState = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	//hmac key
	hmac_key.attributeID = TEE_ATTR_SECRET_VALUE;
	hmac_key.content.ref.length = SIZE_OF_VEC(hmac_sha1_key);
	hmac_key.content.ref.buffer = hmac_sha1_key;
	
	msg = TEE_Malloc(msg_len, 0);
	mac = TEE_Malloc(mac_len, 0);
	expect_mac = TEE_Malloc(expect_mac_len, 0);
	if (!msg || !mac || !expect_mac) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(msg, hmac_sha1_msg, msg_len);
	TEE_MemMove(expect_mac, hmac_sha1_mac, expect_mac_len);

	ret = TEE_AllocateTransientObject(key_type, max_key_size, &nistKey);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_PopulateTransientObject(nistKey, &hmac_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("TEE_PopulateTransientObject failure : 0x%x", ret);
		goto err;
	}

	if (fromStorage) {
		ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
						 0, nistKey, NULL, 0,
						 (TEE_ObjectHandle *)NULL);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Create persisten object failed : 0x%x", ret);
			goto err;
		}
		
		ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       (void *)objID, objID_len, flags, &perObject);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Open failed : 0x%x", ret);
			goto err;
		}
		
		usedKey = perObject;
	} else {
		usedKey = nistKey;
	}
		
	ret = TEE_AllocateOperation(&operation, alg, TEE_MODE_MAC, max_key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}

	
	ret = TEE_SetOperationKey(operation, usedKey);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	expectInfoM.keyInformation[0].keySize = key_size;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	TEE_MACInit(operation, NULL, 0);

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED;
	expectInfoM.operationState = TEE_OPERATION_STATE_ACTIVE;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	TEE_MACUpdate(operation, msg, msg_len);

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}

	mac_len = 2; //SHORT!
	ret = TEE_MACComputeFinal(operation, NULL, 0, mac, &mac_len);
	if (ret != TEE_ERROR_SHORT_BUFFER) {
		PRI_FAIL("First final failed : 0x%x", ret);
		goto err;
	}

	mac_len = 189;
	ret = TEE_MACComputeFinal(operation, NULL, 0, mac, &mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("First final failed : 0x%x", ret);
		goto err;
	}

	if (mac_len != expect_mac_len) {
		PRI_FAIL("Not expected mac lenght (calculated[%lu]; expected[%lu])",
			 mac_len, expect_mac_len);
		goto err;
	}

	if (TEE_MemCompare(mac, expect_mac, expect_mac_len)) {
		PRI_FAIL("Not expected MAC");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (4)");
		goto err;
	}
	
	/*ret = TEE_MACCompareFinal(operation, msg, msg_len, mac, mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("MAC Invalid");
		goto err;
		}*/

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(nistKey);
	if (fromStorage) {
		TEE_CloseAndDeletePersistentObject1(perObject);
	} else {
		//Nothing due nistKey == usedKey
	}
	TEE_FreeOperation(operation);
	TEE_Free(mac);
	TEE_Free(msg);
	TEE_Free(expect_mac);
	
	return fn_ret;
}

static uint32_t aes_192_256_ctr_nist()
{
	TEE_OperationHandle operation = NULL;
	TEE_ObjectHandle key_192 = NULL, key_256 = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t max_key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t op_alg = TEE_ALG_AES_CTR;
	uint32_t fn_ret = 1; // Initialized error return
	TEE_Attribute aes_key_192 = {0}, aes_key_256 = {0};
	uint32_t op_mode = TEE_MODE_ENCRYPT;
	
	size_t plain_192_len = SIZE_OF_VEC(aes_ctr_plain_192);
	size_t cipher_192_len = 210; //Random lenght. Function will assign correct length
	size_t IV_192_len = SIZE_OF_VEC(aes_ctr_ctr_192);
	size_t expect_cipher_192_len = SIZE_OF_VEC(aes_ctr_cipher_192);

	void *plain_192 = NULL;
	void *cipher_192 = NULL;
	void *IV_192 = NULL;
	void *expect_cipher_192 = NULL;
	
	size_t plain_256_len = SIZE_OF_VEC(aes_ctr_plain_256);
	size_t cipher_256_len = 210; //Random lenght. Function will assign correct length
	size_t IV_256_len = SIZE_OF_VEC(aes_ctr_ctr_256);
	size_t expect_cipher_256_len = SIZE_OF_VEC(aes_ctr_cipher_256);

	void *plain_256 = NULL;
	void *cipher_256 = NULL;
	void *IV_256 = NULL;
	void *expect_cipher_256 = NULL;

	//AES key 192
	aes_key_192.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key_192.content.ref.length = SIZE_OF_VEC(aes_ctr_key_192);
	aes_key_192.content.ref.buffer = aes_ctr_key_192;

	//AES key 256
	aes_key_256.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key_256.content.ref.length = SIZE_OF_VEC(aes_ctr_key_256);
	aes_key_256.content.ref.buffer = aes_ctr_key_256;	
	
	IV_192 = TEE_Malloc(IV_192_len, 0);
	plain_192 = TEE_Malloc(plain_192_len, 0);
	cipher_192 = TEE_Malloc(cipher_192_len, 0);
	expect_cipher_192 =  TEE_Malloc(expect_cipher_192_len, 0);
	if (!IV_192 || !plain_192 || !cipher_192 || !expect_cipher_192) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain_192, aes_ctr_plain_192, plain_192_len);
	TEE_MemMove(IV_192, aes_ctr_ctr_192, IV_192_len);
	TEE_MemMove(expect_cipher_192, aes_ctr_cipher_192, expect_cipher_192_len);

	IV_256 = TEE_Malloc(IV_256_len, 0);
	plain_256 = TEE_Malloc(plain_256_len, 0);
	cipher_256 = TEE_Malloc(cipher_256_len, 0);
	expect_cipher_256 =  TEE_Malloc(expect_cipher_256_len, 0);
	if (!IV_256 || !plain_256 || !cipher_256 || !expect_cipher_256) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain_256, aes_ctr_plain_256, plain_256_len);
	TEE_MemMove(IV_256, aes_ctr_ctr_256, IV_256_len);
	TEE_MemMove(expect_cipher_256, aes_ctr_cipher_256, expect_cipher_256_len);
	
	ret = TEE_AllocateTransientObject(obj_type, 192, &key_192);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle (192) : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key_192, (TEE_Attribute *)&aes_key_192, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("AES 192 key population failed");
		goto err;
	}

	ret = TEE_AllocateTransientObject(obj_type, 256, &key_256);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle (256): 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key_256, (TEE_Attribute *)&aes_key_256, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("AES 256 key population failed");
		goto err;
	}

	ret = TEE_AllocateOperation(&operation, op_alg, op_mode, max_key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_SetOperationKey(operation, key_192);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key (192) : 0x%x", ret);
		goto err;
	}

	TEE_CipherInit(operation, IV_192, IV_192_len);

	ret = TEE_CipherDoFinal(operation, plain_192, plain_192_len, cipher_192, &cipher_192_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Do final failure : 0x%x", ret);
		goto err;
	}

	if (expect_cipher_192_len != cipher_192_len) {
		PRI_FAIL("Cipher text length is wrong (192) (expectLen[%lu]; cipherLen[%lu])",
			 expect_cipher_192_len, cipher_192_len);
		goto err;
	}
	
	if (TEE_MemCompare(cipher_192, expect_cipher_192, expect_cipher_192_len)) {
		PRI_FAIL("Cipher text is wrong (192)");
		goto err;
	}

	ret = TEE_SetOperationKey(operation, key_256);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key (256) : 0x%x", ret);
		goto err;
	}

	TEE_CipherInit(operation, IV_256, IV_256_len);

	ret = TEE_CipherDoFinal(operation, plain_256, plain_256_len, cipher_256, &cipher_256_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Do final failure (256) : 0x%x", ret);
		goto err;
	}

	if (expect_cipher_256_len != cipher_256_len) {
		PRI_FAIL("Cipher text length is wrong (256) (expectLen[%lu]; cipherLen[%lu])",
			 expect_cipher_256_len, cipher_256_len);
		goto err;
	}
	
	if (TEE_MemCompare(cipher_256, expect_cipher_256, expect_cipher_256_len)) {
		PRI_FAIL("Cipher text is wrong (256)");
		goto err;
	}
	
	fn_ret = 0; //Ok
err:
	TEE_FreeOperation(operation);
	TEE_FreeTransientObject(key_192);
	TEE_FreeTransientObject(key_256);

	TEE_Free(plain_192);
	TEE_Free(IV_192);
	TEE_Free(cipher_192);
	TEE_Free(expect_cipher_192);

	TEE_Free(plain_256);
	TEE_Free(IV_256);
	TEE_Free(cipher_256);
	TEE_Free(expect_cipher_256);
	
	return fn_ret;		
}

static uint32_t aes_tests()
{
	
	if (aes_256_cbc_enc_dec()) {
		return 1;
	}
	
	if (aes_per()) {
		return 1;
	}
	
	if (aes_128_cbc_enc_dec()) {
		return 1;
	}

	if (aes_256_ctr_nist()) {
		return 1;
	}
	
	if (aes_192_256_ctr_nist()) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;	
}

static uint32_t hmac_tests()
{	
	if (HMAC_computation_basic()) {
		return 1;
	}

	if (hmac_sha1_nist(true)) {
		return 1;
	}

	if (hmac_sha1_nist(false)) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;	
}

static uint32_t ae_enc()
{
	TEE_ObjectHandle key = NULL;
	TEE_OperationHandle operation = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t op_alg = TEE_ALG_AES_GCM;
	uint32_t op_class = TEE_OPERATION_AE;
	uint32_t op_mode = TEE_MODE_ENCRYPT;
	uint32_t fn_ret = 1; // Initialized error return
	TEE_Attribute aes_key = {0};
	
	size_t plain_len = SIZE_OF_VEC(aes_gcm_enc_plain_256);
	size_t cipher_len = 210; //Random lenght. Function will assign correct length
	size_t tag_len = 400; //Random lenght. Function will assign correct length
	size_t IVlen = SIZE_OF_VEC(aes_gcm_enc_iv_256);
	size_t aad_len = SIZE_OF_VEC(aes_gcm_enc_aad_256);
	size_t expect_tag_len = SIZE_OF_VEC(aes_gcm_enc_tag_256);
	size_t expect_cipher_len = SIZE_OF_VEC(aes_gcm_enc_cipher_256);
	
	void *plain = NULL;
	void *cipher = NULL;
	void *aad =NULL;
	void *IV = NULL;
	void *tag = NULL;
	void *expect_cipher = NULL;
	void *expect_tag = NULL;

	size_t operationSize;
	TEE_OperationInfoMultiple info;
	TEE_OperationInfoMultiple expectInfoM;
	expectInfoM.algorithm = op_alg;
	expectInfoM.operationClass = op_class;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = 0;
	expectInfoM.maxKeySize = key_size;
	expectInfoM.handleState = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	plain = TEE_Malloc(plain_len, 0);
	IV = TEE_Malloc(IVlen, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	aad = TEE_Malloc(aad_len, 0);
	tag = TEE_Malloc(tag_len, 0);
	expect_cipher =  TEE_Malloc(expect_cipher_len, 0);
	expect_tag =  TEE_Malloc(expect_tag_len, 0);

	if (!IV || !plain || !cipher || !expect_cipher || !aad || !tag || !expect_tag) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(plain, aes_gcm_enc_plain_256, plain_len);
	TEE_MemMove(IV, aes_gcm_enc_iv_256, IVlen);
	TEE_MemMove(expect_cipher, aes_gcm_enc_cipher_256, expect_cipher_len);
	TEE_MemMove(expect_tag, aes_gcm_enc_tag_256, expect_tag_len);
	TEE_MemMove(aad, aes_gcm_enc_aad_256, aad_len);

	//AES key
	aes_key.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key.content.ref.length = SIZE_OF_VEC(aes_gcm_enc_key_256);
	aes_key.content.ref.buffer = aes_gcm_enc_key_256;

	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, &aes_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("TEE_PopulateTransientObject failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&operation, op_alg, op_mode, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}
	
	ret = TEE_SetOperationKey(operation, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = key_size;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	ret = TEE_AEInit(operation,
			 IV, IVlen,
			 128,
			 0, //AADLen ignoed gcm
			 plain_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEInit : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.handleState = (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
	expectInfoM.digestLength = expect_tag_len * 8;
	expectInfoM.operationState = TEE_OPERATION_STATE_ACTIVE;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}

	TEE_AEUpdateAAD(operation, aad, aad_len);

	ret = TEE_AEUpdate(operation,
			   plain, plain_len,
			   cipher, &cipher_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEUpdate : 0x%x", ret);
		goto err;
	}

	ret = TEE_AEEncryptFinal(operation,
				 NULL, 0,
				 NULL, NULL,
				 tag, &tag_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEEncryptFinal : 0x%x", ret);
		goto err;
	}

	if (tag_len != expect_tag_len) {
		PRI_FAIL("Tag lenght mismatch (calculated[%lu]; expected[%lu])", tag_len, expect_tag_len);
		goto err;
	}

	if (cipher_len != expect_cipher_len) {
		PRI_FAIL("Cipher lenght mismatch (calculated[%lu]; expected[%lu])",
			 cipher_len, expect_cipher_len);
	}

	if (TEE_MemCompare(tag, expect_tag, expect_tag_len)) {
		PRI_FAIL("Not expected TAG");
		goto err;
	}

	if (TEE_MemCompare(cipher, expect_cipher, expect_cipher_len)) {
		PRI_FAIL("Not expected Cipher");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	expectInfoM.digestLength = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}
	
	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(operation);
	TEE_Free(plain);
	TEE_Free(cipher);
	TEE_Free(aad);
	TEE_Free(IV);
	TEE_Free(tag);
	TEE_Free(expect_cipher);
	TEE_Free(expect_tag);
	
	return fn_ret;
}

static uint32_t ae_dec()
{
	TEE_ObjectHandle key = NULL;
	TEE_OperationHandle operation = NULL;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_AES;
	uint32_t op_alg = TEE_ALG_AES_GCM;
	uint32_t op_class = TEE_OPERATION_AE;
	uint32_t op_mode = TEE_MODE_DECRYPT;
	uint32_t fn_ret = 1; // Initialized error return
	TEE_Attribute aes_key = {0};

	size_t cipher_len = SIZE_OF_VEC(aes_gcm_dec_cipher_256);
	size_t tag_len = SIZE_OF_VEC(aes_gcm_dec_tag_256);
	size_t IVlen = SIZE_OF_VEC(aes_gcm_dec_iv_256);
	size_t aad_len = SIZE_OF_VEC(aes_gcm_dec_aad_256);
	size_t plain_len = 212;
	size_t expect_plain_len = SIZE_OF_VEC(aes_gcm_dec_plain_256);
	
	void *plain = NULL;
	void *cipher = NULL;
	void *aad =NULL;
	void *IV = NULL;
	void *tag = NULL;
	void *expect_plain = NULL;

	size_t operationSize;
	TEE_OperationInfoMultiple info;
	TEE_OperationInfoMultiple expectInfoM;
	expectInfoM.algorithm = op_alg;
	expectInfoM.operationClass = op_class;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = 0;
	expectInfoM.maxKeySize = key_size;
	expectInfoM.handleState = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = 0;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;

	plain = TEE_Malloc(plain_len, 0);
	IV = TEE_Malloc(IVlen, 0);
	cipher = TEE_Malloc(cipher_len, 0);
	aad = TEE_Malloc(aad_len, 0);
	tag = TEE_Malloc(tag_len, 0);
	expect_plain = TEE_Malloc(expect_plain_len, 0);

	if (!IV || !plain || !cipher || !aad || !tag || !expect_plain) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(cipher, aes_gcm_dec_cipher_256, cipher_len);
	TEE_MemMove(IV, aes_gcm_dec_iv_256, IVlen);
	TEE_MemMove(expect_plain, aes_gcm_dec_plain_256, expect_plain_len);
	TEE_MemMove(tag, aes_gcm_dec_tag_256, tag_len);
	TEE_MemMove(aad, aes_gcm_dec_aad_256, aad_len);

	//AES key
	aes_key.attributeID = TEE_ATTR_SECRET_VALUE;
	aes_key.content.ref.length = SIZE_OF_VEC(aes_gcm_dec_key_256);
	aes_key.content.ref.buffer = aes_gcm_dec_key_256;

	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, &aes_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("TEE_PopulateTransientObject failure : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&operation, op_alg, op_mode, key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}
	
	ret = TEE_SetOperationKey(operation, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = key_size;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (2)");
		goto err;
	}
	
	ret = TEE_AEInit(operation,
			 IV, IVlen,
			 tag_len * 8, //bytes
			 0, //AADLen ignoed gcm
			 cipher_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEInit : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.handleState = (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
	expectInfoM.digestLength = tag_len * 8;
	expectInfoM.operationState = TEE_OPERATION_STATE_ACTIVE;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}

	TEE_AEUpdateAAD(operation, aad, aad_len);

	ret = TEE_AEUpdate(operation,
			   cipher, cipher_len,
			   plain, &plain_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEUpdate : 0x%x", ret);
		goto err;
	}

	ret = TEE_AEDecryptFinal(operation,
				 NULL, 0,
				 NULL, NULL,
				 tag, tag_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("failed TEE_AEDecryptFinal : 0x%x", ret);
		goto err;
	}

	if (plain_len != expect_plain_len) {
		PRI_FAIL("Plain lenght mismatch (calculated[%lu]; expected[%lu])",
			 plain_len, expect_plain_len);
	}

	if (TEE_MemCompare(plain, expect_plain, expect_plain_len)) {
		PRI_FAIL("Not expected plain");
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &info, &operationSize);
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	expectInfoM.digestLength = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	if (compare_opmultiple_info(&info, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (3)");
		goto err;
	}
	
	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(operation);
	TEE_Free(plain);
	TEE_Free(cipher);
	TEE_Free(aad);
	TEE_Free(IV);
	TEE_Free(tag);
	TEE_Free(expect_plain);
	
	return fn_ret;
}

static uint32_t ae_tests()
{	
	if (ae_enc()) {
		return 1;
	}

	if (ae_dec()) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;	
}

static uint32_t rsa_sign_verify_sha1_pkcs()
{	
	if (do_rsa_sign_nist_sha1_pkcs(true)) {
		return 1;
	}

	if (do_rsa_sign_nist_sha1_pkcs(false)) {
		return 1;
	}
	
	PRI_OK("-");
	return 0;	
}

static uint32_t ecdh_derivate()
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL, derivKey = NULL;
	TEE_OperationHandle operation = NULL;
	uint32_t key_size = 256;
	uint32_t obj_type = TEE_TYPE_ECDH_KEYPAIR;
	uint32_t op_alg = TEE_ALG_ECDH_DERIVE_SHARED_SECRET;
	uint32_t op_mode_derivate = TEE_MODE_DERIVE;
	uint32_t op_max_size = 256;
	uint32_t obj_derv_type = TEE_TYPE_GENERIC_SECRET, obj_derv_key_size = 3000;
	uint32_t param_count = 4, fn_ret = 1; /* Initialized error return */
	TEE_Attribute params[4] = {0};
	uint8_t shared[256] = {0};
	size_t sharedLen = 256;
	
	// Qx
	params[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	params[0].content.ref.buffer = ecdh_256_qx;
	params[0].content.ref.length = SIZE_OF_VEC(ecdh_256_qx);

	// Qy
	params[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	params[1].content.ref.buffer = ecdh_256_qy;
	params[1].content.ref.length = SIZE_OF_VEC(ecdh_256_qy);

	// d
	params[2].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
	params[2].content.ref.buffer = ecdh_256_d;
	params[2].content.ref.length = SIZE_OF_VEC(ecdh_256_d);

	// Curve
	params[3].attributeID = TEE_ATTR_ECC_CURVE;
	params[3].content.value.a = TEE_ECC_CURVE_NIST_P256;
	params[3].content.value.b = 0;
	
	ret = TEE_AllocateTransientObject(obj_type, key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateTransientObject(obj_derv_type, obj_derv_key_size, &derivKey);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}
	
	ret = TEE_PopulateTransientObject(key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("ECC key pair population failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocateOperation(&operation, op_alg, op_mode_derivate, op_max_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc operation handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_SetOperationKey(operation, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set key : 0x%x", ret);
		goto err;
	}

	TEE_DeriveKey(operation, params, param_count, derivKey);

	ret = TEE_GetObjectBufferAttribute(derivKey, TEE_ATTR_SECRET_VALUE, shared, &sharedLen);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to get TEE_ATTR_SECRET_VALUE : 0x%x", ret);
		goto err;
	}

	if (sharedLen != SIZE_OF_VEC(ecdh_256_shared)) {
		PRI_FAIL("Not expected lenght (expected[%lu]; fetch[%lu])",
			 SIZE_OF_VEC(ecdh_256_shared), sharedLen);
		goto err;
	}

	if (TEE_MemCompare(shared, ecdh_256_shared, sharedLen)) {
		PRI_FAIL("Not expected shared");
		goto err;
	}
	
	fn_ret = 0; // OK

err:
	TEE_FreeTransientObject(derivKey);
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(operation);

	if (fn_ret == 0)
		PRI_OK("-");
		
	return fn_ret;
}

static uint32_t mac_compare_final()
{
	TEE_Result ret;
	TEE_ObjectHandle key = NULL;
	TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
	uint32_t key_type = TEE_TYPE_HMAC_SHA1;
	uint32_t key_size = SIZE_OF_VEC(hmac_sha1_key) * 8; // x * 8 = converts to bits
	uint32_t max_key_size = 504;
	uint32_t alg = TEE_ALG_HMAC_SHA1;
	uint32_t op_mode = TEE_MODE_MAC;
	uint32_t fn_ret = 1; /* Initialized error return */
	TEE_Attribute hmac_key;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META;
	
	size_t msg_len = SIZE_OF_VEC(hmac_sha1_msg);
	size_t expect_mac_len = SIZE_OF_VEC(hmac_sha1_mac);
	
	void *msg = NULL;
	void *expect_mac = NULL;

	TEE_OperationInfoMultiple infoM;
	TEE_OperationInfoMultiple expectInfoM;
	size_t operationSize;
	
	expectInfoM.algorithm = alg;
	expectInfoM.operationClass = TEE_OPERATION_MAC;
	expectInfoM.mode = op_mode;
	expectInfoM.digestLength = expect_mac_len;
	expectInfoM.maxKeySize = max_key_size;
	expectInfoM.handleState = 0;
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.numberOfKeys = 1;
	expectInfoM.keyInformation[0].keySize = SIZE_OF_VEC(hmac_sha1_key) * 8;
	expectInfoM.keyInformation[0].requiredKeyUsage = 0;
	
	//hmac key
	hmac_key.attributeID = TEE_ATTR_SECRET_VALUE;
	hmac_key.content.ref.length = SIZE_OF_VEC(hmac_sha1_key);
	hmac_key.content.ref.buffer = hmac_sha1_key;
	
	msg = TEE_Malloc(msg_len, 0);
	expect_mac = TEE_Malloc(expect_mac_len, 0);
	if (!msg || !expect_mac) {
		PRI_FAIL("Out of memory");
		goto err;
	}

	TEE_MemMove(msg, hmac_sha1_msg, msg_len);
	TEE_MemMove(expect_mac, hmac_sha1_mac, expect_mac_len);

	ret = TEE_AllocateTransientObject(key_type, max_key_size, &key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to alloc transient object handle : 0x%x", ret);
		goto err;
	}

	ret = TEE_PopulateTransientObject(key, &hmac_key, 1);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("TEE_PopulateTransientObject failure : 0x%x", ret);
		goto err;
	}
		
	ret = TEE_AllocateOperation(&operation, alg, TEE_MODE_MAC, max_key_size);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Cant alloc first handler");
		goto err;
	}

	ret = TEE_SetOperationKey(operation, key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Failed to set first operation key : 0x%x", ret);
		goto err;
	}
	
	TEE_MACInit(operation, NULL, 0);

	ret = TEE_MACCompareFinal(operation, msg, msg_len, expect_mac, expect_mac_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Maccomparefinal failed : 0x%x", ret);
		goto err;
	}

	TEE_GetOperationInfoMultiple(operation, &infoM, &operationSize);
	expectInfoM.operationState = TEE_OPERATION_STATE_INITIAL;
	expectInfoM.handleState = TEE_HANDLE_FLAG_KEY_SET;
	if (compare_opmultiple_info(&infoM, &expectInfoM)) {
		PRI_FAIL("OperationInfo bad state (1)");
		goto err;
	}

	fn_ret = 0; /* OK */
err:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(operation);
	TEE_Free(msg);
	TEE_Free(expect_mac);

	if (fn_ret == 0)
		PRI_OK("-");
		
	return fn_ret;	
}

uint32_t crypto_test(uint32_t loop_count)
{
        uint32_t i, test_have_fail = 0;
	
	PRI_STR("START: crypto tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {
				
		if (mac_compare_final() ||
		    ecdh_derivate() ||
		    run_ecdsa_tests() ||
		    read_key_and_do_crypto() ||
		    rsa_sign_verify_sha1_pkcs() ||
		    RSA_keypair_enc_dec() ||
		    hmac_tests() ||
		    sha1_digest_nist() ||
		    set_key_and_rm_and_do_crypto() ||
		    RSA_sig_and_ver() ||
		    sha256_digest_nist() ||
		    sha256_digest() ||		    
		    ae_tests() ||
		    aes_tests()) {
                        test_have_fail = 1;
                        break;
		}
		
	}

	PRI_STR("----Test-has-reached-end----\n");

	PRI_STR("END: crypto tests");

        return test_have_fail ? 1 : 0;
}
