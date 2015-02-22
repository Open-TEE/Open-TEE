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

#include <stdlib.h>
#include <stdint.h>

#include "cryptoki.h"
#include "commands.h"
#include "hal.h"

/*!
 * \brief crypto_init
 * Function is collecting following crypto-init functions: C_EncryptInit, C_DecryptInit,
 * C_DigestInit, C_SignInit and C_VerifyInit.
 * \param command_id invoked command from TEE
 * \param hSession see PKCS11
 * \param pMechanism see PKCS11
 * \param hKey see PKCS11.
 * \return
 */
static CK_RV crypto_init(uint32_t command_id,
			 CK_SESSION_HANDLE hSession,
			 CK_MECHANISM_PTR pMechanism,
			 CK_OBJECT_HANDLE hKey)
{
	if (hSession == CK_INVALID_HANDLE)
		return CKR_SESSION_HANDLE_INVALID;

	if (hKey == CK_INVALID_HANDLE)
		return CKR_OBJECT_HANDLE_INVALID;

	if (!pMechanism)
		return CKR_ARGUMENTS_BAD;

	return hal_crypto_init(command_id, hSession, pMechanism, hKey);
}

/*!
 * \brief crypto
 * Function is collecting following crypto functions: C_Encryp, C_Decrypt, C_Digest, C_Sign and
 * C_Verify.
 * \param command_id invoked command from TEE
 * \param hSession see PKCS11
 * \param src is operation target buffer
 * \param src_len is src buffer lenghtn in bytes
 * \param dst operation output is placed into dst buffer
 * \param dst_len is dst buffer length in bytes
 * \return
 */
static CK_RV crypto(uint32_t command_id,
		    CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR src,
		    CK_ULONG src_len,
		    CK_BYTE_PTR dst,
		    CK_ULONG_PTR dst_len)
{
	if (hSession == CK_INVALID_HANDLE)
		return CKR_SESSION_HANDLE_INVALID;

	if (!src || !dst || !dst_len)
		return CKR_ARGUMENTS_BAD;

	return hal_crypto(command_id, hSession, src, src_len, dst, dst_len);
}

/*!
 * \brief crypto_update
 * Function is collecting following crypto functions: C_EncrypUpdate, C_DecryptUpdate,
 * C_DigestUpdate, C_SignUpdate and C_VerifyUpdate.
 * \param command_id invoked command from TEE
 * \param hSession see PKCS11
 * \param src is operation target buffer
 * \param src_len is src buffer lenghtn in bytes
 * \param dst operation output is placed into dst buffer
 * \param dst_len is dst buffer length in bytes
 * \return
 */
static CK_RV crypto_update(uint32_t command_id,
			   CK_SESSION_HANDLE hSession,
			   CK_BYTE_PTR src,
			   CK_ULONG src_len,
			   CK_BYTE_PTR dst,
			   CK_ULONG_PTR dst_len)
{
	if (hSession == CK_INVALID_HANDLE)
		return CKR_SESSION_HANDLE_INVALID;

	if (!src || !dst || !dst_len)
		return CKR_ARGUMENTS_BAD;

	return hal_crypto(command_id, hSession, src, src_len, dst, dst_len);
}
/*!
 * \brief crypto_final
 * Function is collecting following crypto functions: C_EncrypFinal, C_DecryptFinal,
 * C_DigestFinal, C_SignFinal and C_VerifyFinal.
 * \param command_id invoked command from TEE
 * \param hSession see PKCS11
 * \param dst operation output is placed into dst buffer
 * \param dst_len is dst buffer length in bytes
 * \return
 */
static CK_RV crypto_final(uint32_t command_id,
			  CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR dst,
			  CK_ULONG_PTR dst_len)
{
	if (hSession == CK_INVALID_HANDLE)
		return CKR_SESSION_HANDLE_INVALID;

	if (!dst || !dst_len)
		return CKR_ARGUMENTS_BAD;

	return hal_crypto(command_id, hSession, NULL, 0, dst, dst_len);
}

/*
 * 11.8 ENCRYPTION FUNCTIONS
 */


CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return crypto_init(TEE_ENCRYPT_INIT, hSession, pMechanism, hKey);
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	return crypto(TEE_ENCRYPT, hSession, pData,
		      ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	return crypto_update(TEE_ENCRYPT_UPDATE, hSession, pPart,
			     ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return crypto_final(TEE_ENCRYPT_FINAL, hSession,
			    pLastEncryptedPart, pulLastEncryptedPartLen);
}


/*
 * 11.9 DECRYPTION FUNCTIONS
 */


CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return crypto_init(TEE_DECRYPT_INIT, hSession, pMechanism, hKey);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	return crypto(TEE_DECRYPT, hSession, pEncryptedData,
		      ulEncryptedDataLen, pData, pulDataLen);
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	return crypto_update(TEE_DECRYPT_UPDATE, hSession, pEncryptedPart,
			     ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	return crypto_final(TEE_DECRYPT_FINAL, hSession, pLastPart, pulLastPartLen);
}


/*
 * 11.10 MESSAGE DIGESTING FUNCTIONS
 */


CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return crypto_init(TEE_DIGEST_INIT, hSession, pMechanism, NULL_PTR);
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	return crypto(TEE_DIGEST, hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return crypto(TEE_DIGEST_UPDATE, hSession, pPart, ulPartLen, NULL_PTR, NULL_PTR);
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	return crypto_final(TEE_DIGEST_FINAL, hSession, pDigest, pulDigestLen);
}


/*
 * 11.11 SIGNING AND MACING FUNCTIONS
 */


CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return crypto_init(TEE_SIGN_INIT, hSession, pMechanism, hKey);
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
	     CK_BYTE_PTR pData,
	     CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature,
	     CK_ULONG_PTR pulSignatureLen)
{
	return crypto(TEE_SIGN, hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return crypto_update(TEE_SIGN_UPDATE, hSession, pPart, ulPartLen, NULL_PTR, NULL_PTR);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return crypto_final(TEE_SIGN_FINAL, hSession, pSignature, pulSignatureLen);
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	hSession = hSession;
	pData = pData;
	ulDataLen = ulDataLen;
	pSignature = pSignature;
	pulSignatureLen = pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/*
 * 11.12 FUNCTIONS FOR VERIFYING SIGNATURES AND MACS
 */


CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	return crypto_init(TEE_VERIFY_INIT, hSession, pMechanism, hKey);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	return crypto(TEE_VERIFY, hSession, pData, ulDataLen, pSignature, &ulSignatureLen);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return crypto_update(TEE_VERIFY_UPDATE, hSession, pPart, ulPartLen, NULL_PTR, NULL_PTR);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return crypto_final(TEE_VERIFY_FINAL, hSession, pSignature, &ulSignatureLen);
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hKey = hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen,
		      CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	hSession = hSession;
	pSignature = pSignature;
	ulSignatureLen = ulSignatureLen;
	pData = pData;
	pulDataLen = pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/*
 * 11.13 DUAL-FUNCTION CRYPTOGRAPHIC FUNCTIONS
 */


CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;
	pEncryptedPart = pEncryptedPart;
	pulEncryptedPartLen = pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	hSession = hSession;
	pEncryptedPart = pEncryptedPart;
	ulEncryptedPartLen = ulEncryptedPartLen;
	pPart = pPart;
	pulPartLen = pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen,
			  CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	hSession = hSession;
	pPart = pPart;
	ulPartLen = ulPartLen;
	pEncryptedPart = pEncryptedPart;
	pulEncryptedPartLen = pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	hSession = hSession;
	pEncryptedPart = pEncryptedPart;
	ulEncryptedPartLen = ulEncryptedPartLen;
	pPart = pPart;
	pulPartLen = pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/*
 * 11.14 KEY MANAGEMENT FUNCTIONS
 */


CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	pTemplate = pTemplate;
	ulCount = ulCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	pPublicKeyTemplate = pPublicKeyTemplate;
	ulPublicKeyAttributeCount = ulPublicKeyAttributeCount;
	pPrivateKeyTemplate = pPrivateKeyTemplate;
	ulPrivateKeyAttributeCount = ulPrivateKeyAttributeCount;
	phPublicKey = phPublicKey;
	phPrivateKey = phPrivateKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hWrappingKey = hWrappingKey;
	hKey = hKey;
	pWrappedKey = pWrappedKey;
	pulWrappedKeyLen = pulWrappedKeyLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey,
		  CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hUnwrappingKey = hUnwrappingKey;
	pWrappedKey = pWrappedKey;
	ulWrappedKeyLen = ulWrappedKeyLen;
	pTemplate = pTemplate;
	ulAttributeCount = ulAttributeCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	hSession = hSession;
	pMechanism = pMechanism;
	hBaseKey = hBaseKey;
	pTemplate = pTemplate;
	ulAttributeCount = ulAttributeCount;
	phKey = phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/*
 * 11.15 RANDOM NUMBER GENERATOR FUNCTIONS
 */


CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	hSession = hSession;
	pSeed = pSeed;
	ulSeedLen = ulSeedLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	hSession = hSession;
	RandomData = RandomData;
	ulRandomLen = ulRandomLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}
