/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tpm_crypto.c 444 2010-06-12 09:14:18Z mast $
 */

#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include "../crypto/sha1.h"
#include "../Core/ftrx.h"

extern unsigned char ExtendBuf[0x400];
extern unsigned char InOutBuf[0x400];
/*
 * Cryptographic Functions ([TPM_Part3], Section 13)
 */

int tpm_setup_key_parms(TPM_KEY_DATA *key, TPM_KEY_PARMS *parms)
{
  parms->algorithmID = TPM_ALG_RSA;
  parms->encScheme = key->encScheme;
  parms->sigScheme = key->sigScheme;
  parms->parmSize = 12;
  parms->parms.rsa.keyLength = 2048;
  parms->parms.rsa.numPrimes = 2;
  parms->parms.rsa.exponentSize = 0;
  /*
  parms->parms.rsa.keyLength = key->key.size;
  parms->parms.rsa.numPrimes = 2;
  if (tpm_bn_cmp_ui(key->key.e, 65537) == 0) {
    parms->parms.rsa.exponentSize = 0;
    parms->parms.rsa.exponent = NULL;
  } else {
    parms->parms.rsa.exponentSize = tpm_rsa_exponent_length(&key->key);
    parms->parms.rsa.exponent = tpm_malloc(parms->parms.rsa.exponentSize);
    if (parms->parms.rsa.exponent == NULL) return -1;
    tpm_rsa_export_exponent(&key->key, parms->parms.rsa.exponent, &exp_len);
    parms->parms.rsa.exponentSize = exp_len;
  }
  parms->parmSize = 12 + parms->parms.rsa.exponentSize;
  */
  return 0;
}


#if 0
static tpm_sha1_ctx_t sha1_ctx;
static BOOL sha1_ctx_valid = FALSE;

TPM_RESULT TPM_SHA1Start(UINT32 *maxNumBytes)
{
  info("TPM_SHA1Start()");
  tpm_sha1_init(&sha1_ctx);
  sha1_ctx_valid = TRUE;
  /* this limit was arbitrarily chosen */
  *maxNumBytes = 2048;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1Update(UINT32 numBytes, BYTE *hashData)
{
  info("TPM_SHA1Update()");
  if (!sha1_ctx_valid) return TPM_SHA_THREAD;
  tpm_sha1_update(&sha1_ctx, hashData, numBytes);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1Complete(UINT32 hashDataSize, BYTE *hashData, 
                            TPM_DIGEST *hashValue)
{
  info("TPM_SHA1Complete()");
  if (!sha1_ctx_valid) return TPM_SHA_THREAD;
  sha1_ctx_valid = FALSE;
  tpm_sha1_update(&sha1_ctx, hashData, hashDataSize);
  tpm_sha1_final(&sha1_ctx, hashValue->digest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SHA1CompleteExtend(TPM_PCRINDEX pcrNum, UINT32 hashDataSize, 
                                  BYTE *hashData, TPM_DIGEST *hashValue, 
                                  TPM_PCRVALUE *outDigest)
{
  TPM_RESULT res;
  info("TPM_SHA1CompleteExtend()");
  res = TPM_SHA1Complete(hashDataSize, hashData, hashValue);
  if (res != TPM_SUCCESS) return res;
  return TPM_Extend(pcrNum, hashValue, outDigest);
}

TPM_RESULT tpm_verify(TPM_PUBKEY_DATA *key, TPM_AUTH *auth, BOOL isInfo,
                      BYTE *data, UINT32 dataSize, BYTE *sig, UINT32 sigSize)
{
  if (sigSize != key->key.size >> 3) return TPM_BAD_SIGNATURE;
  if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_SHA1) {
    /* use signature scheme PKCS1_SHA1_RAW */
    if (dataSize != 20) return TPM_BAD_PARAMETER;
    if (tpm_rsa_verify(&key->key, RSA_SSA_PKCS1_SHA1_RAW,
         data, dataSize, sig) != 0)  return TPM_BAD_SIGNATURE;
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_DER) {
    /* use signature scheme PKCS1_DER */
    if ((dataSize + 11) > (UINT32)(key->key.size >> 3)
        || dataSize == 0) return TPM_BAD_PARAMETER;
    if (tpm_rsa_verify(&key->key, RSA_SSA_PKCS1_DER,
        data, dataSize, sig) != 0)  return TPM_BAD_SIGNATURE;
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO && !isInfo) {
    /* use signature scheme PKCS1_SHA1 and TPM_SIGN_INFO container */
    BYTE buf[dataSize + 30];
    if ((dataSize + 30) > (UINT32)(key->key.size >> 3)
        || dataSize == 0) return TPM_BAD_PARAMETER;
    /* setup TPM_SIGN_INFO structure */
    memcpy(&buf[0], "\x00\x05SIGN", 6);
    memcpy(&buf[6], auth->nonceOdd.nonce, 20);
    buf[26] = (dataSize >> 24) & 0xff;
    buf[27] = (dataSize >> 16) & 0xff;
    buf[28] = (dataSize >>  8) & 0xff;
    buf[29] = (dataSize      ) & 0xff;
    memcpy(&buf[30], data, dataSize);
    if (tpm_rsa_verify(&key->key, RSA_SSA_PKCS1_SHA1,
        data, dataSize, sig) != 0)  return TPM_BAD_SIGNATURE;
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO && isInfo) {
    /* TPM_SIGN_INFO structure is already set up */
    if (dataSize > (UINT32)(key->key.size >> 3)
        || dataSize == 0) return TPM_BAD_PARAMETER;
    if (tpm_rsa_verify(&key->key, RSA_SSA_PKCS1_SHA1,
        data, dataSize, sig) != 0)  return TPM_BAD_SIGNATURE;
  } else {
    return TPM_INVALID_KEYUSAGE;
  }
  return TPM_SUCCESS;
}

TPM_RESULT tpm_sign(TPM_KEY_DATA *key, TPM_AUTH *auth, BOOL isInfo,
                    BYTE *areaToSign, UINT32 areaToSignSize, 
                    BYTE **sig, UINT32 *sigSize)
{  
  if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_SHA1) {
    /* use signature scheme PKCS1_SHA1_RAW */ 
    if (areaToSignSize != 20) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL || tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1_RAW, 
        areaToSign, areaToSignSize, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_DER) {
    /* use signature scheme PKCS1_DER */ 
    if ((areaToSignSize + 11) > (UINT32)(key->key.size >> 3)
        || areaToSignSize == 0) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL || tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_DER, 
        areaToSign, areaToSignSize, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO && !isInfo) {
    /* use signature scheme PKCS1_SHA1 and TPM_SIGN_INFO container */
    BYTE buf[areaToSignSize + 30];
    if ((areaToSignSize + 30) > (UINT32)(key->key.size >> 3)
        || areaToSignSize == 0) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL) return TPM_FAIL; 
    /* setup TPM_SIGN_INFO structure */
    memcpy(&buf[0], "\x00\x05SIGN", 6);
    memcpy(&buf[6], auth->nonceOdd.nonce, 20);
    buf[26] = (areaToSignSize >> 24) & 0xff;
    buf[27] = (areaToSignSize >> 16) & 0xff;
    buf[28] = (areaToSignSize >>  8) & 0xff;
    buf[29] = (areaToSignSize      ) & 0xff;
    memcpy(&buf[30], areaToSign, areaToSignSize);
    if (tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1, 
        buf, areaToSignSize + 30, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO && isInfo) {
    /* TPM_SIGN_INFO structure is already set up */
    if (areaToSignSize > (UINT32)(key->key.size >> 3)
        || areaToSignSize == 0) return TPM_BAD_PARAMETER;
    *sigSize = key->key.size >> 3;
    *sig = tpm_malloc(*sigSize);
    if (*sig == NULL) return TPM_FAIL; 
    if (tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1, 
        areaToSign, areaToSignSize, *sig)) {
      tpm_free(*sig);
      return TPM_FAIL;
    }    
  } else {
    return TPM_INVALID_KEYUSAGE;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Sign(TPM_KEY_HANDLE keyHandle, UINT32 areaToSignSize, 
                    BYTE *areaToSign, TPM_AUTH *auth1,  
                    UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  info("TPM_Sign()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */ 
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY) 
    return TPM_INVALID_KEYUSAGE;
  /* sign data */
  return tpm_sign(key, auth1, FALSE, areaToSign, areaToSignSize, sig, sigSize);
}

void tpm_get_random_bytes(void *buf, size_t nbytes)
{
  if (tpmConf & TPM_CONF_USE_INTERNAL_PRNG) {
    tpm_rc4_ctx_t ctx;
    tpm_rc4_init(&ctx, tpmData.permanent.data.rngState,
      sizeof(tpmData.permanent.data.rngState));
    tpm_rc4_crypt(&ctx, buf, buf, nbytes);
    tpm_rc4_crypt(&ctx, tpmData.permanent.data.rngState,
      tpmData.permanent.data.rngState, sizeof(tpmData.permanent.data.rngState));
  } else {
    tpm_get_extern_random_bytes(buf, nbytes);
  }
}

TPM_RESULT TPM_GetRandom(UINT32 bytesRequested, UINT32 *randomBytesSize, 
                         BYTE **randomBytes)
{
  info("TPM_GetRandom()");
  *randomBytesSize = (bytesRequested < 2048) ? bytesRequested : 2048;
  *randomBytes = tpm_malloc(*randomBytesSize);
  if (*randomBytes == NULL) return TPM_SIZE;
  tpm_get_random_bytes(*randomBytes, *randomBytesSize);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_StirRandom(UINT32 dataSize, BYTE *inData)
{
  info("TPM_StirRandom()");
  UINT32 i, length = sizeof(tpmData.permanent.data.rngState);
  while (dataSize > length) {
    for (i = 0; i < length; i++) {
        tpmData.permanent.data.rngState[i] ^= *inData++;
    }
    dataSize -= length;
  }
  for (i = 0; i < dataSize; i++) {
    tpmData.permanent.data.rngState[i] ^= *inData++;
  }
  return TPM_SUCCESS;
}
#endif

TPM_RESULT TPM_CertifyKey(TPM_KEY_HANDLE certHandle, TPM_KEY_HANDLE keyHandle,
                          TPM_NONCE *antiReplay, TPM_AUTH *auth1, 
                          TPM_AUTH *auth2, TPM_CERTIFY_INFO *certifyInfo,
                          UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA cert, key;
  int cert_index, key_index;
  TPM_MODIFIER_INDICATOR locality;
  tpm_sha1_ctx_t sha1_ctx;
  BYTE *buf, *p;
  UINT32 length, size;
  UINT32 errcode;
  UINT16 dataSize;
  /* get keys */
  cert_index = tpm_get_key(certHandle);
  if (cert_index == -1) return TPM_INVALID_KEYHANDLE;
  read_TPM_PERMANENT_DATA_keys(cert_index, &cert);
  key_index = tpm_get_key(keyHandle);
  if (key_index == -1) return TPM_INVALID_KEYHANDLE;
  read_TPM_PERMANENT_DATA_keys(key_index, &key);
  /* verify authorization */ 
  if (auth2->authHandle != TPM_INVALID_HANDLE
      || cert.authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, cert.usageAuth, certHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key.authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth2, key.usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
  }
  /* verify key usage */
  if (cert.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1 
      && cert.sigScheme != TPM_SS_RSASSAPKCS1v15_INFO) return TPM_BAD_SCHEME;
  if (cert.keyUsage == TPM_KEY_IDENTITY 
      && (key.keyFlags & TPM_KEY_FLAG_MIGRATABLE)
      && !(key.keyFlags & TPM_KEY_FLAG_AUTHORITY)) return TPM_MIGRATEFAIL;
  if (key.keyFlags & TPM_KEY_FLAG_HAS_PCR) {
    if (!(key.keyFlags & TPM_KEY_FLAG_PCR_IGNORE)) {
      TPM_DIGEST digest;
      res = tpm_compute_pcr_digest(&key.pcrInfo.releasePCRSelection, 
        &digest, NULL);
      if (res != TPM_SUCCESS) {
          return res;
      }
      if (memcmp(&digest, &key.pcrInfo.digestAtRelease, sizeof(TPM_DIGEST)))
        return TPM_WRONGPCRVAL;
      if (key.pcrInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(key.pcrInfo.localityAtRelease
             & (1 << stanyFlags.localityModifier)))
        return TPM_BAD_LOCALITY;
    } 
    /* if sizeOfSelect is two use a TPM_CERTIFY_INFO structure ... */
    if (key.pcrInfo.releasePCRSelection.sizeOfSelect == 2) {
      certifyInfo->tag = 0x0101;
      certifyInfo->fill = 0x0000;
      certifyInfo->migrationAuthoritySize = 0;
      memcpy(&certifyInfo->PCRInfo, &key.pcrInfo, sizeof(TPM_PCR_INFO));
      memset(&certifyInfo->PCRInfo.digestAtCreation, 0, sizeof(TPM_DIGEST));
      certifyInfo->PCRInfoSize = sizeof(TPM_PCR_INFO);
    /* ... otherwise use a TPM_CERTIFY_INFO2 structure */
    } else {
      certifyInfo->tag = TPM_TAG_CERTIFY_INFO2;
      certifyInfo->fill = 0x0000;
      certifyInfo->migrationAuthoritySize = 0;
      memcpy(&certifyInfo->PCRInfo, &key.pcrInfo, sizeof(TPM_PCR_INFO));
      certifyInfo->PCRInfoSize = sizeof(TPM_PCR_INFO);
    } 
  } else {
    /* setup TPM_CERTIFY_INFO structure */
    certifyInfo->tag = 0x0101;
    certifyInfo->fill = 0x0000;
    certifyInfo->migrationAuthoritySize = 0;
    certifyInfo->PCRInfoSize = 0;
  }
  /* setup CERTIFY_INFO[2] structure */
  certifyInfo->keyUsage = key.keyUsage;
  certifyInfo->keyFlags = key.keyFlags & TPM_KEY_FLAG_MASK;
  certifyInfo->authDataUsage = key.authDataUsage;
  certifyInfo->parentPCRStatus = key.parentPCRStatus;
  if (tpm_setup_key_parms(&key, &certifyInfo->algorithmParms)) {
      return TPM_FAIL;
  }
  memcpy(&certifyInfo->data, antiReplay, sizeof(TPM_NONCE));
  /* compute pubKeyDigest */
  length = sizeof(RSA_PUBLIC_KEY);
  buf = InOutBuf;
  //tpm_rsa_export_modulus(&key->key, buf, NULL);
  errcode = read_file(key.pubkeyFileid, 0, length, buf);
  if (errcode != ERR_SUCCESS) {
      return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, length);
  tpm_sha1_final(&sha1_ctx, certifyInfo->pubkeyDigest.digest);
  /* compute the digest of the CERTIFY_INFO[2] structure and sign it */
  length = size = sizeof_TPM_CERTIFY_INFO((*certifyInfo));
  p = buf = InOutBuf;
  if (tpm_marshal_TPM_CERTIFY_INFO(&p, &length, certifyInfo)) {
    return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, size);
  tpm_sha1_final(&sha1_ctx, buf);
  /* encrypt it !!! treat it as a signature. */
  errcode = rsa_pri(cert.keyFileid, buf, SHA1_DIGEST_LENGTH, *outData, &dataSize, MODE_ENCODE);
  *outDataSize = dataSize;
  if (errcode != ERR_SUCCESS) {
      return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;
}
