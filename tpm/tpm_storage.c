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
 * $Id: tpm_storage.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "../crypto/sha1.h"
#include "tpm_marshalling.h"
#include "../Core/ftrx.h"

/*
 * Storage functions ([TPM_Part3], Section 10)
 */
extern unsigned char ExtendBuf[0x400];
extern unsigned char InOutBuf[0x400];

TPM_KEY_HANDLE tpm_get_free_key(void)
{
  int i;
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (!read_TPM_PERMANENT_DATA_keys_payload(i)) {
      write_TPM_PERMANENT_DATA_keys_payload(i, TPM_PT_ASYM);
      return INDEX_TO_KEY_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

int tpm_rsa_import_key(TPM_KEY_DATA *key, TPM_STORE_PRIVKEY *prikey, TPM_STORE_PUBKEY *pubkey) {
     if (prikey->keyLength != 256 || pubkey->keyLength != sizeof(RSA_PUBLIC_KEY)) {
         return -1;
     }
     memcpy(ExtendBuf, pubkey->key, pubkey->keyLength);
     memcpy(ExtendBuf+pubkey->keyLength, prikey->key, prikey->keyLength);
     if (write_file(FILE_PRIKEY_RSA, key->keyFileid, 0, sizeof(RSA_PRIVATE_KEY), ExtendBuf) != ERR_SUCCESS
        || write_file(FILE_DATA, key->pubkeyFileid, 0, sizeof(RSA_PUBLIC_KEY), pubkey->key) != ERR_SUCCESS) 
         return -1;
     return 0;
}

int tpm_encrypt_private_key(TPM_KEY_DATA *key, TPM_STORE_ASYMKEY *store, BYTE *enc, UINT32 *enc_size)
{
 UINT16 dataSize;
/*
 UINT32 data = 0xffffffff;
 if (rsa_pri(key->keyFileid, (BYTE *)&data, 4, enc, &dataSize, MODE_ENCODE) != ERR_SUCCESS) return -1;
 return 0;
 // if (rsa_pri(key->keyFileid, store->usageAuth, 20, enc+256, &dataSize, MODE_ENCODE) != ERR_SUCCESS) return 0x01;
 // */
  UINT32 size, len;
  BYTE *buf, *ptr, *public;
  /* size is 321 */
  size = len = sizeof_TPM_STORE_ASYMKEY((*store));
  ptr = ExtendBuf;
  if (tpm_marshal_TPM_STORE_ASYMKEY(&ptr, &len, store)) {
    return -1;
  }
  buf = InOutBuf + sizeof(RSA_PUBLIC_KEY);
  memcpy(buf, ExtendBuf, size);
  public = InOutBuf + sizeof(RSA_PUBLIC_KEY) + size + 7; // memory allginment
  if (read_file(key->pubkeyFileid, 0, sizeof(RSA_PUBLIC_KEY), public) != ERR_SUCCESS) return -1;
  if (rsa_pub(buf, size / 2, (RSA_PUBLIC_KEY *)public, enc, &dataSize, MODE_ENCODE) != ERR_SUCCESS ||
      rsa_pub(buf+size/2, size - size/2, (RSA_PUBLIC_KEY *)public, enc+256, &dataSize, MODE_ENCODE) != ERR_SUCCESS) return -1;
  return 0;
}

int tpm_decrypt_private_key(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size, TPM_STORE_ASYMKEY *store)
{
  BYTE *buf, *ptr;
  UINT16 part1_size;
  UINT16 part2_size;
  /* enc_size should be 321 */
  buf = ptr = malloc(enc_size);
  if (buf == NULL) {
    return -1;
  }
  if (rsa_pri(key->keyFileid, enc, 256, buf, &part1_size, MODE_DECODE) != ERR_SUCCESS ||
      rsa_pri(key->keyFileid, enc+256, 256, buf+part1_size, &part2_size, MODE_DECODE) != ERR_SUCCESS) {
      free(buf);
      return -1;
  }
  if (tpm_unmarshal_TPM_STORE_ASYMKEY(&ptr, (UINT32 *)&enc_size, store) != 0) {
    free(buf);
    return -1;
  }
  return 0;
}

int tpm_rsa_decrypt(UINT16 keyFileid, BYTE *inData, UINT32 inDataSize, BYTE *outData, UINT32 *outDataSize) {
    UINT16 dataSize;
    if (inDataSize > 256) return -1;
    if (rsa_pri(keyFileid, inData, (UINT16)inDataSize, outData, &dataSize, MODE_DECODE) != ERR_SUCCESS) return -1;
    *outDataSize = dataSize;
    return 0;
}

int tpm_compute_key_digest(TPM_KEY *key, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_KEY((*key));
  BYTE *buf, *ptr;
  buf = ptr = ExtendBuf;
  if (buf == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, key)) {
    free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_KEY((*key)) - key->encDataSize - 4);
  tpm_sha1_final(&sha1, digest->digest);
  //free(buf);
  return 0;
}

static int tpm_verify_key_digest(TPM_KEY *key, TPM_DIGEST *digest)
{
  TPM_DIGEST key_digest;
  if (tpm_compute_key_digest(key, &key_digest)) return -1;
  return memcmp(key_digest.digest, digest->digest, sizeof(key_digest.digest));
}

int tpm_extract_pubkey(TPM_KEY_DATA *key, TPM_PUBKEY *pubKey)
{
  pubKey->pubKey.keyLength = sizeof(RSA_PUBLIC_KEY);
  pubKey->pubKey.key = malloc(pubKey->pubKey.keyLength);
  if (pubKey->pubKey.key == NULL) {
    return -1;
  }
  if (read_file(key->pubkeyFileid, 0, sizeof(RSA_PUBLIC_KEY), pubKey->pubKey.key) != ERR_SUCCESS) {
      free(pubKey->pubKey.key);
      return -1;
  }
 /* TODO Setup pubkey->algorithmParms.
  * if (tpm_setup_key_parms(key, &pubKey->algorithmParms) != 0) {
    debug("tpm_setup_key_parms() failed.");
    tpm_free(pubKey->pubKey.key);
    return -1;
  }
  */
  return 0;
}

#if 0
TPM_RESULT TPM_Seal(TPM_KEY_HANDLE keyHandle, TPM_ENCAUTH *encAuth,
                    UINT32 pcrInfoSize, TPM_PCR_INFO *pcrInfo,
                    UINT32 inDataSize, BYTE *inData,
                    TPM_AUTH *auth1, TPM_STORED_DATA *sealedData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;
  info("TPM_Seal()");
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
    return TPM_INVALID_KEYUSAGE;
  /* setup store */
  if (pcrInfo->tag == TPM_TAG_PCR_INFO_LONG) {
    sealedData->tag = TPM_TAG_STORED_DATA12;
    sealedData->et = 0x0000;
  } else {
    sealedData->tag = 0x0101;
    sealedData->et = 0x0000;
  }   
  sealedData->encDataSize = 0;
  sealedData->encData = NULL;
  sealedData->sealInfoSize = pcrInfoSize;
  if (pcrInfoSize > 0) {
    sealedData->sealInfoSize = pcrInfoSize;
    memcpy(&sealedData->sealInfo, pcrInfo, sizeof(TPM_PCR_INFO));
    res = tpm_compute_pcr_digest(&pcrInfo->creationPCRSelection, 
      &sealedData->sealInfo.digestAtCreation, NULL);
    if (res != TPM_SUCCESS) return res;
    sealedData->sealInfo.localityAtCreation = 
      tpmData.stany.flags.localityModifier;
  }
  /* setup seal */
  seal.payload = TPM_PT_SEAL;
  memcpy(&seal.tpmProof, &tpmData.permanent.data.tpmProof, 
    sizeof(TPM_NONCE));
  if (compute_store_digest(sealedData, &seal.storedDigest)) {
    debug("TPM_Seal(): compute_store_digest() failed.");
    return TPM_FAIL;
  }
  if ((session->entityType & 0xff00) !=  TPM_ET_XOR)
    return TPM_INAPPROPRIATE_ENC;
  tpm_decrypt_auth_secret(*encAuth, session->sharedSecret,
    &session->lastNonceEven, seal.authData);
  seal.dataSize = inDataSize; 
  seal.data = inData;
  /* encrypt sealed data */
  sealedData->encDataSize = key->key.size >> 3;
  sealedData->encData = tpm_malloc(sealedData->encDataSize);
  if (sealedData->encData == NULL) return TPM_NOSPACE;
  if (tpm_encrypt_sealed_data(key, &seal, sealedData->encData, 
                              &sealedData->encDataSize)) {
    tpm_free(sealedData->encData);
    return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Sealx(TPM_KEY_HANDLE keyHandle, TPM_ENCAUTH *encAuth,
                    UINT32 pcrInfoSize, TPM_PCR_INFO *pcrInfo,
                    UINT32 inDataSize, BYTE *inData,
                    TPM_AUTH *auth1, TPM_STORED_DATA *sealedData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;

  info("TPM_Sealx()");
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
    return TPM_INVALID_KEYUSAGE;
  /* setup store */
  if (pcrInfo->tag != TPM_TAG_PCR_INFO_LONG)
    return TPM_BAD_PARAMETER;
  if ((session->entityType & 0xff00) !=  TPM_ET_XOR)
    return TPM_INAPPROPRIATE_ENC;
  sealedData->tag = TPM_TAG_STORED_DATA12;
  sealedData->et = TPM_ET_XOR | TPM_ET_KEY;
  sealedData->encDataSize = 0;
  sealedData->encData = NULL;
  sealedData->sealInfoSize = pcrInfoSize;
  if (pcrInfoSize > 0) {
    sealedData->sealInfoSize = pcrInfoSize;
    memcpy(&sealedData->sealInfo, pcrInfo, sizeof(TPM_PCR_INFO));
    res = tpm_compute_pcr_digest(&pcrInfo->creationPCRSelection,
      &sealedData->sealInfo.digestAtCreation, NULL);
    if (res != TPM_SUCCESS) return res;
    sealedData->sealInfo.localityAtCreation =
      tpmData.stany.flags.localityModifier;
  }  
  /* setup seal */
  seal.payload = TPM_PT_SEAL;
  memcpy(&seal.tpmProof, &tpmData.permanent.data.tpmProof,
    sizeof(TPM_NONCE));
  if (compute_store_digest(sealedData, &seal.storedDigest)) {
    debug("TPM_Sealx(): compute_store_digest() failed.");
    return TPM_FAIL;
  }
  tpm_decrypt_auth_secret(*encAuth, session->sharedSecret,
    &session->lastNonceEven, seal.authData);
  tpm_xor_encrypt(session, &auth1->nonceOdd, inData, inDataSize);
  seal.dataSize = inDataSize;
  seal.data = inData;
  /* encrypt sealed data */
  sealedData->encDataSize = key->key.size >> 3;
  sealedData->encData = tpm_malloc(sealedData->encDataSize);
  if (sealedData->encData == NULL) return TPM_NOSPACE;
  if (tpm_encrypt_sealed_data(key, &seal, sealedData->encData,
                              &sealedData->encDataSize)) {
    tpm_free(sealedData->encData);
    return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;

}

TPM_RESULT TPM_Unseal(TPM_KEY_HANDLE parentHandle, TPM_STORED_DATA *inData,
                      TPM_AUTH *auth1, TPM_AUTH *auth2,  UINT32 *sealedDataSize, 
                      BYTE **secret)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;
  BYTE *seal_buf;
  TPM_DIGEST digest;
  info("TPM_Unseal()");
  /* get key */
  key = tpm_get_key(parentHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization, if only auth1 is present we use it for the data */
  if (auth2->authHandle != TPM_INVALID_HANDLE 
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
    auth1->continueAuthSession = FALSE;
    session = tpm_get_auth(auth1->authHandle);
  } else {
    session = NULL;
  }
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE) return TPM_INVALID_KEYUSAGE;
  /* verify PCR info */
  if (inData->sealInfoSize > 0) {
    res = tpm_compute_pcr_digest(&inData->sealInfo.releasePCRSelection,
      &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &inData->sealInfo.digestAtRelease, sizeof(TPM_DIGEST)))
      return TPM_WRONGPCRVAL;
    if (inData->sealInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(inData->sealInfo.localityAtRelease 
             & (1 << tpmData.stany.flags.localityModifier)))
       return TPM_BAD_LOCALITY;
  }
  /* decrypt sealed data */
  if (tpm_decrypt_sealed_data(key, inData->encData, inData->encDataSize,
                              &seal, &seal_buf)) return TPM_DECRYPT_ERROR;
  inData->encDataSize = 0;
  if (seal.payload != TPM_PT_SEAL
      || memcmp(&tpmData.permanent.data.tpmProof, &seal.tpmProof, 
             sizeof(TPM_NONCE))
      || verify_store_digest(inData, &seal.storedDigest)) {
    tpm_free(seal_buf);
    return TPM_NOTSEALED_BLOB;
  }
  /* verify data auth */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth2, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
  } else {
    res = tpm_verify_auth(auth1, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return res;
  }
  /* encrypt data if required */
  debug("entity type = %04x", inData->et & 0xff00);
  if (inData->et != 0) {
     if (auth2->authHandle == TPM_INVALID_HANDLE) return TPM_AUTHFAIL;
     if (session->type != TPM_ST_OSAP) return TPM_BAD_MODE;
     if ((inData->et & 0xff00) == TPM_ET_XOR) {
        tpm_xor_encrypt(session, &auth1->nonceOdd, seal.data, seal.dataSize);
     } else return TPM_INAPPROPRIATE_ENC;
  }
  /* return secret */
  *sealedDataSize = seal.dataSize;
  *secret = tpm_malloc(*sealedDataSize);
  if (*secret == NULL) {
    tpm_free(seal_buf);
    return TPM_NOSPACE;
  }
  memcpy(*secret, seal.data, seal.dataSize);
  tpm_free(seal_buf);
  return TPM_SUCCESS;
}
#endif

TPM_RESULT TPM_UnBind(TPM_KEY_HANDLE keyHandle, UINT32 inDataSize,
                      BYTE *inData, TPM_AUTH *auth1, 
                      UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  int key_index;
  TPM_KEY_DATA key;
  UINT32 out_len;
  BYTE bound_flag[] = {0x01, 0x01, 0x00, 0x00, 0x02};
  //int scheme;
  
  /* get key */
  key_index = tpm_get_key(keyHandle);
  if (key_index == -1) return TPM_INVALID_KEYHANDLE;
  if (key_index == SRK_HANDLE) read_TPM_PERMANENT_DATA_srk(&key);
  else read_TPM_PERMANENT_DATA_keys(key_index, &key);
  /* verify auth */
  if (auth1->authHandle != TPM_INVALID_HANDLE 
      || key.authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key.usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* verify key properties */
  if (key.keyUsage != TPM_KEY_BIND 
      && key.keyUsage != TPM_KEY_LEGACY) return TPM_INVALID_KEYUSAGE;
  /* the size of the input data muss be greater than zero */
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* decrypt data */
  *outDataSize = inDataSize;
  *outData = malloc(*outDataSize);
  if (*outData == NULL) return TPM_NOSPACE;
  /* TODO
  switch (key->encScheme) {
    case TPM_ES_RSAESOAEP_SHA1_MGF1: scheme = RSA_ES_OAEP_SHA1; break;
    case TPM_ES_RSAESPKCSv15: scheme = RSA_ES_PKCSV15; break;
    default: tpm_free(*outData); return TPM_DECRYPT_ERROR;
  }
  */
  if (tpm_rsa_decrypt(key.keyFileid, inData, inDataSize, *outData, &out_len)) {
    free(*outData);
    return TPM_DECRYPT_ERROR;
  }
  *outDataSize = out_len;
  /* verify data if it is of type TPM_BOUND_DATA */
  if (key.encScheme == TPM_ES_RSAESOAEP_SHA1_MGF1 
      || key.keyUsage != TPM_KEY_LEGACY) {
    if (*outDataSize < 5 || memcmp(*outData, bound_flag, 5) != 0) {
      free(*outData);
      return TPM_DECRYPT_ERROR;
    }
    *outDataSize -= 5;
    memmove(*outData, &(*outData)[5], *outDataSize);
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CreateWrapKey(TPM_KEY_HANDLE parentHandle, 
                             TPM_ENCAUTH *dataUsageAuth,
                             TPM_ENCAUTH *dataMigrationAuth,
                             TPM_KEY *keyInfo, TPM_AUTH *auth1,  
                             TPM_KEY *wrappedKey)
{
  TPM_RESULT res;
  TPM_KEY_DATA parent;
  int parent_index;
  TPM_SESSION_DATA session;
  int session_index;
  TPM_STORE_ASYMKEY store;
  BYTE *key_buf;

  /* get parent key */
  parent_index = tpm_get_key(parentHandle);
  if (parent_index == -1) return TPM_INVALID_KEYHANDLE;
  if (parent_index == SRK_HANDLE) read_TPM_PERMANENT_DATA_srk(&parent);
  else read_TPM_PERMANENT_DATA_keys(parent_index, &parent);
  /* verify authorization */
  res = tpm_verify_auth(auth1, parent.usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session_index = tpm_get_auth(auth1->authHandle);
  read_TPM_STANY_DATA_sessions(session_index, &session);
  if (session.type != TPM_ST_OSAP && session.type != TPM_ST_DSAP)
    return TPM_AUTHFAIL;
  /* verify key parameters */
  if (parent.keyUsage != TPM_KEY_STORAGE
      || parent.encScheme == TPM_ES_NONE
      || ((parent.keyFlags & TPM_KEY_FLAG_MIGRATABLE)
          && !(keyInfo->keyFlags & TPM_KEY_FLAG_MIGRATABLE))
      || keyInfo->keyUsage == TPM_KEY_IDENTITY
      || keyInfo->keyUsage == TPM_KEY_AUTHCHANGE) return TPM_INVALID_KEYUSAGE;
  if (keyInfo->algorithmParms.algorithmID != TPM_ALG_RSA
      || keyInfo->algorithmParms.parmSize == 0
      || keyInfo->algorithmParms.parms.rsa.keyLength < 512
      || keyInfo->algorithmParms.parms.rsa.numPrimes != 2
      || keyInfo->algorithmParms.parms.rsa.exponentSize != 0)
    return TPM_BAD_KEY_PROPERTY;
  /*
  if (permanentFlags.FIPS
      && (keyInfo->algorithmParms.parms.rsa.keyLength < 1024
          || keyInfo->authDataUsage == TPM_AUTH_NEVER
          || keyInfo->keyUsage == TPM_KEY_LEGACY)) return TPM_NOTFIPS;
  */
  if ((keyInfo->keyUsage == TPM_KEY_STORAGE
       || keyInfo->keyUsage == TPM_KEY_MIGRATE)
      && (keyInfo->algorithmParms.algorithmID != TPM_ALG_RSA
          || keyInfo->algorithmParms.parms.rsa.keyLength != 2048
          || keyInfo->algorithmParms.sigScheme != TPM_SS_NONE
          || keyInfo->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1))
    return TPM_BAD_KEY_PROPERTY;
  /* setup the wrapped key */
  memcpy(wrappedKey, keyInfo, sizeof(TPM_KEY));
  /* setup key store */
  store.payload = TPM_PT_ASYM;
  tpm_decrypt_auth_secret(*dataUsageAuth, session.sharedSecret, 
    &session.lastNonceEven, store.usageAuth);
  if (keyInfo->keyFlags & TPM_KEY_FLAG_MIGRATABLE) {
    tpm_decrypt_auth_secret(*dataMigrationAuth, session.sharedSecret, 
      &auth1->nonceOdd, store.migrationAuth);
    /* clear PCR digest */
    /* TODO PCR related.
    if (keyInfo->PCRInfoSize > 0) {
      memset(keyInfo->PCRInfo.digestAtCreation.digest, 0,
          sizeof(keyInfo->PCRInfo.digestAtCreation.digest));
      keyInfo->PCRInfo.localityAtCreation = 0;
    }
    */
  } else {
    //memcpy(store.migrationAuth, tpmData.permanent.data.tpmProof.nonce, 
      //sizeof(TPM_SECRET));
    read_TPM_PERMANENT_DATA_tpmProof((TPM_NONCE *)store.migrationAuth);
    /* compute PCR digest */
    /* TODO PCR related.
    if (keyInfo->PCRInfoSize > 0) {
      tpm_compute_pcr_digest(&keyInfo->PCRInfo.creationPCRSelection, 
        &keyInfo->PCRInfo.digestAtCreation, NULL);
      keyInfo->PCRInfo.localityAtCreation = 
        tpmData.stany.flags.localityModifier;
    }
    */
  }
  /* generate key and store it */
  key_buf = InOutBuf;

  rsa_genkey(FILEID_RSA_TEMP, (RSA_PRIVATE_KEY *)key_buf);
  wrappedKey->pubKey.keyLength = sizeof(RSA_PUBLIC_KEY);
  wrappedKey->pubKey.key = key_buf;
  store.privKey.keyLength = sizeof(RSA_PRIVATE_KEY) - sizeof(RSA_PUBLIC_KEY);
  store.privKey.key = key_buf + sizeof(RSA_PUBLIC_KEY);

  /* compute the digest of the wrapped key (without encData) */ 
  if (tpm_compute_key_digest(wrappedKey, &store.pubDataDigest)) {
    return TPM_FAIL;
  }

  wrappedKey->encDataSize = 512;
  wrappedKey->encData = malloc(wrappedKey->encDataSize);
  if (wrappedKey->encData == NULL) {
    free(wrappedKey->encData);
    return TPM_NOSPACE;
  }
  
  /* encrypt private key data */
  if (tpm_encrypt_private_key(&parent, &store, wrappedKey->encData, 
      &wrappedKey->encDataSize)) {
    free(wrappedKey->encData);
    return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadKey(TPM_KEY_HANDLE parentHandle, TPM_KEY *inKey,
                       TPM_AUTH *auth1, TPM_KEY_HANDLE *inkeyHandle)
{
  TPM_RESULT res;
  TPM_KEY_DATA parent, key;
  int parent_index, key_index;
  TPM_STORE_ASYMKEY store;
  TPM_NONCE tpmProof;
  /* get parent key */
  parent_index = tpm_get_key(parentHandle);
  if (parent_index == -1) return TPM_INVALID_KEYHANDLE;
  if (parent_index == SRK_HANDLE) read_TPM_PERMANENT_DATA_srk(&parent);
  else read_TPM_PERMANENT_DATA_keys(parent_index, &parent);
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth1, parent.usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
  } else if (parent.authDataUsage != TPM_AUTH_NEVER) {
    return TPM_AUTHFAIL;
  }
  if (parent.keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* verify key properties */
  if (inKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || inKey->algorithmParms.parmSize == 0
      || inKey->algorithmParms.parms.rsa.keyLength > 2048
      || inKey->algorithmParms.parms.rsa.numPrimes != 2)
    return TPM_BAD_KEY_PROPERTY;
  if (inKey->keyUsage == TPM_KEY_AUTHCHANGE) return TPM_INVALID_KEYUSAGE;
  if (inKey->keyUsage == TPM_KEY_STORAGE
       && (inKey->algorithmParms.algorithmID != TPM_ALG_RSA
           || inKey->algorithmParms.parms.rsa.keyLength != 2048
           || inKey->algorithmParms.sigScheme != TPM_SS_NONE)) 
    return TPM_INVALID_KEYUSAGE;
  if (inKey->keyUsage == TPM_KEY_IDENTITY
      && (inKey->keyFlags & TPM_KEY_FLAG_MIGRATABLE
          || inKey->algorithmParms.algorithmID != TPM_ALG_RSA
          || inKey->algorithmParms.parms.rsa.keyLength != 2048
          || inKey->algorithmParms.encScheme != TPM_ES_NONE)) 
    return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  if (tpm_decrypt_private_key(&parent, inKey->encData, inKey->encDataSize, &store)) return TPM_DECRYPT_ERROR;
  /* get a free key-slot, if any free slot is left */
  *inkeyHandle = tpm_get_free_key();
  key_index = tpm_get_key(*inkeyHandle);
  if (key_index == -1) {
    return TPM_NOSPACE;
  }
  if (key_index == SRK_HANDLE) read_TPM_PERMANENT_DATA_srk(&key);
  else read_TPM_PERMANENT_DATA_keys(key_index, &key);
  
  /* import key */
  if (tpm_verify_key_digest(inKey, &store.pubDataDigest) != 0) {
    memset(&key, 0, sizeof(TPM_KEY_DATA));
    return TPM_FAIL;
  }

  if (tpm_rsa_import_key(&key, &store.privKey, &inKey->pubKey)) {
    memset(&key, 0, sizeof(TPM_KEY_DATA));
    return TPM_FAIL;
  }
  /* verify tpmProof */
  if (!(inKey->keyFlags & TPM_KEY_FLAG_MIGRATABLE)) {
    read_TPM_PERMANENT_DATA_tpmProof(&tpmProof);
    if (memcmp(tpmProof.nonce,
               store.migrationAuth, sizeof(TPM_NONCE))) {
      memset(&key, 0, sizeof(TPM_KEY_DATA));
      return TPM_FAIL;
    }
  }
  if (store.payload) key.payload = store.payload;
  key.keyUsage = inKey->keyUsage;
  key.keyFlags = inKey->keyFlags;
  key.authDataUsage = inKey->authDataUsage;
  key.encScheme = inKey->algorithmParms.encScheme;
  key.sigScheme = inKey->algorithmParms.sigScheme;
  memcpy(key.usageAuth, store.usageAuth, sizeof(TPM_SECRET));
  memcpy(key.migrationAuth, store.migrationAuth, sizeof(TPM_SECRET));
  /* setup PCR info */
  /* TODO
  if (inKey->PCRInfoSize > 0) {
    memcpy(&key->pcrInfo, &inKey->PCRInfo, sizeof(TPM_PCR_INFO));
    key->keyFlags |= TPM_KEY_FLAG_HAS_PCR;
  } else {
    key->keyFlags |= TPM_KEY_FLAG_PCR_IGNORE;
    key->keyFlags &= ~TPM_KEY_FLAG_HAS_PCR;
  }
  key->parentPCRStatus = parent->parentPCRStatus;
  */
  write_TPM_PERMANENT_DATA_keys(key_index, &key);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadKey2(TPM_KEY_HANDLE parentHandle, TPM_KEY *inKey,
                        TPM_AUTH *auth1, TPM_KEY_HANDLE *inkeyHandle)
{
  return TPM_LoadKey(parentHandle, inKey, auth1, inkeyHandle);
}

TPM_RESULT TPM_GetPubKey(TPM_KEY_HANDLE keyHandle, TPM_AUTH *auth1,
                         TPM_PUBKEY *pubKey)
{
  TPM_RESULT res;
  int key_index;
  TPM_KEY_DATA key;
  //TPM_DIGEST digest;
  /* get key */
  if (keyHandle == TPM_KH_SRK
      && permanentFlags.readSRKPub) return TPM_INVALID_KEYHANDLE;
  key_index = tpm_get_key(keyHandle);
  if (key_index == -1) return TPM_INVALID_KEYHANDLE;
  if (key_index == SRK_HANDLE) read_TPM_PERMANENT_DATA_srk(&key);
  else read_TPM_PERMANENT_DATA_keys(key_index, &key);
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || (key.authDataUsage != TPM_AUTH_NEVER
          && key.authDataUsage != TPM_AUTH_PRIV_USE_ONLY)) {
              res = tpm_verify_auth(auth1, key.usageAuth, keyHandle);
              if (res != TPM_SUCCESS) return res;
  }
  if (!(key.keyFlags & TPM_KEY_FLAG_PCR_IGNORE)) {
      /* TODO PCR 
    res = tpm_compute_pcr_digest(&key->pcrInfo.releasePCRSelection,
      &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &key->pcrInfo.digestAtRelease, sizeof(TPM_DIGEST)))
      return TPM_WRONGPCRVAL;
    if (key->pcrInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(key->pcrInfo.localityAtRelease
             & (1 << tpmData.stany.flags.localityModifier)))
       return TPM_BAD_LOCALITY;
       */
  }
  /* extract pubKey */
  if (tpm_extract_pubkey(&key, pubKey) != 0) return TPM_FAIL;
  return TPM_SUCCESS;
}
