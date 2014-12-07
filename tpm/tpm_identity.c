/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *               2005-2008 Heiko Stamer <stamer@gaos.org>
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
 * $Id: tpm_identity.c 468 2011-09-09 07:58:42Z mast $
 */

#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include "../crypto/sha1.h"
#include "ftrx.h"

extern unsigned char ExtendBuf[0x400];
extern unsigned char InOutBuf[0x400];


/*
 * Identity Creation and Activation ([TPM_Part3], Section 15)
 */

TPM_RESULT TPM_MakeIdentity(
  TPM_ENCAUTH *identityAuth,
  TPM_CHOSENID_HASH *labelPrivCADigest,
  TPM_KEY *idKeyParams,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_KEY *idKey,
  UINT32 *identityBindingSize,
  BYTE **identityBinding
)
{
  TPM_RESULT res;
  TPM_SESSION_DATA ownerAuth_sessionData;
  int ownerAuth_sessionIndex;
  TPM_SECRET A1;
  TPM_STORE_ASYMKEY store;
  TPM_SECRET ownerAuth;
  TPM_SECRET srkAuth;
  TPM_NONCE tpmProof;
  BYTE *key_buf;
  
  /* 1. Validate the idKeyParams parameters for the key description */ if (idKeyParams->algorithmParms.encScheme != TPM_ES_NONE
      || idKeyParams->algorithmParms.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
        return TPM_BAD_KEY_PROPERTY;
    switch (idKeyParams->algorithmParms.algorithmID) {
      case TPM_ALG_RSA:
        if (idKeyParams->algorithmParms.parmSize == 0
          || idKeyParams->algorithmParms.parms.rsa.keyLength != 2048
          || idKeyParams->algorithmParms.parms.rsa.numPrimes != 2
          || idKeyParams->algorithmParms.parms.rsa.exponentSize != 0)
            return TPM_BAD_KEY_PROPERTY;
        break;
      default:
        return TPM_BAD_KEY_PROPERTY;
    }

  /* 2. Use authHandle to verify that the Owner authorized all TPM_MakeIdentity 
   * input parameters. */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    read_TPM_PERMANENT_DATA_ownerAuth(&ownerAuth);
    res = tpm_verify_auth(auth2, ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) {
        return res;
    }
    ownerAuth_sessionIndex = tpm_get_auth(auth2->authHandle);
    if (ownerAuth_sessionIndex == -1) return TPM_INVALID_AUTHHANDLE;
    read_TPM_STANY_DATA_sessions(ownerAuth_sessionIndex, &ownerAuth_sessionData);

  } else {
    read_TPM_PERMANENT_DATA_ownerAuth(&ownerAuth);
    res = tpm_verify_auth(auth1, ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) {
        return res;
    }
    ownerAuth_sessionIndex = tpm_get_auth(auth1->authHandle);
    if (ownerAuth_sessionIndex == -1) return TPM_INVALID_AUTHHANDLE;
    read_TPM_STANY_DATA_sessions(ownerAuth_sessionIndex, &ownerAuth_sessionData);
  }
  /* 3. Use srkAuthHandle to verify that the SRK owner authorized all 
   * TPM_MakeIdentity input parameters. */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
      read_TPM_PERMANENT_DATA_srk_usageAuth(&srkAuth);
    res = tpm_verify_auth(auth1, srkAuth, 
      TPM_KH_SRK);
    if (res != TPM_SUCCESS) return res;
  }
  /* 4. Verify that idKeyParams->keyUsage is TPM_KEY_IDENTITY. If it is not, 
   * return TPM_INVALID_KEYUSAGE */
  if (idKeyParams->keyUsage != TPM_KEY_IDENTITY)
    return TPM_INVALID_KEYUSAGE;
  /* 5. Verify that idKeyParams->keyFlags->migratable is FALSE. If it is not,
   * return TPM_INVALID_KEYUSAGE */
  if ((idKeyParams->keyFlags & TPM_KEY_FLAG_MIGRATABLE) == 
    TPM_KEY_FLAG_MIGRATABLE)
      return TPM_INVALID_KEYUSAGE;
  /* 6. If ownerAuth indicates XOR encryption for the AuthData secrets */
  if ((ownerAuth_sessionData.entityType & 0xFF00) == TPM_ET_XOR) {
    /* a. Create X1 the SHA-1 of the concatenation of (ownerAuth->sharedSecret 
     * || authLastNonceEven) */
    /* b. Create A1 by XOR X1 and identityAuth */
    tpm_decrypt_auth_secret(*identityAuth, ownerAuth_sessionData.sharedSecret, 
      &ownerAuth_sessionData.lastNonceEven, A1);
  } else {
  /* 7. Else */
    /* a. Create A1 by decrypting identityAuth using the algorithm indicated 
     * in the OSAP session */
    /* b. Key is from ownerAuth->sharedSecret */
    /* c. IV is SHA-1 of (authLastNonceEven || nonceOdd) */
    return TPM_FAIL;
  }
  /* 8. Set continueAuthSession and continueSRKSession to FALSE. */
  auth2->continueAuthSession = FALSE, auth1->continueAuthSession = FALSE;
  /* 9. Determine the structure version */
    /* a. If idKeyParms->tag is TPM_TAG_KEY12 */
    if (idKeyParams->tag == TPM_TAG_KEY12) {
      /* i. Set V1 to 2 */
      /* ii. Create idKey a TPM_KEY12 structure using idKeyParams as the 
       * default values for the structure */
      idKey->tag = TPM_TAG_KEY12;
      idKey->fill = 0x0000;
      idKey->keyUsage = TPM_KEY_IDENTITY;
      idKey->keyFlags = idKeyParams->keyFlags;
      idKey->authDataUsage = idKeyParams->authDataUsage;
      idKey->algorithmParms.algorithmID = 
        idKeyParams->algorithmParms.algorithmID;
      idKey->algorithmParms.encScheme = idKeyParams->algorithmParms.encScheme;
      idKey->algorithmParms.sigScheme = idKeyParams->algorithmParms.sigScheme;
      idKey->algorithmParms.parmSize = idKeyParams->algorithmParms.parmSize;
      switch (idKeyParams->algorithmParms.algorithmID) {
        case TPM_ALG_RSA:
          idKey->algorithmParms.parms.rsa.keyLength =
            idKeyParams->algorithmParms.parms.rsa.keyLength;
          idKey->algorithmParms.parms.rsa.numPrimes =
            idKeyParams->algorithmParms.parms.rsa.numPrimes;
          idKey->algorithmParms.parms.rsa.exponentSize =
            idKeyParams->algorithmParms.parms.rsa.exponentSize;
          break;
        default:
          return TPM_BAD_KEY_PROPERTY;
      }
      idKey->PCRInfoSize = idKeyParams->PCRInfoSize;
      idKey->PCRInfo.tag = TPM_TAG_PCR_INFO_LONG;
      idKey->PCRInfo.localityAtCreation = 
        idKeyParams->PCRInfo.localityAtCreation;
      idKey->PCRInfo.localityAtRelease = 
        idKeyParams->PCRInfo.localityAtRelease;
      idKey->PCRInfo.creationPCRSelection = 
        idKeyParams->PCRInfo.creationPCRSelection;
      idKey->PCRInfo.releasePCRSelection = 
        idKeyParams->PCRInfo.releasePCRSelection;
      idKey->PCRInfo.digestAtCreation = 
        idKeyParams->PCRInfo.digestAtCreation;
      idKey->PCRInfo.digestAtRelease = 
        idKeyParams->PCRInfo.digestAtRelease;
    } else if (idKeyParams->tag == 0x0101) {
    /* b. If idKeyParms->ver is 1.1 */
      /* i. Set V1 to 1 */
      /* ii. Create idKey a TPM_KEY structure using idKeyParams as the 
       * default values for the structure */
      idKey->tag = 0x0101;
      idKey->fill = 0x0000;
      idKey->keyUsage = TPM_KEY_IDENTITY;
      idKey->keyFlags = idKeyParams->keyFlags;
      idKey->authDataUsage = idKeyParams->authDataUsage;
      idKey->algorithmParms.algorithmID = 
        idKeyParams->algorithmParms.algorithmID;
      idKey->algorithmParms.encScheme = idKeyParams->algorithmParms.encScheme;
      idKey->algorithmParms.sigScheme = idKeyParams->algorithmParms.sigScheme;
      idKey->algorithmParms.parmSize = idKeyParams->algorithmParms.parmSize;
      switch (idKeyParams->algorithmParms.algorithmID) {
        case TPM_ALG_RSA:
          idKey->algorithmParms.parms.rsa.keyLength =
            idKeyParams->algorithmParms.parms.rsa.keyLength;
          idKey->algorithmParms.parms.rsa.numPrimes =
            idKeyParams->algorithmParms.parms.rsa.numPrimes;
          idKey->algorithmParms.parms.rsa.exponentSize =
            idKeyParams->algorithmParms.parms.rsa.exponentSize;
          break;
        default:
          return TPM_BAD_KEY_PROPERTY;
      }
      idKey->PCRInfoSize = idKeyParams->PCRInfoSize;
      idKey->PCRInfo.tag = 0x0000;
      idKey->PCRInfo.creationPCRSelection = 
        idKeyParams->PCRInfo.creationPCRSelection;
      idKey->PCRInfo.digestAtRelease = 
        idKeyParams->PCRInfo.digestAtRelease;
      idKey->PCRInfo.digestAtCreation = 
        idKeyParams->PCRInfo.digestAtCreation;
    } else {
      return TPM_FAIL;
    }

  /* 11. Create an asymmetric key pair (identityPubKey and tpm_signature_key) 
   * using a TPM-protected capability, in accordance with the algorithm 
   * specified in idKeyParams */
  key_buf = InOutBuf;
  if (rsa_genkey(FILEID_RSA_TEMP, (RSA_PRIVATE_KEY *)key_buf) != ERR_SUCCESS) {
    return TPM_FAIL;
  }
  /* 12. Ensure that the AuthData information in A1 is properly stored in the 
   * idKey as usageAuth. */
  memcpy(store.usageAuth, A1, sizeof(TPM_SECRET));
  /* 13. Attach identityPubKey and tpm_signature_key to idKey */
  idKey->pubKey.keyLength = sizeof(RSA_PUBLIC_KEY);
  idKey->pubKey.key = key_buf;

  store.privKey.keyLength = sizeof(RSA_PRIVATE_KEY) - sizeof(RSA_PUBLIC_KEY);
  store.privKey.key = key_buf + sizeof(RSA_PUBLIC_KEY);

  idKey->encDataSize = 512;
  idKey->encData = malloc(idKey->encDataSize);
  if (idKey->encData == NULL) {
    free(idKey->encData);
    return TPM_NOSPACE;
  }
  /* 14. Set idKey->migrationAuth to TPM_PERMANENT_DATA->tpmProof */
  read_TPM_PERMANENT_DATA_tpmProof(&tpmProof);
  memcpy(store.migrationAuth, tpmProof.nonce, 
    sizeof(TPM_SECRET));
  /* 15. Ensure that all TPM_PAYLOAD_TYPE structures identify this key as 
   * TPM_PT_ASYM */
  store.payload = TPM_PT_ASYM;
  /* compute the digest on all public data of this key */
  if (tpm_compute_key_digest(idKey, &store.pubDataDigest)) {
    return TPM_FAIL;
  }
  /* 16. Encrypt the private portion of idKey using the SRK as the parent key */
  //read_TPM_PERMANENT_DATA_srk(&srk);
  if (tpm_encrypt_private_key_new(FILEID_SRK_PUB, &store, idKey->encData, 
    &idKey->encDataSize)) {
      free(idKey->encData);
      return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;
}

