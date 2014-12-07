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
 * $Id: tpm_integrity.c 474 2011-12-20 10:27:45Z mast $
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
 * Integrity Collection and Reporting ([TPM_Part3], Section 16)
 * This section deals with what commands have direct access to the PCR.
 */

TPM_RESULT TPM_Extend(TPM_PCRINDEX pcrNum, TPM_DIGEST *inDigest, 
                      TPM_PCRVALUE *outDigest)
{
  tpm_sha1_ctx_t ctx;
  TPM_PCR_ATTRIBUTES attrib;
  TPM_PCRVALUE pcrValue;

  if (pcrNum >= TPM_NUM_PCR) return TPM_BADINDEX;
  read_TPM_PERMANENT_DATA_pcrAttrib(pcrNum, &attrib);
  if (!(attrib.pcrExtendLocal & (1 << stanyFlags.localityModifier))) return TPM_BAD_LOCALITY;
  /* compute new PCR value as SHA-1(old PCR value || inDigest) */
  read_TPM_PERMANENT_DATA_pcrValue(pcrNum, &pcrValue);
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, pcrValue.digest, sizeof(pcrValue.digest));
  tpm_sha1_update(&ctx, inDigest->digest, sizeof(inDigest->digest));
  tpm_sha1_final(&ctx, pcrValue.digest);  
  /* set output digest */
  if (permanentFlags.disable) {
    memset(outDigest->digest, 0, sizeof(*outDigest->digest));
  } else {
    memcpy(outDigest, &pcrValue, sizeof(TPM_PCRVALUE));
  }
  write_TPM_PERMANENT_DATA_pcrValue(pcrNum, &pcrValue);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PCRRead(TPM_PCRINDEX pcrIndex, TPM_PCRVALUE *outDigest)
{
    TPM_PCRVALUE pcrValue;
  if (pcrIndex >= TPM_NUM_PCR) return TPM_BADINDEX;
  read_TPM_PERMANENT_DATA_pcrValue(pcrIndex, &pcrValue);
  memcpy(outDigest, &pcrValue, sizeof(TPM_PCRVALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Quote(TPM_KEY_HANDLE keyHandle, TPM_NONCE *extrnalData, 
                     TPM_PCR_SELECTION *targetPCR, TPM_AUTH *auth1, 
                     TPM_PCR_COMPOSITE *pcrData, 
                     UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA key;
  int key_index;
  TPM_COMPOSITE_HASH hash;
  UINT32 errcode;
  UINT16 dataSize;
  BYTE buf[48];
  /* get key */
  key_index = tpm_get_key(keyHandle);
  if (key_index == -1) return TPM_INVALID_KEYHANDLE;
  read_TPM_PERMANENT_DATA_keys(key_index, &key);
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key.authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key.usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (key.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
    return TPM_INAPPROPRIATE_SIG;
  if (key.keyUsage != TPM_KEY_SIGNING && key.keyUsage != TPM_KEY_LEGACY
      && key.keyUsage != TPM_KEY_IDENTITY)
    return TPM_INVALID_KEYUSAGE;
  /* compute composite hash */
  res = tpm_compute_pcr_digest(targetPCR, &hash, pcrData);
  if (res != TPM_SUCCESS) return res;
  /* setup quote info and sign it */
  memcpy(&buf[ 0], "\x01\x01\x00\x00QUOT", 8);
  memcpy(&buf[ 8], hash.digest, 20);
  memcpy(&buf[28], extrnalData->nonce, 20);
  *sigSize = 256;
  *sig = malloc(*sigSize);
  errcode = rsa_pri(key.keyFileid, buf, 48, *sig, &dataSize, MODE_ENCODE );
  if (errcode != ERR_SUCCESS) return TPM_FAIL;
  return TPM_SUCCESS;
}

TPM_RESULT tpm_compute_pcr_digest(TPM_PCR_SELECTION *pcrSelection, 
                                  TPM_COMPOSITE_HASH *digest, 
                                  TPM_PCR_COMPOSITE *composite)
{
  int i,j;
  TPM_PCR_COMPOSITE *comp;
  tpm_sha1_ctx_t ctx;
  UINT32 len;
  BYTE *buf, *ptr;
  TPM_PCRVALUE pcrValue;
  comp = (TPM_PCR_COMPOSITE *)(InOutBuf + 512);
  /* create PCR composite */
  if ((pcrSelection->sizeOfSelect * 8) > TPM_NUM_PCR
      || pcrSelection->sizeOfSelect == 0) return TPM_INVALID_PCR_INFO;
  for (i = 0, j = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      read_TPM_PERMANENT_DATA_pcrValue(i, &pcrValue);
      memcpy(&comp->pcrValue[j++], &pcrValue, sizeof(TPM_PCRVALUE));
    }
  }
  memcpy(&comp->select, pcrSelection, sizeof(TPM_PCR_SELECTION));
  comp->valueSize = j * sizeof(TPM_PCRVALUE);
  if (comp->valueSize > 0) {
    /* marshal composite and compute hash */
    len = sizeof_TPM_PCR_COMPOSITE((*comp));
    //buf = ptr = malloc(len);
    buf = ptr = ExtendBuf;
    if (buf == NULL
        || tpm_marshal_TPM_PCR_COMPOSITE(&ptr, &len, comp)) {
       free(buf);
       return TPM_FAIL;
    }
    tpm_sha1_init(&ctx);
    tpm_sha1_update(&ctx, buf, sizeof_TPM_PCR_COMPOSITE((*comp)));
    tpm_sha1_final(&ctx, digest->digest);
    free(buf);
  } else {
    memset(digest, 0, sizeof(TPM_COMPOSITE_HASH));
  }
  /* copy composite if requested */
  if (composite != NULL)
    memcpy(composite, comp, sizeof(TPM_PCR_COMPOSITE));
  return TPM_SUCCESS;
}

