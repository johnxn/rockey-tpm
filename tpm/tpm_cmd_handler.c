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
 * $Id: tpm_cmd_handler.c 467 2011-07-19 17:36:12Z mast $
 */

#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_marshalling.h"
#include "tpm_handles.h"
#include "stdlib.h"
#include "../crypto/hmac.h"
#include "../crypto/sha1.h"

extern unsigned char InOutBuf[0x400];
extern unsigned char ExtendBuf[0x400];

UINT32 tpm_get_in_param_offset(TPM_COMMAND_CODE ordinal)
{
  switch (ordinal) {
    case TPM_ORD_ActivateIdentity:
    case TPM_ORD_ChangeAuth:
    case TPM_ORD_ChangeAuthAsymStart:
    case TPM_ORD_CMK_ConvertMigration:
    case TPM_ORD_CMK_CreateBlob:
    case TPM_ORD_CMK_CreateKey:
    case TPM_ORD_ConvertMigrationBlob:
    case TPM_ORD_CreateMigrationBlob:
    case TPM_ORD_CreateWrapKey:
    case TPM_ORD_Delegate_CreateKeyDelegation:
    case TPM_ORD_DSAP:
    case TPM_ORD_EstablishTransport:
    case TPM_ORD_EvictKey:
    case TPM_ORD_FlushSpecific:
    case TPM_ORD_GetAuditDigestSigned:
    case TPM_ORD_GetPubKey:
    case TPM_ORD_KeyControlOwner:
    case TPM_ORD_LoadKey:
    case TPM_ORD_LoadKey2:
    case TPM_ORD_MigrateKey:
    case TPM_ORD_Quote:
    case TPM_ORD_Quote2:
    case TPM_ORD_ReleaseTransportSigned:
    case TPM_ORD_SaveKeyContext:
    case TPM_ORD_Seal:
    case TPM_ORD_Sealx:
    case TPM_ORD_SetRedirection:
    case TPM_ORD_Sign:
    case TPM_ORD_TickStampBlob:
    case TPM_ORD_UnBind:
    case TPM_ORD_Unseal:
    case TPM_ORD_DAA_Join:
    case TPM_ORD_DAA_Sign:
      return 4;

    case TPM_ORD_CertifyKey:
    case TPM_ORD_CertifyKey2:
    case TPM_ORD_ChangeAuthAsymFinish:
      return 8;

    case TPM_ORD_OSAP:
      return 26;

    default:
      return 0;
  }
}											

UINT32 tpm_get_out_param_offset(TPM_COMMAND_CODE ordinal)
{
  switch (ordinal) {

    case TPM_ORD_EstablishTransport:
    case TPM_ORD_LoadKey2:
      return 4;

    case TPM_ORD_OIAP:
      return 24;

    case TPM_ORD_OSAP:
      return 44;

    default:
      return 0;
  }
}

void tpm_engine_first_time() {
    //create_tpmdata_files();
    tpm_init_data();
    set_permanent_flags();
    TPM_Init(TPM_ST_CLEAR);
    save_flags();
}

int tpm_engine_init() {
    return restore_flags();
}

int tpm_engine_final() {
    return save_flags();
}

  
#if 0
int tpm_emulator_init(unsigned int startup)
{
    /* initialize the emulator */
    //create_tpmdata_files();
    //tpm_init_data();
    if (restore_flags() == -1)  set_permanent_flags();
    //TPM_Init(startup);
    return 0;
}
#endif

int tpm_emulator_shutdown()
{
    if (TPM_SaveState() != TPM_SUCCESS) {
        return -1;
    }
    return 0;
}
 
void tpm_compute_in_param_digest(TPM_REQUEST *req)
{
  tpm_sha1_ctx_t sha1;
  UINT32 offset = tpm_get_in_param_offset(req->ordinal);

  /* compute SHA1 hash */
  if (offset <= req->paramSize) {
    tpm_sha1_init(&sha1);
    tpm_sha1_update_be32(&sha1, req->ordinal);
    /* skip all handles at the beginning */
    tpm_sha1_update(&sha1, req->param + offset, req->paramSize - offset);
    tpm_sha1_final(&sha1, req->auth1.digest);
    memcpy(req->auth2.digest, req->auth1.digest, sizeof(req->auth1.digest));
  }
}

void tpm_compute_out_param_digest(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp)
{
  tpm_sha1_ctx_t sha1;
  UINT32 offset = tpm_get_out_param_offset(ordinal);

  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update_be32(&sha1, rsp->result);
  tpm_sha1_update_be32(&sha1, ordinal);

  tpm_sha1_update(&sha1, rsp->param + offset, rsp->paramSize - offset);
  tpm_sha1_final(&sha1, rsp->auth1->digest);
  if (rsp->auth2 != NULL) memcpy(rsp->auth2->digest, 
    rsp->auth1->digest, sizeof(rsp->auth1->digest));
}


static void tpm_setup_error_response(TPM_RESULT res, TPM_RESPONSE *rsp)
{
    rsp->tag = TPM_TAG_RSP_COMMAND;
    rsp->size = 10;
    rsp->result = res;
    rsp->param = NULL;
    rsp->paramSize = 0;
}


static TPM_RESULT tpm_check_status_and_mode(TPM_REQUEST *req)
{
    /* verify that self-test succeeded */
    //debug((BYTE *)&permanentFlags.selfTestSucceeded, sizeof(permanentFlags.selfTestSucceeded));
    if (!permanentFlags.selfTestSucceeded) return TPM_FAILEDSELFTEST;
    /* initialisation must be finished before we execute any command */
    //debug((BYTE *)&stanyFlags.postInitialise, sizeof(stanyFlags.postInitialise));
    if (stanyFlags.postInitialise) return TPM_INVALID_POSTINIT;
    /* if the TPM is deactivated only a subset of all commands can be performed */
    if ((permanentFlags.deactivated || stclearFlags.deactivated)
            && req->ordinal != TPM_ORD_Reset
            && req->ordinal != TPM_ORD_Init
            && req->ordinal != TPM_ORD_Startup
            && req->ordinal != TPM_ORD_SaveState
            && req->ordinal != TPM_ORD_SHA1Start
            && req->ordinal != TPM_ORD_SHA1Update
            && req->ordinal != TPM_ORD_SHA1Complete
            && req->ordinal != TPM_ORD_SHA1CompleteExtend
            && req->ordinal != TPM_ORD_OIAP
            && req->ordinal != TPM_ORD_OSAP
            && req->ordinal != TPM_ORD_DSAP
            && req->ordinal != TPM_ORD_GetCapability
            && req->ordinal != TPM_ORD_SetCapability
            && req->ordinal != TPM_ORD_TakeOwnership
            && req->ordinal != TPM_ORD_OwnerSetDisable
            && req->ordinal != TPM_ORD_PhysicalDisable
            && req->ordinal != TPM_ORD_PhysicalEnable
            && req->ordinal != TPM_ORD_PhysicalSetDeactivated
            && req->ordinal != TPM_ORD_ContinueSelfTest
            && req->ordinal != TPM_ORD_SelfTestFull
            && req->ordinal != TPM_ORD_GetTestResult
            && req->ordinal != TPM_ORD_FlushSpecific
            && req->ordinal != TPM_ORD_Terminate_Handle
            && req->ordinal != TPM_ORD_Extend
            && req->ordinal != TPM_ORD_PCR_Reset
            && req->ordinal != TPM_ORD_NV_DefineSpace
            && req->ordinal != TPM_ORD_NV_ReadValue
            && req->ordinal != TPM_ORD_NV_WriteValue
            && req->ordinal != TSC_ORD_PhysicalPresence
            && req->ordinal != TSC_ORD_ResetEstablishmentBit
            ) return TPM_DEACTIVATED;
    /* if the TPM is disabled only a subset of all commands can be performed */
    if (permanentFlags.disable
            && req->ordinal != TPM_ORD_Reset
            && req->ordinal != TPM_ORD_Init
            && req->ordinal != TPM_ORD_Startup
            && req->ordinal != TPM_ORD_SaveState
            && req->ordinal != TPM_ORD_SHA1Start
            && req->ordinal != TPM_ORD_SHA1Update
            && req->ordinal != TPM_ORD_SHA1Complete
            && req->ordinal != TPM_ORD_SHA1CompleteExtend
            && req->ordinal != TPM_ORD_OIAP
            && req->ordinal != TPM_ORD_OSAP
            && req->ordinal != TPM_ORD_DSAP
            && req->ordinal != TPM_ORD_GetCapability
            && req->ordinal != TPM_ORD_SetCapability
            && req->ordinal != TPM_ORD_OwnerSetDisable
            && req->ordinal != TPM_ORD_PhysicalEnable
            && req->ordinal != TPM_ORD_ContinueSelfTest
            && req->ordinal != TPM_ORD_SelfTestFull
            && req->ordinal != TPM_ORD_GetTestResult
            && req->ordinal != TPM_ORD_FlushSpecific
            && req->ordinal != TPM_ORD_Terminate_Handle
            && req->ordinal != TPM_ORD_Extend
            && req->ordinal != TPM_ORD_PCR_Reset
            && req->ordinal != TPM_ORD_NV_DefineSpace
            && req->ordinal != TPM_ORD_NV_ReadValue
            && req->ordinal != TPM_ORD_NV_WriteValue
            && req->ordinal != TSC_ORD_PhysicalPresence
            && req->ordinal != TSC_ORD_ResetEstablishmentBit
            ) return TPM_DISABLED;
    return TPM_SUCCESS; 
}

static void tpm_setup_rsp_auth(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp) 
{
    tpm_hmac_ctx_t hmac;

    /* compute parameter digest */
    if (ordinal != TPM_ORD_ExecuteTransport)
        tpm_compute_out_param_digest(ordinal, rsp);
    /* compute authorization values */
    switch (rsp->tag) {
        case TPM_TAG_RSP_AUTH2_COMMAND:
            tpm_hmac_init(&hmac, rsp->auth2->secret, sizeof(rsp->auth2->secret));
            tpm_hmac_update(&hmac, rsp->auth2->digest, sizeof(rsp->auth2->digest));
            tpm_hmac_update(&hmac, rsp->auth2->nonceEven.nonce, 
                    sizeof(rsp->auth2->nonceEven.nonce));
            tpm_hmac_update(&hmac, rsp->auth2->nonceOdd.nonce, 
                    sizeof(rsp->auth2->nonceOdd.nonce));
            tpm_hmac_update(&hmac, (BYTE*)&rsp->auth2->continueAuthSession, 1);
            tpm_hmac_final(&hmac, rsp->auth2->auth);
        case TPM_TAG_RSP_AUTH1_COMMAND:
            tpm_hmac_init(&hmac, rsp->auth1->secret, sizeof(rsp->auth1->secret));
            tpm_hmac_update(&hmac, rsp->auth1->digest, sizeof(rsp->auth1->digest));
            tpm_hmac_update(&hmac, rsp->auth1->nonceEven.nonce, 
                    sizeof(rsp->auth1->nonceEven.nonce));
            tpm_hmac_update(&hmac, rsp->auth1->nonceOdd.nonce, 
                    sizeof(rsp->auth1->nonceOdd.nonce));
            tpm_hmac_update(&hmac, (BYTE*)&rsp->auth1->continueAuthSession, 1);
            tpm_hmac_final(&hmac, rsp->auth1->auth);
            break;
    }
}

static TPM_RESULT execute_TPM_Startup(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
    BYTE *ptr;
    UINT32 len;
    TPM_STARTUP_TYPE startupType;
    /* unmarshal input */
    ptr = req->param;
    len = req->paramSize;
    if (tpm_unmarshal_TPM_STARTUP_TYPE(&ptr, &len, &startupType)
            || len != 0) return TPM_BAD_PARAMETER;
    /* execute command */
    return TPM_Startup(startupType);
}

static TPM_RESULT execute_TPM_SaveState(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
    /* execute command */
    return TPM_SaveState();
}

static TPM_RESULT execute_TPM_FlushSpecific(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE handle;
  TPM_RESOURCE_TYPE resourceType;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &handle)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(&ptr, &len, &resourceType)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_FlushSpecific(handle, resourceType);
}

static TPM_RESULT execute_TPM_OIAP(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
    BYTE *ptr;
    UINT32 len;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_RESULT res;
    /* execute command */
    res = TPM_OIAP(&authHandle, &nonceEven);
    if (res != TPM_SUCCESS) return res;
    /* marshal output */
    rsp->paramSize = len = 4 + 20;
    rsp->param = ptr = malloc(len);
    if (ptr == NULL
            || tpm_marshal_TPM_AUTHHANDLE(&ptr, &len, authHandle)
            || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEven)) {
        free(rsp->param);
        res = TPM_FAIL;
    }
    return res;
}

static TPM_RESULT execute_TPM_OSAP(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
    BYTE *ptr;
    UINT32 len;
    TPM_ENTITY_TYPE entityType;
    UINT32 entityValue;
    TPM_NONCE nonceOddOSAP;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceEvenOSAP;
    TPM_RESULT res;
    /* unmarshal input */
    ptr = req->param;
    len = req->paramSize;
    if (tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
            || tpm_unmarshal_UINT32(&ptr, &len, &entityValue)
            || tpm_unmarshal_TPM_NONCE(&ptr, &len, &nonceOddOSAP)
            || len != 0) return TPM_BAD_PARAMETER;
    /* execute command */
    res = TPM_OSAP(entityType, entityValue, &nonceOddOSAP, &authHandle, 
            &nonceEven, &nonceEvenOSAP);
    if (res != TPM_SUCCESS) return res;
    /* marshal output */
    rsp->paramSize = len = 4 + 20 + 20;
    rsp->param = ptr = malloc(len);
    if (ptr == NULL
            || tpm_marshal_TPM_AUTHHANDLE(&ptr, &len, authHandle)
            || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEven)
            || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEvenOSAP)) {
        free(rsp->param);
        res = TPM_FAIL;
    }
    return res;
}

static TPM_RESULT execute_TPM_TakeOwnership(TPM_REQUEST *req, TPM_RESPONSE *rsp) {
   BYTE *ptr;
   UINT32 len;
   TPM_PROTOCOL_ID protocolID;
   UINT32 encOwnerAuthSize;
   BYTE *encOwnerAuth;
   UINT32 encSrkAuthSize;
   BYTE *encSrkAuth;
   TPM_KEY srkParams;
   TPM_KEY srkPub;
   TPM_RESULT res;
   /* compute parameter digest */
   tpm_compute_in_param_digest(req);
   /* unmarshal input */
   ptr = req->param;
   len = req->paramSize;
   if (tpm_unmarshal_TPM_PROTOCOL_ID(&ptr, &len, &protocolID)
       || tpm_unmarshal_UINT32(&ptr, &len, &encOwnerAuthSize)
       || tpm_unmarshal_BLOB(&ptr, &len, &encOwnerAuth, encOwnerAuthSize)
       || tpm_unmarshal_UINT32(&ptr, &len, &encSrkAuthSize)
       || tpm_unmarshal_BLOB(&ptr, &len, &encSrkAuth, encSrkAuthSize)
       || tpm_unmarshal_TPM_KEY(&ptr, &len, &srkParams)
       || len != 0) return TPM_BAD_PARAMETER;
   /* execute command */
   res = TPM_TakeOwnership(protocolID, encOwnerAuthSize, encOwnerAuth, 
     encSrkAuthSize, encSrkAuth, &srkParams, &req->auth1, &srkPub);
   if (res != TPM_SUCCESS) return res;
   /* marshal output */
   rsp->paramSize = len = sizeof_TPM_KEY(srkPub);
   rsp->param = ptr = malloc(len);
   if (ptr == NULL
       || tpm_marshal_TPM_KEY(&ptr, &len, &srkPub)) {
     free(rsp->param);
     res = TPM_FAIL;
   }
   free_TPM_KEY(srkPub);
   return res;
 }

static TPM_RESULT execute_TPM_CreateWrapKey(TPM_REQUEST *req, TPM_RESPONSE *rsp) {
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_ENCAUTH dataUsageAuth;
  TPM_ENCAUTH dataMigrationAuth;
  TPM_KEY keyInfo;
  TPM_KEY wrappedKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &dataUsageAuth)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &dataMigrationAuth)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &keyInfo)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateWrapKey(parentHandle, &dataUsageAuth, &dataMigrationAuth, 
    &keyInfo, &req->auth1, &wrappedKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(wrappedKey);
  //rsp->param = ptr = malloc(len);
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, &wrappedKey)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_KEY(wrappedKey);
  return res;
}

static TPM_RESULT execute_TPM_LoadKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_KEY inKey;
  TPM_KEY_HANDLE inkeyHandle;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &inKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadKey(parentHandle, &inKey, &req->auth1, &inkeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, inkeyHandle)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_LoadKey2(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;		 
  TPM_KEY inKey;
  TPM_KEY_HANDLE inkeyHandle;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &inKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadKey2(parentHandle, &inKey, &req->auth1, &inkeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, inkeyHandle)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_GetPubKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_PUBKEY pubKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_GetPubKey(keyHandle, &req->auth1, &pubKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubKey);
  rsp->param = ptr = malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubKey)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubKey);
  return res;
}

static TPM_RESULT execute_TPM_UnBind(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  UINT32 inDataSize;
  BYTE *inData;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_UnBind(keyHandle, inDataSize, inData, &req->auth1, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  free(outData);
  return res;
}


static TPM_RESULT execute_TPM_MakeIdentity(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENCAUTH identityAuth;
  TPM_CHOSENID_HASH labelPrivCADigest;
  TPM_KEY idKeyParams;
  TPM_KEY idKey;
  UINT32 identityBindingSize;
  BYTE *identityBinding = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &identityAuth)
      || tpm_unmarshal_TPM_CHOSENID_HASH(&ptr, &len, &labelPrivCADigest)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &idKeyParams)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_MakeIdentity(&identityAuth, &labelPrivCADigest, &idKeyParams, 
    &req->auth1, &req->auth2, &idKey, &identityBindingSize, &identityBinding);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(idKey) + 4 + identityBindingSize;
  rsp->param = ptr = ExtendBuf;
  if (tpm_marshal_TPM_KEY(&ptr, &len, &idKey)
      || tpm_marshal_UINT32(&ptr, &len, identityBindingSize)
      || tpm_marshal_BLOB(&ptr, &len, identityBinding, identityBindingSize)) {
    res = TPM_FAIL;
  }
  return res;
}


static TPM_RESULT execute_TPM_CertifyKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE certHandle;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE antiReplay;
  TPM_CERTIFY_INFO certifyInfo;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &certHandle)
      || tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CertifyKey(certHandle, keyHandle, &antiReplay, &req->auth1, 
    &req->auth2, &certifyInfo, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_CERTIFY_INFO(certifyInfo) + 4 + outDataSize;
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL
      || tpm_marshal_TPM_CERTIFY_INFO(&ptr, &len, &certifyInfo)
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_CERTIFY_INFO(certifyInfo);
  free(outData);
  return res;
}


static TPM_RESULT execute_TPM_Extend(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCRINDEX pcrNum;
  TPM_DIGEST inDigest;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCRINDEX(&ptr, &len, &pcrNum)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &inDigest)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Extend(pcrNum, &inDigest, &outDigest);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL												
      || tpm_marshal_TPM_PCRVALUE(&ptr, &len, &outDigest)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_PCRRead(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCRINDEX pcrIndex;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCRINDEX(&ptr, &len, &pcrIndex)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_PCRRead(pcrIndex, &outDigest);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL
      || tpm_marshal_TPM_PCRVALUE(&ptr, &len, &outDigest)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_Quote(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE extrnalData;
  TPM_PCR_SELECTION targetPCR;
  TPM_PCR_COMPOSITE *pcrData;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  pcrData = (TPM_PCR_COMPOSITE *)InOutBuf;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &extrnalData)
      || tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &len, &targetPCR)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Quote(keyHandle, &extrnalData, &targetPCR, &req->auth1, pcrData, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PCR_COMPOSITE((*pcrData)) + 4 + sigSize;
  rsp->param = ptr = ExtendBuf;
  if (ptr == NULL
      || tpm_marshal_TPM_PCR_COMPOSITE(&ptr, &len, pcrData)
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    free(rsp->param);
    res = TPM_FAIL;
  }
  free(sig);
  return res;
}


void tpm_execute_command(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
    TPM_RESULT res;
    /* setup authorization as well as response tag and size */
    memset(rsp, 0, sizeof(*rsp));
    switch (req->tag) {
        case TPM_TAG_RQU_AUTH2_COMMAND:
            rsp->tag = TPM_TAG_RSP_AUTH2_COMMAND;
            rsp->size = 10 + 2 * 41;
            rsp->auth1 = &req->auth1;
            rsp->auth2 = &req->auth2;
            break;

        case TPM_TAG_RQU_AUTH1_COMMAND:
            rsp->tag = TPM_TAG_RSP_AUTH1_COMMAND;
            rsp->size = 10 + 41;
            rsp->auth1 = &req->auth1;
            break;

        case TPM_TAG_RQU_COMMAND:
            rsp->tag = TPM_TAG_RSP_COMMAND;
            rsp->size = 10;
            break;

        default:
            tpm_setup_error_response(TPM_BADTAG, rsp);
            return;
    }

    /* check whether the command is allowed in the current mode of the TPM */
    res = tpm_check_status_and_mode(req);
    if (res != TPM_SUCCESS) {
        tpm_setup_error_response(res, rsp);
        return;
    }
    /* handle command ordinal */
    switch (req->ordinal) {
        case TPM_ORD_Startup:
            res = execute_TPM_Startup(req, rsp);
            break;
        case TPM_ORD_SaveState:
            res = execute_TPM_SaveState(req, rsp);
            break;
        case TPM_ORD_FlushSpecific:
            res = execute_TPM_FlushSpecific(req, rsp);
            break;
        case TPM_ORD_OIAP:
            res = execute_TPM_OIAP(req, rsp);
            break;
        case TPM_ORD_OSAP:
            res = execute_TPM_OSAP(req, rsp);
            break;
        case TPM_ORD_TakeOwnership:
            res = execute_TPM_TakeOwnership(req, rsp);
            break;
        case TPM_ORD_CreateWrapKey:
            res = execute_TPM_CreateWrapKey(req, rsp);
            break;
        case TPM_ORD_LoadKey:
            res = execute_TPM_LoadKey(req, rsp);
            break;
        case TPM_ORD_LoadKey2:
            res = execute_TPM_LoadKey2(req, rsp);
            break;
        case TPM_ORD_GetPubKey:
            res = execute_TPM_GetPubKey(req, rsp);
            break;
        case TPM_ORD_UnBind:
            res = execute_TPM_UnBind(req, rsp);
            break;
        case TPM_ORD_MakeIdentity:
            res = execute_TPM_MakeIdentity(req, rsp);
            break;
        case TPM_ORD_CertifyKey:
            res = execute_TPM_CertifyKey(req, rsp);
            break;
        case TPM_ORD_Extend:
            res = execute_TPM_Extend(req, rsp);
            break;
        case TPM_ORD_PCRRead:
            res = execute_TPM_PCRRead(req, rsp);
            break;
        case TPM_ORD_Quote:
            res = execute_TPM_Quote(req, rsp);
            break;
        default:
            tpm_setup_error_response(TPM_BAD_ORDINAL, rsp);
            return ;
    }
    /* setup response */
    if (res != TPM_SUCCESS) {
        tpm_setup_error_response(res, rsp);
        if (!(res & TPM_NON_FATAL)) {
            if (rsp->auth1 != NULL) rsp->auth1->continueAuthSession = FALSE;
            if (rsp->auth2 != NULL) rsp->auth2->continueAuthSession = FALSE;
        }
    } else {
        rsp->size += rsp->paramSize;
        if (rsp->tag != TPM_TAG_RSP_COMMAND) tpm_setup_rsp_auth(req->ordinal, rsp);
    }
    /* terminate authorization sessions if necessary */
    if (rsp->auth1 != NULL && !rsp->auth1->continueAuthSession) 
        TPM_FlushSpecific(rsp->auth1->authHandle, HANDLE_TO_RT(rsp->auth1->authHandle));
    if (rsp->auth2 != NULL && !rsp->auth2->continueAuthSession) 
        TPM_FlushSpecific(rsp->auth2->authHandle, TPM_RT_AUTH);
    /* if transportExclusive is set, only the execution of TPM_ExecuteTransport
       and TPM_ReleaseTransportSigned is allowed */
    if (stanyFlags.transportExclusive
            && req->ordinal != TPM_ORD_ExecuteTransport
            && req->ordinal != TPM_ORD_ReleaseTransportSigned) {
        TPM_FlushSpecific(read_TPM_STANY_DATA_transExclusive(), TPM_RT_TRANS);
        stanyFlags.transportExclusive = FALSE;
    }
}

int tpm_handle_command(const unsigned char *in, unsigned int in_size, unsigned char *out, unsigned int *out_size)
{
    TPM_REQUEST req;
    TPM_RESPONSE rsp;
    unsigned int out_size_tmp;
    if (tpm_unmarshal_TPM_REQUEST((unsigned char **)&in, &in_size, &req) != 0) return -1;

    tpm_execute_command(&req, &rsp);
    //debug((BYTE *)&rsp.tag, sizeof(TPM_TAG));
    //debug((BYTE *)&rsp.size, sizeof(UINT32));
    //debug((BYTE *)&rsp.result, sizeof(TPM_RESULT));
    //debug((BYTE *)&rsp.param, sizeof(BYTE *));
    //debug((BYTE *)&rsp.paramSize, sizeof(UINT32));
    //debug((BYTE *)rsp.auth1, sizeof(TPM_AUTH));
    //debug((BYTE *)rsp.auth2, sizeof(TPM_AUTH));

    if (out == NULL || *out_size < rsp.size) return -1;
    *out_size = rsp.size; // we still need out_size in main.
    out_size_tmp = rsp.size;
    if (tpm_marshal_TPM_RESPONSE((unsigned char **)&out, &out_size_tmp, &rsp) != 0) return -1;
    return 0;
}

