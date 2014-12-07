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
 * $Id: tpm_authorization.c 467 2011-07-19 17:36:12Z mast $
 */

#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"
#include "tpm_marshalling.h"
#include "../crypto/hmac.h"
#include "../crypto/sha1.h"
#include "ftrx.h"

/*
 * Authorization Changing ([TPM_Part3], Section 17)
 */

#if 0
TPM_RESULT TPM_ChangeAuth(TPM_KEY_HANDLE parentHandle,
                          TPM_PROTOCOL_ID protocolID, TPM_ENCAUTH *newAuth,
                          TPM_ENTITY_TYPE entityType, UINT32 encDataSize,
                          BYTE *encData, TPM_AUTH *auth1, TPM_AUTH *auth2,
                          UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  TPM_SECRET plainAuth;
  info("TPM_ChangeAuth()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify entity authorization */ 
  auth2->continueAuthSession = FALSE;
  session = tpm_get_auth(auth2->authHandle);
  if (session->type != TPM_ST_OIAP) return TPM_BAD_MODE; 
  /* verify parent authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_BAD_MODE;  
  /* decrypt auth */
  tpm_decrypt_auth_secret(*newAuth, session->sharedSecret,
                          &session->lastNonceEven, plainAuth);
  /* decrypt the entity, replace authData, and encrypt it again */
  if (entityType == TPM_ET_DATA) {
    TPM_SEALED_DATA seal;
    BYTE *seal_buf;
    /* decrypt entity */
    if (tpm_decrypt_sealed_data(parent, encData, encDataSize,
        &seal, &seal_buf)) return TPM_DECRYPT_ERROR;
    /* verify auth2 */
    res = tpm_verify_auth(auth2, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
    /* change authData and use it also for auth2 */
    memcpy(seal.authData, plainAuth, sizeof(TPM_SECRET));    
    /* encrypt entity */
    *outDataSize = parent->key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (tpm_encrypt_sealed_data(parent, &seal, *outData, outDataSize)) {
      tpm_free(encData);
      tpm_free(seal_buf);      
      return TPM_ENCRYPT_ERROR;
    }                    
    tpm_free(seal_buf); 
  } else if (entityType == TPM_ET_KEY) {
    TPM_STORE_ASYMKEY store;
    BYTE *store_buf;
    /* decrypt entity */
    if (tpm_decrypt_private_key(parent, encData, encDataSize,
        &store, &store_buf, NULL)) return TPM_DECRYPT_ERROR;
    /* verify auth2 */
    res = tpm_verify_auth(auth2, store.usageAuth, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
    /* change usageAuth and use it also for auth2 */
    memcpy(store.usageAuth, plainAuth, sizeof(TPM_SECRET));  
    /* encrypt entity */
    *outDataSize = parent->key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (tpm_encrypt_private_key(parent, &store, *outData, outDataSize)) {
      tpm_free(encData);
      tpm_free(store_buf);      
      return TPM_ENCRYPT_ERROR;
    }                    
    tpm_free(store_buf); 
  } else {
    return TPM_WRONG_ENTITYTYPE;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ChangeAuthOwner(TPM_PROTOCOL_ID protocolID, 
                               TPM_ENCAUTH *newAuth, 
                               TPM_ENTITY_TYPE entityType, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_SECRET plainAuth;
  int i;
  info("TPM_ChangeAuthOwner()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* decrypt auth */
  tpm_decrypt_auth_secret(*newAuth, session->sharedSecret,
                          &session->lastNonceEven, plainAuth);
  /* change authorization data */
  if (entityType == TPM_ET_OWNER) {
    memcpy(tpmData.permanent.data.ownerAuth, plainAuth, sizeof(TPM_SECRET));
    /* invalidate all associated sessions but the current one */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      if (tpmData.stany.data.sessions[i].handle == TPM_KH_OWNER
          && &tpmData.stany.data.sessions[i] != session) {
          memset(&tpmData.stany.data.sessions[i], 0, sizeof(TPM_SESSION_DATA));
      }
    }
  } else if (entityType == TPM_ET_SRK) {
    memcpy(tpmData.permanent.data.srk.usageAuth, plainAuth, sizeof(TPM_SECRET));
/* probably not correct; spec. v1.2 rev94 says nothing about authDataUsage
    tpmData.permanent.data.srk.authDataUsage = TPM_AUTH_ALWAYS;
*/
    /* invalidate all associated sessions but the current one */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      if (tpmData.stany.data.sessions[i].handle == TPM_KH_SRK
          && &tpmData.stany.data.sessions[i] != session) {
          memset(&tpmData.stany.data.sessions[i], 0, sizeof(TPM_SESSION_DATA));
      }
    }
  } else {
    return TPM_WRONG_ENTITYTYPE;
  }
  return TPM_SUCCESS;
}
#endif

/*
 * Authorization Sessions ([TPM_Part3], Section 18)
 */

TPM_RESULT TPM_OIAP(TPM_AUTHHANDLE *authHandle, TPM_NONCE *nonceEven)
{
    int session_index;
    /* get a free session if any is left */
    *authHandle = tpm_get_free_session(TPM_ST_OIAP);
    session_index = tpm_get_auth(*authHandle);
    if (session_index == -1) return TPM_RESOURCES;
    /* setup session */
    get_random((BYTE *)nonceEven, sizeof(TPM_NONCE));
    write_TPM_STANY_DATA_sessions_nonceEven(session_index, nonceEven);
    return TPM_SUCCESS;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType, UINT32 entityValue, 
        TPM_NONCE *nonceOddOSAP, TPM_AUTHHANDLE *authHandle,
        TPM_NONCE *nonceEven, TPM_NONCE *nonceEvenOSAP)
{
    tpm_hmac_ctx_t ctx;
    int session_index;
    int key_index;
    int counters_index;
    TPM_SECRET tmp_secret;
    TPM_SECRET sharedSecret;
    BYTE *secret = NULL;
    TPM_HANDLE handle;
    /* get a free session if any is left */
    *authHandle = tpm_get_free_session(TPM_ST_OSAP);
    session_index = tpm_get_auth(*authHandle);
    if (session_index == -1) return TPM_RESOURCES;

    /* check whether ADIP encryption scheme is supported */
    switch (entityType & 0xFF00) {
        case TPM_ET_XOR:
            break;
        default:
            return TPM_INAPPROPRIATE_ENC;
    }
    /* get resource handle and the respective secret */
    switch (entityType & 0x00FF) {
        case TPM_ET_KEYHANDLE:
            handle = entityValue;
            write_TPM_STANY_DATA_sessions_handle(session_index, handle);
            if (entityValue == TPM_KH_OPERATOR) return TPM_BAD_HANDLE;
            key_index = tpm_get_key(handle);
            if (key_index != -1) {
                read_TPM_PERMANENT_DATA_keys_usageAuth(key_index, &tmp_secret);
                secret = tmp_secret;
            }
            break;
        case TPM_ET_OWNER:
        case TPM_ET_VERIFICATION_AUTH:
            handle = TPM_KH_OWNER;
            write_TPM_STANY_DATA_sessions_handle(session_index, handle);
            if (permanentFlags.owned) {
                read_TPM_PERMANENT_DATA_ownerAuth(&tmp_secret);
                secret = tmp_secret;
            }
            break;
        case TPM_ET_SRK:
            handle = TPM_KH_SRK;
            write_TPM_STANY_DATA_sessions_handle(session_index, handle);
            if (read_TPM_PERMANENT_DATA_srk_payload()) {
                read_TPM_PERMANENT_DATA_srk_usageAuth(&tmp_secret);
                secret = tmp_secret;
            }
            break;
        case TPM_ET_COUNTER:
            handle = entityValue;
            write_TPM_STANY_DATA_sessions_handle(session_index, handle);
            if ((counters_index = tpm_get_counter(handle)) != -1) {
                read_TPM_PERMANENT_DATA_counters_usageAuth(counters_index, &tmp_secret);
                secret = tmp_secret;
            }
            break;
        /* TODO 
        case TPM_ET_NV:
            write_TPM_STANY_DATA_sessions_handle(session_index, entityValue);
            if (tpm_get_nvs(session->handle) != NULL)
                secret = &tpm_get_nvs(session->handle)->authValue;
            break;
        */
        default:
            return TPM_BAD_PARAMETER;
    }
    if (secret == NULL) {
        write_TPM_STANY_DATA_sessions_zero(session_index);
        return TPM_BAD_PARAMETER;
    }
    /* save entity type */
    write_TPM_STANY_DATA_sessions_entityType(session_index, entityType);
    /* generate nonces */
    get_random(nonceEven->nonce, sizeof(nonceEven->nonce));
    write_TPM_STANY_DATA_sessions_nonceEven(session_index, nonceEven);
    get_random(nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    /* compute shared secret */
    tpm_hmac_init(&ctx, tmp_secret, sizeof(tmp_secret));
    tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
    tpm_hmac_final(&ctx, sharedSecret);
    write_TPM_STANY_DATA_sessions_sharedSecret(session_index, &sharedSecret);
    return TPM_SUCCESS;
}

TPM_RESULT tpm_verify_auth(TPM_AUTH *auth, TPM_SECRET secret,
                           TPM_HANDLE handle)
{
  tpm_hmac_ctx_t ctx;
  int session_index;
  TPM_SESSION_DATA session;
  BYTE digest[SHA1_DIGEST_LENGTH];

  /* get dedicated authorization or transport session */
  session_index = tpm_get_auth(auth->authHandle);
  if (session_index == -1) session_index = tpm_get_transport(auth->authHandle);
  if (session_index == -1) return TPM_INVALID_AUTHHANDLE;
  /* setup authorization */
  read_TPM_STANY_DATA_sessions(session_index, &session);
  if (session.type == TPM_ST_OIAP) {
    /* We copy the secret because it might be deleted or invalidated
       afterwards, but we need it again for authorizing the response. */
    memcpy(session.sharedSecret, secret, sizeof(TPM_SECRET));
  } 
  else if (session.type == TPM_ST_OSAP) {
    if (session.handle != handle) return TPM_AUTHFAIL;
  } 
#if 0
  else if (session.type == TPM_ST_DSAP) {
    if (session.handle != handle) return TPM_AUTHFAIL;
    /* check permissions */
    if (session.permissions.delegateType == TPM_DEL_OWNER_BITS) {
      if (!is_owner_delegation_permitted(auth->ordinal, //TODO
             session.permissions.per1, session.permissions.per2))
        return TPM_DISABLED_CMD;
    } else if (session.permissions.delegateType == TPM_DEL_KEY_BITS) {
      if (!is_key_delegation_permitted(auth->ordinal, //TODO
             session.permissions.per1, session.permissions.per2))
        return TPM_DISABLED_CMD;
    } else {
      return TPM_AUTHFAIL;
    }
  } else if (session.type == TPM_ST_TRANSPORT) {
    memcpy(session.sharedSecret, session.transInternal.authData,
           sizeof(TPM_SECRET));
  } 
#endif
  else {
    return TPM_INVALID_AUTHHANDLE;
  }
  memcpy(auth->secret, session.sharedSecret, sizeof(TPM_SECRET));
  /* verify authorization */
  tpm_hmac_init(&ctx, auth->secret, sizeof(auth->secret));
  tpm_hmac_update(&ctx, auth->digest, sizeof(auth->digest));
  tpm_hmac_update(&ctx, session.nonceEven.nonce, sizeof(session.nonceEven.nonce));
  tpm_hmac_update(&ctx, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
  tpm_hmac_update(&ctx, &auth->continueAuthSession, 1);
  tpm_hmac_final(&ctx, digest);
  if (memcmp(digest, auth->auth, sizeof(auth->auth))) return TPM_AUTHFAIL;
  /* generate new nonceEven */
  memcpy(&session.lastNonceEven, &session.nonceEven, sizeof(TPM_NONCE));
  get_random(auth->nonceEven.nonce, sizeof(auth->nonceEven.nonce));
  memcpy(&session.nonceEven, &auth->nonceEven, sizeof(TPM_NONCE));
  write_TPM_STANY_DATA_sessions(session_index, &session);
  return TPM_SUCCESS;
}

void tpm_decrypt_auth_secret(TPM_ENCAUTH encAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_SECRET plainAuth)
{
  unsigned int i;
  tpm_sha1_ctx_t ctx;
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, secret, sizeof(TPM_SECRET));
  tpm_sha1_update(&ctx, nonce->nonce, sizeof(nonce->nonce));
  tpm_sha1_final(&ctx, plainAuth);
  for (i = 0; i < sizeof(TPM_SECRET); i++)
    plainAuth[i] ^= encAuth[i];
}

