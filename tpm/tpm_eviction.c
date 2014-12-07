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
 * $Id: tpm_eviction.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"

/*
 * Eviction ([TPM_Part3], Section 22)
 * The TPM has numerous resources held inside of the TPM that may need 
 * eviction. The need for eviction occurs when the number or resources 
 * in use by the TPM exceed the available space. In version 1.1 there were 
 * separate commands to evict separate resource types. This new command 
 * set uses the resource types defined for context saving and creates a 
 * generic command that will evict all resource types.
 */

/*
static void dump_sessions(void)
{
  int i;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpmData.stany.data.sessions[i].type != TPM_ST_INVALID) {
      debug("session[%d] = %08x", i, INDEX_TO_AUTH_HANDLE(i));
    }
  }
}
*/

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle, TPM_RESOURCE_TYPE resourceType)
{
    int session_index;
    int sessionDAA_index;
    int key_index;
    int i;
    switch (resourceType) {
        case TPM_RT_CONTEXT:
            for (i = 0; i < TPM_MAX_SESSION_LIST; i++)
                if (read_TPM_STANY_DATA_contextList(i) == handle) break;
            if (i != TPM_MAX_SESSION_LIST) {
                write_TPM_STANY_DATA_contextList(i, 0);
            }
            return TPM_SUCCESS;

        case TPM_RT_KEY:
            key_index = tpm_get_key(handle);
            if (key_index != -1) {
                if (read_TPM_PERMANENT_DATA_keys_keyControl(key_index) & TPM_KEY_CONTROL_OWNER_EVICT)
                    return TPM_KEY_OWNER_CONTROL;
                if (handle == SRK_HANDLE) return TPM_FAIL;
                write_TPM_PERMANENT_DATA_keys_payload(key_index, 0);
                tpm_invalidate_sessions(handle);
            }
            return TPM_SUCCESS;

        case TPM_RT_HASH:
        case TPM_RT_COUNTER:
        case TPM_RT_DELEGATE:
            return TPM_INVALID_RESOURCE;

        case TPM_RT_AUTH:
            session_index = tpm_get_auth(handle);
            if (session_index != -1)
                write_TPM_STANY_DATA_sessions_zero(session_index);
            //dump_sessions();
            return TPM_SUCCESS;

        case TPM_RT_TRANS:
            session_index = tpm_get_transport(handle);
            if (session_index != -1)
                write_TPM_STANY_DATA_sessions_zero(session_index);
            //dump_sessions();
            return TPM_SUCCESS;

        case TPM_RT_DAA_TPM:
            sessionDAA_index = tpm_get_daa(handle);
            if (sessionDAA_index != -1) {
                write_TPM_STANY_DATA_sessionsDAA_zero(sessionDAA_index);
                if (handle == read_TPM_STANY_DATA_currentDAA())
                    write_TPM_STANY_DATA_currentDAA(0);
                tpm_invalidate_sessions(handle);
            }
            return TPM_SUCCESS;
    }
    return TPM_INVALID_RESOURCE;
}
