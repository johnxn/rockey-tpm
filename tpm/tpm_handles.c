/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of																						   kk
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tpm_handles.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_handles.h"
#include "tpm_data.h"

int tpm_get_key_slot(TPM_KEY_HANDLE handle)
{
    if (handle == TPM_INVALID_HANDLE) return -1;
    handle &= 0x00ffffff;
    if (handle >= TPM_MAX_KEYS) return -1;
    return handle;
}

int tpm_get_session_slot(TPM_HANDLE handle)
{
    if (handle == TPM_INVALID_HANDLE) return -1;
    handle &= 0x00ffffff;
    if (handle >= TPM_MAX_SESSIONS) return -1;
    return handle;
}

int tpm_get_daa_slot(TPM_HANDLE handle)
{
    if (handle == TPM_INVALID_HANDLE) return -1;
    handle &= 0x00ffffff;
    if (handle >= TPM_MAX_SESSIONS_DAA) return -1;
    return handle;
}

int tpm_get_key(TPM_KEY_HANDLE handle)
{
    /* handle reserved key handles */
    switch (handle) {
        case TPM_KH_EK:
        case TPM_KH_OWNER:
        case TPM_KH_REVOKE:
        case TPM_KH_TRANSPORT:
        case TPM_KH_OPERATOR:
        case TPM_KH_ADMIN:
            return -1;
        case TPM_KH_SRK:
            if (read_TPM_PERMANENT_DATA_srk_payload()) return SRK_HANDLE;
            else return -1;
    }
    if (handle == TPM_INVALID_HANDLE 
            || (handle >> 24) != TPM_RT_KEY) return -1;
    handle &= 0x00ffffff;
    if (handle >= TPM_MAX_KEYS
            || !read_TPM_PERMANENT_DATA_keys_payload(handle)) return -1;
    return handle;
}

int tpm_get_auth(TPM_AUTHHANDLE handle)
{
    BYTE type;
    if (handle == TPM_INVALID_HANDLE
            || (handle >> 24) != TPM_RT_AUTH) return -1;
    handle &= 0x00ffffff;
    type = read_TPM_STANY_DATA_sessions_type(handle);
    if (handle >= TPM_MAX_SESSIONS
            || (type != TPM_ST_OIAP
                && type != TPM_ST_OSAP
                && type != TPM_ST_DSAP)) return -1;
    return handle;
}

int tpm_get_transport(TPM_TRANSHANDLE handle)
{
    if (handle == TPM_INVALID_HANDLE
            || (handle >> 24) != TPM_RT_TRANS) return -1;
    handle &= 0x00ffffff;
    if (handle >= TPM_MAX_SESSIONS
            || read_TPM_STANY_DATA_sessions_type(handle) != TPM_ST_TRANSPORT) return -1;
    return handle;
}

int tpm_get_counter(TPM_COUNT_ID handle)
{
    if ((handle == TPM_INVALID_HANDLE) || ((handle >> 24) != TPM_RT_COUNTER))
        return -1;
    handle &= 0x00ffffff;
    if ((handle >= TPM_MAX_COUNTERS)
            || !read_TPM_PERMANENT_DATA_counters_valid(handle)) return -1;
    return handle;
}

int tpm_get_daa(TPM_DAAHANDLE handle)
{
    if ((handle == TPM_INVALID_HANDLE) || ((handle >> 24) != TPM_RT_DAA_TPM))
        return -1;
    handle &= 0x00ffffff;
    if ((handle >= TPM_MAX_SESSIONS_DAA)
            || (read_TPM_STANY_DATA_sessionsDAA_type(handle) != TPM_ST_DAA)) return -1;
    return handle;
}
