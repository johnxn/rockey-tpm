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
 * $Id: tpm_startup.c 367 2010-02-13 15:52:18Z mast $
 */

#include "tpm_handles.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "string.h"
#include "ftrx.h"


/*
 * Admin Startup and State ([TPM_Part3], Section 3)
 * This section describes the commands that start a TPM.
 */

void TPM_Init(TPM_STARTUP_TYPE startupType)
{
    /* startup the TPM */
    stanyFlags.postInitialise = TRUE;
    permanentFlags.selfTestSucceeded = TRUE;
    //TPM_SelfTestFull();
    TPM_Startup(startupType);
}

#define SET_TO_ZERO(a) memset(a, 0x00, sizeof(*a))
#define SET_TO_0xFF(a) memset(a, 0xff, sizeof(*a)) 
#define SET_TO_RAND(a) get_random(a, sizeof(*a))
#define SET_NONCE_RAND(a) get_random(a->nonce, sizeof(TPM_NONCE))

void set_nonce_rand(TPM_NONCE *a) {
    get_random(a->nonce, sizeof(TPM_NONCE));
}

TPM_RESULT TPM_Startup(TPM_STARTUP_TYPE startupType)
{
    int i;
    TPM_NONCE contextNonceSession;
    TPM_PCRVALUE pcrValue;
    TPM_PCR_ATTRIBUTES pcrAttrib[TPM_NUM_PCR];
    TPM_KEY_DATA key;
    TPM_NONCE contextNonceKey;
    TPM_NV_DATA_SENSITIVE nvStorage;
    if (stanyFlags.postInitialise == FALSE) return TPM_INVALID_POSTINIT;
    /* reset STANY_FLAGS */

    SET_TO_ZERO(&stanyFlags);
    stanyFlags.tag = TPM_TAG_STANY_FLAGS;
    /* set data and flags according to the given startup type */
    if (startupType == TPM_ST_CLEAR) {
        /* reset STANY_DATA (invalidates ALL sessions) */
        set_TPM_STANY_DATA_zero();
        write_TPM_STANY_DATA_tag(TPM_TAG_STANY_DATA);
        /* init session-context nonce */
        set_nonce_rand(&contextNonceSession);
        write_TPM_STANY_DATA_contextNonceSession(&contextNonceSession);
        /* reset PCR values */
        read_TPM_PERMANENT_DATA_pcrAttrib(pcrAttrib);
        for (i = 0; i < TPM_NUM_PCR; i++) {
            if (pcrAttrib[i].pcrReset)
                SET_TO_0xFF(pcrValue.digest);
            else
                SET_TO_ZERO(pcrValue.digest);
            write_TPM_PERMANENT_DATA_pcrValue(i, &pcrValue);
        }
        /* reset STCLEAR_FLAGS */
        SET_TO_ZERO(&stclearFlags);
        stclearFlags.tag = TPM_TAG_STCLEAR_FLAGS;
        stclearFlags.deactivated = permanentFlags.deactivated;
        /* reset STCLEAR_DATA */
        set_TPM_STCLEAR_DATA_zero();
        write_TPM_STCLEAR_DATA_tag(TPM_TAG_STCLEAR_DATA);
        /* flush volatiles and PCR dependent keys */
        for (i = 0; i < TPM_MAX_KEYS; i++) {
            read_TPM_PERMANENT_DATA_keys(i, &key);
            if (key.payload
                    && ((key.keyFlags & TPM_KEY_FLAG_VOLATILE)
                        || key.parentPCRStatus))
            TPM_FlushSpecific(INDEX_TO_KEY_HANDLE(i), TPM_RT_KEY); 
        }
        
        /* init key-context nonce */
        set_nonce_rand(&contextNonceKey);
        write_TPM_STCLEAR_DATA_contextNonceKey(&contextNonceKey);
        /* invalidate counter handle */
        write_TPM_STCLEAR_DATA_countID(TPM_INVALID_HANDLE);
        /* reset NV read and write flags */
        for (i = 0; i < TPM_MAX_NVS; i++) {
            nvStorage.pubInfo.bReadSTClear = FALSE;
            nvStorage.pubInfo.bWriteSTClear = FALSE;
            write_TPM_PERMANENT_DATA_nvStorage(i, &nvStorage);
        }
    } else if (startupType == TPM_ST_STATE) {
        if (!permanentFlags.dataSaved) { /* dataSaved is FLASE by default, set to TRUE by TPM_SaveState(). */
            permanentFlags.selfTestSucceeded = FALSE;
            return TPM_FAIL;
        }
    } else if (startupType == TPM_ST_DEACTIVATED) {
        stclearFlags.deactivated = TRUE;
        permanentFlags.dataSaved = FALSE;
    } else {
        return TPM_BAD_PARAMETER;
    }
    stanyFlags.postInitialise = FALSE;
    stanyFlags.TOSPresent = FALSE;
    return TPM_SUCCESS;
}

TPM_RESULT TPM_SaveState()
{
    if (permanentFlags.selfTestSucceeded && !stclearFlags.deactivated){
        permanentFlags.dataSaved = TRUE;
        return TPM_SUCCESS;
    }
    return TPM_FAIL;
}
