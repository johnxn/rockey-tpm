#include "printfs.h"

void printf_buf(char *head, void *buff, int size) {
    int i;
    BYTE *buf = (BYTE *)buff;
    if (head) printf("%s\n", head);
    for (i = 0; i < size; i++) {
        printf("%02x ", 0xff & buf[i]);
        if (i % 8 == 7) printf("  ");
        if (i % 16 == 15 || i == size -1) printf("\n");
    }
}

void printf_TPM_AUTH_REQ(BYTE **ptr, UINT32 *length) {
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceOdd;
    BOOL continueAuthSession;
    TPM_AUTHDATA auth;
    tpm_unmarshal_TPM_AUTHHANDLE(ptr, length, &authHandle);
    tpm_unmarshal_TPM_NONCE(ptr, length, &nonceOdd);
    tpm_unmarshal_BOOL(ptr, length, &continueAuthSession);
    tpm_unmarshal_TPM_AUTHDATA(ptr, length, &auth);
    printf("TPM_AUTHHANDLE authHandle: 0x%x\n", authHandle);
    printf_buf("TPM_NONCE nonceOdd:", &nonceOdd, sizeof(TPM_NONCE));
    printf("BOOL continueAuthSession: 0x%x\n", continueAuthSession);
    printf_buf("TPM_AUTHDATA auth:", &auth, sizeof(TPM_AUTHDATA));
}

void printf_TPM_AUTH_RES(BYTE **ptr, UINT32 *length) {
    TPM_NONCE nonceEven;
    BOOL continueAuthSession;
    TPM_AUTHDATA auth;
    tpm_unmarshal_TPM_NONCE(ptr, length, &nonceEven);
    tpm_unmarshal_BOOL(ptr, length, &continueAuthSession);
    tpm_unmarshal_TPM_AUTHDATA(ptr, length, &auth);
    printf_buf("TPM_NONCE nonceEven: ", &nonceEven, sizeof(TPM_NONCE));
    printf_buf("BOOL continueAuthSession: ", &continueAuthSession, sizeof(BOOL));
    printf_buf("TPM_AUTHDATA auth:", &auth, sizeof(TPM_AUTHDATA));
}
void printf_TPM_REQUEST(BYTE *buf) {
    printf("\033[;32m");
    printf("TPM_REQUEST\n");
    UINT32 length;
    memcpy(&length, buf, sizeof(UINT32));
    BYTE *ptr = buf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    TPM_COMMAND_CODE ordinal;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_COMMAND_CODE(&ptr, &length, &ordinal);
    printf("TPM_TAG tag: 0x%x\n", tag);
    printf("UINT32 size: 0x%x\n", size);
    printf("TPM_COMMAND_CODE ordinal: 0x%x\n", ordinal);
    switch (ordinal) {
        case TPM_ORD_Startup:
            /* TODO */
            printf("print TPM_ORD_Startup TPM_REQUEST TODO\n");
            break;
        case TPM_ORD_OIAP:
            break;
        case TPM_ORD_OSAP: {
            TPM_ENTITY_TYPE entityType;
            UINT32 entityValue;
            TPM_NONCE nonceOddOSAP;
            tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &length, &entityType);
            tpm_unmarshal_UINT32(&ptr, &length, &entityValue);
            tpm_unmarshal_TPM_NONCE(&ptr, &length, &nonceOddOSAP);
            printf("TPM_ENTITY_TYPE entityType: 0x%x\n", entityType);
            printf("UINT32 entityValue: 0x%x\n", entityValue);
            printf_buf("TPM_NONCE nonceOddOSAP:", &nonceOddOSAP, sizeof(TPM_NONCE));
            break;
        }
        case TPM_ORD_TakeOwnership: {
            TPM_PROTOCOL_ID protocolID;
            tpm_unmarshal_UINT16(&ptr, &length, &protocolID);
            UINT32 encOwnerAuthSize;
            tpm_unmarshal_UINT32(&ptr, &length, &encOwnerAuthSize);
            printf_buf("BYTE encOwnerAuth", ptr, encOwnerAuthSize);
            ptr += encOwnerAuthSize;
            length -= encOwnerAuthSize;
            UINT32 encSrkAuthSize;
            tpm_unmarshal_UINT32(&ptr, &length, &encSrkAuthSize);
            printf_buf("BYTE encSrkAuth", ptr, encSrkAuthSize);
            ptr += encOwnerAuthSize;
            length -= encOwnerAuthSize;
            TPM_KEY srkParams;
            tpm_unmarshal_TPM_KEY(&ptr, &length, &srkParams);
            break;
        }
        case TPM_ORD_CreateWrapKey: {
            TPM_KEY_HANDLE parentHandle;
            TPM_ENCAUTH dataUsageAuth;
            TPM_ENCAUTH dataMigrationAuth;
            TPM_KEY keyInfo;
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &parentHandle);
            tpm_unmarshal_TPM_ENCAUTH(&ptr, &length, &dataUsageAuth);
            tpm_unmarshal_TPM_ENCAUTH(&ptr, &length, &dataMigrationAuth);
            tpm_unmarshal_TPM_KEY(&ptr, &length, &keyInfo);
            printf("TPM_KEY_HANDLE parentHandle: 0x%x\n", parentHandle);
            printf_buf("TPM_ENCAUTH dataUsageAuth:", &dataUsageAuth, sizeof(TPM_ENCAUTH));
            printf_buf("TPM_ENCAUTH dataMigrationAuth:", &dataMigrationAuth, sizeof(TPM_ENCAUTH));
            printf_buf("TPM_KEY keyInfo:", &keyInfo, sizeof_TPM_KEY((keyInfo)));
            break;
        }
        case TPM_ORD_LoadKey: {
            TPM_KEY_HANDLE parentHandle;
            TPM_KEY inKey;
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &parentHandle);
            tpm_unmarshal_TPM_KEY(&ptr, &length, &inKey);
            printf("TPM_KEY_HANDLE parentHandle: 0x%x\n", parentHandle);
            printf_TPM_KEY(&inKey);
            break;
        }
        case TPM_ORD_UnBind: {
            TPM_KEY_HANDLE keyHandle;
            UINT32 inDataSize;
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &keyHandle);
            tpm_unmarshal_UINT32(&ptr, &length, &inDataSize);
            printf("TPM_KEY_HANDLE keyHandle: 0x%x\n", keyHandle);
            printf("UINT32 inDataSize :%x\n", inDataSize);
            printf_buf("BYTE inData:", ptr, inDataSize);
            ptr += inDataSize;
            length -= inDataSize;
            break;
        }
        case TPM_ORD_MakeIdentity: {
            TPM_ENCAUTH identityAuth;
            TPM_CHOSENID_HASH labelPrivCADigest;
            TPM_KEY idKeyParams;
            tpm_unmarshal_TPM_ENCAUTH(&ptr, &length, &identityAuth);
            tpm_unmarshal_TPM_CHOSENID_HASH(&ptr, &length, &labelPrivCADigest);
            tpm_unmarshal_TPM_KEY(&ptr, &length, &idKeyParams);
            printf_buf("TPM_ENCAUTH identityAuth:", identityAuth, sizeof(TPM_ENCAUTH));
            printf_buf("TPM_CHOSENID_HASH labelPrivCADigest:", &labelPrivCADigest, sizeof(TPM_CHOSENID_HASH));
            break;
        }
        case TPM_ORD_CertifyKey: {
            TPM_KEY_HANDLE certHandle;
            TPM_KEY_HANDLE keyHandle;
            TPM_NONCE antiReplay;
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &certHandle);
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &keyHandle);
            tpm_unmarshal_TPM_NONCE(&ptr, &length, &antiReplay);
            printf("TPM_KEY_HANDLE certHandle: 0x%x\n", certHandle);
            printf("TPM_KEY_HANDLE keyHandle: 0x%x\n", keyHandle);
            printf_buf("TPM_NONCE antiReplay:", antiReplay.nonce, sizeof(TPM_NONCE));
            break;
        }
        case TPM_ORD_Extend: {
            TPM_PCRINDEX pcrNum;
            TPM_DIGEST inDigest;
            tpm_unmarshal_TPM_PCRINDEX(&ptr, &length, &pcrNum);
            tpm_unmarshal_TPM_DIGEST(&ptr, &length, &inDigest);
            printf("TPM_PCRINDEX pcrNum: 0x%x\n", pcrNum);
            printf_buf("TPM_DIGEST inDigest: ", inDigest.digest, sizeof(TPM_DIGEST));
            break;
        }
        case TPM_ORD_PCRRead: {
            TPM_PCRINDEX pcrIndex;
            tpm_unmarshal_TPM_PCRINDEX(&ptr, &length, &pcrIndex);
            printf("TPM_PCRINDEX pcrIndex: 0x%x\n", pcrIndex);
            break;
        }
       case TPM_ORD_Quote: {
            TPM_KEY_HANDLE keyHandle;
            TPM_NONCE externalData;
            TPM_PCR_SELECTION targetPCR;
            tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &keyHandle);
            tpm_unmarshal_TPM_NONCE(&ptr, &length, &externalData);
            tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &length, &targetPCR);
            printf("TPM_KEY_HANDLE keyHandle: 0x%x\n", keyHandle);
            printf_buf("TPM_NONCE externalData:", externalData.nonce, sizeof(TPM_NONCE));
            printf_TPM_PCR_SELECTION(&targetPCR);
            break;
        }
        default:
            printf("Wrong ordinal\n");
            return;
    }
    if (tag == TPM_TAG_RQU_AUTH2_COMMAND) {
        printf("TPM_AUTH auth1 list as follows:\n");
        printf_TPM_AUTH_REQ(&ptr, &length);
        printf("TPM_AUTH auth2 list as follows:\n");
        printf_TPM_AUTH_REQ(&ptr, &length);
    }
    else if (tag == TPM_TAG_RQU_AUTH1_COMMAND) {
        printf("TPM_AUTH auth1 list as follows:\n");
        printf_TPM_AUTH_REQ(&ptr, &length);
    }
    else ;
    printf("\033[0m");
}

void printf_TPM_RESPONSE(BYTE const *buf, TPM_COMMAND_CODE ordinal) {
    printf("\033[;31m");
    printf("TPM_RESPONSE\n");
    UINT32 length;
    memcpy(&length, buf, sizeof(UINT32));
    BYTE *ptr = buf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    TPM_RESULT res;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, &res);
    printf("TPM_TAG tag: 0x%x\n", tag);
    printf("UINT32 size: 0x%x\n", size);
    printf("TPM_RESULT res: 0x%x\n", res);
    switch (ordinal) {
        case TPM_ORD_OIAP: {
            if (res == TPM_SUCCESS) {
                TPM_AUTHHANDLE authHandle;
                TPM_NONCE nonceEven;
                tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &length, &authHandle);
                tpm_unmarshal_TPM_NONCE(&ptr, &length, &nonceEven);
                printf("TPM_AUTHHANDLE authHandle: 0x%x\n", authHandle);
                printf_buf("TPM_NONCE nonceEven: ", &nonceEven, sizeof(TPM_NONCE));
            }
            break;
        }
        case TPM_ORD_OSAP: { 
            if (res == TPM_SUCCESS) {
                TPM_AUTHHANDLE authHandle;
                TPM_NONCE nonceEven;
                TPM_NONCE nonceEvenOSAP;
                tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &length, &authHandle);
                tpm_unmarshal_TPM_NONCE(&ptr, &length, &nonceEven);
                tpm_unmarshal_TPM_NONCE(&ptr, &length, &nonceEvenOSAP);
                printf("TPM_AUTHHANDLE authHandle: 0x%x\n", authHandle);
                printf_buf("TPM_NONCE nonceEven: ", &nonceEven, sizeof(TPM_NONCE));
                printf_buf("TPM_NONCE nonceEvenOSAP: ", &nonceEvenOSAP, sizeof(TPM_NONCE));
            }
            break;
        }
        case TPM_ORD_TakeOwnership: {
            if (res == TPM_SUCCESS) {
                TPM_KEY srkPub;
                tpm_unmarshal_TPM_KEY(&ptr, &length, &srkPub);
            }
            break;
        }
        case TPM_ORD_CreateWrapKey: {
            if (res == TPM_SUCCESS) {
                TPM_KEY wrappedKey;
                tpm_unmarshal_TPM_KEY(&ptr, &length, &wrappedKey);
                printf_buf("Public portion of WrappedKey:", wrappedKey.pubKey.key, sizeof(RSA_PUBLIC_KEY));
                printf_buf("Encrypted private portion of WrappedKey:", wrappedKey.encData, wrappedKey.encDataSize);
            }
            break;
        }
        case TPM_ORD_LoadKey: {
            if (res == TPM_SUCCESS) {
                TPM_KEY_HANDLE keyHandle;
                tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, &keyHandle);
                printf("TPM_KEY_HANDLE inkeyHandle: 0x%x\n", keyHandle);
            }
            break;
        }
        case TPM_ORD_UnBind: {
            if (res == TPM_SUCCESS) {
                UINT32 outDataSize;
                tpm_unmarshal_UINT32(&ptr, &length, &outDataSize);
                printf("UINT32 outDataSize: 0x%x\n", outDataSize);
                printf_buf("BYTE outData", ptr, outDataSize);
                ptr += outDataSize;
                length -= outDataSize;
            }
            break;
        }
        case TPM_ORD_MakeIdentity: {
            if (res == TPM_SUCCESS) {
                TPM_KEY idKey;
                UINT32 identityBindingSize;
                tpm_unmarshal_TPM_KEY(&ptr, &length, &idKey);
                tpm_unmarshal_UINT32(&ptr, &length, &identityBindingSize);
                printf_buf("Public portion of idKey:", idKey.pubKey.key, sizeof(RSA_PUBLIC_KEY));
                printf_buf("Encrypted private portion of idKey:", idKey.encData, idKey.encDataSize);
                printf("UINT32 identityBindingSize: 0x%x\n", identityBindingSize);
                printf_buf("BYTE identityBinding:", ptr, identityBindingSize);
                ptr += identityBindingSize;
                length -= identityBindingSize;
            }
            break;
        }
        case TPM_ORD_CertifyKey: {
            if (res == TPM_SUCCESS) {
                TPM_CERTIFY_INFO certifyInfo;
                UINT32 outDataSize;
                BYTE *outData;
                tpm_unmarshal_TPM_CERTIFY_INFO(&ptr, &length, &certifyInfo);
                tpm_unmarshal_UINT32(&ptr, &length, &outDataSize);
                outData = ptr;
                printf("TPM_CERTIFY_INFO certifyInfo\n");
                printf_TPM_CERIFTY_INFO(&certifyInfo);
                printf("UINT32 outDataSize: 0x%x\n", outDataSize);
                printf_buf("BYTE outData:", outData, outDataSize);
                ptr += outDataSize;
                length -= outDataSize;

            }
            break;
        }
        case TPM_ORD_Extend: {
            if (res == TPM_SUCCESS) {
                TPM_PCRVALUE outDigest;
                tpm_unmarshal_TPM_PCRVALUE(&ptr, &length, &outDigest);
                printf_buf("TPM_PCRVALUE outDigest:", outDigest.digest, sizeof(TPM_PCRVALUE));
            }
            break;
        }
        case TPM_ORD_PCRRead: {
            if (res == TPM_SUCCESS) {
                TPM_PCRVALUE outDigest;
                tpm_unmarshal_TPM_PCRVALUE(&ptr, &length, &outDigest);
                printf_buf("TPM_PCRVALUE outDigest:", outDigest.digest, sizeof(TPM_PCRVALUE));
            }
            break;
        }
        case TPM_ORD_Quote: {
            if (res == TPM_SUCCESS) {
                TPM_PCR_COMPOSITE pcrData;
                UINT32 sigSize;
                BYTE *sig;
                tpm_unmarshal_TPM_PCR_COMPOSITE(&ptr, &length, &pcrData);
                tpm_unmarshal_UINT32(&ptr, &length, &sigSize);
                //printf_buf("TPM_PCR_COMPOSITE pcrData", &pcrData, sizeof(pcrData));
                printf_TPM_PCR_COMPOSITE(&pcrData);
                printf("UINT32 sigSize: 0x%x\n", sigSize);
                sig = ptr;
                printf_buf("BYTE sig", sig, sigSize);
                ptr += sigSize;
                length -= sigSize;
            }
            break;
        }

    }
    if (tag == TPM_TAG_RSP_AUTH2_COMMAND) {
        printf("TPM_AUTH auth1 list as follows:\n");
        printf_TPM_AUTH_RES(&ptr, &length);
        printf("TPM_AUTH auth2 list as follows:\n");
        printf_TPM_AUTH_RES(&ptr, &length);
    }
    else if (tag == TPM_TAG_RSP_AUTH1_COMMAND) {
        printf("TPM_AUTH auth1 list as follows:\n");
        printf_TPM_AUTH_RES(&ptr, &length);
    }
    else ;
    printf("\033[0m");
}

void printf_TPM_KEY_DATA(TPM_KEY_DATA *key) {
    printf("TPM_PAYLOAD_TYPE payload          : 0x%x\n", key->payload);
    printf("TPM_KEY_USAGE keyUsage            : 0x%x\n", key->keyUsage);
    printf("TPM_KEY_FLAGS keyFlags            : 0x%x\n", key->keyFlags);
    printf("TPM_KEY_CONTROL keyControl        : 0x%x\n", key->keyControl);
    printf("TPM_AUTH_DATA_USAGE authDataUsage : 0x%x\n", key->authDataUsage);
    printf("TPM_ENC_SCHEME encScheme          : 0x%x\n", key->encScheme);
    printf("TPM_SIG_SCHEME sigScheme          : 0x%x\n", key->sigScheme);
    printf_buf("TPM_SECRET usageAuth", key->usageAuth, sizeof(TPM_SECRET));
    printf_buf("TPM_SECRET migrationAuth", key->migrationAuth, sizeof(TPM_SECRET));
    printf_buf("TPM_PCR_INFO pcrInfo", &key->pcrInfo, sizeof(TPM_PCR_INFO));
    printf("UINT16 keyFileid: 0x%x\n", key->keyFileid);
    printf("UINT16 pubkeyFileid: 0x%x\n", key->pubkeyFileid);
}

void printf_PERMANENT_DATA() {
    int i;
    TPM_PERMANENT_DATA permanentData;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_PERMANENT_DATA_PART1, 0, (BYTE *)&permanentData, 4096) != DONGLE_SUCCESS ||
    Dongle_ReadFile(rockeyHandle, FILEID_TPM_PERMANENT_DATA_PART2, 0, (BYTE *)&permanentData+4096, 4096) != DONGLE_SUCCESS ||
    Dongle_ReadFile(rockeyHandle, FILEID_TPM_PERMANENT_DATA_PART3, 0, (BYTE *)&permanentData+4096*2, sizeof(TPM_PERMANENT_DATA) - 4096*2) != DONGLE_SUCCESS){
        printf("Failed to read TPM_PERMANENT_DATA.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Permanenent Data ***\n");
    printf("TPM_STRUCTURE_TAG tag                     \n%04x\n", permanentData.tag);
    printf_buf("TPM_VERSION version                        ", &permanentData.version, sizeof(TPM_VERSION));
    printf_buf("TPM_NONCE tpmProof                            ", &permanentData.tpmProof, sizeof(TPM_NONCE));
    printf_buf("TPM_NONCE ekReset                             ", &permanentData.ekReset, sizeof(TPM_NONCE));
    printf_buf("TPM_SECRET ownerAuth                          ", &permanentData.ownerAuth, sizeof(TPM_SECRET));
    printf_buf("TPM_SECRET operatorAuth                       ", &permanentData.operatorAuth, sizeof(TPM_SECRET));
    //printf_buf("TPM_DAA_TPM_SEED tpmDAASeed                   ", &permanentData.tpmDAASeed, sizeof(TPM_DAA_TPM_SEED));
    //printf_buf("TPM_NONCE daaProof                            ", &permanentData.daaProof, sizeof(TPM_NONCE));
    //printf_buf("TPM_PUBKEY_DATA manuMaintPub                  ", &permanentData.manuMaintPub, sizeof(TPM_PUBKEY_DATA));
    printf("UINT16 ekFileid                           \n%04x\n", permanentData.ekFileid);
    //printf_buf("TPM_KEY_DATA srk                              ", &permanentData.srk, sizeof(TPM_KEY_DATA));
    printf("TPM_KYE_DATA srk: \n");
    printf_TPM_KEY_DATA(&permanentData.srk);
    //printf_buf("BYTE contextKey[TPM_SYM_KEY_SIZE]             ", &permanentData.contextKey, sizeof(BYTE)*TPM_SYM_KEY_SIZE);
    //printf_buf("BYTE delegateKey[TPM_SYM_KEY_SIZE]            ", &permanentData.delegateKey, sizeof(BYTE)*TPM_SYM_KEY_SIZE);
    //printf_buf("BYTE daaKey[TPM_SYM_KEY_SIZE]                 ", &permanentData.daaKey, sizeof(BYTE)*TPM_SYM_KEY_SIZE);
    //printf("TPM_ACTUAL_COUNT auditMonotonicCounter        %04x\n", permanentData.auditMonotonicCounter);
    //printf_buf("TPM_COUNTER_VALUE counters[TPM_MAX_COUNTERS]  ", &permanentData.counters, sizeof(TPM_COUNTER_VALUE)*TPM_MAX_COUNTERS);
    //printf_buf("TPM_PCR_ATTRIBUTES pcrAttrib[TPM_NUM_PCR]     ", &permanentData.pcrAttrib, sizeof(TPM_PCR_ATTRIBUTES)*TPM_NUM_PCR);
    //printf_buf("TPM_PCRVALUE pcrValue[TPM_NUM_PCR]            ", &permanentData.pcrValue, sizeof(TPM_PCRVALUE)*TPM_NUM_PCR);
    //printf_buf("BYTE ordinalAuditStatus[TPM_ORD_MAX / 8]      ", &permanentData.ordinalAuditStatus, sizeof(BYTE)*(TPM_ORD_MAX/8));
    //printf_buf("BYTE rngState[16]                             ", &permanentData.rngState, sizeof(BYTE)*16);
    //printf_buf("TPM_FAMILY_TABLE familyTable                  ", &permanentData.familyTable, sizeof(TPM_FAMILY_TABLE));
    //printf_buf("TPM_DELEGATE_TABLE delegateTable              ", &permanentData.delegateTable, sizeof(TPM_DELEGATE_TABLE));
    //printf("UINT32 lastFamilyID                           %04x\n", permanentData.lastFamilyID);
    //printf_buf("TPM_CMK_DELEGATE restrictDelegate             ", &permanentData.restrictDelegate, sizeof(TPM_CMK_DELEGATE));
    //printf("UINT32 maxNVBufSize                           %04x\n", permanentData.maxNVBufSize);
    //printf("UINT32 noOwnerNVWrite                         %04x\n", permanentData.noOwnerNVWrite);
    //printf("UINT32 nvDataSize                             %04x\n", permanentData.nvDataSize);
    //printf_buf("BYTE nvData[TPM_MAX_NV_SIZE]                  ", &permanentData.nvData, sizeof(BYTE)*TPM_MAX_NV_SIZE);
    //printf_buf("BYTE nvStorage[TPM_MAX_NVS]                   ", &permanentData.nvStorage, sizeof(BYTE)*TPM_MAX_NVS);
    //printf_buf("TPM_KEY_DATA keys[TPM_MAX_KEYS]               ", &permanentData.keys, sizeof(TPM_KEY_DATA)*TPM_MAX_KEYS);
    printf("TPM_KEY_DATA keys:\n");
    for (i = 0; i < TPM_MAX_KEYS; i++) {
        printf("KEY %d\n", i);
        printf_TPM_KEY_DATA(permanentData.keys+i);
    }
    //printf_buf("UINT32 tis_timeouts[TPM_NUM_TIS_TIMEOUTS]         ", &permanentData.tis_timeouts, sizeof(UINT32)*TPM_NUM_TIS_TIMEOUTS);
    //printf_buf("UINT32 cmd_durations[TPM_NUM_CMD_DURATIONS]     ", &permanentData.cmd_durations, sizeof(UINT32)*TPM_NUM_CMD_DURATIONS);
    printf("\n");
}

void printf_PERMANENT_FLAGS() {
    TPM_PERMANENT_FLAGS permanentFlags;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_PERMANENT_FLAGS, 0, (BYTE *)&permanentFlags, sizeof(TPM_PERMANENT_FLAGS)) != DONGLE_SUCCESS) {
        printf("Failed to Read TPM_PERMANENT_FLAGS.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Permanent Flags ***\n");
    printf("TPM_STRUCTURE_TAG tag             : %04x\n", permanentFlags.tag);
    printf("BOOL disable                      : %02x\n", permanentFlags.disable);
    printf("BOOL ownership                    : %02x\n", permanentFlags.ownership);
    printf("BOOL deactivated                  : %02x\n", permanentFlags.deactivated);
    printf("BOOL readPubek                    : %02x\n", permanentFlags.readPubek);
    printf("BOOL disableOwnerClear            : %02x\n", permanentFlags.disableOwnerClear);
    printf("BOOL allowMaintenance             : %02x\n", permanentFlags.allowMaintenance);
    printf("BOOL physicalPresenceLifetimeLock : %02x\n", permanentFlags.physicalPresenceLifetimeLock);
    printf("BOOL physicalPresenceHWEnable     : %02x\n", permanentFlags.physicalPresenceHWEnable);
    printf("BOOL physicalPresenceCMDEnable    : %02x\n", permanentFlags.physicalPresenceCMDEnable);
    printf("BOOL CEKPUsed                     : %02x\n", permanentFlags.CEKPUsed);
    printf("BOOL TPMpost                      : %02x\n", permanentFlags.TPMpost);
    printf("BOOL TPMpostLock                  : %02x\n", permanentFlags.TPMpostLock);
    printf("BOOL FIPS                         : %02x\n", permanentFlags.FIPS);
    printf("BOOL operator                     : %02x\n", permanentFlags.operator);
    printf("BOOL enableRevokeEK               : %02x\n", permanentFlags.enableRevokeEK);
    printf("BOOL nvLocked                     : %02x\n", permanentFlags.nvLocked);
    printf("BOOL readSRKPub                   : %02x\n", permanentFlags.readSRKPub);
    printf("BOOL tpmEstablished               : %02x\n", permanentFlags.tpmEstablished);
    printf("BOOL maintenanceDone              : %02x\n", permanentFlags.maintenanceDone);
    printf("BOOL disableFullDALogicInfo       : %02x\n", permanentFlags.disableFullDALogicInfo);
    printf("BOOL selfTestSucceeded            : %02x\n", permanentFlags.selfTestSucceeded);
    printf("BOOL owned                        : %02x\n", permanentFlags.owned);
    printf("BOOL dataSaved                    : %02x\n", permanentFlags.dataSaved);
    printf("\n");
}

void printf_STCLEAR_DATA() {
    TPM_STCLEAR_DATA stclearData;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_STCLEAR_DATA, 0, (BYTE *)&stclearData, sizeof(TPM_STCLEAR_DATA)) != DONGLE_SUCCESS) {
        printf("Failed to Read TPM_STCLEAR_DATA.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Stclear Data ***\n");
    printf("TPM_STRUCTURE_TAG tag\n%04x\n", stclearData.tag);
    printf_buf("TPM_NONCE contextNonceKey", &stclearData.contextNonceKey, sizeof(TPM_NONCE));
    printf("TPM_COUNT_ID countID\n%08x\n", stclearData.countID);
    printf("UINT32 ownerReference\n%08x\n", stclearData.ownerReference);
    printf("BOOL disableResetLock\n%02x\n", stclearData.disableResetLock);
    printf("UINT32 deferredPhysicalPresence\n%08x\n", stclearData.deferredPhysicalPresence);
    printf("\n");
}

void printf_STCLEAR_FLAGS() {
    TPM_STCLEAR_FLAGS stclearFlags;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_STCLEAR_FLAGS, 0, (BYTE *)&stclearFlags, sizeof(TPM_STCLEAR_FLAGS)) != DONGLE_SUCCESS) {
        printf("Failed Read TPM_STCLEAR_FLAGS.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Stclear Flags ***\n");
    printf("TPM_STRUCTURE_TAG tag     : %04x\n", stclearFlags.tag);
    printf("BOOL deactivated          : %02x\n", stclearFlags.deactivated);
    printf("BOOL disableForceClear    : %02x\n", stclearFlags.disableForceClear);
    printf("BOOL physicalPresence     : %02x\n", stclearFlags.physicalPresence);
    printf("BOOL physicalPresenceLock : %02x\n", stclearFlags.physicalPresenceLock);
    printf("BOOL bGlobalLock          : %02x\n", stclearFlags.bGlobalLock);
    printf("\n");
}

void printf_STANY_DATA() {
    TPM_STANY_DATA stanyData;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_STANY_DATA, 0, (BYTE *)&stanyData, sizeof(TPM_STANY_DATA)) != DONGLE_SUCCESS) {
        printf("Failed Read TPM_STANY_DATA.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Stany Data ***\n");
    //printf("TPM_STRUCTURE_TAG tag \n%04x\n", stanyData.tag);
    //printf_buf("TPM_NONCE contextNonceSession", &stanyData.contextNonceSession, sizeof(TPM_NONCE));
    //printf_buf("TPM_DIGEST auditDigest", &stanyData.auditDigest, sizeof(TPM_DIGEST));
    //printf("BOOL auditSession\n%02x\n", stanyData.auditSession);
    //printf_buf("TPM_CURRENT_TICKS currentTicks", &stanyData.currentTicks, sizeof(TPM_CURRENT_TICKS));
    //printf("UINT32 contextCount\n%08x\n", stanyData.contextCount);
    //printf_buf("UINT32 contextList[TPM_MAX_SESSION_LIST]", stanyData.contextList, sizeof(UINT32) * TPM_MAX_SESSION_LIST);
    printf("TPM_SESSION_DATA sessions[TPM_MAX_SESSIONS]\n");
    printf_sessions(stanyData.sessions);
    //TPM_DAA_SESSION_DATA sessionsDAA[TPM_MAX_SESSIONS_DAA]; TODO
    //printf("TPM_DAAHANDLE currentDAA\n%08x\n", stanyData.currentDAA);
    //printf("TPM_TRANSHANDLE transExclusive\n%08x\n", stanyData.transExclusive);
    printf("\n");
}

void printf_STANY_FLAGS() {
    TPM_STANY_FLAGS stanyFlags;
    if (Dongle_ReadFile(rockeyHandle, FILEID_TPM_STANY_FLAGS, 0, (BYTE *)&stanyFlags, sizeof(TPM_STANY_FLAGS)) != DONGLE_SUCCESS) {
        printf("Failed Read TPM_STANY_FLAGS.\n");
        exit(EXIT_FAILURE);
    }
    printf("*** Now list the Stany Flags ***\n");
    printf("TPM_STRUCTURE_TAG tag                   : %02x\n", stanyFlags.tag);
    printf("BOOL postInitialise                     : %02x\n", stanyFlags.postInitialise);
    printf("TPM_MODIFIER_INDICATOR localityModifier : %08x\n", stanyFlags.localityModifier);
    printf("BOOL transportExclusive                 : %02x\n", stanyFlags.transportExclusive);
    printf("BOOL TOSPresent                         : %02x\n", stanyFlags.TOSPresent);
    printf("\n");
}

void printf_sessions(TPM_SESSION_DATA *sessions) {
    int i;
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
        printf("Session %d: \n", i);
        printf_TPM_SESSION_DATA(sessions+i);
    }
}

void printf_TPM_SESSION_DATA(TPM_SESSION_DATA *session) {
    printf("BYTE type\n%02x\n", session->type);
    printf_buf("TPM_NONCE nonceEven", &session->nonceEven, sizeof(TPM_NONCE));
    printf_buf("TPM_NONCE lastNonceEven", &session->lastNonceEven, sizeof(TPM_NONCE));
    printf_buf("TPM_SECRET sharedSecret", &session->sharedSecret, sizeof(TPM_SECRET));
    printf("TPM_HANDLE handle\n%08x\n", session->handle);
    printf("TPM_ENTITY_TYPE entityType\n%04x\n", session->entityType);
    printf_buf("TPM_DELEGATIONS permissions", &session->permissions, sizeof(TPM_DELEGATIONS));
    printf("TPM_FAMILY_ID familyID\n%08x\n", session->familyID);
    printf_buf("TPM_TRANSPORT_INTERNAL transInternal", &session->transInternal, sizeof(TPM_TRANSPORT_INTERNAL));
}

void printf_TPM_KEY(TPM_KEY *wrappedKey) {
    printf("TPM_STRUCTURE_TAG tag: 0x%x\n", wrappedKey->tag);
    printf("UINT16 fill : 0x%x\n", wrappedKey->fill);
    printf("TPM_KEY_USAGE keyUsage: 0x%x\n", wrappedKey->keyUsage);
    printf("TPM_KEY_FLAGS keyFlags: 0x%x\n", wrappedKey->keyFlags);
    printf("TPM_AUTH_DATA_USAGE authDataUsage :%x\n", wrappedKey->authDataUsage);
    //printf_buf("TPM_KEY_PARMS algorithmParms", &wrappedKey->algorithmParms, sizeof(TPM_KEY_PARMS));
    printf("UINT32 PCRInfoSize 0x%x\n", wrappedKey->PCRInfoSize);
    //printf_buf("TPM_PCR_INFO PCRInfoSize ", &wrappedKey->PCRInfo, sizeof(wrappedKey->PCRInfo));
    printf("TPM_STORE_ASYMKEY pubkey.\n");
    printf("pubkey size 0x%x\n", wrappedKey->pubKey.keyLength);
    printf_buf("pubkey key", wrappedKey->pubKey.key, wrappedKey->pubKey.keyLength);
    printf("UINT32 encDataSize: 0x%x\n", wrappedKey->encDataSize);
    printf_buf("BYTE encData:", wrappedKey->encData, wrappedKey->encDataSize);
}

void printf_TPM_CERIFTY_INFO(TPM_CERTIFY_INFO *certInfo) {
    printf("TPM_STRUCTURE_TAG tag: 0x%x\n", certInfo->tag);
    printf("BYTE fill: 0x%x\n", certInfo->fill);
    printf("TPM_PAYLOAD_TYPE payloadType: 0x%x\n", certInfo->payloadType);
    printf("TPM_KEY_USAGE keyUsage: 0x%x\n", certInfo->keyUsage);
    printf("TPM_KEY_FLAGS keyFlags: 0x%x\n", certInfo->keyFlags);
    printf("TPM_AUTH_DATA_USAGE authDataUsage: 0x%x\n", certInfo->authDataUsage);
    //printf("TPM_KEY_PARMS algorithmParms");
    printf_buf("TPM_DIGEST pubkeyDigest: ", certInfo->pubkeyDigest.digest, sizeof(TPM_DIGEST));
    printf_buf("TPM_NONCE data: ", certInfo->data.nonce, sizeof(TPM_NONCE));
    printf("BOOL parentPCRStatus: 0x%x\n", certInfo->parentPCRStatus);
    printf("UINT32 PCRInfoSize: 0x%x\n", certInfo->PCRInfoSize);
    //printf("TPM_PCR_INFO PCRInfo")
    printf("UINT32 migrationAuthoritySize: 0x%x\n", certInfo->migrationAuthoritySize);
    //printf("migrationAuthortity");
}

void printf_TPM_PCR_SELECTION(TPM_PCR_SELECTION *pcrSelection) {
    printf("UINT16 sizeOfSelect: 0x%x\n", pcrSelection->sizeOfSelect);
    printf_buf("BYTE pcrSelect[TPM_NUM_PCR/8]", pcrSelection->pcrSelect, pcrSelection->sizeOfSelect);
}

void printf_TPM_PCR_COMPOSITE(TPM_PCR_COMPOSITE *pcrComposite) {
    printf_TPM_PCR_SELECTION(&pcrComposite->select);
    printf("UINT32 valueSize: 0x%x\n", pcrComposite->valueSize);
    int i;
    printf("PCRValue\n");
    for (i = 0; i < pcrComposite->valueSize / sizeof(TPM_PCRVALUE); i++) {
        char buffer[100];
        sprintf(buffer, "PCR%d:", i);
        printf_buf(buffer, &pcrComposite->pcrValue[i], sizeof(TPM_PCRVALUE));
    }
}
