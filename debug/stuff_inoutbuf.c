#include "stuff_inoutbuf.h"

void stuff_inoutbuf_firsttime(unsigned char *InOutBuf, int size) {
    
    unsigned int in_size = 0xffffffff;
    memcpy(InOutBuf, &in_size, sizeof(unsigned int));
}

void stuff_inoutbuf_startup(unsigned char *InOutBuf, int size) {
    unsigned int in_size = 2 + 4 + 4 + 2;
    memcpy(InOutBuf, &in_size, 4);

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size;

    TPM_TAG tag = TPM_TAG_RQU_COMMAND; // 0x00c1
    UINT32 paramSize = 2 + 4 + 4 + 2; // 0x0000000c
    TPM_COMMAND_CODE ordinal = TPM_ORD_Startup; // 153
    TPM_STARTUP_TYPE startupType = TPM_ST_CLEAR; //0x0001

    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, paramSize);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_STARTUP_TYPE(&ptr, &length, startupType);
}

void stuff_inoutbuf_oiap(unsigned char *InOutBuf, int size) {
    /* TPM_OIAP */
    unsigned int in_size = 2 + 4 + 4;
    memcpy(InOutBuf, &in_size, 4);

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size; 

    TPM_TAG tag = TPM_TAG_RQU_COMMAND; //0x00C1
    UINT32 paramSize = 2 + 4 + 4; 
    TPM_COMMAND_CODE oridnal = TPM_ORD_OIAP; //10
    tpm_marshal_UINT16(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, paramSize);
    tpm_marshal_UINT32(&ptr, &length, oridnal);
}

void stuff_inoutbuf_ownership(unsigned char *InOutBuf, int buf_size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven) {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           2 + //protocolID
                           4 + //encOwnerAuthSize
                           256 + //encOwnerAuth
                           4 + //encSrkAuthSize
                           256 + //encSrkAuth
                           2 + //srkParams.tag
                           2 + //srkParams.fill
                           2 + //srkParams.keyUsage
                           4 + //srkParams.keyFlags
                           1 + //srkParams.authDataUsage
                           4 + //srkParams.algorithmParms.algorithmID
                           2 + //srkParams.algorithmParms.encScheme
                           2 + //srkParams.algorithmParms.sigScheme
                           4 + //srkParams.algorithmParms.parmSize
                           4 + //srkParams.algorithmParms.rsa.keyLength
                           4 + //srkParams.algorithmParms.rsa.numPrimes
                           4 + //srkParams.algorithmParms.rsa.exponentSize
                           4 + //srkParams.PCRInfoSize
                           4 + //srkParams.pubKey.keyLength
                           4 + //srkParams.encDataSize
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //ownerAuth
    memcpy(InOutBuf, &in_size, 4);

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size;

    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size =  in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_TakeOwnership;
    tpm_marshal_UINT16(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_UINT32(&ptr, &length, ordinal);

    /* setup encSrkAuth and encOwnerAuth */
    TPM_PROTOCOL_ID protocolID = TPM_PID_OWNER;
    UINT32 encOwnerAuthSize = 256;
    BYTE encOwnerAuth[256];
    TPM_SECRET secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    RSA_PUBLIC_KEY pubkey;
    if (read_rsa_pubkey(FILEID_EK_PUB, &pubkey) != 0) {
        printf("read_rsa_pubkey error.\n");
        exit(EXIT_FAILURE);
    }
    printf_buf("Public key is: ", &pubkey, sizeof(RSA_PUBLIC_KEY));
    if (encrypt_with_pubkey(&pubkey, secret, sizeof(TPM_SECRET), encOwnerAuth, &encOwnerAuthSize) != 0) {
        printf("encrypt_with_pubkey error.\n");
        exit(EXIT_FAILURE);
    }
    TPM_SECRET dec_secret;
    UINT32 dec_secret_size = sizeof(TPM_SECRET);
    if (decrypt_with_prikey(FILEID_EK, encOwnerAuth, encOwnerAuthSize, dec_secret, &dec_secret_size) != 0) {
        printf("decrypt_with_prikey error.\n");
    }
    if (dec_secret_size != sizeof(TPM_SECRET)){
        printf("decrytp_with_prikey error. \n");
        exit(EXIT_FAILURE);
    }
    //printf_buf("Decrypted secret is", dec_secret, dec_secret_size);
    if (encOwnerAuthSize != 256) {
        printf("encOwnerAuthSize is not right.\n");
        exit(EXIT_FAILURE);
    }
    UINT32 encSrkAuthSize = 256;
    BYTE encSrkAuth[256]; 
    memcpy(encSrkAuth, encOwnerAuth, 256);
    if (decrypt_with_prikey(FILEID_EK, encSrkAuth, encSrkAuthSize, dec_secret, &dec_secret_size) != 0) {
        printf("decrypt_with_prikey error.\n");
    }

    tpm_marshal_UINT16(&ptr, &length, protocolID);
    tpm_marshal_UINT32(&ptr, &length, encOwnerAuthSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, encOwnerAuth, encOwnerAuthSize);
    tpm_marshal_UINT32(&ptr, &length, encSrkAuthSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, encSrkAuth, encSrkAuthSize);

    /* set up srkParams */
    TPM_KEY srkParams;
    srkParams.tag = 0x0000; // doesn't matter here.
    srkParams.fill = 0x0000;
    srkParams.keyUsage = TPM_KEY_STORAGE;
    srkParams.authDataUsage = TPM_AUTH_NEVER; //not sure what TPM_AUTH_NEVER means.
    srkParams.algorithmParms.algorithmID = TPM_ALG_RSA;
    srkParams.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    srkParams.algorithmParms.sigScheme = TPM_SS_NONE;
    srkParams.algorithmParms.parmSize = 12;
    srkParams.algorithmParms.parms.rsa.keyLength = 2048;
    srkParams.algorithmParms.parms.rsa.numPrimes = 2;
    srkParams.algorithmParms.parms.rsa.exponentSize = 0;
    srkParams.PCRInfoSize = 0;
    srkParams.pubKey.keyLength = 0;
    srkParams.encDataSize = 0;

    tpm_marshal_TPM_KEY(&ptr, &length, &srkParams);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, secret, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_TakeOwnership, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
}

void stuff_inoutbuf_osap(unsigned char *InOutBuf, int buf_size) {
   unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           2 + //entityType
                           4 + //entityValue
                           20; //nonceOddOSAP
    memcpy(InOutBuf, &in_size, 4);

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_OSAP;
    TPM_ENTITY_TYPE entityType = TPM_ET_SRK;
    UINT32 entityValue = TPM_KH_SRK;
    TPM_NONCE nonceOddOSAP;
    get_random(nonceOddOSAP.nonce, sizeof(TPM_NONCE));
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_ENTITY_TYPE(&ptr, &length, entityType);
    tpm_marshal_UINT32(&ptr, &length, entityValue);
    tpm_marshal_TPM_NONCE(&ptr, &length, &nonceOddOSAP);
}

void stuff_inoutbuf_createcrapkey(unsigned char *InOutBuf, int buf_size, TPM_NONCE *nonceOddOSAP, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceEven, TPM_AUTHHANDLE authHandle) {
    unsigned int in_size = 2 + //tag
                           4 + //size
                           4 + //ordinal
                           4 + //parentHandle
                           20 + //dataUsageAuth
                           20 + //dataMigrationAuth
                           2 + //keyInfo.tag
                           2 + //keyInfo.fill
                           2 + //keyInfo.keyUsage
                           4 + //keyInfo.keyFlags
                           1 + //keyInfo.authDataUsage
                           4 + //keyInfo.algorithmParms.algorithmID
                           2 + //keyInfo.algorithmParms.encScheme
                           2 + //keyInfo.algorithmParms.sigScheme
                           4 + //keyInfo.algorithmParms.parmSize
                           4 + //keyInfo.algorithmParms.rsa.keyLength
                           4 + //keyInfo.algorithmParms.rsa.numPrimes
                           4 + //keyInfo.algorithmParms.rsa.exponentSize
                           4 + //keyInfo.PCRInfoSize
                           4 + //keyInfo.pubKey.keyLength
                           4 + //keyInfo.encDataSize
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //pubAuth
    memcpy(InOutBuf, &in_size, 4);

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_CreateWrapKey;
    TPM_KEY_HANDLE parentHandle = TPM_KH_SRK;
    TPM_SECRET sharedSecret; //sharedSecret generated by srkSecret.
    TPM_SECRET srkSecret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    compute_shared_secret(srkSecret, nonceEvenOSAP, nonceOddOSAP, sharedSecret);
    printf_buf("debug: srkSecret:", srkSecret, sizeof(TPM_SECRET));
    printf_buf("debug: nonceEvenOSAP:", nonceEvenOSAP, sizeof(TPM_NONCE));
    printf_buf("debug: nonceOddOSAP:", nonceOddOSAP, sizeof(TPM_NONCE));
    printf_buf("debug: sharedSecret:", sharedSecret, sizeof(TPM_SECRET));
    TPM_SECRET keySecret = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    TPM_SECRET migSecret = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    TPM_ENCAUTH dataUsageAuth;
    TPM_ENCAUTH dataMigrationAuth;
    TPM_NONCE nonceOdd;
    get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    tpm_encrypt_auth_secret(keySecret, sharedSecret, nonceEven, dataUsageAuth);
    tpm_encrypt_auth_secret(migSecret, sharedSecret, &nonceOdd, dataMigrationAuth);
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, parentHandle);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &dataUsageAuth);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &dataMigrationAuth);
    TPM_KEY keyInfo;
    keyInfo.tag = 0x0000; // doesn't matter here.
    keyInfo.fill = 0x0000;
    keyInfo.keyUsage = TPM_KEY_BIND;
    //keyInfo.authDataUsage = TPM_AUTH_NEVER; 
    keyInfo.algorithmParms.algorithmID = TPM_ALG_RSA;
    //keyInfo.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    //keyInfo.algorithmParms.sigScheme = TPM_SS_NONE;
    keyInfo.algorithmParms.parmSize = 12;
    keyInfo.algorithmParms.parms.rsa.keyLength = 2048;
    keyInfo.algorithmParms.parms.rsa.numPrimes = 2;
    keyInfo.algorithmParms.parms.rsa.exponentSize = 0;
    keyInfo.PCRInfoSize = 0;
    keyInfo.pubKey.keyLength = 0;
    keyInfo.encDataSize = 0;
    tpm_marshal_TPM_KEY(&ptr, &length, &keyInfo);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd.nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, sharedSecret, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_CreateWrapKey, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
}

void stuff_inoutbuf_loadkey(unsigned char *InOutBuf, int buf_size, TPM_KEY *inKey, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven) {
    unsigned int in_size = 2 + //tag
                           4 + //size
                           4 + //ordinal
                           4 + //parentHandle
                           sizeof_TPM_KEY((*inKey)) +
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //pubAuth
    memcpy(InOutBuf, &in_size, 4);
    //printf("wrapped key size is:%d\n", sizeof_TPM_KEY((*inKey)));

    unsigned char *ptr = InOutBuf + 4;
    unsigned int length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_LoadKey;
    TPM_KEY_HANDLE parentHandle = TPM_KH_SRK;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, parentHandle);
    tpm_marshal_TPM_KEY(&ptr, &length, inKey);
    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    TPM_SECRET secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}; // SRK secret.
    memcpy(auth1.secret, secret, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_LoadKey, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
     
}

void stuff_inoutbuf_unbind(unsigned char *InOutBuf, int buf_size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven, TPM_KEY_HANDLE keyHandle, BYTE *inData, UINT32 inDataSize) {
     unsigned int in_size = 2 + //tag
                           4 + //size
                           4 + //ordinal
                           4 + //keyHandle
                           4 + //inDataSize
                           inDataSize + //inData
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //pubAuth
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_UnBind;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    tpm_marshal_UINT32(&ptr, &length, inDataSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, inData, inDataSize);
    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    TPM_SECRET secret = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07}; //binding key secret.
    memcpy(auth1.secret, secret, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_UnBind, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
}
