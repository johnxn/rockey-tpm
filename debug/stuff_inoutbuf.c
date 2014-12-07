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
void stuff_inoutbuf_osap_new(unsigned char *InOutBuf, int buf_size, TPM_ENTITY_TYPE entityType, UINT32 entityValue) {
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
    keyInfo.keyFlags = 0x0;
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
void stuff_inoutbuf_loadkey_new(unsigned char *InOutBuf, int buf_size, TPM_KEY *inKey, TPM_SECRET secret, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven) {
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

void stuff_inoutbuf_makeidentity(unsigned char *InOutBuf, int buf_size, TPM_AUTHHANDLE srkAuthHandle, TPM_NONCE *srkNonceEven, TPM_NONCE *nonceOddOSAP, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceEven, TPM_AUTHHANDLE authHandle)  {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           20 + //identityAuth
                           20 + //labelPrivCADigest
                           2 + //idkeyParams.tag
                           2 + //idkeyParams.fill
                           2 + //idkeyParams.keyUsage
                           4 + //idkeyParams.keyFlags
                           1 + //idkeyParams.authDataUsage
                           4 + //idkeyParams.algorithmParms.algorithmID
                           2 + //idkeyParams.algorithmParms.encScheme
                           2 + //idkeyParams.algorithmParms.sigScheme
                           4 + //idkeyParams.algorithmParms.parmSize
                           4 + //idkeyParams.algorithmParms.rsa.keyLength
                           4 + //idkeyParams.algorithmParms.rsa.numPrimes
                           4 + //idkeyParams.algorithmParms.rsa.exponentSize
                           4 + //idkeyParams.PCRInfoSize
                           4 + //idkeyParams.pubKey.keyLength
                           4 + //idkeyParams.encDataSize
                           4 + //srkAuthHandle
                           20 + //srkNonceOdd
                           1 + //continueAuthSession
                           20 + //srkAuth
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //ownerAuth
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_MakeIdentity;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    /* generate identityAuth */
    TPM_SECRET ownerSecret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TPM_SECRET sharedSecret;
    compute_shared_secret(ownerSecret, nonceEvenOSAP, nonceOddOSAP, sharedSecret);
    TPM_ENCAUTH identityAuth;
    TPM_SECRET identitySecret = {0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    tpm_encrypt_auth_secret(identitySecret, sharedSecret, nonceEven, identityAuth);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &identityAuth);

    TPM_CHOSENID_HASH labelPrivCADigest;
    memset(labelPrivCADigest.digest, 0, sizeof(TPM_CHOSENID_HASH)); // we don't need this.
    tpm_marshal_TPM_CHOSENID_HASH(&ptr, &length, &labelPrivCADigest);
 
    TPM_KEY idkeyParams;
    idkeyParams.tag = 0x0101; //TPM_KEY_STRUCTURE
    idkeyParams.keyUsage = TPM_KEY_IDENTITY;
    idkeyParams.algorithmParms.algorithmID = TPM_ALG_RSA;
    idkeyParams.algorithmParms.encScheme = TPM_ES_NONE;
    idkeyParams.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    idkeyParams.algorithmParms.parmSize = 12;
    idkeyParams.algorithmParms.parms.rsa.keyLength = 2048;
    idkeyParams.algorithmParms.parms.rsa.numPrimes = 2;
    idkeyParams.algorithmParms.parms.rsa.exponentSize = 0;
    idkeyParams.PCRInfoSize = 0;
    idkeyParams.pubKey.keyLength = 0;
    idkeyParams.encDataSize = 0;
    tpm_marshal_TPM_KEY(&ptr, &length, &idkeyParams);

    /* set up auth1 */
    TPM_SECRET srkSecret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TPM_AUTH auth1;
    auth1.authHandle = srkAuthHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, srkNonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, srkSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1) * 2;
    compute_in_parm_digest(auth1.digest, TPM_ORD_MakeIdentity, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);

    /* set up auth2 */
    TPM_AUTH auth2;
    auth2.authHandle = authHandle;
    memcpy(auth2.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth2.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth2.continueAuthSession = 0x00; 
    memcpy(auth2.secret, sharedSecret, sizeof(TPM_SECRET));
    memcpy(auth2.digest, auth1.digest, sizeof(TPM_DIGEST));
    compute_auth_data(&auth2);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth2.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth2.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth2.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth2.auth);

    if (length != 0) {
        printf("stuff make identity inoutbuf failed.\n");
        exit(EXIT_FAILURE);
    }

}

void stuff_inoutbuf_flush(unsigned char *InOutBuf, int buf_size, TPM_HANDLE handle, TPM_RESOURCE_TYPE resourceType) {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //handle
                           4; //resourceType
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_FlushSpecific;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_HANDLE(&ptr, &length, handle);
    tpm_marshal_TPM_RESOURCE_TYPE(&ptr, &length, resourceType);
    if (length != 0) {
        printf("stuff flush failed.\n");
        exit(EXIT_FAILURE);
    }
}

void stuff_inoutbuf_certify(
        unsigned char *InOutBuf, 
        int buf_size, 
        TPM_HANDLE certAuthHandle, 
        TPM_NONCE *certNonceEven, 
        TPM_HANDLE keyAuthHandle, 
        TPM_NONCE *keyNonceEven, 
        TPM_KEY_HANDLE certHandle, 
        TPM_KEY_HANDLE keyHandle, 
        TPM_SECRET certSecret,
        TPM_SECRET keySecret
) 
{
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //certHandle
                           4 + //keyHandle
                           20 + //antiReplay
                           4 + //certAuthHandle
                           20 + //certNonceEven
                           1 + //continueAuthSession
                           20 + //certAuth
                           4 + //keyAuthHandle
                           20 + //keyNonceEven
                           1 + //continueAuthSession
                           20; //keyAuth
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_CertifyKey;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, certHandle);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    TPM_NONCE antiReplay;
    get_random(antiReplay.nonce, sizeof(TPM_NONCE));
    tpm_marshal_TPM_NONCE(&ptr, &length, &antiReplay);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = certAuthHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, certNonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, certSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1) * 2;
    compute_in_parm_digest(auth1.digest, TPM_ORD_CertifyKey, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);

    /* set up auth2 */
    TPM_AUTH auth2;
    auth2.authHandle = keyAuthHandle;
    memcpy(auth2.nonceEven.nonce, keyNonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth2.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth2.continueAuthSession = 0x00; 
    memcpy(auth2.secret, keySecret, sizeof(TPM_SECRET));
    memcpy(auth2.digest, auth1.digest, sizeof(TPM_DIGEST));
    compute_auth_data(&auth2);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth2.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth2.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth2.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth2.auth);

    if (length != 0) {
        printf("stuff certify key inoutbuf failed.\n");
        exit(EXIT_FAILURE);
    }

}

void stuff_inoutbuf_extend(unsigned char *InOutBuf, int buf_size) {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //pcrNum
                           20; //inDigest
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_Extend;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    TPM_PCRINDEX pcrNum = 0;
    TPM_DIGEST inDigest = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0f, 0x0e, 0x0c, 0x0d, 0x0c, 0x0d, 0x0c, 0x0a};
    tpm_marshal_TPM_PCRINDEX(&ptr, &length, pcrNum);
    tpm_marshal_TPM_DIGEST(&ptr, &length, &inDigest);
    if (length != 0) {
        printf("stuff extend failed.\n");
        exit(EXIT_FAILURE);
    }
}

void stuff_inoutbuf_read(unsigned char *InOutBuf, int buf_size) {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4; //pcrIndex
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_PCRRead;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    TPM_PCRINDEX pcrIndex = 0;
    tpm_marshal_TPM_PCRINDEX(&ptr, &length, pcrIndex);
    if (length != 0) {
        printf("stuff pcr read failed.\n");
    }
}

void stuff_inoutbuf_quote(unsigned char *InOutBuf, int buf_size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven) {
    unsigned int in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //keyHandle
                           20 + //externalData
                           2 + //targetPCR.sizeOfSelect
                           1 + //targetPCR.pcrSelect
                           4 + //authHandle
                           20 + //nonceEven
                           1 + //continueAuthSession
                           20; //auth
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_Quote;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    TPM_KEY_HANDLE keyHandle = 0x1000000;
    TPM_NONCE externalData = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a};
    TPM_PCR_SELECTION targetPCR;
    targetPCR.sizeOfSelect = 1;
    targetPCR.pcrSelect[0] = 0x01; // select PCR0
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &externalData);
    tpm_marshal_TPM_PCR_SELECTION(&ptr, &length, &targetPCR);

    /* set up auth1 */
    TPM_SECRET aikSecret = {0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    TPM_AUTH auth1;
    auth1.authHandle = authHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, aikSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1);
    compute_in_parm_digest(auth1.digest, TPM_ORD_Quote, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) {
        printf("stuff quote failed.\n");
        exit(EXIT_FAILURE);
    }
}
