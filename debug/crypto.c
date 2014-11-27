#include "crypto.h"

void login_rockey() {
    int key_count;
    int key_id;
    DWORD errcode;
    int remain_count;
    printf("Start Dongle_Enum...\n");
    errcode = Dongle_Enum(NULL, &key_count);
    if (errcode != DONGLE_SUCCESS || key_count == 0) {
        printf("ROCKEY not found.\n");
        exit(EXIT_FAILURE);
    }
    printf("Dongle_Enum succeed...\n");
    if (key_count > 1) {
        printf("Input which key to use <0-%d>: ", key_count-1);
        scanf("%d", &key_id);
    }
    else {
        key_id = 0;
    }
    errcode = Dongle_Open(&rockeyHandle, key_id);
    if (errcode != DONGLE_SUCCESS) {
        printf("Failed to open ROCKEY %x\n.", key_id);
        exit(EXIT_FAILURE);
    }
    printf("Dongle_Open succeed...\n");
    errcode = Dongle_VerifyPIN(rockeyHandle, FLAG_ADMINPIN, CONST_ADMINPIN, &remain_count);
    if (errcode != DONGLE_SUCCESS) {
        printf("Wrong password.\n Have you reset the password?\n");
        exit(EXIT_FAILURE);
    }
    printf("Dongle_Verify succeed...\nLogin succeed!\n");
}

void download_bin() {
    char bin_data[1024*64];
    memset(bin_data, 0, sizeof(bin_data));
    FILE *bin_file;
    short data_size;
    short i;
    int errcode;
    bin_file = fopen("../demo.bin", "r");
    if (bin_file == NULL) {
        perror("../demo.bin");
        exit(EXIT_FAILURE);
    }
    fseek(bin_file, 0, SEEK_END);
    data_size = ftell(bin_file);
    fseek(bin_file, 0, SEEK_SET);
    fread(bin_data, sizeof(char), data_size, bin_file);
    if (fclose(bin_file) != 0) {
        perror("../demo.bin");
        exit(EXIT_FAILURE);
    }
    /*for (i = 0; i < data_size; i++) {
        printf("%02x ", 0xff & bin_data[i]);
        if (i % 16 == 15 || i == data_size - 1) printf("\n");
    } */
    EXE_FILE_INFO pExeFileInfo;
    pExeFileInfo.m_dwSize = data_size;
    pExeFileInfo.m_wFileID = 0x0001;
    pExeFileInfo.m_Priv = 0;
    pExeFileInfo.m_pData = bin_data;
    if ((errcode = Dongle_DownloadExeFile(rockeyHandle, &pExeFileInfo, 1)) != DONGLE_SUCCESS) {
        printf("Failed to Download bin file. Errcode: %x\n", errcode);
        exit(EXIT_FAILURE);
    }
    printf("Download bin file succeeed...\nSize of the bin file is: %d Bytes.\n", data_size);
}
void run_bin_file(unsigned char *InOutBuf, int size) {
    DWORD errcode;
    if ((errcode = Dongle_RunExeFile(rockeyHandle, 0x0001, InOutBuf, size, NULL)) != DONGLE_SUCCESS) {
        printf("Failed to Run. Errcode: %x\n", errcode);
        exit(EXIT_FAILURE);
    }
}


int generate_rsa_key(UINT16 fileid, RSA_PUBLIC_KEY *pubkey, RSA_PRIVATE_KEY *prikey) {
    UINT32 errcode;
    errcode = Dongle_RsaGenPubPriKey(rockeyHandle, fileid, pubkey, prikey);
    if (errcode != DONGLE_SUCCESS) {
        printf("Generate key error. %x\n", errcode);
        return -1;
    }
    return 0;
}

int read_rsa_pubkey(UINT32 fileid, RSA_PUBLIC_KEY *pubkey) {
    UINT32 errcode;
    errcode = Dongle_ReadFile(rockeyHandle, fileid, 0, (BYTE *)pubkey, sizeof(RSA_PUBLIC_KEY));
    if (errcode != DONGLE_SUCCESS) {
        printf("Read rsa pubkey error. %x\n", errcode);
        return -1;
    }
    return 0;
}

int encrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, UINT32 inputSize, BYTE *output, UINT32 *outputSize) {
    UINT32 errcode;
    errcode = Dongle_RsaPub(rockeyHandle, FLAG_ENCODE, pubkey, input, inputSize, output, outputSize);
    if (errcode != DONGLE_SUCCESS) {
        printf("Encrypted error. %x\n", errcode);
        return -1;
    }
    return 0;
}

int decrypt_with_prikey(UINT16 fileid, BYTE *input, UINT32 inputSize, BYTE *output, UINT32 *outputSize) {
    UINT32 errcode;
    errcode = Dongle_RsaPri(rockeyHandle, fileid, FLAG_DECODE, input, inputSize, output, outputSize);
    if (errcode != DONGLE_SUCCESS) {
        printf("Decrypted error. %x\n", errcode);
        return -1;
    }
    return 0;
}

int get_random(BYTE *buf, UINT32 size) {
    UINT32 errcode;
    errcode = Dongle_GenRandom(rockeyHandle, size, buf);
    if (errcode != DONGLE_SUCCESS) {
        printf("Get random error. %x\n", errcode);
        return -1;
    }
    return 0;
}

UINT32 get_in_param_offset(TPM_COMMAND_CODE ordinal)
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

void compute_in_parm_digest(BYTE *digest, TPM_COMMAND_CODE ordinal, BYTE *ptr, UINT32 length) {
    ptr += get_in_param_offset(ordinal);
    length -= get_in_param_offset(ordinal);
    tpm_sha1_ctx_t sha1;
    tpm_sha1_init(&sha1);
    tpm_sha1_update_be32(&sha1, ordinal);
    tpm_sha1_update(&sha1, ptr, length);
    tpm_sha1_final(&sha1, digest);
}

void compute_auth_data(TPM_AUTH *auth) {
    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, auth->secret, sizeof(auth->secret));
    tpm_hmac_update(&ctx, auth->digest, sizeof(auth->digest));
    tpm_hmac_update(&ctx, auth->nonceEven.nonce, sizeof(auth->nonceEven.nonce));
    tpm_hmac_update(&ctx, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
    tpm_hmac_update(&ctx, &auth->continueAuthSession, 1);
    tpm_hmac_final(&ctx, auth->auth);
}

void compute_shared_secret(TPM_SECRET secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET sharedSecret) {
    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, secret, sizeof(TPM_SECRET));
    tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
    tpm_hmac_final(&ctx, sharedSecret);
}

void compute_shared_secret2(TPM_SECRET *secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET *sharedSecret) {
    printf_buf("secret is:", secret, sizeof(TPM_SECRET));
    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, *secret, sizeof(*secret));
    //tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    //tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
    tpm_hmac_final(&ctx, *sharedSecret);
}
void tpm_encrypt_auth_secret(TPM_SECRET plainAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_ENCAUTH encAuth)
{
  unsigned int i;
  tpm_sha1_ctx_t ctx;
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, secret, sizeof(TPM_SECRET));
  tpm_sha1_update(&ctx, nonce->nonce, sizeof(nonce->nonce));
  tpm_sha1_final(&ctx, encAuth);
  for (i = 0; i < sizeof(TPM_SECRET); i++)
    encAuth[i] ^= plainAuth[i];
}


