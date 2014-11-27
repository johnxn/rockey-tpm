#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Dongle_CORE.h"
#include "Dongle_API.h"
#include <time.h>

#undef TRUE
#undef FALSE


#include "../tpm/tpm_structures.h"
#include "../tpm/tpm_data.h"
#include "../tpm/tpm_marshalling.h"
#include "printfs.h"
#include "crypto.h"

void run_first_time() {
    struct timeval start;
    struct timeval end;
    unsigned char InOutBuf[1020]; // Size bigger than 1020 will cause a segmentation fault.
    memset(InOutBuf, 0, sizeof(InOutBuf));
    printf("Now run bin file for the first time...\n");
    stuff_inoutbuf_firsttime(InOutBuf, 1020);
    gettimeofday(&start, NULL);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    gettimeofday(&end, NULL);
    double diff = (double)(end.tv_usec - start.tv_usec) / 1000000 + (double)(end.tv_sec - start.tv_sec);
    printf("Running succeed... Time %lf s\n", diff);
    //printf_buf("InoutBuf", InOutBuf, sizeof(InOutBuf));
}
/* This function can't be run alone.
void run_TPM_Startup() {
    unsigned char InOutBuf[1020];
    memset(InOutBuf, 0, sizeof(InOutBuf));
    printf("Now run TPM_Startup...\n");
    printf_TPM_REQUEST(InOutBuf);
    stuff_inoutbuf_startup(InOutBuf, sizeof(InOutBuf));
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf("Running succeed...\n");
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_Startup);
}
*/
void run_TPM_OIAP() {
    unsigned char InOutBuf[1020];
    memset(InOutBuf, 0, sizeof(InOutBuf));
    printf("Now run TPM_OIAP...\n");
    stuff_inoutbuf_oiap(InOutBuf, sizeof(InOutBuf));
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf("Running succeed...\n");
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OIAP);
}


void run_TPM_TakeOwnership() {
    unsigned char InOutBuf[1020];
    memset(InOutBuf, 0, sizeof(InOutBuf));
    printf("Now run TPM_TakeOwnership...\n") ;
    stuff_inoutbuf_oiap(InOutBuf, sizeof(InOutBuf));
    printf("Step 1. Open a OIAP Session...\n");
    printf_TPM_REQUEST(InOutBuf);
    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    gettimeofday(&end, NULL);
    double diff = (double)(end.tv_usec - start.tv_usec) / 1000000 + (double)(end.tv_sec - start.tv_sec);
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OIAP);
    printf("Running succeed... Time %lf s\n", diff);
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    BYTE *ptr = InOutBuf + (4+2+4+4); //pass out_size, tag, size, res
    UINT32 length = 24; // authHandle, nonceEven
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &length, &authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr, &length, &nonceEven);
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_ownership(InOutBuf, sizeof(InOutBuf), authHandle, &nonceEven);
    printf("Step 2. Take Ownership...\n");
    printf_TPM_REQUEST(InOutBuf);
    gettimeofday(&start, NULL);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    gettimeofday(&end, NULL);
    diff = (double)(end.tv_usec - start.tv_usec) / 1000000 + (double)(end.tv_sec - start.tv_sec);
    //printf_buf("InoutBuf", InOutBuf, sizeof(InOutBuf));
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_TakeOwnership);
    printf("Running succeed...Time %lf s\n", diff);
}

void run_unbind_data() {
    unsigned char InOutBuf[1020];
    BYTE *ptr_in;
    UINT32 length_in;
    BYTE *ptr_out;
    UINT32 length_out;
    memset(InOutBuf, 0, sizeof(InOutBuf));
    printf("Now let's bind and unbind some data...\n");
    printf("Step1. Open a OSAP session...\n");
    stuff_inoutbuf_osap(InOutBuf, sizeof(InOutBuf));
    /* get nonceOddOSAP from InOutBuf */
    TPM_NONCE nonceOddOSAP;
    ptr_in = InOutBuf + (4+2+4+4+2+4);
    length_in = 20;
    tpm_unmarshal_TPM_NONCE(&ptr_in, &length_in, &nonceOddOSAP);
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    /* get nonceEvenOSAP, nonceEven, authHandle */
    TPM_NONCE nonceEvenOSAP;
    TPM_NONCE nonceEven;
    TPM_AUTHHANDLE authHandle;
    ptr_out = InOutBuf + (4+2+4+4);
    length_out = 4+20+20;
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr_out, &length_out, &authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr_out, &length_out, &nonceEven);
    tpm_unmarshal_TPM_NONCE(&ptr_out, &length_out, &nonceEvenOSAP);
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OSAP);

    printf("Step2. Create a binding key...\n");
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_createcrapkey(InOutBuf, sizeof(InOutBuf), &nonceOddOSAP, &nonceEvenOSAP, &nonceEven, authHandle);
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf_buf("InOutBuf is :\n", InOutBuf, sizeof(InOutBuf));
    TPM_KEY wrappedKey;
    unsigned char buffer[1024];
    memcpy(buffer, InOutBuf, sizeof(InOutBuf));
    ptr_out = buffer + (4+2+4+4);
    length_out = 1024; //because we don't know the size of the wrappedKey;
    tpm_unmarshal_TPM_KEY(&ptr_out, &length_out, &wrappedKey);
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_CreateWrapKey);

    printf("Step3. Open another OIAP session...\n");
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_oiap(InOutBuf, sizeof(InOutBuf));
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OIAP);
    ptr_out = InOutBuf + (4+2+4+4); //pass out_size, tag, size, res
    length_out = 24; // authHandle, nonceEven
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr_out, &length_out, &authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr_out, &length_out, &nonceEven);
    printf("Step4. Load the key we just created...\n");
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_loadkey(InOutBuf, sizeof(InOutBuf), &wrappedKey, authHandle, &nonceEven);
    //printf_buf("InOutBuf is:", InOutBuf, sizeof(InOutBuf));
    //printf_buf("Wrapped key is:", &wrappedKey, sizeof_TPM_KEY((wrappedKey)));
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_LoadKey);
    TPM_KEY_HANDLE keyHandle;
    ptr_out = InOutBuf + (4+2+4+4);
    length_out = 4;
    tpm_unmarshal_TPM_KEY_HANDLE(&ptr_out, &length_out, &keyHandle);
    printf("Step4.5. Bind some data...\n");
    RSA_PUBLIC_KEY pubkey;
    if (wrappedKey.pubKey.keyLength != sizeof(RSA_PUBLIC_KEY)) {
        printf("Public key length doesn't match.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(&pubkey, wrappedKey.pubKey.key, sizeof(RSA_PUBLIC_KEY));
    BYTE data[] = {0x01, 0x01, 0x00, 0x00, 0x02, /*DATA*/ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    BYTE encData[256];
    UINT32 encDataSize = 256;
    encrypt_with_pubkey(&pubkey, data, sizeof(data), encData, &encDataSize );
    printf("Step5. Open another OIAP session...\n");
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_oiap(InOutBuf, sizeof(InOutBuf));
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OIAP);
    ptr_out = InOutBuf + (4+2+4+4); //pass out_size, tag, size, res
    length_out = 24; // authHandle, nonceEven
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr_out, &length_out, &authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr_out, &length_out, &nonceEven);
    printf("Step6. Unbind the data...\n");
    memset(InOutBuf, 0, sizeof(InOutBuf));
    stuff_inoutbuf_unbind(InOutBuf, sizeof(InOutBuf), authHandle, &nonceEven, keyHandle, encData, encDataSize);
    printf_TPM_REQUEST(InOutBuf);
    run_bin_file(InOutBuf, sizeof(InOutBuf));
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_UnBind);
}

void run() {
    //run_first_time();
    //run_TPM_Startup(); //WARNING! Should never run this alone, it should be proceed with TPM_Init();
    //run_TPM_OIAP(); //WARNING! May run out of session if not procceed with run_first_time().
    //run_TPM_TakeOwnership();
    run_unbind_data();
}

int in_argv(int argc, char **argv, char *flags) {
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], flags) == 0) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    login_rockey();
    if (in_argv(argc, argv, "-d")) {
        download_bin();
    }
    run();
    if (in_argv(argc, argv, "-f")) {
        printf_PERMANENT_FLAGS();
        printf_STANY_FLAGS();
        printf_STCLEAR_FLAGS();
        printf_PERMANENT_DATA();
        printf_STANY_DATA();
        printf_STCLEAR_DATA();
    }
}
