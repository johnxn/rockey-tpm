#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Dongle_CORE.h"
#include "Dongle_API.h"

#undef TRUE
#undef FALSE

#include "../tpm/tpm_structures.h"
#include "../tpm/tpm_data.h"
#include "../tpm/tpm_marshalling.h"
#include "../crypto/hmac.h"
#include "../crypto/sha1.h"

DONGLE_HANDLE rockeyHandle;

void login_rockey();
void download_bin();
void run_bin_file(unsigned char *InOutBuf, int size);

int generate_rsa_key(UINT16 fileid, RSA_PUBLIC_KEY *pubkey, RSA_PRIVATE_KEY *prikey);

int read_rsa_pubkey(UINT32 fileid, RSA_PUBLIC_KEY *pubkey);

int encrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, UINT32 inputSize, BYTE *output, UINT32 *outputSize);

int decrypt_with_prikey(UINT16 prikey_fileid, BYTE *input, UINT32 inputSize, BYTE *output, UINT32 *outputSize);

int get_random(BYTE *buf, UINT32 size);

void compute_in_parm_digest(BYTE *digest, TPM_COMMAND_CODE ordinal, BYTE *ptr, UINT32 length);


void compute_shared_secret(TPM_SECRET secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET sharedSecret);
void compute_shared_secret2(TPM_SECRET *secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET *sharedSecret);
void compute_auth_data(TPM_AUTH *auth);
void tpm_encrypt_auth_secret(TPM_SECRET plainAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_ENCAUTH encAuth);

#endif /* _CRYPTO_H */
