#include "crypto.h"

int main() {
    TPM_SECRET secret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TPM_SECRET sharedSecret;
    compute_shared_secret2(secret, NULL, NULL, sharedSecret);
    printf_buf("function", sharedSecret, sizeof(TPM_SECRET));

    tpm_hmac_ctx_t ctx;
    tpm_hmac_init(&ctx, secret, sizeof(secret));
    //tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
    //tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
    tpm_hmac_final(&ctx, sharedSecret);
    printf_buf("with out function", sharedSecret, sizeof(TPM_SECRET));
}
