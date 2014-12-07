#ifndef _STUFF_INOUTBUF_H
#define _STUFF_INOUTBUF_H
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
#include "../crypto/sha1.h"
#include "../crypto/hmac.h"


void stuff_inoutbuf_firsttime(unsigned char *InOutBuf, int size);
void stuff_inoutbuf_startup(unsigned char *InOutBuf, int size);
void stuff_inoutbuf_oiap(unsigned char *InOutBuf, int size);
void stuff_inoutbuf_ownership(unsigned char *InOutBuf, int buf_size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven);
void stuff_inoutbuf_osap(unsigned char *InOutBuf, int size); // session for SRK
void stuff_inoutbuf_osap_new(unsigned char *InOutBuf, int size, TPM_ENTITY_TYPE entityType, UINT32 entityValue);
void stuff_inoutbuf_createcrapkey(unsigned char *InOutBuf, int size, TPM_NONCE *nonceOddOSAP, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceEven, TPM_AUTHHANDLE authHandle); // create a key wrapped by SRK
void stuff_inoutbuf_loadkey(unsigned char *InOutBuf, int size, TPM_KEY *inKey, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven); // load the key just created
void stuff_inoutbuf_getpubkey(unsigned char *InOutBuf, int size); // get the public key
void stuff_inoutbuf_unbind(unsigned char *InOutBuf, int size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven, TPM_KEY_HANDLE keyHandle, BYTE *data, UINT32 dataSize); // unbind a TPM_BOUND_DATA
void stuff_inoutbuf_makeidentity(unsigned char *InOutBuf, int size, TPM_AUTHHANDLE srkAuthHandle, TPM_NONCE *srkNonceEven, TPM_NONCE *nonceOddOSAP, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceEven, TPM_AUTHHANDLE authHandle); // OSAP session for owner, OIAP session for srk.
void stuff_flush_specific(unsigned char *InOutBuf, int size, TPM_HANDLE handle, TPM_RESOURCE_TYPE resourceType);
void stuff_inoutbuf_certify(unsigned char *InOutBuf, int size, TPM_HANDLE certAuthHandle, TPM_NONCE *certNonceEven, TPM_HANDLE keyAuthHandle, TPM_NONCE *keyNonceEven, TPM_KEY_HANDLE certHandle, TPM_KEY_HANDLE keyHandle, TPM_SECRET certSecret, TPM_SECRET keySecret);
void stuff_inoutbuf_extend(unsigned char *InOutBuf, int size);
void stuff_inoutbuf_read(unsigned  char *InOutBuf, int size);
void stuff_inoutbuf_quote(unsigned char *InOutBuf, int size, TPM_HANDLE authHandle, TPM_NONCE *nonceEven);


#endif /* _STUFF_INOUTBUF_H */
