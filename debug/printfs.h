#ifndef _PRINTFS_H
#define _PRINTFS_H

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

extern DONGLE_HANDLE rockeyHandle;


void printf_buf(char *head, void *buff, int size);
void printf_TPM_AUTH_REQ(BYTE **ptr, UINT32 *length);
void printf_TPM_AUTH_RES(BYTE **ptr, UINT32 *length);
void printf_TPM_REQUEST(BYTE *buf);
void printf_TPM_RESPONSE(BYTE const *buf, TPM_COMMAND_CODE ordinal);

void printf_PERMANENT_DATA();
void printf_PERMANENT_FLAGS();
void printf_STANY_DATA();
void printf_STANY_FLAGS();
void printf_STCLEAR_DATA();
void printf_STCLEAR_FLAGS();

void printf_sessions(TPM_SESSION_DATA *sessions);
void printf_TPM_SESSION_DATA(TPM_SESSION_DATA *session);
void printf_TPM_KEY_DATA(TPM_KEY_DATA *key);
void printf_TPM_KEY(TPM_KEY *wrappedKey);
void printf_TPM_CERIFTY_INFO(TPM_CERTIFY_INFO *certInfo);
void printf_TPM_PCR_SELECTION(TPM_PCR_SELECTION *pcrSelection);
void printf_TPM_PCR_COMPOSITE(TPM_PCR_COMPOSITE *pcrComposite);

#endif /* _PRINTFS_H */
