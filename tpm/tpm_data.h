#ifndef _TPM_DATA_H_
#define _TPM_DATA_H_

#include "tpm_structures.h"
//#include "ftrx.h" /*for userspaece debug */
#include "string.h"
#include "stdlib.h"

extern TPM_PERMANENT_FLAGS permanentFlags;
extern TPM_STANY_FLAGS stanyFlags;
extern TPM_STCLEAR_FLAGS stclearFlags;

void debug(BYTE *buf, UINT32 size);
void debug_stany_flags(void);

#define READ 0x01
#define WRITE 0x02

#define FILEID_TPM_PERMANENT_FLAGS        0x1000
#define FILEID_TPM_PERMANENT_DATA_PART1   0x1001
#define FILEID_TPM_PERMANENT_DATA_PART2   0x1002
#define FILEID_TPM_PERMANENT_DATA_PART3   0x1003
#define FILEID_TPM_STCLEAR_FLAGS          0x1004
#define FILEID_TPM_STCLEAR_DATA           0x1005
#define FILEID_TPM_STANY_FLAGS            0x1006
#define FILEID_TPM_STANY_DATA             0x1007

#define FILEID_EK    0x2000
#define FILEID_SRK   0x2001


#define FILEID_RSA_OFFSET 0x2002
/* FILED_RSA_0 0x2002
 * FILED_RSA_1 0x2003
 * FILED_RSA_2 0x2004
 * FILED_RSA_3 0x2005
 * FILED_RSA_4 0x2006
 */
#define FILEID_RSA_TEMP 0x2007

#define FILEID_EK_PUB  0x3000
#define FILEID_SRK_PUB 0x3001

#define FILEID_RSA_PUB_OFFSET 0x3002
/* FILEID_RSA_0_PUB 0x3002
 * FILEID_RSA_1_PUB 0x3003
 * FILEID_RSA_2_PUB 0x3004
 * FILEID_RSA_3_PUB 0x3005
 * FILEID_RSA_4_PUB 0x3006
 */

#define PERM_DATA_OFFSET_TAG                  offsetof(TPM_PERMANENT_DATA, tag)
#define PERM_DATA_OFFSET_VERSION              offsetof(TPM_PERMANENT_DATA, version) 
#define PERM_DATA_OFFSET_TPMPROOF             offsetof(TPM_PERMANENT_DATA, tpmProof) 
#define PERM_DATA_OFFSET_EKRESET              offsetof(TPM_PERMANENT_DATA, ekReset) 
#define PERM_DATA_OFFSET_OWNREAUTH            offsetof(TPM_PERMANENT_DATA, ownerAuth) 
#define PERM_DATA_OFFSET_OPERATORAUTH         offsetof(TPM_PERMANENT_DATA, operatorAuth) 
#define PERM_DATA_OFFSET_TPMDAASEED           offsetof(TPM_PERMANENT_DATA, tpmDAASeed) 
#define PERM_DATA_OFFSET_DAAPROOF             offsetof(TPM_PERMANENT_DATA, daaProof) 
#define PERM_DATA_OFFSET_MANUMAINTPUB         offsetof(TPM_PERMANENT_DATA, manuMaintPub) 
#define PERM_DATA_OFFSET_EKFILEID             offsetof(TPM_PERMANENT_DATA, ekFileid) 
#define PERM_DATA_OFFSET_SRK                  offsetof(TPM_PERMANENT_DATA, srk) 
#define PERM_DATA_OFFSET_CONTEXTKEY           offsetof(TPM_PERMANENT_DATA, contextKey) 
#define PERM_DATA_OFFSET_DELEGATKEY           offsetof(TPM_PERMANENT_DATA, delegateKey) 
#define PERM_DATA_OFFSET_DAAKEY               offsetof(TPM_PERMANENT_DATA, daaKey) 
#define PERM_DATA_OFFSET_AUDITMONCOUNTER      offsetof(TPM_PERMANENT_DATA, auditMonotonicCounter) 
#define PERM_DATA_OFFSET_COUNTERS             offsetof(TPM_PERMANENT_DATA, counters) 
#define PERM_DATA_OFFSET_PCRATTRIB            offsetof(TPM_PERMANENT_DATA, pcrAttrib) 
#define PERM_DATA_OFFSET_PCRVALUE             offsetof(TPM_PERMANENT_DATA, pcrValue) 
#define PERM_DATA_OFFSET_ORDINALAUDITSATUS    offsetof(TPM_PERMANENT_DATA, ordinalAuditStatus) 
#define PERM_DATA_OFFSET_RNGSTATE             offsetof(TPM_PERMANENT_DATA, rngState) 
#define PERM_DATA_OFFSET_FAMILYTABLE          offsetof(TPM_PERMANENT_DATA, familyTable) 
#define PERM_DATA_OFFSET_DELEGATETABLE        offsetof(TPM_PERMANENT_DATA, delegateTable) 
#define PERM_DATA_OFFSET_LASTFAMILYID         offsetof(TPM_PERMANENT_DATA, lastFamilyID) 
#define PERM_DATA_OFFSET_RESTRICTDELEGATE     offsetof(TPM_PERMANENT_DATA, restrictDelegate) 
#define PERM_DATA_OFFSET_MAXNVBUFSIZE         offsetof(TPM_PERMANENT_DATA, maxNVBufSize) 
#define PERM_DATA_OFFSET_NOOWNERNVWRITE       offsetof(TPM_PERMANENT_DATA, noOwnerNVWrite) 
#define PERM_DATA_OFFSET_NVDATASIZE           offsetof(TPM_PERMANENT_DATA, nvDataSize) 
#define PERM_DATA_OFFSET_NVDATA               offsetof(TPM_PERMANENT_DATA, nvData) 
#define PERM_DATA_OFFSET_NVSTORAGE            offsetof(TPM_PERMANENT_DATA, nvStorage) 
#define PERM_DATA_OFFSET_KEYS                 offsetof(TPM_PERMANENT_DATA, keys) 
#define PERM_DATA_OFFSET_TISTIMEOUS           offsetof(TPM_PERMANENT_DATA, tis_timeouts) 
#define PERM_DATA_OFFSET_CMDURATIONS          offsetof(TPM_PERMANENT_DATA, cmd_durations) 

#define CLEAR_DATA_OFFSET_TAG                 offsetof(TPM_STCLEAR_DATA, tag)
#define CLEAR_DATA_OFFSET_CONTEXTNONCEKEY     offsetof(TPM_STCLEAR_DATA, contextNonceKey)
#define CLEAR_DATA_OFFSET_COUNTID             offsetof(TPM_STCLEAR_DATA, countID)
#define CLEAR_DATA_OFFSET_OWNERREFERENCE      offsetof(TPM_STCLEAR_DATA, ownerReference)
#define CLEAR_DATA_OFFSET_DISABLERESETLOCK    offsetof(TPM_STCLEAR_DATA, disableResetLock)
#define CLEAR_DATA_OFFSET_DEFERREDPHYPRESENCE offsetof(TPM_STCLEAR_DATA, deferredPhysicalPresence)

#define ANY_DATA_OFFSET_TAG                   offsetof(TPM_STANY_DATA, tag)
#define ANY_DATA_OFFSET_CONTEXTNONCESESSION   offsetof(TPM_STANY_DATA, contextNonceSession)
#define ANY_DATA_OFFSET_AUDITDIGEST           offsetof(TPM_STANY_DATA, auditDigest)
#define ANY_DATA_OFFSET_AUDITSESSION          offsetof(TPM_STANY_DATA, auditSession)
#define ANY_DATA_OFFSET_CURRENTTICKS          offsetof(TPM_STANY_DATA, currentTicks)
#define ANY_DATA_OFFSET_CONTEXTCOUNT          offsetof(TPM_STANY_DATA, contextCount)
#define ANY_DATA_OFFSET_CONTEXTLIST           offsetof(TPM_STANY_DATA, contextList)
#define ANY_DATA_OFFSET_SESSIONS              offsetof(TPM_STANY_DATA, sessions)
#define ANY_DATA_OFFSET_SESSIONSDAA           offsetof(TPM_STANY_DATA, sessionsDAA)
#define ANY_DATA_OFFSET_CURRENTDAA            offsetof(TPM_STANY_DATA, currentDAA)
#define ANY_DATA_OFFSET_TRANSEXCLUSIVE        offsetof(TPM_STANY_DATA, transExclusive)

int restore_flags(void);
int save_flags(void);
void set_permanent_flags(void);
void tpm_init_data(void);
void create_tpmdata_files(void);

int write_TPM_PERMANENT_FLAGS(TPM_PERMANENT_FLAGS *flags);
int read_TPM_PERMANENT_FLAGS(TPM_PERMANENT_FLAGS *flags);
int write_TPM_STCLEAR_FLAGS(TPM_STCLEAR_FLAGS *flags);
int read_TPM_STCLEAR_FLAGS(TPM_STCLEAR_FLAGS *flags);
int write_TPM_STANY_FLAGS(TPM_STANY_FLAGS *flags);
int read_TPM_STANY_FLAGS(TPM_STANY_FLAGS *flags);

int set_TPM_STANY_DATA_zero(void);
int set_TPM_STCLEAR_DATA_zero(void);

/* tpmdata.permannent.data apis */
int write_TPM_PERMANENT_DATA_tag(TPM_STRUCTURE_TAG tag); 
TPM_STRUCTURE_TAG read_TPM_PERMANENT_DATA_tag(void);
int write_TPM_PERMANENT_DATA_version(TPM_VERSION *version);
int read_TPM_PERMANENT_DATA_version(TPM_VERSION *version);
int write_TPM_PERMANENT_DATA_tpmProof(TPM_NONCE *tpmProof);
int read_TPM_PERMANENT_DATA_tpmProof(TPM_NONCE *tpmProof);
int write_TPM_PERMANENT_DATA_ekReset(TPM_NONCE *ekReset);
int read_TPM_PERMANENT_DATA_ekReset(TPM_NONCE *ekReset);
int write_TPM_PERMANENT_DATA_ownerAuth(TPM_SECRET *ownerAuth);
int read_TPM_PERMANENT_DATA_ownerAuth(TPM_SECRET *ownerAuth);
int write_TPM_PERMANENT_DATA_operatorAuth(TPM_SECRET *operatorAuth);
int read_TPM_PERMANENT_DATA_operatorAuth(TPM_SECRET *operatorAuth);
int write_TPM_PERMANENT_DATA_tpmDAASeed(TPM_DAA_TPM_SEED *tpmDAASeed);
int read_TPM_PERMANENT_DATA_tpmDAASeed(TPM_DAA_TPM_SEED *tpmDAASeed);
int write_TPM_PERMANENT_DATA_daaProof(TPM_NONCE *daaProof);
int read_TPM_PERMANENT_DATA_daaProof(TPM_NONCE *daaProof);
int write_TPM_PERMANENT_DATA_manuMaintPub(TPM_PUBKEY_DATA *manuMaintPub);
int read_TPM_PERMANENT_DATA_manuMaintPub(TPM_PUBKEY_DATA *manuMaintPub);
int write_TPM_PERMANENT_DATA_ekFileid(UINT16 fileid);
UINT16 read_TPM_PERMANENT_DATA_ekFileid(void);
int write_TPM_PERMANENT_DATA_srk(TPM_KEY_DATA *srk);
int read_TPM_PERMANENT_DATA_srk(TPM_KEY_DATA *srk);
int write_TPM_PERMANENT_DATA_srk_payload(BYTE payload);
BYTE read_TPM_PERMANENT_DATA_srk_payload(void);
int read_TPM_PERMANENT_DATA_srk_usageAuth(TPM_SECRET usageAuth);


int write_TPM_PERMANENT_DATA_contextKey(BYTE *contextKey);
int read_TPM_PERMANENT_DATA_contextKey(BYTE *contextKey);
int write_TPM_PERMANENT_DATA_delegateKey(BYTE *delegateKey);
int read_TPM_PERMANENT_DATA_delegateKey(BYTE *delegateKey);
int write_TPM_PERMANENT_DATA_daaKey(BYTE *daaKey);
int read_TPM_PERMANENT_DATA_daaKey(BYTE *daaKey);
int write_TPM_PERMANENT_DATA_auditMonotonicCounter(TPM_ACTUAL_COUNT auditMonotonicCounter);
TPM_ACTUAL_COUNT read_TPM_PERMANENT_DATA_auditMonotonicCounter(void);
int write_TPM_PERMANENT_DATA_counters(UINT16 index, TPM_COUNTER_VALUE *counters);
int read_TPM_PERMANENT_DATA_counters(UINT16 index, TPM_COUNTER_VALUE *counters);
int read_TPM_PERMANENT_DATA_counters_usageAuth(UINT16 index, TPM_SECRET *usageAuth);
int write_TPM_PERMANENT_DATA_counters_valid(UINT16 index, BOOL valid);
BOOL read_TPM_PERMANENT_DATA_counters_valid(UINT16 index);
int write_TPM_PERMANENT_DATA_pcrAttrib(TPM_PCR_ATTRIBUTES *pcrAttrib);
int read_TPM_PERMANENT_DATA_pcrAttrib(TPM_PCR_ATTRIBUTES *pcrAttrib);
int write_TPM_PERMANENT_DATA_pcrValue(UINT16 index, TPM_PCRVALUE *pcrValue);
int read_TPM_PERMANENT_DATA_pcrValue(UINT16 index, TPM_PCRVALUE *pcrValue);
int write_TPM_PERMANENT_DATA_ordinalAuditStatus(BYTE *ordinalAuditStatus);
int read_TPM_PERMANENT_DATA_ordinalAuditStatus(BYTE *ordinalAuditStatus);
int write_TPM_PERMANENT_DATA_rngState(BYTE *rngState);
int read_TPM_PERMANENT_DATA_rngState(BYTE *rngState);
int write_TPM_PERMANENT_DATA_familyTable(TPM_FAMILY_TABLE *familyTable);
int read_TPM_PERMANENT_DATA_familyTable(TPM_FAMILY_TABLE *familyTable);
int write_TPM_PERMANENT_DATA_delegateTable(TPM_DELEGATE_TABLE *delegateTable);
int read_TPM_PERMANENT_DATA_delegateTable(TPM_DELEGATE_TABLE *delegateTable);
int write_TPM_PERMANENT_DATA_lastFamilyID(UINT32 lastFamilyID);
UINT32 read_TPM_PERMANENT_DATA_lastFamilyID(void);
int write_TPM_PERMANENT_DATA_restrictDelegate(TPM_CMK_DELEGATE restrictDelegate);
TPM_CMK_DELEGATE read_TPM_PERMANENT_DATA_restrictDelegate(void);
int write_TPM_PERMANENT_DATA_maxNVBufSize(UINT32 maxNVBufSize);
UINT32 read_TPM_PERMANENT_DATA_maxNVBufSize(void);
int write_TPM_PERMANENT_DATA_noOwnerNVWrite(UINT32 noOwnerNVWrite);
UINT32 read_TPM_PERMANENT_DATA_noOwnerNVWrite(void);
int write_TPM_PERMANENT_DATA_nvDataSize(UINT32 nvDataSize);
UINT32 read_TPM_PERMANENT_DATA_nvDataSize(void);
int write_TPM_PERMANENT_DATA_nvData(BYTE *nvData);
int read_TPM_PERMANENT_DATA_nvData(BYTE *nvData);
int write_TPM_PERMANENT_DATA_nvData_Stuff(BYTE stuff);
int write_TPM_PERMANENT_DATA_nvStorage(UINT16 index, TPM_NV_DATA_SENSITIVE *nvStorage);
int read_TPM_PERMANENT_DATA_nvStorage(TPM_NV_DATA_SENSITIVE *nvStorage);
int write_TPM_PERMANENT_DATA_keys(UINT16 index, TPM_KEY_DATA *key);
int read_TPM_PERMANENT_DATA_keys(UINT16 index, TPM_KEY_DATA *key);
int write_TPM_PERMANENT_DATA_keys_keyFileid(UINT16 index, UINT16 keyFileid);
UINT16 read_TPM_PERMANENT_DATA_keys_keyFileid(UINT16 index);
int write_TPM_PERMANENT_DATA_keys_pubkeyFileid(UINT16 index, UINT16 pubkeyFileid);
UINT16 read_TPM_PERMANENT_DATA_keys_pubkeyFileid(UINT16 index);
int write_TPM_PERMANENT_DATA_keys_payload(UINT16 index, BYTE payload);
BYTE read_TPM_PERMANENT_DATA_keys_payload(UINT16 index);
int read_TPM_PERMANENT_DATA_keys_usageAuth(UINT16 index, TPM_SECRET *secret);
int write_TPM_PERMANENT_DATA_keys_keyControl(UINT16 index, TPM_KEY_CONTROL keyControl);
TPM_KEY_CONTROL read_TPM_PERMANENT_DATA_keys_keyControl(UINT16 index);
int write_TPM_PERMANENT_DATA_keys_zero(UINT16 index);

int write_TPM_PERMANENT_DATA_tis_timeouts(UINT32 *tis_timeouts);
int read_TPM_PERMANENT_DATA_tis_timeouts(UINT32 *tis_timeouts);
int write_TPM_PERMANENT_DATA_cmd_durations(UINT32 *cmd_durations);
int read_TPM_PERMANENT_DATA_cmd_durations(UINT32 *cmd_durations);

/* tpmdata.stclear.data apis */
int write_TPM_STCLEAR_DATA_tag(TPM_STRUCTURE_TAG tag);
TPM_STRUCTURE_TAG read_TPM_STCLEAR_DATA_tag(void);
int write_TPM_STCLEAR_DATA_contextNonceKey(TPM_NONCE *contextNonceKey);
int read_TPM_STCLEAR_DATA_contextNonceKey(TPM_NONCE *contextNonceKey);
int write_TPM_STCLEAR_DATA_countID(TPM_COUNT_ID countId);
TPM_COUNT_ID read_TPM_STCLEAR_DATA_countID(void);
int write_TPM_STCLEAR_DATA_ownerReference(UINT32 ownerReference);
UINT32 read_TPM_STCLEAR_DATA_ownerReference(void);
int write_TPM_STCLEAR_DATA_disableResetLock(BOOL disableResetLock);
BOOL read_TPM_STCLEAR_DATA_disableResetLock(void);
int write_TPM_STCLEAR_DATA_deferredPhysicalPresence(UINT32 deferredPhysicalPresence);
UINT32 read_TPM_STCLEAR_DATA_deferredPhysicalPresence(void);

/* tpmdata.stany.data apis */
int write_TPM_STANY_DATA_tag(TPM_STRUCTURE_TAG tag);
TPM_STRUCTURE_TAG read_TPM_STANY_DATA_tag(void);
int write_TPM_STANY_DATA_contextNonceSession(TPM_NONCE *contextNonceSession);
int read_TPM_STANY_DATA_contextNonceSession(TPM_NONCE *contextNonceSession);
int write_TPM_STANY_DATA_auditDigest(TPM_DIGEST *auditDigest);
int read_TPM_STANY_DATA_auditDigest(TPM_DIGEST *auditDigest);
int write_TPM_STANY_DATA_auditSession(BOOL auditSession);
BOOL read_TPM_STANY_DATA_auditSession(void);
int write_TPM_STANY_DATA_currentTicks(TPM_CURRENT_TICKS *currentTicks);
int read_TPM_STANY_DATA_currentTicks(TPM_CURRENT_TICKS *currentTicks);
int write_TPM_STANY_DATA_contextCount(UINT32 contextCount);
UINT32 read_TPM_STANY_DATA_contextCount(void);
int write_TPM_STANY_DATA_contextList(UINT16 index, UINT32 value);
UINT32 read_TPM_STANY_DATA_contextList(UINT16 index);
int write_TPM_STANY_DATA_sessions(UINT16 index, TPM_SESSION_DATA *session);
int read_TPM_STANY_DATA_sessions(UINT16 index, TPM_SESSION_DATA *session);
int write_TPM_STANY_DATA_sessions_entityType(UINT16 index, TPM_ENTITY_TYPE entityType);
int write_TPM_STANY_DATA_sessions_nonceEven(UINT16 index, TPM_NONCE *nonceEven);
int write_TPM_STANY_DATA_sessions_handle(UINT16 index, TPM_HANDLE handle);
TPM_HANDLE read_TPM_STANY_DATA_sessions_handle(UINT16 index);
int write_TPM_STANY_DATA_sessions_zero(UINT16 index);
int write_TPM_STANY_DATA_sessions_sharedSecret(UINT16 index, TPM_SECRET *secret);
int write_TPM_STANY_DATA_sessions_type(UINT16 index, BYTE type);
BYTE read_TPM_STANY_DATA_sessions_type(UINT16 index);
int write_TPM_STANY_DATA_sessionsDAA(UINT16 index, TPM_DAA_SESSION_DATA * sessionsDAA);
int read_TPM_STANY_DATA_sessionsDAA(UINT16 index, TPM_DAA_SESSION_DATA *sessiosnDAA);
int write_TPM_STANY_DATA_sessionsDAA_zero(UINT16 index);
int write_TPM_STANY_DATA_sessionsDAA_type(UINT16 index, BYTE type);
BYTE read_TPM_STANY_DATA_sessionsDAA_type(UINT16 index);
int write_TPM_STANY_DATA_currentDAA(TPM_DAAHANDLE currentDAA);
TPM_DAAHANDLE read_TPM_STANY_DATA_currentDAA(void);
int write_TPM_STANY_DATA_transExclusive(TPM_TRANSHANDLE *transExclusive);
TPM_TRANSHANDLE read_TPM_STANY_DATA_transExclusive(void);
#endif
