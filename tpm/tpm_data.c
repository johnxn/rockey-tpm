#include "tpm_data.h"
#include "tpm_structures.h"
#include "ftrx.h"

TPM_PERMANENT_FLAGS permanentFlags;
TPM_STCLEAR_FLAGS stclearFlags;
TPM_STANY_FLAGS stanyFlags;


extern unsigned char *pInOutBuf;
extern unsigned char *originInOutBuf;

void debug(BYTE *buf, UINT32 size) {
    char tail[4];
    int add;
    tail[0] = 0xee;
    tail[1] = 0x00;
    tail[2] = 0x00;
    tail[3] = 0xee;
    memcpy(pInOutBuf, buf, size);
    pInOutBuf += size;
    memcpy(pInOutBuf, tail, sizeof(tail));
    pInOutBuf += sizeof(tail);
    add = (pInOutBuf - originInOutBuf) % 16;
    if (add != 0) {
        pInOutBuf +=  (16 - add);
    }
}

void debug_stany_flags() {
    debug((BYTE *)&stanyFlags.tag, sizeof(TPM_STRUCTURE_TAG)); // 2 bytes
    debug((BYTE *)&stanyFlags.postInitialise, sizeof(BYTE)); // 1 byte
    debug((BYTE *)&stanyFlags.localityModifier, sizeof(TPM_MODIFIER_INDICATOR)); //4 bytes
    debug((BYTE *)&stanyFlags.transportExclusive, sizeof(BYTE)); // 1 byte
    debug((BYTE *)&stanyFlags.TOSPresent, sizeof(BYTE)); // 1 byte
}


static void init_pcr_attr(TPM_PCR_ATTRIBUTES *pcrAttrib, BOOL reset, BYTE rl, BYTE el) {
    pcrAttrib->pcrReset = reset;
    pcrAttrib->pcrResetLocal = rl;
    pcrAttrib->pcrExtendLocal = el;
}

static void init_nv_storage(void) {
    TPM_NV_DATA_SENSITIVE nv;

    /* set nvData to 0xff */
    write_TPM_PERMANENT_DATA_nvData_Stuff(0xff);

    memset(&nv, 0, sizeof(TPM_NV_DATA_SENSITIVE));
    nv.tag = TPM_TAG_NV_DATA_SENSITIVE;
    nv.pubInfo.tag = TPM_TAG_NV_DATA_PUBLIC;
    nv.pubInfo.nvIndex = TPM_NV_INDEX_DIR;
    nv.pubInfo.pcrInfoRead.localityAtRelease = 0x1f;
    nv.pubInfo.pcrInfoWrite.localityAtRelease = 0x1f;
    nv.pubInfo.permission.tag = TPM_TAG_NV_ATTRIBUTES;
    nv.pubInfo.permission.attributes = TPM_NV_PER_OWNERWRITE | TPM_NV_PER_WRITEALL;
    nv.pubInfo.dataSize = 20;
    nv.dataIndex = 0;
    nv.valid = TRUE;

    write_TPM_PERMANENT_DATA_nvDataSize(20);
    write_TPM_PERMANENT_DATA_nvStorage(0, &nv);
}

static void init_timeouts(void) {
    UINT32 tis_timeouts[TPM_NUM_TIS_TIMEOUTS];
    UINT32 cmd_durations[TPM_NUM_CMD_DURATIONS];
    tis_timeouts[0] = 750;
    tis_timeouts[1] = 2000;
    tis_timeouts[2] = 750;
    tis_timeouts[3] = 750;

    cmd_durations[0] = 1;
    cmd_durations[1] = 10;
    cmd_durations[2] = 1000;
    write_TPM_PERMANENT_DATA_tis_timeouts(tis_timeouts);
    write_TPM_PERMANENT_DATA_cmd_durations(cmd_durations);
}

int restore_flags(void) {
    if (read_TPM_PERMANENT_FLAGS(&permanentFlags) != 0 ||
        read_TPM_STCLEAR_FLAGS(&stclearFlags) != 0 ||
        read_TPM_STANY_FLAGS(&stanyFlags) != 0) return -1;
    return 0;
}

int save_flags(void) {
    if (write_TPM_PERMANENT_FLAGS(&permanentFlags) != 0 ||
        write_TPM_STCLEAR_FLAGS(&stclearFlags) != 0 ||
        write_TPM_STANY_FLAGS(&stanyFlags) != 0) return -1;
    return 0;
}

void set_permanent_flags(void) {
    permanentFlags.tag = TPM_TAG_PERMANENT_FLAGS;
    permanentFlags.disable = FALSE;
    permanentFlags.deactivated = FALSE;
    permanentFlags.ownership = FALSE;
    permanentFlags.readPubek = TRUE;
    permanentFlags.allowMaintenance = TRUE;
    permanentFlags.enableRevokeEK = TRUE;
    permanentFlags.readSRKPub = TRUE;
    permanentFlags.nvLocked = TRUE;
    permanentFlags.dataSaved = FALSE;
}

void tpm_init_data(void) {
    int i;
    BYTE rngState[16];
    TPM_DAA_TPM_SEED tpmDAASeed;
    TPM_NONCE ekReset;
    RSA_PRIVATE_KEY prikey;
    TPM_PCR_ATTRIBUTES pcrAttrib[TPM_NUM_PCR];
    TPM_VERSION version;
    version.major = 0x01;
    version.minor = 0x02;
    version.revMajor = 0x00;
    version.revMinor = 0x01;



    /* set permannet data tag */
    write_TPM_PERMANENT_DATA_tag(TPM_TAG_PERMANENT_DATA);

    /* set TPM version */
    write_TPM_PERMANENT_DATA_version(&version);

    /* seed PRNG */
    get_random(rngState, sizeof(rngState));
    write_TPM_PERMANENT_DATA_rngState(rngState);

    /* setup PCR attributes */
    for (i = 0; i < TPM_NUM_PCR && i < 16; i++) {
      init_pcr_attr(pcrAttrib+i, FALSE, 0x00, 0x1f);
    }
    if (TPM_NUM_PCR >= 24) {
      init_pcr_attr(pcrAttrib+16, TRUE, 0x1f, 0x1f);
      init_pcr_attr(pcrAttrib+17, TRUE, 0x10, 0x1c);
      init_pcr_attr(pcrAttrib+18, TRUE, 0x10, 0x1c);
      init_pcr_attr(pcrAttrib+19, TRUE, 0x10, 0x0c);
      init_pcr_attr(pcrAttrib+20, TRUE, 0x14, 0x0e);
      init_pcr_attr(pcrAttrib+21, TRUE, 0x04, 0x04);
      init_pcr_attr(pcrAttrib+22, TRUE, 0x04, 0x04);
      init_pcr_attr(pcrAttrib+23, TRUE, 0x1f, 0x1f);
    }
    for (i = 24; i < TPM_NUM_PCR; i++) {
      init_pcr_attr(pcrAttrib+i, TRUE, 0x00, 0x00);
    }
    write_TPM_PERMANENT_DATA_pcrAttrib(pcrAttrib);
    /* set endoresement key */
    write_TPM_PERMANENT_DATA_ekFileid(FILEID_EK);
    rsa_genkey(FILEID_EK, &prikey);
    /* we only need the public part of the prikey */
    write_file(FILE_DATA, FILEID_EK_PUB, 0, sizeof(RSA_PUBLIC_KEY), (BYTE *)&prikey);

    /* set DAA seed */
    get_random(tpmDAASeed.nonce, sizeof(TPM_NONCE));
    write_TPM_PERMANENT_DATA_tpmDAASeed(&tpmDAASeed);

    /* set ekReset */
    memset(ekReset.nonce, 0, sizeof(TPM_NONCE));
    memcpy(ekReset.nonce, "\xde\xad\xbe\xef", 4);
    write_TPM_PERMANENT_DATA_ekReset(&ekReset);

    /* set fileid of public and private portion of keys */
    for (i = 0; i < TPM_MAX_KEYS; i++)  {
        write_TPM_PERMANENT_DATA_keys_zero(i);
        write_TPM_PERMANENT_DATA_keys_keyFileid(i, FILEID_RSA_OFFSET + i);
        write_TPM_PERMANENT_DATA_keys_pubkeyFileid(i, FILEID_RSA_PUB_OFFSET + i);
    }


    /* initialize predefined non-volatile storage */
    init_nv_storage();
    /* set the timeout and duration values */
    init_timeouts();
}

void delete_tpmdata_files(void) {
    int i;
    delete_file(FILE_DATA, FILEID_TPM_PERMANENT_FLAGS);
    delete_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART1);
    delete_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART2);
    delete_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART3);
    delete_file(FILE_DATA, FILEID_TPM_STCLEAR_FLAGS);
    delete_file(FILE_DATA, FILEID_TPM_STCLEAR_DATA);
    delete_file(FILE_DATA, FILEID_TPM_STANY_FLAGS);
    delete_file(FILE_DATA, FILEID_TPM_STANY_DATA);
    delete_file(FILE_PRIKEY_RSA, FILEID_EK);
    delete_file(FILE_DATA, FILEID_EK_PUB);
    delete_file(FILE_PRIKEY_RSA, FILEID_SRK);
    delete_file(FILE_DATA, FILEID_SRK_PUB);
    for (i = 0; i < TPM_MAX_KEYS; i++) {
        delete_file(FILE_PRIKEY_RSA, FILEID_RSA_OFFSET + i);
        delete_file(FILE_DATA, FILEID_RSA_PUB_OFFSET + i);
    }
}

void create_tpmdata_files(void) {
    int i;
    DATA_FILE_ATTR dfa;
    PRIKEY_FILE_ATTR pfa;
    dfa.m_Lic.m_Read_Priv = 2;
    dfa.m_Lic.m_WritePriv = 2;
    /* delete all files */
    delete_tpmdata_files();
    /* create TPM_PERMANENT_FLAGS file */
    dfa.m_Size = sizeof(TPM_PERMANENT_FLAGS);
    create_file(FILE_DATA, FILEID_TPM_PERMANENT_FLAGS, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    /* create TPM_PERMANENT_DATA file */
    dfa.m_Size = 4096; /* Max DATA_FILE we can create. */
    create_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART1, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    create_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART2, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    dfa.m_Size = sizeof(TPM_PERMANENT_DATA) - 4096*2;
    create_file(FILE_DATA, FILEID_TPM_PERMANENT_DATA_PART3, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    /* create TPM_STCLEAR_FLAGS file */
    dfa.m_Size = sizeof(TPM_STCLEAR_FLAGS);
    create_file(FILE_DATA, FILEID_TPM_STCLEAR_FLAGS, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    /* create TPM_STCLEAR_DATA file */
    dfa.m_Size = sizeof(TPM_STCLEAR_DATA);
    create_file(FILE_DATA, FILEID_TPM_STCLEAR_DATA, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    /* create TPM_STANY_FLAGS file */
    dfa.m_Size = sizeof(TPM_STANY_FLAGS);
    create_file(FILE_DATA, FILEID_TPM_STANY_FLAGS, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    /* create TPM_STANY_DATA file */
    dfa.m_Size = sizeof(TPM_STANY_DATA);
    create_file(FILE_DATA, FILEID_TPM_STANY_DATA, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));

    pfa.m_Type = FILE_PRIKEY_RSA;
    pfa.m_Size = 2048;
    pfa.m_Lic.m_Count = 0xFFFFFFFF;
    pfa.m_Lic.m_Priv = 2;
    pfa.m_Lic.m_IsDecOnRAM = 0;
    pfa.m_Lic.m_IsReset = 0;
    pfa.m_Lic.m_Reserve = 0;
    /* create EK, SRK and other RSA private key files. */
    create_file(FILE_PRIKEY_RSA, FILEID_EK, (BYTE*)&pfa, sizeof(PRIKEY_FILE_ATTR));
    create_file(FILE_PRIKEY_RSA, FILEID_SRK, (BYTE*)&pfa, sizeof(PRIKEY_FILE_ATTR));
    for (i = 0; i < TPM_MAX_KEYS; i++ ) {
        create_file(FILE_PRIKEY_RSA, FILEID_RSA_OFFSET+i, (BYTE *)&pfa, sizeof(PRIKEY_FILE_ATTR));
    }
    create_file(FILE_PRIKEY_RSA, FILEID_RSA_TEMP, (BYTE*)&pfa, sizeof(PRIKEY_FILE_ATTR));

    /* create EK, SRK and other RSA pbulic key files. */
    dfa.m_Size = sizeof(RSA_PUBLIC_KEY);
    create_file(FILE_DATA, FILEID_EK_PUB, (BYTE*)&dfa, sizeof(DATA_FILE_ATTR));
    create_file(FILE_DATA, FILEID_SRK_PUB, (BYTE *)&dfa, sizeof(DATA_FILE_ATTR));
    for (i = 0; i < TPM_MAX_KEYS; i++) {
        create_file(FILE_DATA, FILEID_RSA_PUB_OFFSET+i, (BYTE *)&dfa, sizeof(DATA_FILE_ATTR));
    }
}

int write_TPM_PERMANENT_FLAGS(TPM_PERMANENT_FLAGS *flags) {
    if (write_file(FILE_DATA,FILEID_TPM_PERMANENT_FLAGS, 0, \
        sizeof(TPM_PERMANENT_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}
int read_TPM_PERMANENT_FLAGS(TPM_PERMANENT_FLAGS *flags) {
    if (read_file(FILEID_TPM_PERMANENT_FLAGS, 0, \
        sizeof(TPM_PERMANENT_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}
int write_TPM_STCLEAR_FLAGS(TPM_STCLEAR_FLAGS *flags) {
    if (write_file(FILE_DATA,FILEID_TPM_STCLEAR_FLAGS, 0, \
        sizeof(TPM_STCLEAR_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}
int read_TPM_STCLEAR_FLAGS(TPM_STCLEAR_FLAGS *flags) {
    if (read_file(FILEID_TPM_STCLEAR_FLAGS, 0, \
        sizeof(TPM_STCLEAR_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}
int write_TPM_STANY_FLAGS(TPM_STANY_FLAGS *flags) {
    if (write_file(FILE_DATA,FILEID_TPM_STANY_FLAGS, 0, \
        sizeof(TPM_STANY_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}
int read_TPM_STANY_FLAGS(TPM_STANY_FLAGS *flags) {
    if (read_file(FILEID_TPM_STANY_FLAGS, 0, \
        sizeof(TPM_STANY_FLAGS), (BYTE*)flags) != ERR_SUCCESS) return -1;
    return 0;
}

/* TPM_PERMANENT_DATA read and write functions */
int write_TPM_PERMANENT_DATA(UINT16 offset, BYTE *buf, UINT32 size) {
    WORD errcode;
    if (offset + size < 4096) {
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART1, offset, size, buf);
    }
    else if (offset < 4096 && offset + size > 4096) {
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART1, offset, 4096-offset, buf);
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART2, 0, size+offset-4096, buf+(4096-offset));
    }
    else if (offset >=4096 && offset + size < 4096*2) {
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART2, offset-4096, size, buf);
    }
    else if (offset < 4096*2 && offset + size > 4096*2) {
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART2, offset-4096, 4096*2-offset, buf);
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART3, 0, size+offset-4096*2, buf+(4096*2 -offset));
    }
    else {
        errcode = write_file(FILE_DATA,FILEID_TPM_PERMANENT_DATA_PART3, offset-4096*2, size, buf);
    }
    if (errcode != ERR_SUCCESS) return -1;
    return 0;
}

int read_TPM_PERMANENT_DATA(UINT16 offset, BYTE *buf, UINT32 size) {
    WORD errcode;
    if (offset + size < 4096) {
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART1, offset, size, buf);
    }
    else if (offset < 4096 && offset + size > 4096) {
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART1, offset, 4096-offset, buf);
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART2, 0, size+offset-4096, buf+(4096-offset));
    }
    else if (offset >=4096 && offset + size < 4096*2) {
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART2, offset-4096, size, buf);
    }
    else if (offset < 4096*2 && offset + size > 4096*2) {
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART2, offset-4096, 4096*2-offset, buf);
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART3, 0, size+offset-4096*2, buf+(4096*2-offset));
    }
    else {
        errcode = read_file(FILEID_TPM_PERMANENT_DATA_PART3, offset-4096*2, size, buf);
    }
    if (errcode != ERR_SUCCESS) return -1;
    return 0;

}

int write_TPM_PERMANENT_DATA_tag(TPM_STRUCTURE_TAG tag) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TAG, (BYTE*)&tag, sizeof(TPM_STRUCTURE_TAG));
}

TPM_STRUCTURE_TAG read_TPM_PERMANENT_DATA_tag() {
    TPM_STRUCTURE_TAG tag;
    read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TAG, (BYTE *)&tag, sizeof(TPM_STRUCTURE_TAG));
    return tag;
}

int write_TPM_PERMANENT_DATA_version(TPM_VERSION *version) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_VERSION, (BYTE *)version, sizeof(TPM_VERSION));
}
int read_TPM_PERMANENT_DATA_version(TPM_VERSION *version) {
    return read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_VERSION, (BYTE *)version, sizeof(TPM_VERSION));
}

int write_TPM_PERMANENT_DATA_tpmProof(TPM_NONCE *tpmProof) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TPMPROOF, (BYTE *)tpmProof, sizeof(TPM_NONCE));
}

int read_TPM_PERMANENT_DATA_tpmProof(TPM_NONCE *tpmProof) {
    return read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TPMPROOF, (BYTE *)tpmProof, sizeof(TPM_NONCE));
}

int write_TPM_PERMANENT_DATA_daaProof(TPM_NONCE *daaProof) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_DAAPROOF, (BYTE *)daaProof, sizeof(TPM_NONCE));
}

BOOL read_TPM_PERMANENT_DATA_counters_valid(UINT16 index) {
    BOOL valid;
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, counters[index]) + offsetof(TPM_COUNTER_VALUE, valid);
    read_TPM_PERMANENT_DATA(offset, &valid, sizeof(BOOL));
    return valid;
}

int read_TPM_PERMANENT_DATA_counters_usageAuth(UINT16 index, TPM_SECRET *usageAuth) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, counters[index]) + offsetof(TPM_COUNTER_VALUE, usageAuth);
    return read_TPM_PERMANENT_DATA(offset, (BYTE *)usageAuth, sizeof(TPM_SECRET));
}

int write_TPM_PERMANENT_DATA_ownerAuth(TPM_SECRET *ownerAuth) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_OWNREAUTH, (BYTE *)ownerAuth, sizeof(TPM_SECRET));
}

int read_TPM_PERMANENT_DATA_ownerAuth(TPM_SECRET *ownerAuth) {
    return read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_OWNREAUTH, (BYTE *)ownerAuth, sizeof(TPM_SECRET));
}

int write_TPM_PERMANENT_DATA_srk(TPM_KEY_DATA *srk) {
    UINT16 offset = PERM_DATA_OFFSET_SRK;
    return write_TPM_PERMANENT_DATA(offset, (BYTE *)srk, sizeof(TPM_KEY_DATA));
}

int read_TPM_PERMANENT_DATA_srk(TPM_KEY_DATA *srk) {
    UINT16 offset = PERM_DATA_OFFSET_SRK;
    return read_TPM_PERMANENT_DATA(offset, (BYTE *)srk, sizeof(TPM_KEY_DATA));
}

int read_TPM_PERMANENT_DATA_srk_usageAuth(TPM_SECRET usageAuth) {
    UINT16 offset = PERM_DATA_OFFSET_SRK + offsetof(TPM_KEY_DATA, usageAuth);
    return read_TPM_PERMANENT_DATA(offset, (BYTE *)usageAuth, sizeof(TPM_SECRET));
}

BYTE read_TPM_PERMANENT_DATA_srk_payload() {
    BYTE payload;
    read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_SRK, &payload, sizeof(BYTE));
    return payload;
}


int write_TPM_PERMANENT_DATA_rngState(BYTE *rngState) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_RNGSTATE, rngState, 16);
}
int read_TPM_PERMANENT_DATA_rngState(BYTE *rngState) {
    return read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_RNGSTATE, rngState, 16);
}

int write_TPM_PERMANENT_DATA_keys_zero(UINT16 index) {
    TPM_KEY_DATA key;
    UINT16 offset;
    memset(&key, 0, sizeof(TPM_KEY_DATA));
    offset = offsetof(TPM_PERMANENT_DATA, keys[index]);
    return write_TPM_PERMANENT_DATA(offset, (BYTE *)&key, sizeof(TPM_KEY_DATA));
}

int write_TPM_PERMANENT_DATA_keys(UINT16 index, TPM_KEY_DATA *key) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]);
    return write_TPM_PERMANENT_DATA(offset, (BYTE *)key, sizeof(TPM_KEY_DATA));
}

int read_TPM_PERMANENT_DATA_keys(UINT16 index, TPM_KEY_DATA *key) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]);
    return read_TPM_PERMANENT_DATA(offset, (BYTE *)key, sizeof(TPM_KEY_DATA));
}

int write_TPM_PERMANENT_DATA_keys_payload(UINT16 index, BYTE payload) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, payload);
     return write_TPM_PERMANENT_DATA(offset, &payload, sizeof(BYTE));
}

BYTE read_TPM_PERMANENT_DATA_keys_payload(UINT16 index) {
    BYTE payload;
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, payload);
    read_TPM_PERMANENT_DATA(offset, &payload, sizeof(BYTE));
    return payload;
}

int write_TPM_PERMANENT_DATA_keys_keyFileid(UINT16 index, UINT16 keyFileid) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, keyFileid);
    return write_TPM_PERMANENT_DATA(offset, (BYTE *)&keyFileid, sizeof(UINT16));
}

UINT16 read_TPM_PERMANENT_DATA_keys_keyFileid(UINT16 index) {
    UINT16 keyFileid;
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, keyFileid);
    read_TPM_PERMANENT_DATA(offset, (BYTE *)&keyFileid, sizeof(UINT16));
    return keyFileid;
}

int write_TPM_PERMANENT_DATA_keys_pubkeyFileid(UINT16 index, UINT16 pubkeyFileid) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, pubkeyFileid);
    return write_TPM_PERMANENT_DATA(offset, (BYTE *)&pubkeyFileid, sizeof(UINT16));

}
UINT16 read_TPM_PERMANENT_DATA_keys_pubkeyFileid(UINT16 index) {
    UINT16 pubkeyFileid;
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, pubkeyFileid);
    read_TPM_PERMANENT_DATA(offset, (BYTE *)&pubkeyFileid, sizeof(UINT16));
    return pubkeyFileid;

}

TPM_KEY_CONTROL read_TPM_PERMANENT_DATA_keys_keyControl(UINT16 index) {
    TPM_KEY_CONTROL keyControl;
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, keyControl);
    read_TPM_PERMANENT_DATA(offset, (BYTE *)&keyControl, sizeof(TPM_KEY_CONTROL));
    return keyControl;
}

int read_TPM_PERMANENT_DATA_keys_usageAuth(UINT16 index, TPM_SECRET *usageAuth) {
    UINT16 offset = offsetof(TPM_PERMANENT_DATA, keys[index]) + offsetof(TPM_KEY_DATA, usageAuth);
    return read_TPM_PERMANENT_DATA(offset, (BYTE *)usageAuth , sizeof(TPM_SECRET));
}

int write_TPM_PERMANENT_DATA_pcrAttrib(TPM_PCR_ATTRIBUTES *pcrAttribs) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_PCRATTRIB, (BYTE *)pcrAttribs, sizeof(TPM_PCR_ATTRIBUTES) * TPM_NUM_PCR);
}

int read_TPM_PERMANENT_DATA_pcrAttrib(TPM_PCR_ATTRIBUTES *pcrAttribs) {
    return read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_PCRATTRIB, (BYTE *)pcrAttribs, sizeof(TPM_PCR_ATTRIBUTES) * TPM_NUM_PCR);
}

int write_TPM_PERMANENT_DATA_ekFileid(UINT16 ekFileid) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_EKFILEID, (BYTE*)&ekFileid, sizeof(UINT16));
}

UINT16 read_TPM_PERMANENT_DATA_ekFileid() {
    UINT16 ekFileid;
    read_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_EKFILEID, (BYTE *)&ekFileid, sizeof(UINT16));
    return ekFileid;
}

int write_TPM_PERMANENT_DATA_contextKey(BYTE *contextKey) {
    UINT16 offset;
    offset = offsetof(TPM_PERMANENT_DATA, contextKey);
    return write_TPM_PERMANENT_DATA(offset, contextKey, TPM_SYM_KEY_SIZE);
}

int write_TPM_PERMANENT_DATA_delegateKey(BYTE *delegateKey) {
    UINT16 offset;
    offset = offsetof(TPM_PERMANENT_DATA, delegateKey);
    return write_TPM_PERMANENT_DATA(offset, delegateKey, TPM_SYM_KEY_SIZE);
}

int write_TPM_PERMANENT_DATA_daaKey(BYTE *daaKey) {
    UINT16 offset;
    offset = offsetof(TPM_PERMANENT_DATA, daaKey);
    return write_TPM_PERMANENT_DATA(offset, daaKey, TPM_SYM_KEY_SIZE);
}

int write_TPM_PERMANENT_DATA_tpmDAASeed(TPM_DAA_TPM_SEED *tpmDAASeed) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TPMDAASEED, (BYTE*)tpmDAASeed, sizeof(TPM_DAA_TPM_SEED));
}

int write_TPM_PERMANENT_DATA_ekReset(TPM_NONCE *ekReset) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_EKRESET, (BYTE*)ekReset, sizeof(TPM_NONCE));
}

int write_TPM_PERMANENT_DATA_nvDataSize(UINT32 nvDataSize) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_NVDATASIZE, (BYTE*)&nvDataSize, sizeof(UINT32));
}

int write_TPM_PERMANENT_DATA_nvData(BYTE *nvData) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_NVDATA, nvData, sizeof(BYTE)*TPM_MAX_NV_SIZE);
}

int write_TPM_PERMANENT_DATA_nvData_Stuff(BYTE stuff) {
    BYTE buf[512];
    WORD errcode;
    
    /* set buf to stuff */
    int i;
    for (i = 0; i < 512; i++) {
        buf[i] = stuff;
    }
    for (i = 0; i < TPM_MAX_NV_SIZE / 512; i++) {
        errcode = write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_NVDATA+i*512, buf, 512);
    }
    if (errcode != ERR_SUCCESS) return -1;
    return 0;
}

int write_TPM_PERMANENT_DATA_nvStorage(UINT16 index, TPM_NV_DATA_SENSITIVE *nvStorage) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_NVSTORAGE+index*sizeof(TPM_NV_DATA_SENSITIVE), \
            (BYTE*)nvStorage, sizeof(TPM_NV_DATA_SENSITIVE));
}

int write_TPM_PERMANENT_DATA_tis_timeouts(UINT32 *tis_timeouts) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_TISTIMEOUS, \
            (BYTE*)tis_timeouts, sizeof(UINT32)*TPM_NUM_TIS_TIMEOUTS);
}

int write_TPM_PERMANENT_DATA_cmd_durations(UINT32 *cmd_durations) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_CMDURATIONS, \
            (BYTE*)cmd_durations, sizeof(UINT32)*TPM_NUM_CMD_DURATIONS);
}

int write_TPM_PERMANENT_DATA_pcrValue(UINT16 index, TPM_PCRVALUE *pcrValue) {
    return write_TPM_PERMANENT_DATA(PERM_DATA_OFFSET_PCRVALUE + \
            index*sizeof(TPM_PCRVALUE), (BYTE *)pcrValue, sizeof(TPM_PCRVALUE));
}

/* TPM_STCLEAR_DATA read and write functions */
int write_TPM_STCLEAR_DATA(UINT16 offset, BYTE *buf, UINT32 size) {
    WORD errcode;
    errcode = write_file(FILE_DATA,FILEID_TPM_STCLEAR_DATA, offset, size, buf);
    if (errcode != ERR_SUCCESS) return -1;
    return 0;
}

int write_TPM_STCLEAR_DATA_tag(TPM_STRUCTURE_TAG tag) {
    return write_TPM_STCLEAR_DATA(CLEAR_DATA_OFFSET_TAG, (BYTE *)&tag, sizeof(TPM_STRUCTURE_TAG));
}

int write_TPM_STCLEAR_DATA_contextNonceKey(TPM_NONCE *contextNonceKey) {
    return write_TPM_STCLEAR_DATA(CLEAR_DATA_OFFSET_CONTEXTNONCEKEY, \
            (BYTE *)contextNonceKey, sizeof(contextNonceKey));
}

int write_TPM_STCLEAR_DATA_countID(TPM_COUNT_ID countId) {
    return write_TPM_STCLEAR_DATA(CLEAR_DATA_OFFSET_COUNTID, \
            (BYTE *)&countId, sizeof(TPM_COUNT_ID));
}

int set_TPM_STCLEAR_DATA_zero(void) {
    BYTE buf[sizeof(TPM_STCLEAR_DATA)];
    memset(buf, 0, sizeof(buf));
    return write_TPM_STCLEAR_DATA(0, buf, sizeof(TPM_STCLEAR_DATA));
}

/* TPM_STANY_DATA read and write functions */
int read_TPM_STANY_DATA(UINT16 offset, BYTE *buf, UINT32 size) {
    WORD errcode;
    errcode = read_file(FILEID_TPM_STANY_DATA, offset, size, buf);
    if (errcode != ERR_SUCCESS) return -1;
    return 0;
}

int write_TPM_STANY_DATA(UINT16 offset, BYTE *buf, UINT32 size) {
    WORD errcode;
    errcode = write_file(FILE_DATA,FILEID_TPM_STANY_DATA, offset, size, buf);
    if (errcode != ERR_SUCCESS) return -1;
    return 0;
}

int set_TPM_STANY_DATA_zero(void) {
    BYTE buf[512];
    int res;
    int offset = 0;
    memset(buf, 0, sizeof(buf));
    while (1) {
        if (offset + 512 < sizeof(TPM_STANY_DATA)) {
            res = write_TPM_STANY_DATA(offset, buf, 512);
        }
        else {
            res =write_TPM_STANY_DATA(offset, buf, sizeof(TPM_STANY_DATA)-offset);
            break;
        }
        offset += 512;
    }
    return res;
}

int write_TPM_STANY_DATA_tag(TPM_STRUCTURE_TAG tag) {
    return write_TPM_STANY_DATA(ANY_DATA_OFFSET_TAG, (BYTE *)&tag, sizeof(TPM_STRUCTURE_TAG));
}

int write_TPM_STANY_DATA_contextNonceSession(TPM_NONCE *contextNonceSession) {
    return write_TPM_STANY_DATA(ANY_DATA_OFFSET_CONTEXTNONCESESSION, \
            (BYTE *)contextNonceSession, sizeof(TPM_NONCE));
}

int write_TPM_STANY_DATA_sessionsDAA(UINT16 index, TPM_DAA_SESSION_DATA *session) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessionsDAA[index]);
    return write_TPM_STANY_DATA(offset, (BYTE *)session, sizeof(TPM_DAA_SESSION_DATA));
}

int write_TPM_STANY_DATA_sessionsDAA_zero(UINT16 index) {
    TPM_DAA_SESSION_DATA session;
    memset(&session, 0, sizeof(TPM_DAA_SESSION_DATA));
    return write_TPM_STANY_DATA_sessionsDAA(index, &session);
}

BYTE read_TPM_STANY_DATA_sessionsDAA_type(UINT16 index) {
    BYTE type;
    UINT16 offset = offsetof(TPM_STANY_DATA, sessionsDAA[index]) + offsetof(TPM_DAA_SESSION_DATA, type);
    read_TPM_STANY_DATA(offset, &type, sizeof(BYTE));
    return type;
}

int write_TPM_STANY_DATA_sessions(UINT16 index, TPM_SESSION_DATA *session) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]);
    return write_TPM_STANY_DATA(offset, (BYTE *)session, sizeof(TPM_SESSION_DATA));
}

int read_TPM_STANY_DATA_sessions(UINT16 index, TPM_SESSION_DATA *session) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]);
    return read_TPM_STANY_DATA(offset, (BYTE *)session, sizeof(TPM_SESSION_DATA));
}

BYTE read_TPM_STANY_DATA_sessions_type(UINT16 index) {
    BYTE type;
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, type);
    read_TPM_STANY_DATA(offset, &type, sizeof(BYTE));
    return type;
}

int write_TPM_STANY_DATA_sessions_type(UINT16 index, BYTE type) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, type);
    return write_TPM_STANY_DATA(offset, (BYTE *)&type, sizeof(BYTE));
}

int write_TPM_STANY_DATA_sessions_entityType(UINT16 index, TPM_ENTITY_TYPE type) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, entityType);
    return write_TPM_STANY_DATA(offset, (BYTE *)&type, sizeof(TPM_ENTITY_TYPE));
    
}

int write_TPM_STANY_DATA_sessions_handle(UINT16 index, TPM_HANDLE handle) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, handle);
    return write_TPM_STANY_DATA(offset, (BYTE *)&handle, sizeof(TPM_HANDLE));
}

TPM_HANDLE read_TPM_STANY_DATA_sessions_handle(UINT16 index) {
    TPM_HANDLE handle;
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, handle);
    read_TPM_STANY_DATA(offset, (BYTE *)&handle, sizeof(TPM_HANDLE));
    return handle;

}

int write_TPM_STANY_DATA_sessions_nonceEven(UINT16 index, TPM_NONCE *nonceEven) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, nonceEven);
    return write_TPM_STANY_DATA(offset, (BYTE *)nonceEven, sizeof(TPM_NONCE));
}

int write_TPM_STANY_DATA_sessions_sharedSecret(UINT16 index, TPM_SECRET *sharedSecret) {
    UINT16 offset = offsetof(TPM_STANY_DATA, sessions[index]) + offsetof(TPM_SESSION_DATA, sharedSecret);
    return write_TPM_STANY_DATA(offset , (BYTE *)sharedSecret, sizeof(TPM_SECRET));
}

int write_TPM_STANY_DATA_sessions_zero(UINT16 index) {
    TPM_SESSION_DATA session;
    memset(&session, 0, sizeof(TPM_SESSION_DATA));
    return write_TPM_STANY_DATA_sessions(index, &session);
}

int write_TPM_STANY_DATA_contextList(UINT16 index, UINT32 value) {
    UINT16 offset = offsetof(TPM_STANY_DATA, contextList[index]);
    return write_TPM_STANY_DATA(offset, (BYTE *)&value, sizeof(UINT32));
}

UINT32 read_TPM_STANY_DATA_contextList(UINT16 index) {
    UINT32 value;
    UINT16 offset = offsetof(TPM_STANY_DATA, contextList[index]);
    read_TPM_STANY_DATA(offset, (BYTE *)&value, sizeof(UINT32));
    return value;
}

int write_TPM_STANY_DATA_currentDAA(TPM_DAAHANDLE handle) {
    return write_TPM_STANY_DATA(ANY_DATA_OFFSET_CURRENTDAA, (BYTE *)&handle, sizeof(TPM_DAAHANDLE));
}

TPM_DAAHANDLE read_TPM_STANY_DATA_currentDAA(void) {
    TPM_DAAHANDLE currentDAA;
    read_TPM_STANY_DATA(ANY_DATA_OFFSET_CURRENTDAA, (BYTE *)&currentDAA, sizeof(TPM_DAAHANDLE));
    return currentDAA;
}

TPM_TRANSHANDLE read_TPM_STANY_DATA_transExclusive(void) {
    TPM_TRANSHANDLE transExclusive;
    read_TPM_STANY_DATA(ANY_DATA_OFFSET_TRANSEXCLUSIVE, (BYTE *)&transExclusive, sizeof(TPM_TRANSHANDLE));
    return transExclusive;
}
