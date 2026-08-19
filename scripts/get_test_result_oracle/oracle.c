#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_types.h>

static unsigned char *nv_data[8];
static uint32_t nv_len[8];
static const char *nv_names[8];
static int nv_count;
static int store_fails;

static TPM_RESULT cb_init(void) { return TPM_SUCCESS; }

static int slot_for(const char *name, int create)
{
    for (int i = 0; i < nv_count; i++)
        if (!strcmp(nv_names[i], name))
            return i;
    if (!create)
        return -1;
    nv_names[nv_count] = strdup(name);
    return nv_count++;
}

static TPM_RESULT cb_load(unsigned char **data, uint32_t *length,
                          uint32_t tpm_number, const char *name)
{
    (void)tpm_number;
    int i = slot_for(name, 0);
    if (i < 0 || !nv_data[i])
        return TPM_RETRY;
    *data = malloc(nv_len[i]);
    memcpy(*data, nv_data[i], nv_len[i]);
    *length = nv_len[i];
    return TPM_SUCCESS;
}

static TPM_RESULT cb_store(const unsigned char *data, uint32_t length,
                           uint32_t tpm_number, const char *name)
{
    (void)tpm_number;
    if (store_fails)
        return TPM_FAIL;
    int i = slot_for(name, 1);
    free(nv_data[i]);
    nv_data[i] = malloc(length);
    memcpy(nv_data[i], data, length);
    nv_len[i] = length;
    return TPM_SUCCESS;
}

static TPM_RESULT cb_delete(uint32_t tpm_number, const char *name, TPM_BOOL must_exist)
{
    (void)tpm_number; (void)must_exist;
    int i = slot_for(name, 0);
    if (i >= 0) { free(nv_data[i]); nv_data[i] = NULL; nv_len[i] = 0; }
    return TPM_SUCCESS;
}

static void wipe_nvram(void)
{
    for (int i = 0; i < nv_count; i++) { free(nv_data[i]); nv_data[i] = NULL; nv_len[i] = 0; }
    nv_count = 0;
}

static void boot(void)
{
    TPMLIB_Terminate();
    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2)) exit(1);
    if (TPMLIB_MainInit()) exit(1);
}

static unsigned char last_resp[8192];
static uint32_t last_len;

static void run(const char *label, const unsigned char *cmd, uint32_t len)
{
    unsigned char *resp = NULL;
    uint32_t resp_len = 0, resp_bufsize = 0;
    TPM_RESULT res = TPMLIB_Process(&resp, &resp_len, &resp_bufsize,
                                    (unsigned char *)cmd, len);
    printf("%s: outer=%u resp=", label, res);
    for (uint32_t i = 0; i < resp_len; i++)
        printf("%02x", resp[i]);
    printf("\n");
    last_len = resp_len < sizeof(last_resp) ? resp_len : sizeof(last_resp);
    memcpy(last_resp, resp, last_len);
    free(resp);
}

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static const unsigned char SU_CLEAR[] = {0x80,0x01,0,0,0,0x0c,0,0,0x01,0x44,0,0};

static const unsigned char GTR[] = {0x80,0x01,0,0,0,0x0a,0,0,0x01,0x7c};

static const unsigned char CAP_CC_GTR[] = {0x80,0x01,0,0,0,0x16,0,0,0x01,0x7a,
                                           0,0,0,2, 0,0,0x01,0x7c, 0,0,0,1};

static const unsigned char CAP_CC_PAGE[] = {0x80,0x01,0,0,0,0x16,0,0,0x01,0x7a,
                                            0,0,0,2, 0,0,0x01,0x7b, 0,0,0,3};

static void gtr_variant(const char *label, uint32_t declared,
                        uint32_t received, uint16_t tag)
{
    unsigned char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = tag >> 8; cmd[1] = tag;
    put32(cmd + 2, declared);
    put32(cmd + 6, 0x0000017c);
    if (received > sizeof(cmd)) exit(4);
    run(label, cmd, received);
}

static void cap_variant(const char *label, uint32_t cap, uint32_t prop,
                        uint32_t count, uint32_t declared, uint32_t received,
                        uint16_t tag)
{
    unsigned char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = tag >> 8; cmd[1] = tag;
    put32(cmd + 2, declared);
    put32(cmd + 6, 0x0000017a);
    put32(cmd + 10, cap);
    put32(cmd + 14, prop);
    put32(cmd + 18, count);
    if (received > sizeof(cmd)) exit(4);
    run(label, cmd, received);
}

static void gtr_pw_session(const char *label)
{
    unsigned char cmd[32];
    uint32_t n = 0;
    cmd[n++] = 0x80; cmd[n++] = 0x02;
    n += 4;
    put32(cmd + n, 0x0000017c); n += 4;
    put32(cmd + n, 9); n += 4;
    put32(cmd + n, 0x40000009); n += 4;
    cmd[n++] = 0; cmd[n++] = 0;
    cmd[n++] = 0;
    cmd[n++] = 0; cmd[n++] = 0;
    put32(cmd + 2, n);
    run(label, cmd, n);
}

static void define_index(const char *label, uint32_t index)
{
    unsigned char cmd[128];
    uint32_t n = 0;
    cmd[n++] = 0x80; cmd[n++] = 0x02;
    n += 4;
    put32(cmd + n, 0x0000012a); n += 4;
    put32(cmd + n, 0x40000001); n += 4;
    put32(cmd + n, 9); n += 4;
    put32(cmd + n, 0x40000009); n += 4;
    cmd[n++] = 0; cmd[n++] = 0;
    cmd[n++] = 0;
    cmd[n++] = 0; cmd[n++] = 0;
    cmd[n++] = 0; cmd[n++] = 0;
    cmd[n++] = 0; cmd[n++] = 0x0e;
    put32(cmd + n, index); n += 4;
    cmd[n++] = 0; cmd[n++] = 0x0b;
    put32(cmd + n, 0x00040004); n += 4;
    cmd[n++] = 0; cmd[n++] = 0;
    cmd[n++] = 0; cmd[n++] = 1;
    put32(cmd + 2, n);
    run(label, cmd, n);
}

static void print_state(const char *label)
{
    int i = slot_for("permall", 0);
    printf("PERMALL_%s=", label);
    if (i >= 0)
        for (uint32_t j = 0; j < nv_len[i]; j++) printf("%02x", nv_data[i][j]);
    printf("\n");

    unsigned char *blob = NULL;
    uint32_t blob_len = 0;
    TPM_RESULT res = TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &blob, &blob_len);
    printf("VOLATILE_%s=", label);
    if (res == TPM_SUCCESS)
        for (uint32_t j = 0; j < blob_len; j++) printf("%02x", blob[j]);
    printf("\n");
    free(blob);
}

static unsigned char *saved_perm, *saved_vol;
static uint32_t saved_perm_len, saved_vol_len;

static void save_state(void)
{
    free(saved_perm); free(saved_vol);
    saved_perm = saved_vol = NULL;
    int i = slot_for("permall", 0);
    if (i < 0 || !nv_data[i]) exit(2);
    saved_perm = malloc(nv_len[i]);
    memcpy(saved_perm, nv_data[i], nv_len[i]);
    saved_perm_len = nv_len[i];
    if (TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &saved_vol, &saved_vol_len)) exit(2);
    printf("PERMALL_BEFORE_SAVE=");
    for (uint32_t j = 0; j < saved_perm_len; j++) printf("%02x", saved_perm[j]);
    printf("\nVOLATILE_BEFORE_SAVE=");
    for (uint32_t j = 0; j < saved_vol_len; j++) printf("%02x", saved_vol[j]);
    printf("\n");
}

static void restore_state(const unsigned char *vol, uint32_t vol_len)
{
    TPMLIB_Terminate();
    TPM_RESULT r1 = TPMLIB_SetState(TPMLIB_STATE_PERMANENT, saved_perm, saved_perm_len);
    TPM_RESULT r2 = TPMLIB_SetState(TPMLIB_STATE_VOLATILE, vol, vol_len);
    TPM_RESULT r3 = TPMLIB_MainInit();
    printf("restore: set_perm=%u set_vol=%u main_init=%u\n", r1, r2, r3);
}

static unsigned char *patched_vol(const unsigned char *fail12,
                                  const unsigned char *replacement12,
                                  uint32_t *out_len)
{
    if (saved_vol_len < 32) exit(5);
    unsigned char *copy = malloc(saved_vol_len);
    memcpy(copy, saved_vol, saved_vol_len);
    uint32_t payload = saved_vol_len - 20;
    int patched = 0;
    for (uint32_t at = 0; at + 15 <= payload; at++) {
        if (copy[at] == 0x01 && copy[at + 1] == 0x00 && copy[at + 2] == 0x0c &&
            !memcmp(copy + at + 3, fail12, 12)) {
            memcpy(copy + at + 3, replacement12, 12);
            patched++;
        }
    }
    printf("patched_fail_blocks=%d\n", patched);
    if (patched != 1) exit(5);
    SHA1(copy, payload, copy + payload);
    *out_len = saved_vol_len;
    return copy;
}

int main(void)
{
    struct libtpms_callbacks cbs = {
        .sizeOfStruct = sizeof(struct libtpms_callbacks),
        .tpm_nvram_init = cb_init,
        .tpm_nvram_loaddata = cb_load,
        .tpm_nvram_storedata = cb_store,
        .tpm_nvram_deletename = cb_delete,
    };
    if (TPMLIB_RegisterCallbacks(&cbs)) return 1;

    wipe_nvram();
    boot();

    run("GTR_BEFORE_STARTUP", GTR, sizeof(GTR));
    run("STARTUP", SU_CLEAR, sizeof(SU_CLEAR));
    run("GTR_OK", GTR, sizeof(GTR));
    run("GTR_OK_REPEAT", GTR, sizeof(GTR));
    gtr_variant("GTR_TRAILING_DECLARED", 11, 11, 0x8001);
    gtr_variant("GTR_TRAILING_UNDECLARED", 10, 11, 0x8001);
    gtr_variant("GTR_DECLARED_SHORT", 9, 9, 0x8001);
    gtr_pw_session("GTR_SESSIONS_PW");
    gtr_variant("GTR_SESSIONS_NO_AUTHSIZE", 10, 10, 0x8002);
    {
        unsigned char cmd[14];
        cmd[0] = 0x80; cmd[1] = 0x02;
        put32(cmd + 2, 14);
        put32(cmd + 6, 0x0000017c);
        put32(cmd + 10, 0);
        run("GTR_SESSIONS_AUTHSIZE_ZERO", cmd, 14);
    }
    run("CAP_CC_GTR", CAP_CC_GTR, sizeof(CAP_CC_GTR));
    run("CAP_CC_PAGE", CAP_CC_PAGE, sizeof(CAP_CC_PAGE));

    print_state("BEFORE_FAILURE");
    store_fails = 1;
    define_index("NVFAIL_TRIGGER", 0x01000010);
    store_fails = 0;
    print_state("FAILURE_ENTRY");

    run("FM_GTR_OK", GTR, sizeof(GTR));
    if (last_len < 26) { printf("unexpected FM_GTR_OK length\n"); return 6; }
    unsigned char fail12[12];
    memcpy(fail12, last_resp + 12, 12);
    run("FM_GTR_REPEAT", GTR, sizeof(GTR));
    gtr_variant("FM_GTR_TRAILING_UNDECLARED", 10, 14, 0x8001);
    gtr_variant("FM_GTR_DECLARED_11", 11, 11, 0x8001);
    gtr_variant("FM_GTR_DECLARED_9", 9, 10, 0x8001);
    gtr_variant("FM_GTR_TRUNC9", 9, 9, 0x8001);
    gtr_variant("FM_GTR_SESSIONS", 10, 10, 0x8002);
    run("FM_STARTUP", SU_CLEAR, sizeof(SU_CLEAR));
    { unsigned char cmd[10] = {0x80,0x01,0,0,0,0x0a,0x20,0,0,0}; run("FM_UNKNOWN", cmd, 10); }
    { unsigned char cmd[12] = {0x80,0x01,0,0,0,0x0c,0,0,0x01,0x7b,0,8}; run("FM_GETRANDOM", cmd, 12); }

    cap_variant("FM_CAP_PT000_C1", 6, 0x000, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT104_C1", 6, 0x104, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT105_C1", 6, 0x105, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT106_C1", 6, 0x106, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT107_C1", 6, 0x107, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT108_C1", 6, 0x108, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT109_C1", 6, 0x109, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10A_C1", 6, 0x10a, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10B_C1", 6, 0x10b, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10C_C1", 6, 0x10c, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10D_C1", 6, 0x10d, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT200_C1", 6, 0x200, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PTMAX_C1", 6, 0xffffffff, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT000_C0", 6, 0x000, 0, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT105_C0", 6, 0x105, 0, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10C_C0", 6, 0x10c, 0, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT10D_C0", 6, 0x10d, 0, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT105_C2", 6, 0x105, 2, 22, 22, 0x8001);
    cap_variant("FM_CAP_PT105_CMAX", 6, 0x105, 0xffffffff, 22, 22, 0x8001);
    cap_variant("FM_CAP_ALGS", 0, 0x105, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_HANDLES", 1, 0x105, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_COMMANDS", 2, 0x105, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_CAPMAX", 0xffffffff, 0x105, 1, 22, 22, 0x8001);
    cap_variant("FM_CAP_DECLARED_21", 6, 0x105, 1, 21, 22, 0x8001);
    cap_variant("FM_CAP_DECLARED_23", 6, 0x105, 1, 23, 23, 0x8001);
    cap_variant("FM_CAP_TRAILING_UNDECLARED", 6, 0x105, 1, 22, 26, 0x8001);
    cap_variant("FM_CAP_TRUNC18", 6, 0x105, 1, 22, 18, 0x8001);
    cap_variant("FM_CAP_SESSIONS", 6, 0x105, 1, 22, 22, 0x8002);
    print_state("AFTER_QUERIES");

    save_state();
    restore_state(saved_vol, saved_vol_len);
    run("FM_GTR_AFTER_RESTORE", GTR, sizeof(GTR));
    cap_variant("FM_CAP_AFTER_RESTORE", 6, 0x105, 1, 22, 22, 0x8001);

    {
        unsigned char repl[12];
        memcpy(repl, fail12, 12);
        put32(repl + 8, 8);
        uint32_t plen = 0;
        unsigned char *pvol = patched_vol(fail12, repl, &plen);
        restore_state(pvol, plen);
        free(pvol);
        run("FM_GTR_NV_UNRECOVERABLE", GTR, sizeof(GTR));
        run("FM_GTR_NV_UNRECOVERABLE_REPEAT", GTR, sizeof(GTR));
        cap_variant("FM_CAP_NV_UNRECOVERABLE", 6, 0x105, 1, 22, 22, 0x8001);
    }

    TPMLIB_Terminate();
    return 0;
}
