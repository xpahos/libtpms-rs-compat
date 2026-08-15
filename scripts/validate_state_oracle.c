/*
 * Oracle harness for the vendored TPMLIB_ValidateState, covering permanent,
 * volatile, save-state and sequential masks as well as the permanent state
 * TPMLIB_SetState installs.
 *
 * Driven by scripts/generate_validate_state_oracle.py: one scenario per
 * process (the vendored library keeps its installed state in globals), each
 * printing "<scenario>\t0x<result>\t<callback events>".  Blobs are read from
 * the directory given on the command line, by the names the crate's fixture
 * dumpers write.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_types.h>

#define MAX_SLOTS 8
#define MAX_EVENTS 64

static unsigned char *nv_data[MAX_SLOTS];
static uint32_t nv_len[MAX_SLOTS];
static const char *nv_names[MAX_SLOTS];
static int nv_count;
static char events[MAX_EVENTS][64];
static int event_count;
static int store_enabled;

static void record(const char *name)
{
    if (event_count < MAX_EVENTS)
        snprintf(events[event_count++], sizeof(events[0]), "%s", name);
}

static int slot_for(const char *name, int create)
{
    for (int i = 0; i < nv_count; i++)
        if (!strcmp(nv_names[i], name))
            return i;
    if (!create || nv_count == MAX_SLOTS)
        return -1;
    nv_names[nv_count] = strdup(name);
    return nv_count++;
}

static void put_backend(const char *name, const unsigned char *data, uint32_t len)
{
    int i = slot_for(name, 1);
    free(nv_data[i]);
    nv_data[i] = malloc(len ? len : 1);
    memcpy(nv_data[i], data, len);
    nv_len[i] = len;
}

static void drop_backend(const char *name)
{
    int i = slot_for(name, 0);
    if (i < 0)
        return;
    free(nv_data[i]);
    nv_data[i] = NULL;
    nv_len[i] = 0;
}

static TPM_RESULT cb_init(void)
{
    record("init");
    return TPM_SUCCESS;
}

static TPM_RESULT cb_load(unsigned char **d, uint32_t *l, uint32_t n, const char *name)
{
    char event[64];
    (void)n;
    snprintf(event, sizeof(event), "load:%s", name);
    record(event);
    int i = slot_for(name, 0);
    if (i < 0 || !nv_data[i])
        return TPM_RETRY;
    *d = malloc(nv_len[i] ? nv_len[i] : 1);
    memcpy(*d, nv_data[i], nv_len[i]);
    *l = nv_len[i];
    return TPM_SUCCESS;
}

static TPM_RESULT cb_store(const unsigned char *d, uint32_t l, uint32_t n, const char *name)
{
    char event[64];
    (void)n;
    snprintf(event, sizeof(event), "store:%s", name);
    record(event);
    if (!store_enabled)
        return TPM_SUCCESS;
    put_backend(name, d, l);
    return TPM_SUCCESS;
}

static TPM_RESULT cb_delete(uint32_t n, const char *name, TPM_BOOL must_exist)
{
    (void)n;
    (void)must_exist;
    drop_backend(name);
    return TPM_SUCCESS;
}

static TPM_RESULT cb_locality(TPM_MODIFIER_INDICATOR *loc, uint32_t n)
{
    (void)n;
    *loc = 0;
    return TPM_SUCCESS;
}

static unsigned char *slurp_in(const char *dir, const char *name, uint32_t *len)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n)
        exit(2);
    fclose(f);
    *len = (uint32_t)n;
    return buf;
}

static void report(const char *scenario, TPM_RESULT res)
{
    printf("%s\t0x%x\t", scenario, res);
    for (int i = 0; i < event_count; i++)
        printf("%s%s", i ? "," : "", events[i]);
    printf("\n");
}

static const int VOLATILE_ONLY = TPMLIB_STATE_VOLATILE;

static unsigned char *object_blob(const char *kind, unsigned char *rsa, uint32_t rsa_len,
                                  unsigned char *ecc, uint32_t ecc_len, unsigned char *aes128,
                                  uint32_t aes128_len, unsigned char *aes192,
                                  uint32_t aes192_len, uint32_t *len)
{
    if (!strcmp(kind, "rsa")) {
        *len = rsa_len;
        return rsa;
    }
    if (!strcmp(kind, "ecc")) {
        *len = ecc_len;
        return ecc;
    }
    if (!strcmp(kind, "aes128")) {
        *len = aes128_len;
        return aes128;
    }
    if (!strcmp(kind, "aes192")) {
        *len = aes192_len;
        return aes192;
    }
    fprintf(stderr, "unknown object kind %s\n", kind);
    exit(2);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <scenario> <blob-directory>\n", argv[0]);
        return 2;
    }
    const char *scenario = argv[1];
    const char *blobs = argv[2];
    uint32_t permall_len = 0, volatile_len = 0, bad_tag_len = 0, seed_mismatch_len = 0;
    uint32_t rsa_len = 0, ecc_len = 0, aes128_len = 0, aes192_len = 0;
    unsigned char *permall = slurp_in(blobs, "permall.bin", &permall_len);
    unsigned char *volatilestate = slurp_in(blobs, "volatile-valid.bin", &volatile_len);
    unsigned char *bad_tag = slurp_in(blobs, "volatile-bad_tag.bin", &bad_tag_len);
    unsigned char *seed_mismatch =
        slurp_in(blobs, "volatile-seed_mismatch.bin", &seed_mismatch_len);
    unsigned char *rsa_object = slurp_in(blobs, "volatile-rsa_object.bin", &rsa_len);
    unsigned char *ecc_object = slurp_in(blobs, "volatile-ecc_object.bin", &ecc_len);
    unsigned char *aes128_object = slurp_in(blobs, "volatile-aes128_object.bin", &aes128_len);
    unsigned char *aes192_object = slurp_in(blobs, "volatile-aes192_object.bin", &aes192_len);

    struct libtpms_callbacks cbs = {
        .sizeOfStruct = sizeof(cbs),
        .tpm_nvram_init = cb_init,
        .tpm_nvram_loaddata = cb_load,
        .tpm_nvram_storedata = cb_store,
        .tpm_nvram_deletename = cb_delete,
        .tpm_io_init = NULL,
        .tpm_io_getlocality = cb_locality,
    };
    TPMLIB_RegisterCallbacks(&cbs);
    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2))
        return 1;

    TPM_RESULT res;
    uint32_t object_len = 0;

    if (!strcmp(scenario, "permanent_only")) {
        put_backend("permall", permall, permall_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_PERMANENT, 0);
    } else if (!strcmp(scenario, "save_state_only")) {
        put_backend("permall", permall, permall_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_SAVE_STATE, 0);
    } else if (!strcmp(scenario, "combined_permanent_volatile")) {
        put_backend("permall", permall, permall_len);
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_PERMANENT | TPMLIB_STATE_VOLATILE, 0);
    } else if (!strcmp(scenario, "cached_volatile_no_backend_permall")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        if (TPMLIB_SetState(TPMLIB_STATE_VOLATILE, volatilestate, volatile_len))
            return 4;
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "backend_volatile_no_backend_permall")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "backend_truncated_volatile_no_backend_permall")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        put_backend("volatilestate", volatilestate, volatile_len / 2);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "backend_bad_digest_volatile_no_backend_permall")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        volatilestate[volatile_len - 1] ^= 0xff;
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "no_volatile_anywhere")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "empty_cached_volatile")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        if (TPMLIB_SetState(TPMLIB_STATE_VOLATILE, NULL, 0))
            return 4;
        put_backend("volatilestate", volatilestate, volatile_len);
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "installed_then_empty_cached_permanent")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        if (TPMLIB_SetState(TPMLIB_STATE_VOLATILE, volatilestate, volatile_len))
            return 4;
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, NULL, 0))
            return 5;
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "empty_cached_permanent_nothing_installed")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, NULL, 0))
            return 3;
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "changed_backend_permall")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        if (TPMLIB_SetState(TPMLIB_STATE_VOLATILE, volatilestate, volatile_len))
            return 4;
        put_backend("permall", (const unsigned char *)"\x01\x02\x03", 3);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "nothing_installed_valid_volatile")) {
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "nothing_installed_truncated_volatile")) {
        put_backend("volatilestate", volatilestate, volatile_len / 2);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "nothing_installed_bad_digest_volatile")) {
        volatilestate[volatile_len - 1] ^= 0xff;
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "permanent_then_volatile_only")) {
        put_backend("permall", permall, permall_len);
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_PERMANENT, 0);
        report("permanent_then_volatile_only.permanent", res);
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report("permanent_then_volatile_only.volatile", res);
        return 0;
    } else if (!strcmp(scenario, "save_state_then_volatile_only")) {
        put_backend("permall", permall, permall_len);
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_SAVE_STATE, 0);
        report("save_state_then_volatile_only.save_state", res);
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report("save_state_then_volatile_only.volatile", res);
        return 0;
    } else if (!strcmp(scenario, "failed_permanent_then_volatile_only")) {
        put_backend("permall", (const unsigned char *)"\x01\x02\x03", 3);
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_PERMANENT, 0);
        report("failed_permanent_then_volatile_only.permanent", res);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report("failed_permanent_then_volatile_only.volatile", res);
        return 0;
    } else if (!strcmp(scenario, "combined_seed_mismatch_then_volatile_only")) {
        put_backend("permall", permall, permall_len);
        put_backend("volatilestate", seed_mismatch, seed_mismatch_len);
        event_count = 0;
        res = TPMLIB_ValidateState(TPMLIB_STATE_PERMANENT | TPMLIB_STATE_VOLATILE, 0);
        report("combined_seed_mismatch_then_volatile_only.combined", res);
        drop_backend("permall");
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report("combined_seed_mismatch_then_volatile_only.volatile", res);
        return 0;
    } else if (!strcmp(scenario, "nothing_installed_bad_trailing_magic_volatile")) {
        put_backend("volatilestate", bad_tag, bad_tag_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "nothing_installed_seed_mismatch_volatile")) {
        put_backend("volatilestate", seed_mismatch, seed_mismatch_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "nothing_installed_bad_header_magic_volatile")) {
        volatilestate[3] ^= 0xff;
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "installed_bad_trailing_magic_volatile")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        put_backend("volatilestate", bad_tag, bad_tag_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "installed_seed_mismatch_volatile")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        put_backend("volatilestate", seed_mismatch, seed_mismatch_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "installed_bad_header_magic_volatile")) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        volatilestate[3] ^= 0xff;
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "failed_set_state_volatile_then_volatile_only")) {
        put_backend("permall", permall, permall_len);
        event_count = 0;
        res = TPMLIB_SetState(TPMLIB_STATE_VOLATILE, seed_mismatch, seed_mismatch_len);
        report("failed_set_state_volatile_then_volatile_only.set_state", res);
        drop_backend("permall");
        put_backend("volatilestate", volatilestate, volatile_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report("failed_set_state_volatile_then_volatile_only.volatile", res);
        return 0;
    } else if (!strncmp(scenario, "nothing_installed_object_", 25)) {
        unsigned char *object = object_blob(scenario + 25, rsa_object, rsa_len, ecc_object,
                                            ecc_len, aes128_object, aes128_len, aes192_object,
                                            aes192_len, &object_len);
        put_backend("volatilestate", object, object_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strncmp(scenario, "installed_object_", 17)) {
        if (TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permall, permall_len))
            return 3;
        drop_backend("permall");
        unsigned char *object = object_blob(scenario + 17, rsa_object, rsa_len, ecc_object,
                                            ecc_len, aes128_object, aes128_len, aes192_object,
                                            aes192_len, &object_len);
        put_backend("volatilestate", object, object_len);
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
    } else if (!strcmp(scenario, "running_tpm")) {
        unsigned char *vol = NULL;
        uint32_t vlen = 0;
        store_enabled = 1;
        if (TPMLIB_MainInit())
            return 3;
        if (TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &vol, &vlen))
            return 4;
        put_backend("volatilestate", vol, vlen);
        drop_backend("permall");
        event_count = 0;
        res = TPMLIB_ValidateState(VOLATILE_ONLY, 0);
        report(scenario, res);
        TPMLIB_Terminate();
        return 0;
    } else {
        fprintf(stderr, "unknown scenario %s\n", scenario);
        return 2;
    }

    report(scenario, res);
    return 0;
}
