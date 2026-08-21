#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

struct nvram_entry {
    struct nvram_entry *next;
    uint32_t tpm_number;
    char *name;
    unsigned char *data;
    uint32_t length;
};

#define FAILURE_MODE_RESULT 0x101

static struct nvram_entry *g_nvram;
static void put32(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static int g_store_fails;
static unsigned char g_last_response[4096];
static uint32_t g_last_response_len;
static int g_last_response_valid;
static unsigned char g_session_response[4096];
static uint32_t g_session_response_len;
static uint32_t g_locality;

static struct nvram_entry *nvram_find(uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e;
    for (e = g_nvram; e; e = e->next)
        if (e->tpm_number == tpm_number && strcmp(e->name, name) == 0)
            return e;
    return NULL;
}

static TPM_RESULT cb_nvram_init(void)
{
    return TPM_SUCCESS;
}

static TPM_RESULT cb_nvram_loaddata(unsigned char **data, uint32_t *length,
                                    uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e = nvram_find(tpm_number, name);

    *data = NULL;
    *length = 0;
    if (!e)
        return TPM_RETRY;

    *data = malloc(e->length ? e->length : 1);
    if (!*data)
        return TPM_SIZE;
    memcpy(*data, e->data, e->length);
    *length = e->length;
    return TPM_SUCCESS;
}

static TPM_RESULT cb_nvram_storedata(const unsigned char *data,
                                     uint32_t length,
                                     uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e = nvram_find(tpm_number, name);
    unsigned char *copy;

    if (g_store_fails)
        return TPM_FAIL;

    copy = malloc(length ? length : 1);
    if (!copy)
        return TPM_SIZE;
    memcpy(copy, data, length);

    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e) {
            free(copy);
            return TPM_SIZE;
        }
        e->tpm_number = tpm_number;
        e->name = strdup(name);
        if (!e->name) {
            free(copy);
            free(e);
            return TPM_SIZE;
        }
        e->next = g_nvram;
        g_nvram = e;
    } else {
        free(e->data);
    }
    e->data = copy;
    e->length = length;
    return TPM_SUCCESS;
}

static TPM_RESULT cb_nvram_deletename(uint32_t tpm_number, const char *name,
                                      TPM_BOOL mustExist)
{
    struct nvram_entry **pp;
    for (pp = &g_nvram; *pp; pp = &(*pp)->next) {
        if ((*pp)->tpm_number == tpm_number &&
            strcmp((*pp)->name, name) == 0) {
            struct nvram_entry *e = *pp;
            *pp = e->next;
            free(e->name);
            free(e->data);
            free(e);
            return TPM_SUCCESS;
        }
    }
    return mustExist ? TPM_FAIL : TPM_SUCCESS;
}

static TPM_RESULT cb_io_init(void)
{
    return TPM_SUCCESS;
}

static TPM_RESULT cb_io_getlocality(TPM_MODIFIER_INDICATOR *localityModifier,
                                    uint32_t tpm_number)
{
    (void)tpm_number;
    *localityModifier = g_locality;
    return TPM_SUCCESS;
}

struct snapshot {
    struct snapshot *next;
    char *name;
    unsigned char *permanent;
    uint32_t permanent_len;
    unsigned char *volatil;
    uint32_t volatil_len;
};

static struct snapshot *g_snapshots;

static struct snapshot *snapshot_find(const char *name)
{
    struct snapshot *s;
    for (s = g_snapshots; s; s = s->next)
        if (strcmp(s->name, name) == 0)
            return s;
    return NULL;
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex_decode(const char *hex, uint32_t *out_len)
{
    size_t cap = strlen(hex) / 2 + 1;
    unsigned char *buf;
    uint32_t n = 0;
    int hi = -1;

    if (cap > UINT32_MAX)
        return NULL;
    buf = malloc(cap);
    if (!buf)
        return NULL;
    for (; *hex; hex++) {
        int v;
        if (*hex == ' ' || *hex == '\t')
            continue;
        v = hex_nibble((unsigned char)*hex);
        if (v < 0) {
            free(buf);
            return NULL;
        }
        if (hi < 0) {
            hi = v;
        } else {
            buf[n++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) {
        free(buf);
        return NULL;
    }
    *out_len = n;
    return buf;
}

static void print_hex(const char *label, const unsigned char *data,
                      uint32_t len)
{
    uint32_t i;
    fputs(label, stdout);
    fputc(' ', stdout);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    fputc('\n', stdout);
}

static void die(int lineno, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "runner: line %d: ", lineno);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static unsigned long parse_number(int lineno, const char *op, const char *text,
                                  unsigned long limit)
{
    char *end;
    unsigned long value;

    if (*text == '\0')
        die(lineno, "%s needs a decimal argument", op);
    errno = 0;
    value = strtoul(text, &end, 10);
    while (*end == ' ' || *end == '\t')
        end++;
    if (*end != '\0' || errno == ERANGE)
        die(lineno, "%s: '%s' is not a decimal number", op, text);
    if (value > limit)
        die(lineno, "%s: %lu exceeds %lu", op, value, limit);
    return value;
}

static void record_name(int lineno, const char *op, const char *name,
                        size_t prefix, size_t capacity)
{
    if (*name == '\0')
        die(lineno, "%s needs a name", op);
    if (strlen(name) + prefix >= capacity)
        die(lineno, "%s: name '%s' is too long", op, name);
}

static void run_command(int lineno, const char *hex, const char *print_name)
{
    static unsigned char *resp;
    static uint32_t respbufsize;
    uint32_t resp_size = 0;
    unsigned char *cmd;
    uint32_t cmd_len;
    TPM_RESULT res;

    cmd = hex_decode(hex, &cmd_len);
    if (!cmd || cmd_len == 0)
        die(lineno, "bad command hex '%s'", hex);

    res = TPMLIB_Process(&resp, &resp_size, &respbufsize, cmd, cmd_len);
    free(cmd);
    if (res != TPM_SUCCESS)
        die(lineno, "TPMLIB_Process(%s) failed: 0x%x",
            print_name ? print_name : "raw", res);

    g_last_response_valid = resp_size <= sizeof(g_last_response);
    if (g_last_response_valid) {
        memcpy(g_last_response, resp, resp_size);
        g_last_response_len = resp_size;
    } else {
        g_last_response_len = 0;
    }
    if (print_name)
        print_hex(print_name, resp, resp_size);
}

int main(int argc, char **argv)
{
    FILE *fp;
    char line[65536];
    char label[256];
    int lineno = 0;
    TPM_RESULT res;
    struct libtpms_callbacks cbs;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <scenario-file>\n", argv[0]);
        return 2;
    }
    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "runner: cannot open %s\n", argv[1]);
        return 2;
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.sizeOfStruct = sizeof(cbs);
    cbs.tpm_nvram_init = cb_nvram_init;
    cbs.tpm_nvram_loaddata = cb_nvram_loaddata;
    cbs.tpm_nvram_storedata = cb_nvram_storedata;
    cbs.tpm_nvram_deletename = cb_nvram_deletename;
    cbs.tpm_io_init = cb_io_init;
    cbs.tpm_io_getlocality = cb_io_getlocality;

    res = TPMLIB_RegisterCallbacks(&cbs);
    if (res != TPM_SUCCESS)
        die(0, "TPMLIB_RegisterCallbacks failed: 0x%x", res);

    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (res != TPM_SUCCESS)
        die(0, "TPMLIB_ChooseTPMVersion failed: 0x%x", res);

    res = TPMLIB_MainInit();
    if (res != TPM_SUCCESS)
        die(0, "TPMLIB_MainInit failed: 0x%x", res);

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *nl = strchr(line, '\n');
        lineno++;
        if (!nl && !feof(fp))
            die(lineno, "line too long");
        if (nl)
            *nl = '\0';
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        if (strncmp(p, "profile ", 8) == 0) {
            TPMLIB_Terminate();
            while (g_nvram) {
                struct nvram_entry *dead = g_nvram;
                g_nvram = g_nvram->next;
                free(dead->name);
                free(dead->data);
                free(dead);
            }
            res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
            if (res != TPM_SUCCESS)
                die(lineno, "profile: ChooseTPMVersion failed: 0x%x", res);
            res = TPMLIB_SetProfile(p + 8);
            if (res != TPM_SUCCESS)
                die(lineno, "profile: SetProfile failed: 0x%x", res);
            res = TPMLIB_MainInit();
            if (res != TPM_SUCCESS)
                die(lineno, "profile: MainInit failed: 0x%x", res);
        } else if (strncmp(p, "permall ", 8) == 0) {
            unsigned char *blob = NULL;
            uint32_t blob_len = 0;
            const char *name = p + 8;
            record_name(lineno, "permall", name, 0, sizeof(label));
            res = TPMLIB_GetState(TPMLIB_STATE_PERMANENT, &blob, &blob_len);
            if (res != TPM_SUCCESS)
                die(lineno, "GetState(PERMANENT, %s) failed: 0x%x", name, res);
            print_hex(name, blob, blob_len);
            free(blob);
        } else if (strncmp(p, "advance ", 8) == 0) {
            unsigned long milliseconds =
                parse_number(lineno, "advance", p + 8, 86400000UL);
            void (*advance)(uint64_t) =
                (void (*)(uint64_t))dlsym(RTLD_DEFAULT, "golden_advance_monotonic_ms");
            unsigned long ticks = milliseconds / 10;
            unsigned long tick;
            struct timespec now;
            if (advance)
                advance((uint64_t)milliseconds);
            for (tick = 0; tick < ticks; tick++)
                clock_gettime(CLOCK_REALTIME, &now);
        } else if (strcmp(p, "remember-session") == 0) {
            if (!g_last_response_valid || g_last_response_len == 0)
                die(lineno, "remember-session needs a recorded response");
            memcpy(g_session_response, g_last_response, g_last_response_len);
            g_session_response_len = g_last_response_len;
        } else if (strncmp(p, "audited-getrandom ", 18) == 0) {
            static const unsigned char NONCE_CALLER[32] = {
                0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
            const unsigned char attributes = 0x81;
            const unsigned char parameters[2] = {0x00, 0x04};
            unsigned char cp[6];
            unsigned char cp_hash[SHA256_DIGEST_LENGTH];
            unsigned char to_mac[SHA256_DIGEST_LENGTH + 128];
            unsigned char mac[EVP_MAX_MD_SIZE];
            unsigned char cmd[512];
            unsigned int mac_len = 0;
            uint32_t session, nonce_len, authlen, m = 0, n = 0, i;
            const char *name = p + 18;
            char hex[1024];

            record_name(lineno, "audited-getrandom", name, 0, sizeof(label));
            if (g_session_response_len < 16)
                die(lineno, "audited-getrandom needs a remembered session");
            session = ((uint32_t)g_session_response[10] << 24)
                      | ((uint32_t)g_session_response[11] << 16)
                      | ((uint32_t)g_session_response[12] << 8)
                      | g_session_response[13];
            nonce_len = ((uint32_t)g_session_response[14] << 8) | g_session_response[15];
            if (16 + nonce_len > g_session_response_len)
                die(lineno, "malformed StartAuthSession response");
            if (nonce_len > sizeof(to_mac) - SHA256_DIGEST_LENGTH
                                           - sizeof(NONCE_CALLER) - 1)
                die(lineno, "StartAuthSession nonce of %u bytes does not fit",
                    nonce_len);
            put32(cp, 0x0000017b);
            memcpy(cp + 4, parameters, 2);
            SHA256(cp, sizeof(cp), cp_hash);
            memcpy(to_mac + m, cp_hash, SHA256_DIGEST_LENGTH);
            m += SHA256_DIGEST_LENGTH;
            memcpy(to_mac + m, NONCE_CALLER, sizeof(NONCE_CALLER));
            m += sizeof(NONCE_CALLER);
            memcpy(to_mac + m, g_session_response + 16, nonce_len);
            m += nonce_len;
            to_mac[m++] = attributes;
            HMAC(EVP_sha256(), "", 0, to_mac, m, mac, &mac_len);
            authlen = 4 + 2 + (uint32_t)sizeof(NONCE_CALLER) + 1 + 2 + mac_len;
            if (18 + (size_t)authlen + 2 > sizeof(cmd)
                || (18 + (size_t)authlen + 2) * 2 + 1 > sizeof(hex))
                die(lineno, "audited-getrandom command of %u bytes does not fit",
                    authlen);
            cmd[n++] = 0x80;
            cmd[n++] = 0x02;
            n += 4;
            put32(cmd + n, 0x0000017b);
            n += 4;
            put32(cmd + n, authlen);
            n += 4;
            put32(cmd + n, session);
            n += 4;
            cmd[n++] = 0;
            cmd[n++] = (unsigned char)sizeof(NONCE_CALLER);
            memcpy(cmd + n, NONCE_CALLER, sizeof(NONCE_CALLER));
            n += sizeof(NONCE_CALLER);
            cmd[n++] = attributes;
            cmd[n++] = (unsigned char)(mac_len >> 8);
            cmd[n++] = (unsigned char)mac_len;
            memcpy(cmd + n, mac, mac_len);
            n += mac_len;
            memcpy(cmd + n, parameters, 2);
            n += 2;
            put32(cmd + 2, n);
            for (i = 0; i < n; i++)
                snprintf(hex + i * 2, 3, "%02x", cmd[i]);
            run_command(lineno, hex, name);
        } else if (strncmp(p, "exclusive-audit ", 16) == 0) {
            unsigned char *blob = NULL;
            uint32_t blob_len = 0;
            const char *name = p + 16;
            record_name(lineno, "exclusive-audit", name, 0, sizeof(label));
            res = TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &blob, &blob_len);
            if (res != TPM_SUCCESS || blob_len < 12)
                die(lineno, "exclusive-audit: GetState failed: 0x%x", res);
            print_hex(name, blob + 8, 4);
            free(blob);
        } else if (strncmp(p, "fail-stores ", 12) == 0) {
            g_store_fails = (int)parse_number(lineno, "fail-stores", p + 12, 1);
        } else if (strncmp(p, "patch-failure-code ", 19) == 0) {
            unsigned char *blob = NULL;
            unsigned char needle[15];
            uint32_t blob_len = 0, payload, at, replacement;
            int patched = 0;
            replacement = (uint32_t)parse_number(lineno, "patch-failure-code",
                                                 p + 19, UINT32_MAX);
            if (!g_last_response_valid || g_last_response_len < 24)
                die(lineno, "patch-failure-code needs a failure-mode response");
            needle[0] = 0x01;
            needle[1] = 0x00;
            needle[2] = 0x0c;
            memcpy(needle + 3, g_last_response + 12, 12);
            res = TPMLIB_GetState(TPMLIB_STATE_VOLATILE, &blob, &blob_len);
            if (res != TPM_SUCCESS || blob_len < 32)
                die(lineno, "patch-failure-code: GetState failed: 0x%x", res);
            payload = blob_len - 20;
            for (at = 0; at + sizeof(needle) <= payload; at++) {
                if (!memcmp(blob + at, needle, sizeof(needle))) {
                    put32(blob + at + 11, replacement);
                    patched++;
                }
            }
            if (patched != 1)
                die(lineno, "patch-failure-code matched %d blocks", patched);
            SHA1(blob, payload, blob + payload);
            TPMLIB_Terminate();
            res = TPMLIB_SetState(TPMLIB_STATE_VOLATILE, blob, blob_len);
            if (res != TPM_SUCCESS)
                die(lineno, "patch-failure-code: SetState failed: 0x%x", res);
            res = TPMLIB_MainInit();
            if (res != FAILURE_MODE_RESULT)
                die(lineno, "patch-failure-code: MainInit answered 0x%x, expected 0x%x",
                    res, FAILURE_MODE_RESULT);
            free(blob);
        } else if (strncmp(p, "locality ", 9) == 0) {
            g_locality = (uint32_t)parse_number(lineno, "locality", p + 9, 255);
        } else if (strcmp(p, "version") == 0) {
            printf("VERSION %08x\n", TPMLIB_GetVersion());
        } else if (strcmp(p, "reboot") == 0) {
            TPMLIB_Terminate();
            res = TPMLIB_MainInit();
            if (res != TPM_SUCCESS)
                die(lineno, "reboot: TPMLIB_MainInit failed: 0x%x", res);
        } else if (strncmp(p, "send ", 5) == 0) {
            char *hex;
            p += 5;
            hex = strchr(p, ' ');
            if (!hex || hex == p || (size_t)(hex - p) >= sizeof(label))
                die(lineno, "malformed send op");
            memcpy(label, p, (size_t)(hex - p));
            label[hex - p] = '\0';
            run_command(lineno, hex + 1, label);
        } else if (strncmp(p, "raw ", 4) == 0) {
            run_command(lineno, p + 4, NULL);
        } else if (strncmp(p, "checkpoint ", 11) == 0 || strncmp(p, "snapshot ", 9) == 0) {
            int quiet = (p[0] == 'c');
            struct snapshot *s;
            const char *name = p + (quiet ? 11 : 9);
            record_name(lineno, quiet ? "checkpoint" : "snapshot", name,
                        strlen("VOLATILE_"), sizeof(label));
            s = snapshot_find(name);
            if (!s) {
                s = calloc(1, sizeof(*s));
                if (!s || !(s->name = strdup(name)))
                    die(lineno, "out of memory");
                s->next = g_snapshots;
                g_snapshots = s;
            } else {
                free(s->permanent);
                free(s->volatil);
                s->permanent = s->volatil = NULL;
            }
            res = TPMLIB_GetState(TPMLIB_STATE_PERMANENT,
                                  &s->permanent, &s->permanent_len);
            if (res != TPM_SUCCESS)
                die(lineno, "GetState(PERMANENT, %s) failed: 0x%x",
                    name, res);
            res = TPMLIB_GetState(TPMLIB_STATE_VOLATILE,
                                  &s->volatil, &s->volatil_len);
            if (res != TPM_SUCCESS)
                die(lineno, "GetState(VOLATILE, %s) failed: 0x%x",
                    name, res);
            if (!quiet) {
                snprintf(label, sizeof(label), "PERMALL_%s", name);
                print_hex(label, s->permanent, s->permanent_len);
                snprintf(label, sizeof(label), "VOLATILE_%s", name);
                print_hex(label, s->volatil, s->volatil_len);
            }
        } else if (strncmp(p, "restore ", 8) == 0
                   || strncmp(p, "restore-permanent ", 18) == 0) {
            int permanent_only = (p[7] == '-');
            const char *name = p + (permanent_only ? 18 : 8);
            struct snapshot *s;
            record_name(lineno, permanent_only ? "restore-permanent" : "restore",
                        name, 0, sizeof(label));
            s = snapshot_find(name);
            if (!s)
                die(lineno, "no snapshot named '%s'", name);
            TPMLIB_Terminate();
            res = TPMLIB_SetState(TPMLIB_STATE_PERMANENT,
                                  s->permanent, s->permanent_len);
            if (res != TPM_SUCCESS)
                die(lineno, "SetState(PERMANENT, %s) failed: 0x%x",
                    name, res);
            if (!permanent_only) {
                res = TPMLIB_SetState(TPMLIB_STATE_VOLATILE,
                                      s->volatil, s->volatil_len);
                if (res != TPM_SUCCESS)
                    die(lineno, "SetState(VOLATILE, %s) failed: 0x%x",
                        name, res);
            }
            res = TPMLIB_MainInit();
            if (res != TPM_SUCCESS && res != FAILURE_MODE_RESULT)
                die(lineno, "restore %s: TPMLIB_MainInit failed: 0x%x",
                    name, res);
        } else {
            die(lineno, "unknown op '%s'", p);
        }
    }

    fclose(fp);
    TPMLIB_Terminate();
    return 0;
}
