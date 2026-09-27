#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_tis.h>

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
static TPM_BOOL g_physical_presence;

struct known_blob {
    struct known_blob *next;
    char *label;
    unsigned char *data;
    uint32_t length;
};

static int g_in_case;
static TPM_RESULT g_io_init_result;
static TPM_RESULT g_nvram_init_result;
static TPM_RESULT g_permall_load_result;
static TPM_RESULT g_volatile_load_result;
static char *g_callback_log;
static size_t g_callback_log_length;
static uint32_t g_callback_count;
static struct known_blob *g_known_blobs;

static void die(int lineno, const char *fmt, ...);

static void log_callback(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    int written;
    char *grown;

    if (!g_in_case)
        return;
    va_start(ap, fmt);
    written = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= sizeof(line))
        die(0, "a callback log line does not fit");
    grown = realloc(g_callback_log, g_callback_log_length + (size_t)written + 1);
    if (!grown)
        die(0, "out of memory");
    g_callback_log = grown;
    memcpy(g_callback_log + g_callback_log_length, line, (size_t)written);
    g_callback_log_length += (size_t)written;
    g_callback_log[g_callback_log_length++] = '\n';
    g_callback_count++;
}

static const char *blob_label(const unsigned char *data, uint32_t length)
{
    struct known_blob *k;
    for (k = g_known_blobs; k; k = k->next)
        if (k->length == length && (length == 0 || memcmp(k->data, data, length) == 0))
            return k->label;
    return "new";
}

static struct nvram_entry *nvram_find(uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e;
    for (e = g_nvram; e; e = e->next)
        if (e->tpm_number == tpm_number && strcmp(e->name, name) == 0)
            return e;
    return NULL;
}

static TPM_RESULT load_result(const char *name)
{
    if (strcmp(name, "permall") == 0)
        return g_permall_load_result;
    if (strcmp(name, "volatilestate") == 0)
        return g_volatile_load_result;
    return TPM_SUCCESS;
}

static TPM_RESULT cb_nvram_init(void)
{
    log_callback("tpm_nvram_init -> 0x%x", g_nvram_init_result);
    return g_nvram_init_result;
}

static TPM_RESULT cb_nvram_loaddata(unsigned char **data, uint32_t *length,
                                    uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e = nvram_find(tpm_number, name);
    TPM_RESULT failure = load_result(name);

    *data = NULL;
    *length = 0;
    if (failure != TPM_SUCCESS) {
        log_callback("tpm_nvram_loaddata(%s) -> 0x%x", name, failure);
        return failure;
    }
    if (!e) {
        log_callback("tpm_nvram_loaddata(%s) -> 0x%x", name, TPM_RETRY);
        return TPM_RETRY;
    }

    *data = malloc(e->length ? e->length : 1);
    if (!*data)
        return TPM_SIZE;
    memcpy(*data, e->data, e->length);
    *length = e->length;
    log_callback("tpm_nvram_loaddata(%s) -> 0x0 len=%u content=%s", name,
                 (unsigned)e->length, blob_label(e->data, e->length));
    return TPM_SUCCESS;
}

static TPM_RESULT cb_nvram_storedata(const unsigned char *data,
                                     uint32_t length,
                                     uint32_t tpm_number, const char *name)
{
    struct nvram_entry *e = nvram_find(tpm_number, name);
    unsigned char *copy;

    log_callback("tpm_nvram_storedata(%s) len=%u content=%s", name,
                 (unsigned)length, blob_label(data, length));
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
    log_callback("tpm_nvram_deletename(%s) must_exist=%d", name, mustExist ? 1 : 0);
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
    log_callback("tpm_io_init -> 0x%x", g_io_init_result);
    return g_io_init_result;
}

static TPM_RESULT cb_io_getlocality(TPM_MODIFIER_INDICATOR *localityModifier,
                                    uint32_t tpm_number)
{
    (void)tpm_number;
    log_callback("tpm_io_getlocality");
    *localityModifier = g_locality;
    return TPM_SUCCESS;
}

static TPM_RESULT cb_io_getphysicalpresence(TPM_BOOL *physicalPresence,
                                            uint32_t tpm_number)
{
    (void)tpm_number;
    *physicalPresence = g_physical_presence;
    return TPM_SUCCESS;
}

struct snapshot {
    struct snapshot *next;
    char *name;
    int recorded;
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

static TPM_RESULT register_callbacks(void)
{
    struct libtpms_callbacks cbs;

    memset(&cbs, 0, sizeof(cbs));
    cbs.sizeOfStruct = sizeof(cbs);
    cbs.tpm_nvram_init = cb_nvram_init;
    cbs.tpm_nvram_loaddata = cb_nvram_loaddata;
    cbs.tpm_nvram_storedata = cb_nvram_storedata;
    cbs.tpm_nvram_deletename = cb_nvram_deletename;
    cbs.tpm_io_init = cb_io_init;
    cbs.tpm_io_getlocality = cb_io_getlocality;
    cbs.tpm_io_getphysicalpresence = cb_io_getphysicalpresence;
    return TPMLIB_RegisterCallbacks(&cbs);
}

static char *next_token(char **cursor)
{
    char *start = *cursor;
    char *end;

    while (*start == ' ' || *start == '\t')
        start++;
    if (*start == '\0') {
        *cursor = start;
        return start;
    }
    end = start;
    while (*end != '\0' && *end != ' ' && *end != '\t')
        end++;
    if (*end != '\0')
        *end++ = '\0';
    *cursor = end;
    return start;
}

static void no_more_tokens(int lineno, const char *op, char **cursor)
{
    if (*next_token(cursor) != '\0')
        die(lineno, "%s: unexpected trailing argument", op);
}

static const char *case_record(int lineno, const char *op, char **cursor)
{
    const char *name = next_token(cursor);
    record_name(lineno, op, name, 0, 256);
    return name;
}

static enum TPMLIB_StateType state_type(int lineno, const char *op, const char *kind)
{
    if (strcmp(kind, "permanent") == 0)
        return TPMLIB_STATE_PERMANENT;
    if (strcmp(kind, "volatile") == 0)
        return TPMLIB_STATE_VOLATILE;
    die(lineno, "%s: '%s' is neither permanent nor volatile", op, kind);
    return TPMLIB_STATE_PERMANENT;
}

static const char *nvram_name(int lineno, const char *op, const char *name)
{
    if (strcmp(name, "permall") != 0 && strcmp(name, "volatilestate") != 0)
        die(lineno, "%s: '%s' is neither permall nor volatilestate", op, name);
    return name;
}

static void remember_blob(const char *label, const unsigned char *data,
                          uint32_t length)
{
    struct known_blob **tail = &g_known_blobs;
    struct known_blob *k;

    for (k = g_known_blobs; k; k = k->next) {
        if (strcmp(k->label, label) == 0)
            return;
        tail = &k->next;
    }
    k = calloc(1, sizeof(*k));
    if (!k || !(k->label = strdup(label)) || !(k->data = malloc(length ? length : 1)))
        die(0, "out of memory");
    memcpy(k->data, data, length);
    k->length = length;
    *tail = k;
}

static unsigned char *resolve_blob(int lineno, const char *op, const char *ref,
                                   uint32_t *length)
{
    char name[256];
    char *modifier;
    const char *snapshot_name;
    const unsigned char *source;
    unsigned char *blob;
    unsigned long amount = 0;
    struct snapshot *s;
    int permanent;

    if (strlen(ref) >= sizeof(name))
        die(lineno, "%s: blob '%s' is too long", op, ref);
    strcpy(name, ref);
    modifier = strchr(name, '@');
    if (modifier)
        *modifier++ = '\0';
    if (strncmp(name, "PERMALL_", 8) == 0) {
        permanent = 1;
        snapshot_name = name + 8;
    } else if (strncmp(name, "VOLATILE_", 9) == 0) {
        permanent = 0;
        snapshot_name = name + 9;
    } else {
        die(lineno, "%s: blob '%s' names no snapshot record", op, ref);
        return NULL;
    }
    s = snapshot_find(snapshot_name);
    if (!s)
        die(lineno, "%s: no snapshot named '%s'", op, snapshot_name);
    source = permanent ? s->permanent : s->volatil;
    *length = permanent ? s->permanent_len : s->volatil_len;
    blob = malloc(*length ? *length : 1);
    if (!blob)
        die(lineno, "out of memory");
    memcpy(blob, source, *length);
    while (modifier) {
        char *next = strchr(modifier, '@');
        if (next)
            *next++ = '\0';
        if (strncmp(modifier, "head=", 5) == 0) {
            amount = parse_number(lineno, op, modifier + 5, *length);
            *length = (uint32_t)amount;
        } else if (strncmp(modifier, "drop=", 5) == 0) {
            amount = parse_number(lineno, op, modifier + 5, *length);
            *length -= (uint32_t)amount;
        } else if (strncmp(modifier, "flip=", 5) == 0) {
            amount = parse_number(lineno, op, modifier + 5, UINT32_MAX);
            if (amount >= *length)
                die(lineno, "%s: byte %lu is outside the %u-byte blob", op, amount,
                    (unsigned)*length);
            blob[amount] ^= 0xff;
        } else if (strncmp(modifier, "flip-end=", 9) == 0) {
            amount = parse_number(lineno, op, modifier + 9, *length);
            if (amount == 0)
                die(lineno, "%s: flip-end counts from 1", op);
            blob[*length - amount] ^= 0xff;
        } else if (strncmp(modifier, "set=", 4) == 0) {
            char *bytes_hex = strchr(modifier + 4, ':');
            unsigned char *bytes;
            uint32_t count = 0;
            if (!bytes_hex)
                die(lineno, "%s: set needs N:HEX", op);
            *bytes_hex++ = '\0';
            amount = parse_number(lineno, op, modifier + 4, *length);
            bytes = hex_decode(bytes_hex, &count);
            if (!bytes || count == 0 || count > *length - amount)
                die(lineno, "%s: set=%lu:%s does not fit the %u-byte blob", op, amount,
                    bytes_hex, (unsigned)*length);
            memcpy(blob + amount, bytes, count);
            free(bytes);
        } else if (strcmp(modifier, "sha1") == 0) {
            if (*length < SHA_DIGEST_LENGTH)
                die(lineno, "%s: a %u-byte blob has no SHA-1 trailer", op,
                    (unsigned)*length);
            SHA1(blob, *length - SHA_DIGEST_LENGTH, blob + *length - SHA_DIGEST_LENGTH);
        } else {
            die(lineno, "%s: unknown blob modifier '%s'", op, modifier);
        }
        modifier = next;
    }
    remember_blob(ref, blob, *length);
    return blob;
}

static void nvram_put(const char *name, unsigned char *data, uint32_t length)
{
    struct nvram_entry *e = nvram_find(0, name);

    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e || !(e->name = strdup(name)))
            die(0, "out of memory");
        e->next = g_nvram;
        g_nvram = e;
    } else {
        free(e->data);
    }
    e->data = data;
    e->length = length;
}

static void print_result(const char *name, TPM_RESULT res)
{
    unsigned char out[4];

    put32(out, res);
    print_hex(name, out, sizeof(out));
}

static void print_status_blob(int lineno, const char *name, TPM_RESULT res,
                              unsigned char *blob, uint32_t length)
{
    unsigned char *out;
    uint32_t used = 5;

    if (res == TPM_SUCCESS && !blob && length != 0)
        die(lineno, "%s: no buffer for %u bytes", name, (unsigned)length);
    if (!blob)
        length = 0;
    out = malloc((size_t)length + 5);
    if (!out)
        die(lineno, "out of memory");
    put32(out, res);
    out[4] = blob != NULL;
    if (blob) {
        memcpy(out + 5, blob, length);
        used += length;
    }
    print_hex(name, out, used);
    free(out);
    free(blob);
}

static void case_process(int lineno, const char *name, const char *hex)
{
    unsigned char *resp = NULL;
    unsigned char *cmd;
    unsigned char *record;
    uint32_t resp_size = 0, respbufsize = 0, cmd_len;
    TPM_RESULT res;

    cmd = hex_decode(hex, &cmd_len);
    if (!cmd || cmd_len == 0)
        die(lineno, "bad command hex '%s'", hex);
    res = TPMLIB_Process(&resp, &resp_size, &respbufsize, cmd, cmd_len);
    free(cmd);
    if (res != TPM_SUCCESS) {
        free(resp);
        print_result(name, res);
        return;
    }
    if (!resp && resp_size != 0)
        die(lineno, "%s: TPMLIB_Process returned no buffer for %u bytes", name,
            (unsigned)resp_size);
    if (resp && resp_size > respbufsize)
        die(lineno, "%s: TPMLIB_Process returned %u bytes in a %u-byte buffer", name,
            (unsigned)resp_size, (unsigned)respbufsize);
    record = malloc((size_t)resp_size + 4);
    if (!record)
        die(lineno, "out of memory");
    put32(record, res);
    if (resp_size)
        memcpy(record + 4, resp, resp_size);
    print_hex(name, record, resp_size + 4);
    free(record);
    free(resp);
}

static void run_case_op(int lineno, char *p)
{
    char *cursor;
    const char *name;
    unsigned char *blob;
    uint32_t length = 0;
    TPM_RESULT res;

    if (strcmp(p, "terminate") == 0) {
        TPMLIB_Terminate();
    } else if (strncmp(p, "main-init ", 10) == 0) {
        cursor = p + 10;
        name = case_record(lineno, "main-init", &cursor);
        no_more_tokens(lineno, "main-init", &cursor);
        print_result(name, TPMLIB_MainInit());
    } else if (strncmp(p, "set-state ", 10) == 0) {
        enum TPMLIB_StateType type;
        const char *ref;
        cursor = p + 10;
        name = case_record(lineno, "set-state", &cursor);
        type = state_type(lineno, "set-state", next_token(&cursor));
        ref = next_token(&cursor);
        no_more_tokens(lineno, "set-state", &cursor);
        blob = resolve_blob(lineno, "set-state", ref, &length);
        res = TPMLIB_SetState(type, blob, length);
        free(blob);
        print_result(name, res);
    } else if (strncmp(p, "get-state ", 10) == 0) {
        enum TPMLIB_StateType type;
        cursor = p + 10;
        name = case_record(lineno, "get-state", &cursor);
        type = state_type(lineno, "get-state", next_token(&cursor));
        no_more_tokens(lineno, "get-state", &cursor);
        blob = NULL;
        res = TPMLIB_GetState(type, &blob, &length);
        print_status_blob(lineno, name, res, blob, length);
    } else if (strncmp(p, "volatile-all-store ", 19) == 0) {
        cursor = p + 19;
        name = case_record(lineno, "volatile-all-store", &cursor);
        no_more_tokens(lineno, "volatile-all-store", &cursor);
        blob = NULL;
        res = TPMLIB_VolatileAll_Store(&blob, &length);
        print_status_blob(lineno, name, res, blob, length);
    } else if (strncmp(p, "set-profile ", 12) == 0) {
        cursor = p + 12;
        name = case_record(lineno, "set-profile", &cursor);
        while (*cursor == ' ' || *cursor == '\t')
            cursor++;
        if (*cursor == '\0')
            die(lineno, "set-profile needs a profile");
        print_result(name, TPMLIB_SetProfile(cursor));
    } else if (strncmp(p, "process ", 8) == 0) {
        const char *hex;
        cursor = p + 8;
        name = case_record(lineno, "process", &cursor);
        hex = next_token(&cursor);
        no_more_tokens(lineno, "process", &cursor);
        case_process(lineno, name, hex);
    } else if (strncmp(p, "was-manufactured ", 17) == 0) {
        unsigned char manufactured;
        cursor = p + 17;
        name = case_record(lineno, "was-manufactured", &cursor);
        no_more_tokens(lineno, "was-manufactured", &cursor);
        manufactured = TPMLIB_WasManufactured() ? 1 : 0;
        print_hex(name, &manufactured, 1);
    } else if (strncmp(p, "established ", 12) == 0) {
        unsigned char out[5];
        TPM_BOOL established = 0xee;
        cursor = p + 12;
        name = case_record(lineno, "established", &cursor);
        no_more_tokens(lineno, "established", &cursor);
        res = TPM_IO_TpmEstablished_Get(&established);
        put32(out, res);
        out[4] = (unsigned char)established;
        print_hex(name, out, sizeof(out));
    } else if (strncmp(p, "established-reset ", 18) == 0) {
        cursor = p + 18;
        name = case_record(lineno, "established-reset", &cursor);
        no_more_tokens(lineno, "established-reset", &cursor);
        print_result(name, TPM_IO_TpmEstablished_Reset());
    } else if (strncmp(p, "hash-start ", 11) == 0) {
        cursor = p + 11;
        name = case_record(lineno, "hash-start", &cursor);
        no_more_tokens(lineno, "hash-start", &cursor);
        print_result(name, TPM_IO_Hash_Start());
    } else if (strncmp(p, "hash-data ", 10) == 0) {
        const char *hex;
        cursor = p + 10;
        name = case_record(lineno, "hash-data", &cursor);
        hex = next_token(&cursor);
        no_more_tokens(lineno, "hash-data", &cursor);
        blob = hex_decode(hex, &length);
        if (!blob || length == 0)
            die(lineno, "bad hash-data hex '%s'", hex);
        res = TPM_IO_Hash_Data(blob, length);
        free(blob);
        print_result(name, res);
    } else if (strncmp(p, "hash-end ", 9) == 0) {
        cursor = p + 9;
        name = case_record(lineno, "hash-end", &cursor);
        no_more_tokens(lineno, "hash-end", &cursor);
        print_result(name, TPM_IO_Hash_End());
    } else if (strncmp(p, "nvram-put ", 10) == 0) {
        const char *target, *ref;
        cursor = p + 10;
        target = nvram_name(lineno, "nvram-put", next_token(&cursor));
        ref = next_token(&cursor);
        no_more_tokens(lineno, "nvram-put", &cursor);
        blob = resolve_blob(lineno, "nvram-put", ref, &length);
        nvram_put(target, blob, length);
    } else if (strncmp(p, "load-fails ", 11) == 0) {
        const char *target;
        TPM_RESULT code;
        cursor = p + 11;
        target = nvram_name(lineno, "load-fails", next_token(&cursor));
        code = (TPM_RESULT)parse_number(lineno, "load-fails", next_token(&cursor),
                                        UINT32_MAX);
        if (strcmp(target, "permall") == 0)
            g_permall_load_result = code;
        else
            g_volatile_load_result = code;
    } else if (strncmp(p, "io-init ", 8) == 0) {
        g_io_init_result = (TPM_RESULT)parse_number(lineno, "io-init", p + 8, UINT32_MAX);
    } else if (strncmp(p, "nvram-init ", 11) == 0) {
        g_nvram_init_result =
            (TPM_RESULT)parse_number(lineno, "nvram-init", p + 11, UINT32_MAX);
    } else if (strncmp(p, "callbacks ", 10) == 0) {
        unsigned char *record;
        cursor = p + 10;
        name = case_record(lineno, "callbacks", &cursor);
        no_more_tokens(lineno, "callbacks", &cursor);
        record = malloc(g_callback_log_length + 4);
        if (!record)
            die(lineno, "out of memory");
        put32(record, g_callback_count);
        if (g_callback_log_length)
            memcpy(record + 4, g_callback_log, g_callback_log_length);
        print_hex(name, record, (uint32_t)g_callback_log_length + 4);
        free(record);
        free(g_callback_log);
        g_callback_log = NULL;
        g_callback_log_length = 0;
        g_callback_count = 0;
    } else {
        die(lineno, "unknown case op '%s'", p);
    }
}

static void write_all(int fd, const void *data, size_t length)
{
    const unsigned char *at = data;

    while (length) {
        ssize_t written = write(fd, at, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            die(0, "cannot hand the snapshots to a case: %s", strerror(errno));
        at += written;
        length -= (size_t)written;
    }
}

static void write_chunk(int fd, const void *data, uint32_t length)
{
    unsigned char size[4];

    put32(size, length);
    write_all(fd, size, sizeof(size));
    write_all(fd, data, length);
}

static unsigned char *read_chunk(FILE *in, uint32_t *length)
{
    unsigned char size[4];
    unsigned char *data;

    if (fread(size, 1, sizeof(size), in) != sizeof(size))
        die(0, "the snapshot stream ends early");
    *length = ((uint32_t)size[0] << 24) | ((uint32_t)size[1] << 16)
              | ((uint32_t)size[2] << 8) | size[3];
    data = malloc(*length ? *length : 1);
    if (!data)
        die(0, "out of memory");
    if (*length && fread(data, 1, *length, in) != *length)
        die(0, "the snapshot stream ends early");
    return data;
}

static void send_snapshots(int fd)
{
    struct snapshot *s;

    for (s = g_snapshots; s; s = s->next) {
        if (!s->recorded)
            continue;
        write_chunk(fd, s->name, (uint32_t)strlen(s->name));
        write_chunk(fd, s->permanent, s->permanent_len);
        write_chunk(fd, s->volatil, s->volatil_len);
    }
    write_chunk(fd, "", 0);
}

static void receive_snapshots(FILE *in)
{
    for (;;) {
        uint32_t name_len;
        unsigned char *name = read_chunk(in, &name_len);
        struct snapshot *s;

        if (name_len == 0) {
            free(name);
            return;
        }
        s = calloc(1, sizeof(*s));
        if (!s || !(s->name = calloc(1, (size_t)name_len + 1)))
            die(0, "out of memory");
        memcpy(s->name, name, name_len);
        free(name);
        s->recorded = 1;
        s->permanent = read_chunk(in, &s->permanent_len);
        s->volatil = read_chunk(in, &s->volatil_len);
        s->next = g_snapshots;
        g_snapshots = s;
    }
}

static void spawn_case(int lineno, const char *name, const char *scenario)
{
    char line_text[32];
    int fds[2];
    int status;
    pid_t pid;

    if (*name == '\0')
        die(lineno, "case needs a name");
    fflush(stdout);
    fflush(stderr);
    if (pipe(fds) != 0)
        die(lineno, "pipe: %s", strerror(errno));
    pid = fork();
    if (pid < 0)
        die(lineno, "fork: %s", strerror(errno));
    if (pid == 0) {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0)
            _exit(126);
        close(fds[0]);
        snprintf(line_text, sizeof(line_text), "%d", lineno);
        execl("/proc/self/exe", "golden-runner", "--case", scenario, line_text,
              (char *)NULL);
        fprintf(stderr, "runner: line %d: exec: %s\n", lineno, strerror(errno));
        _exit(127);
    }
    close(fds[0]);
    send_snapshots(fds[1]);
    close(fds[1]);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            die(lineno, "waitpid: %s", strerror(errno));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        die(lineno, "case %s failed (wait status 0x%x)", name, status);
}

static int read_line(FILE *fp, char *line, size_t capacity, int *lineno, char **op)
{
    char *p = line;
    char *nl;

    for (;;) {
        if (!fgets(line, (int)capacity, fp))
            return 0;
        (*lineno)++;
        nl = strchr(line, '\n');
        if (!nl && !feof(fp))
            die(*lineno, "line too long");
        if (nl)
            *nl = '\0';
        p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p != '\0' && *p != '#') {
            *op = p;
            return 1;
        }
    }
}

static int run_case(const char *scenario, const char *line_text)
{
    static char line[65536];
    unsigned long target;
    int lineno = 0;
    char *p = NULL;
    TPM_RESULT res;
    FILE *fp;

    receive_snapshots(stdin);
    target = parse_number(0, "--case", line_text, 1000000);
    fp = fopen(scenario, "r");
    if (!fp)
        die(0, "cannot open %s", scenario);
    while ((unsigned long)lineno < target) {
        if (!read_line(fp, line, sizeof(line), &lineno, &p))
            die(lineno, "the scenario ends before line %lu", target);
    }
    if ((unsigned long)lineno != target || strncmp(p, "case ", 5) != 0)
        die(lineno, "line %lu does not open a case", target);

    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (res != TPM_SUCCESS)
        die(lineno, "TPMLIB_ChooseTPMVersion failed: 0x%x", res);
    res = register_callbacks();
    if (res != TPM_SUCCESS)
        die(lineno, "TPMLIB_RegisterCallbacks failed: 0x%x", res);
    g_in_case = 1;

    while (read_line(fp, line, sizeof(line), &lineno, &p)) {
        if (strcmp(p, "end-case") == 0) {
            fclose(fp);
            fflush(stdout);
            return 0;
        }
        run_case_op(lineno, p);
    }
    die(lineno, "the case is not closed");
    return 1;
}

int main(int argc, char **argv)
{
    FILE *fp;
    char line[65536];
    char label[256];
    int lineno = 0;
    int skipping = 0;
    TPM_RESULT res;

    if (argc == 4 && strcmp(argv[1], "--case") == 0)
        return run_case(argv[2], argv[3]);
    if (argc != 2) {
        fprintf(stderr, "usage: %s <scenario-file>\n", argv[0]);
        return 2;
    }
    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "runner: cannot open %s\n", argv[1]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);

    res = register_callbacks();
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

        if (skipping) {
            if (strcmp(p, "end-case") == 0)
                skipping = 0;
            continue;
        }
        if (strncmp(p, "case ", 5) == 0) {
            spawn_case(lineno, p + 5, argv[1]);
            skipping = 1;
            continue;
        }

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
        } else if (strncmp(p, "physical-presence ", 18) == 0) {
            g_physical_presence =
                (TPM_BOOL)parse_number(lineno, "physical-presence", p + 18, 1);
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
            if (s && quiet && s->recorded)
                die(lineno, "checkpoint %s would overwrite the recorded snapshot %s",
                    name, name);
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
                s->recorded = 1;
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

    if (skipping)
        die(lineno, "the last case is not closed");
    fclose(fp);
    TPMLIB_Terminate();
    return 0;
}
