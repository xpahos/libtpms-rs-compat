#define _GNU_SOURCE
#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <link.h>
#include <sched.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

#define WORKER_PROTOCOL 1
#define RESPONSE_CAPACITY 4096
#define SLOT_SIZE 2048
#define MAX_COMMAND 4096
#define MAX_SETUP 64
#define MAX_PATCHES 16
#define POST_FAILED 0xfffffffeu
#define CONTROL_BASE_ITERATIONS 20000u
#define CONTROL_ITERATIONS_PER_BIT 1000u
#define CONTROL_SCALAR_BYTES 66u
#define CONTROL_COUNTED_BYTES 8u

static const unsigned char CONTROL_MASK[CONTROL_COUNTED_BYTES] = {0xa5, 0x3c, 0x96, 0x0f, 0xe1, 0x78, 0x2d, 0xb4};

typedef TPM_RESULT (*process_fn)(unsigned char **, uint32_t *, uint32_t *, unsigned char *, uint32_t);

enum backend_kind { BACKEND_NONE, BACKEND_TPM, BACKEND_POSITIVE, BACKEND_NEGATIVE };

struct bytes {
    unsigned char *data;
    uint32_t len;
};

static enum backend_kind g_kind = BACKEND_NONE;
static void *g_library;
static process_fn g_process;
typedef TPM_RESULT (*drbg_hook_fn)(const unsigned char *, uint32_t, unsigned char *, uint32_t, uint32_t *);
static drbg_hook_fn g_drbg_hook;
static unsigned char *g_response;
static uint32_t g_response_capacity;
static unsigned long g_nv_stores;
static volatile sig_atomic_t g_interrupted;

static unsigned char *nv_data[16];
static uint32_t nv_len[16];
static char *nv_names[16];
static int nv_count;

static void fail(const char *message)
{
    printf("error %s\n", message);
    fflush(stdout);
    exit(3);
}

static void on_signal(int signo)
{
    (void)signo;
    g_interrupted = 1;
}

static int nv_slot(const char *name, int create)
{
    for (int i = 0; i < nv_count; i++)
        if (strcmp(nv_names[i], name) == 0)
            return i;
    if (!create || nv_count == 16)
        return -1;
    nv_names[nv_count] = strdup(name);
    return nv_count++;
}

static TPM_RESULT nv_init(void)
{
    return TPM_SUCCESS;
}

static TPM_RESULT nv_load(unsigned char **data, uint32_t *length, uint32_t tpm_number, const char *name)
{
    (void)tpm_number;
    int i = nv_slot(name, 0);
    if (i < 0 || nv_data[i] == NULL)
        return TPM_RETRY;
    *data = malloc(nv_len[i]);
    if (*data == NULL)
        return TPM_FAIL;
    memcpy(*data, nv_data[i], nv_len[i]);
    *length = nv_len[i];
    return TPM_SUCCESS;
}

static TPM_RESULT nv_store(const unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name)
{
    (void)tpm_number;
    g_nv_stores++;
    int i = nv_slot(name, 1);
    if (i < 0)
        return TPM_FAIL;
    free(nv_data[i]);
    nv_data[i] = malloc(length ? length : 1);
    if (nv_data[i] == NULL)
        return TPM_FAIL;
    memcpy(nv_data[i], data, length);
    nv_len[i] = length;
    return TPM_SUCCESS;
}

static TPM_RESULT nv_delete(uint32_t tpm_number, const char *name, TPM_BOOL must_exist)
{
    (void)tpm_number;
    (void)must_exist;
    int i = nv_slot(name, 0);
    if (i >= 0) {
        free(nv_data[i]);
        nv_data[i] = NULL;
        nv_len[i] = 0;
    }
    return TPM_SUCCESS;
}

static TPM_RESULT io_locality(TPM_MODIFIER_INDICATOR *locality, uint32_t tpm_number)
{
    (void)tpm_number;
    *locality = 0;
    return TPM_SUCCESS;
}

static uint64_t control_mix_seed(const unsigned char *input, uint32_t len)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (uint32_t i = 0; i < len; i++)
        h = (h ^ input[i]) * 0x100000001b3ull;
    return h;
}

static void control_work(unsigned char *out, uint32_t *out_len, uint64_t seed, uint64_t iterations)
{
    uint64_t x = seed;
    for (uint64_t i = 0; i < iterations; i++) {
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        __asm__ volatile("" : "+r"(x));
    }
    for (int b = 0; b < 8; b++) {
        out[b] = (unsigned char)(x >> (56 - 8 * b));
        out[8 + b] = (unsigned char)(iterations >> (56 - 8 * b));
    }
    *out_len = 16;
}

static TPM_RESULT control_positive(unsigned char **resp, uint32_t *resp_len, uint32_t *resp_cap,
                                   unsigned char *input, uint32_t len)
{
    (void)resp_cap;
    if (len != CONTROL_SCALAR_BYTES)
        return TPM_BAD_PARAMETER;
    uint64_t bits = 0;
    for (uint32_t i = 0; i < CONTROL_COUNTED_BYTES; i++)
        bits += (uint64_t)__builtin_popcount(input[CONTROL_SCALAR_BYTES - CONTROL_COUNTED_BYTES + i] ^ CONTROL_MASK[i]);
    control_work(*resp, resp_len, control_mix_seed(input, len),
                 CONTROL_BASE_ITERATIONS + CONTROL_ITERATIONS_PER_BIT * bits);
    return TPM_SUCCESS;
}

static TPM_RESULT control_negative(unsigned char **resp, uint32_t *resp_len, uint32_t *resp_cap,
                                   unsigned char *input, uint32_t len)
{
    (void)resp_cap;
    (void)input;
    if (len != CONTROL_SCALAR_BYTES)
        return TPM_BAD_PARAMETER;
    control_work(*resp, resp_len, 0x5eed5eed5eed5eedull,
                 CONTROL_BASE_ITERATIONS + CONTROL_ITERATIONS_PER_BIT * 32u);
    return TPM_SUCCESS;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static struct bytes parse_hex(const char *hex)
{
    struct bytes out = {NULL, 0};
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > MAX_COMMAND)
        fail("malformed-hex");
    out.len = (uint32_t)(n / 2);
    out.data = malloc(out.len ? out.len : 1);
    if (out.data == NULL)
        fail("out-of-memory");
    for (uint32_t i = 0; i < out.len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            fail("malformed-hex");
        out.data[i] = (unsigned char)(hi << 4 | lo);
    }
    return out;
}

static void print_hex(const unsigned char *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void report_timer(const char *prefix)
{
    uint64_t ns0 = monotonic_ns();
    int64_t c0 = cpucycles();
    struct timespec pause = {0, 20000000};
    nanosleep(&pause, NULL);
    int64_t c1 = cpucycles();
    uint64_t ns1 = monotonic_ns();
    int64_t previous = cpucycles();
    int64_t granularity = INT64_MAX;
    for (int i = 0; i < 200000; i++) {
        int64_t now = cpucycles();
        if (now != previous) {
            if (now - previous < granularity)
                granularity = now - previous;
            previous = now;
        }
    }
    printf("%stimer dudect-cpucycles-rdtsc-mfence\n", prefix);
    printf("%sticks_per_ns %.6f\n", prefix, (double)(c1 - c0) / (double)(ns1 - ns0));
    printf("%stimer_granularity_ticks %" PRId64 "\n", prefix, granularity);
}

#if defined(__linux__)
struct phdr_search {
    char path[4096];
};

static int find_libcrypto(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    struct phdr_search *search = data;
    if (info->dlpi_name != NULL && strstr(info->dlpi_name, "libcrypto") != NULL) {
        snprintf(search->path, sizeof(search->path), "%s", info->dlpi_name);
        return 1;
    }
    return 0;
}
#endif

static void report_libcrypto(const char *prefix)
{
    char path[4096] = "";
#if defined(__linux__)
    struct phdr_search search;
    search.path[0] = '\0';
    dl_iterate_phdr(find_libcrypto, &search);
    snprintf(path, sizeof(path), "%s", search.path);
#elif defined(__APPLE__)
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name != NULL && strstr(name, "libcrypto") != NULL) {
            snprintf(path, sizeof(path), "%s", name);
            break;
        }
    }
#endif
    printf("%slibcrypto_path %s\n", prefix, path[0] ? path : "-");
    const char *(*version)(int) = NULL;
    if (g_library != NULL)
        *(void **)&version = dlsym(g_library, "OpenSSL_version");
    printf("%sopenssl_version %s\n", prefix, version ? version(0) : "-");
}

static void apply_affinity(const char *prefix, int cpu)
{
    printf("%saffinity_requested %d\n", prefix, cpu);
    if (cpu < 0) {
        printf("%saffinity_applied no\n", prefix);
        printf("%saffinity_detail not-requested\n", prefix);
        return;
    }
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == 0) {
        printf("%saffinity_applied yes\n", prefix);
        printf("%saffinity_detail sched_setaffinity-cpu-%d\n", prefix, cpu);
    } else {
        printf("%saffinity_applied no\n", prefix);
        printf("%saffinity_detail sched_setaffinity-errno-%d\n", prefix, errno);
    }
#else
    printf("%saffinity_applied no\n", prefix);
    printf("%saffinity_detail unsupported-on-this-os\n", prefix);
#endif
}

static void init_backend(const char *prefix, const char *kind, const char *argument, int cpu)
{
    if (g_kind != BACKEND_NONE)
        fail("already-initialized");
    apply_affinity(prefix, cpu);
    g_response_capacity = RESPONSE_CAPACITY;
    g_response = malloc(g_response_capacity);
    if (g_response == NULL)
        fail("out-of-memory");
    unsigned char nonce[16];
    randombytes(nonce, sizeof(nonce));
    printf("%sprotocol %d\n", prefix, WORKER_PROTOCOL);
    printf("%spid %ld\n", prefix, (long)getpid());
    printf("%ssession ", prefix);
    print_hex(nonce, sizeof(nonce));
    printf("\n");
    if (strcmp(kind, "tpm") == 0) {
        g_library = dlopen(argument, RTLD_NOW | RTLD_LOCAL);
        if (g_library == NULL) {
            printf("error library-load-failed %s\n", dlerror());
            fflush(stdout);
            exit(3);
        }
        TPM_RESULT (*register_callbacks)(struct libtpms_callbacks *) = NULL;
        TPM_RESULT (*choose)(TPMLIB_TPMVersion) = NULL;
        TPM_RESULT (*set_profile)(const char *) = NULL;
        TPM_RESULT (*main_init)(void) = NULL;
        uint32_t (*get_version)(void) = NULL;
        *(void **)&register_callbacks = dlsym(g_library, "TPMLIB_RegisterCallbacks");
        *(void **)&choose = dlsym(g_library, "TPMLIB_ChooseTPMVersion");
        *(void **)&set_profile = dlsym(g_library, "TPMLIB_SetProfile");
        *(void **)&main_init = dlsym(g_library, "TPMLIB_MainInit");
        *(void **)&get_version = dlsym(g_library, "TPMLIB_GetVersion");
        *(void **)&g_process = dlsym(g_library, "TPMLIB_Process");
        *(void **)&g_drbg_hook = dlsym(g_library, "TPMS_TIMING_DRBG_v1");
        if (!register_callbacks || !choose || !set_profile || !main_init || !get_version || !g_process)
            fail("missing-libtpms-symbol");
        Dl_info info;
        if (dladdr(*(void **)&g_process, &info) != 0 && info.dli_fname != NULL)
            printf("%slibrary_loaded_path %s\n", prefix, info.dli_fname);
        printf("%stpmlib_version %08x\n", prefix, get_version());
        struct libtpms_callbacks callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.sizeOfStruct = sizeof(callbacks);
        callbacks.tpm_nvram_init = nv_init;
        callbacks.tpm_nvram_loaddata = nv_load;
        callbacks.tpm_nvram_storedata = nv_store;
        callbacks.tpm_nvram_deletename = nv_delete;
        callbacks.tpm_io_getlocality = io_locality;
        if (register_callbacks(&callbacks) != TPM_SUCCESS)
            fail("register-callbacks-failed");
        if (choose(TPMLIB_TPM_VERSION_2) != TPM_SUCCESS)
            fail("choose-tpm-version-failed");
        if (set_profile("{\"Name\":\"default-v1\"}") != TPM_SUCCESS)
            fail("set-profile-failed");
        if (main_init() != TPM_SUCCESS)
            fail("main-init-failed");
        printf("%sprofile default-v1\n", prefix);
        g_kind = BACKEND_TPM;
    } else if (strcmp(kind, "control") == 0 && strcmp(argument, "positive") == 0) {
        g_process = control_positive;
        g_kind = BACKEND_POSITIVE;
    } else if (strcmp(kind, "control") == 0 && strcmp(argument, "negative") == 0) {
        g_process = control_negative;
        g_kind = BACKEND_NEGATIVE;
    } else {
        fail("unknown-backend");
    }
    printf("%sbackend %s %s\n", prefix, kind, argument);
    report_libcrypto(prefix);
    report_timer(prefix);
}

static TPM_RESULT dispatch_command(unsigned char *, uint32_t, uint32_t *);

static TPM_RESULT run_command(const unsigned char *command, uint32_t len, uint32_t *response_len)
{
    static unsigned char work[MAX_COMMAND];
    memcpy(work, command, len);
    *response_len = 0;
    return dispatch_command(work, len, response_len);
}

static int masked_equal(const unsigned char *response, uint32_t len, const struct bytes *expected,
                        const struct bytes *mask)
{
    if (len != expected->len)
        return 0;
    for (uint32_t i = 0; i < len; i++) {
        unsigned char m = (mask != NULL && i < mask->len) ? mask->data[i] : 0xff;
        if ((response[i] & m) != (expected->data[i] & m))
            return 0;
    }
    return 1;
}

static int response_matches_masked(TPM_RESULT rc, uint32_t len, const struct bytes *expected,
                                   const struct bytes *mask)
{
    return rc == TPM_SUCCESS && masked_equal(g_response, len, expected, mask);
}

static int response_matches(TPM_RESULT rc, uint32_t len, const struct bytes *expected)
{
    return response_matches_masked(rc, len, expected, NULL);
}

static uint32_t tpm_response_code(const unsigned char *response, uint32_t len)
{
    if (len < 10)
        return 0xffffffffu;
    return (uint32_t)response[6] << 24 | (uint32_t)response[7] << 16 | (uint32_t)response[8] << 8 | response[9];
}

/* Versioned bounded test-only programs. All interpreter work, TPM steps and declared
 * cleanup are inside the existing timestamps. No upstream dudect changes. */
#define PROGRAM_FAILED 0xfffffffdu
#define PROGRAM_STEPS 8
static int g_poisoned;
struct program_reader { const unsigned char *data; uint32_t len, at; int bad; };
static const unsigned char *pr_take(struct program_reader *r, uint32_t n)
{
    if (r->bad || r->at > r->len || n > r->len - r->at) { r->bad = 1; return NULL; }
    const unsigned char *p = r->data + r->at; r->at += n; return p;
}
static uint32_t pr_int(struct program_reader *r, uint32_t n)
{
    const unsigned char *p = pr_take(r, n); uint32_t v = 0;
    if (p != NULL) for (uint32_t i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}
static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void put_be16(unsigned char *p, uint32_t n) { p[0] = n >> 8; p[1] = n; }
static void put_be32(unsigned char *p, uint32_t n) { p[0] = n >> 24; p[1] = n >> 16; p[2] = n >> 8; p[3] = n; }
struct program_step {
    const unsigned char *command, *expected, *mask, *patches;
    uint32_t command_len, slot, handles, auth_count, resource, consumes, patch_count, code, min, max, expected_len, patch_len;
    unsigned char response[SLOT_SIZE]; uint32_t response_len, param_at, param_len, handle;
    int live;
};
static int program_frame(const unsigned char *p, uint32_t len, uint32_t handles, uint32_t *at, uint32_t *size, uint32_t *auth_count)
{
    if (len < 10 || handles > 1 || be32(p+2) != len || p[0] != 0x80 || (p[1] != 1 && p[1] != 2)) return 0;
    *at = 10; *size = 0; *auth_count=0;
    if (be32(p+6) != 0) return p[1] == 1 && len == 10;
    uint32_t start = 10 + 4*handles;
    if (start > len) return 0;
    if (p[1] == 1) { *at = start; *size = len-start; return 1; }
    if (len-start < 4) return 0;
    *size = be32(p+start); *at = start+4;
    if (*size > len-*at) return 0;
    struct program_reader r = {p,len,*at+*size,0}; uint32_t count = 0;
    while (!r.bad && r.at < len && count < 3) {
        uint32_t n = pr_int(&r,2); pr_take(&r,n); pr_int(&r,1); n = pr_int(&r,2); pr_take(&r,n); count++;
    }
    *auth_count=count;
    return !r.bad && r.at == len && count > 0;
}
static int program_contract(struct program_step *s, const unsigned char *p, uint32_t len)
{
    uint32_t auth_count=0;
    if (!program_frame(p,len,s->handles,&s->param_at,&s->param_len,&auth_count) || auth_count!=s->auth_count || len < s->min || len > s->max || be32(p+6) != s->code) return 0;
    if (s->expected_len) {
        if (len != s->expected_len) return 0;
        for (uint32_t i=0;i<len;i++) if ((p[i]&s->mask[i]) != (s->expected[i]&s->mask[i])) return 0;
    }
    return 1;
}
/* Only ECDAA has a variable-width signature inside these ECC programs. Infer the
 * requested algorithm/hash from Sign, and consume both TPM2B fields completely.
 * Cryptographic equations run independently in Rust outside the timed interval. */
static int program_ecdaa_response(const struct program_step *s, const unsigned char *work,
                                  const unsigned char *response, uint32_t len)
{
    if (be32(work+6)!=0x15d || s->code!=0) return 1;
    if (s->command_len<18 || work[1]!=2) return 0;
    struct program_reader cmd={work,s->command_len,14,0};
    uint32_t n=pr_int(&cmd,4);pr_take(&cmd,n);n=pr_int(&cmd,2);pr_take(&cmd,n);
    uint32_t scheme=pr_int(&cmd,2), hash=pr_int(&cmd,2);
    if (cmd.bad) return 0;
    if (scheme!=0x1a) return 1;
    /* Declared ECDAA bounds encode a minimal 1-byte nonce and a full-width s:
     * min=19+8+1+width, max=19+8+2*width. No curve-dependent guess from output. */
    if (s->min<28) return 0;
    uint32_t width=s->min-28;
    if ((width!=24 && width!=28 && width!=32 && width!=48 && width!=66 && width!=80) || s->max!=27+2*width) return 0;
    struct program_reader r={response+s->param_at,s->param_len,0,0};
    if (pr_int(&r,2)!=scheme || pr_int(&r,2)!=hash) return 0;
    n=pr_int(&r,2);const unsigned char *nonce=pr_take(&r,n);
    if (r.bad || n==0 || n>width || nonce[0]==0) return 0;
    n=pr_int(&r,2);const unsigned char *scalar=pr_take(&r,n);
    if (r.bad || n!=width || r.at!=r.len) return 0;
    unsigned char nonzero=0;for(uint32_t i=0;i<n;i++)nonzero|=scalar[i];
    static const unsigned char auth[5]={0,0,1,0,0};
    return nonzero && s->param_at+s->param_len+5==len && memcmp(response+s->param_at+s->param_len,auth,5)==0;
}
static uint32_t program_resource(uint32_t cc)
{
    if (cc == 0x18b || cc == 0x18e) return 2;
    if (cc == 0x131 || cc == 0x157 || cc == 0x161 || cc == 0x167 || cc == 0x176 || cc == 0x15b || cc == 0x186 || cc == 0x191) return 1;
    return 0;
}
static const unsigned char *program_range(struct program_reader *r, struct program_step *steps, uint32_t current, int execute, uint32_t *len)
{
    uint32_t prior=pr_int(r,1), area=pr_int(r,1), offset=pr_int(r,2); *len=pr_int(r,2);
    if (r->bad || prior >= current || area > 2 || *len == 0 || offset+*len > steps[prior].slot) { r->bad=1; return NULL; }
    struct program_step *s=&steps[prior];
    if (!execute) return r->data; /* structural validation only */
    uint32_t n=area ? s->param_len : s->response_len;
    if (offset+*len > n) { r->bad=1; return NULL; }
    uint32_t start=area ? s->param_at : 0;
    start += area == 2 ? n-offset-*len : offset;
    return s->response+start;
}
/* Reads `count` HMAC-part descriptors, validating their lengths; at execute
 * time the referenced bytes are appended to the message buffer. */
static int program_append_parts(struct program_reader *r, struct program_step *steps, uint32_t index,
                                int execute, uint32_t count,
                                unsigned char *message, uint32_t *message_len)
{
    for (uint32_t j=0; j<count && !r->bad; j++) {
        uint32_t part=pr_int(r,1), m=0; const unsigned char *p=NULL;
        if (part == 0) { m=pr_int(r,2); p=pr_take(r,m); }
        else if (part == 1) p=program_range(r,steps,index,execute,&m);
        else r->bad=1;
        if (!r->bad && m>MAX_COMMAND-*message_len) r->bad=1;
        if (!r->bad) { if (execute) memcpy(message+*message_len,p,m); *message_len+=m; }
    }
    return !r->bad;
}
/* Parses the request-cipher key: fixed bytes, or a run-time session key
 * derived with the same single-block KDFa(hash, kdf_key, "ATH", U, V) the
 * authorization HMAC patch uses, followed by fixed trailer bytes. Writes the
 * resolved key into `buffer` (64+1024 bytes) at execute time and returns its
 * length, or 0 with r->bad set when the descriptor is rejected. */
static uint32_t program_cipher_key(struct program_reader *r, struct program_step *steps, uint32_t index,
                                   int execute, const char *name, uint32_t n,
                                   const unsigned char **key, unsigned char *buffer)
{
    if (r->bad) return 0;
    uint32_t kind=pr_int(r,1);
    if (kind>1) { r->bad=1; return 0; }
    if (kind==0) {
        uint32_t len=pr_int(r,2);
        if (r->bad || len>1024) { r->bad=1; return 0; }
        const unsigned char *fixed=pr_take(r,len);
        if (r->bad) return 0;
        *key=fixed;
        return len;
    }
    uint32_t kdf_key_len=pr_int(r,2), u_count=pr_int(r,1), v_count=pr_int(r,1), extra_len=pr_int(r,2);
    if (r->bad || kdf_key_len>1024 || extra_len>1024 || n>64 || n+extra_len>64+1024 ||
        u_count==0 || v_count==0 || u_count>16 || v_count>16) { r->bad=1; return 0; }
    const unsigned char *kdf_key=pr_take(r,kdf_key_len);
    unsigned char message[MAX_COMMAND]; uint32_t message_len=0, bits=n*8;
    static const unsigned char counter[4]={0x00,0x00,0x00,0x01};
    static const unsigned char ath_label[4]={'A','T','H',0x00};
    if (execute) memcpy(message,counter,4);
    message_len=4;
    if (execute) memcpy(message+message_len,ath_label,4);
    message_len+=4;
    if (!program_append_parts(r,steps,index,execute,u_count+v_count,message,&message_len)) { r->bad=1; return 0; }
    if (message_len>MAX_COMMAND-4) { r->bad=1; return 0; }
    for (uint32_t j=0; j<4 && !r->bad; j++) {
        unsigned char byte=(bits>>(8*(3-j)))&0xff;
        if (execute) message[message_len]=byte;
        message_len++;
    }
    const unsigned char *extra=pr_take(r,extra_len);
    if (r->bad) return 0;
    if (execute) {
        const void *(*md)(void)=NULL;
        unsigned char *(*hmac)(const void *,const void *,int,const unsigned char *,size_t,unsigned char *,unsigned int *)=NULL;
        *(void **)&md=dlsym(g_library,name); *(void **)&hmac=dlsym(g_library,"HMAC");
        unsigned char digest[64]; unsigned int result_len=0;
        if (md==NULL || hmac==NULL ||
            hmac(md(),kdf_key,(int)kdf_key_len,message,message_len,digest,&result_len)==NULL ||
            result_len!=n) { r->bad=1; return 0; }
        memcpy(buffer,digest,n);
        if (extra_len) memcpy(buffer+n,extra,extra_len);
    }
    *key=buffer;
    return n+extra_len;
}
/* Request-parameter cipher shared by the Encrypt patch and the encrypted-cpHash
 * branch of the session HMAC patch: XOR mask blocks ("XOR\0") or one AES-128-CFB
 * KDFa block ("CFB\0", 256 bits -> key || IV). */
static int program_cipher(unsigned char *out, int cfb, uint32_t dsz,
                          const unsigned char *key, uint32_t key_len,
                          const unsigned char *caller, uint32_t caller_len,
                          const unsigned char *nonce, uint32_t nonce_len,
                          const unsigned char *plain, uint32_t plain_len)
{
    const void *(*md)(void)=NULL;
    unsigned char *(*hmac_fn)(const void *,const void *,int,const unsigned char *,size_t,unsigned char *,unsigned int *)=NULL;
    *(void **)&md=dlsym(g_library, dsz==20?"EVP_sha1":dsz==32?"EVP_sha256":dsz==48?"EVP_sha384":"EVP_sha512");
    *(void **)&hmac_fn=dlsym(g_library,"HMAC");
    if (md==NULL || hmac_fn==NULL) return 0;
    /* Both KDF layouts reserve one caller and one nonce field of at most
     * 64 bytes each; reject larger descriptors before touching the stack
     * buffers, for AES-128-CFB and XOR alike. */
    if (nonce_len==0 || nonce_len>64 || caller_len==0 || caller_len>64 || plain_len==0) return 0;
    if (cfb) {
        if (dsz<32) return 0;
        unsigned char kdf[4+4+64+64+4]; uint32_t kdf_len=0;
        kdf[kdf_len++]=0;kdf[kdf_len++]=0;kdf[kdf_len++]=0;kdf[kdf_len++]=1;
        kdf[kdf_len++]='C';kdf[kdf_len++]='F';kdf[kdf_len++]='B';kdf[kdf_len++]=0;
        memcpy(kdf+kdf_len,caller,caller_len); kdf_len+=caller_len;
        memcpy(kdf+kdf_len,nonce,nonce_len); kdf_len+=nonce_len;
        uint32_t bits=256; for(uint32_t j=0;j<4;j++){kdf[kdf_len++]=(bits>>(8*(3-j)))&0xff;}
        unsigned int result_len=0;
        unsigned char material[64];
        if (hmac_fn(md(),key,(int)key_len,kdf,kdf_len,material,&result_len)==NULL || result_len != dsz || dsz<32) return 0;
        int (*set_key)(const unsigned char *,const int,void *)=NULL;
        void (*cfb_enc)(const unsigned char *,unsigned char *,size_t,const void *,unsigned char *,int *,int)=NULL;
        *(void **)&set_key=dlsym(g_library,"AES_set_encrypt_key");
        *(void **)&cfb_enc=dlsym(g_library,"AES_cfb128_encrypt");
        static unsigned char aes_rounds[512];
        if (set_key==NULL || cfb_enc==NULL || set_key(material,128,aes_rounds)!=0) return 0;
        int num=0;
        cfb_enc(plain,out,plain_len,aes_rounds,material+16,&num,1);
        return 1;
    }
    uint32_t request_bits=plain_len*8, block=0, produced=0;
    while (produced<plain_len) {
        block++;
        unsigned char kdf[4+4+64+64+4]; uint32_t kdf_len=0;
        for(uint32_t j=0;j<4;j++){kdf[kdf_len++]=(block>>(8*(3-j)))&0xff;}
        kdf[kdf_len++]='X';kdf[kdf_len++]='O';kdf[kdf_len++]='R';kdf[kdf_len++]=0;
        memcpy(kdf+kdf_len,caller,caller_len); kdf_len+=caller_len;
        memcpy(kdf+kdf_len,nonce,nonce_len); kdf_len+=nonce_len;
        for(uint32_t j=0;j<4;j++){kdf[kdf_len++]=(request_bits>>(8*(3-j)))&0xff;}
        unsigned char digest3[64]; unsigned int result_len=0;
        if (hmac_fn(md(),key,(int)key_len,kdf,kdf_len,digest3,&result_len)==NULL || result_len != dsz) return 0;
        uint32_t take=plain_len<produced+result_len?plain_len-produced:result_len;
        for (uint32_t j=0;j<take;j++) out[produced+j]=digest3[j]^plain[produced+j];
        produced+=take;
    }
    return 1;
}

static int program_patches(struct program_reader *r, struct program_step *steps, uint32_t index, unsigned char *work)
{
    struct program_step *s=&steps[index]; int execute=work != NULL;
    for (uint32_t i=0; i<s->patch_count && !r->bad; i++) {
        uint32_t kind=pr_int(r,1), at=pr_int(r,2), n=0;
        const unsigned char *source=NULL, *delta=NULL; unsigned char digest[64];
        unsigned char out[MAX_COMMAND];
        if (kind == 0) {
            source=program_range(r,steps,index,execute,&n); delta=pr_take(r,n);
        } else if (kind == 1) {
            uint32_t hash=pr_int(r,2), key_len=pr_int(r,2), count=pr_int(r,1);
            const unsigned char *key=pr_take(r,key_len); const char *name=NULL;
            switch (hash) { case 4: name="EVP_sha1"; n=20; break; case 11:name="EVP_sha256";n=32;break;case 12:name="EVP_sha384";n=48;break;case 13:name="EVP_sha512";n=64;break;default:r->bad=1; }
            if (key_len>1024 || count==0 || count>16) r->bad=1;
            unsigned char message[MAX_COMMAND]; uint32_t message_len=0;
            for (uint32_t j=0; j<count && !r->bad; j++) {
                uint32_t part=pr_int(r,1), m=0; const unsigned char *p=NULL;
                if (part == 0) { m=pr_int(r,2); p=pr_take(r,m); }
                else if (part == 1) p=program_range(r,steps,index,execute,&m);
                else r->bad=1;
                if (m>MAX_COMMAND-message_len) r->bad=1;
                if (!r->bad) { if (execute) memcpy(message+message_len,p,m); message_len+=m; }
            }
            delta=pr_take(r,n);
            if (execute && !r->bad) {
                const void *(*md)(void)=NULL;
                unsigned char *(*hmac)(const void *,const void *,int,const unsigned char *,size_t,unsigned char *,unsigned int *)=NULL;
                *(void **)&md=dlsym(g_library,name); *(void **)&hmac=dlsym(g_library,"HMAC"); unsigned int result_len=0;
                if (md==NULL || hmac==NULL || hmac(md(),key,(int)key_len,message,message_len,digest,&result_len)==NULL || result_len != n) r->bad=1;
                source=digest;
            }
        } else if (kind == 2) {
            /* Session-key-deriving authorization HMAC (mirrors program.rs SessionHmac):
             * sessionKey = KDFa(hash, kdf_key, "ATH", u_parts, v_parts) single block
             * authHmac  = HMAC(hash, sessionKey || extra_key, main parts). */
            uint32_t hash=pr_int(r,2), kdf_key_len=pr_int(r,2), u_count=pr_int(r,1),
                     v_count=pr_int(r,1), extra_len=pr_int(r,2), count=pr_int(r,1);
            const char *name=NULL;
            switch (hash) { case 4: name="EVP_sha1"; n=20; break; case 11:name="EVP_sha256";n=32;break;case 12:name="EVP_sha384";n=48;break;case 13:name="EVP_sha512";n=64;break;default:r->bad=1; }
            if (kdf_key_len>1024 || extra_len>1024 || u_count==0 || v_count==0 || u_count>16 || v_count>16 || count==0 || count>16) r->bad=1;
            const unsigned char *kdf_key=pr_take(r,kdf_key_len);
            unsigned char message[MAX_COMMAND]; uint32_t message_len=0, bits=n*8;
            static const unsigned char counter[4]={0x00,0x00,0x00,0x01};
            static const unsigned char ath_label[4]={'A','T','H',0x00};
            for (uint32_t j=0; j<4 && !r->bad; j++) { if (execute) message[message_len]=counter[j]; message_len++; }
            for (uint32_t j=0; j<4 && !r->bad; j++) { if (execute) message[message_len]=ath_label[j]; message_len++; }
            if (!program_append_parts(r,steps,index,execute,u_count+v_count,message,&message_len)) r->bad=1;
            /* The trailing bit-length field is appended after the variable
             * parts, so its four bytes must fit as well. */
            if (!r->bad && message_len>MAX_COMMAND-4) r->bad=1;
            for (uint32_t j=0; j<4 && !r->bad; j++) {
                unsigned char byte=(bits>>(8*(3-j)))&0xff; if (execute) message[message_len]=byte; message_len++;
            }
            const unsigned char *extra_key=pr_take(r,extra_len);
            unsigned char message2[MAX_COMMAND]; uint32_t message2_len=0;
            if (!program_append_parts(r,steps,index,execute,count,message2,&message2_len)) r->bad=1;
            delta=pr_take(r,n);
            /* Encrypted-cpHash descriptor: both backends authorize before
             * decrypting, so the cpHash inside the request HMAC covers the
             * first parameter in encrypted form. Layout mirrors the Rust
             * encoder: [has_cp u8][cc u32][name u16][caller u16]
             * [prefix u16][suffix u16][plain u16][cfb u8][name][cipher key]
             * [caller][nonce range 6][prefix][suffix][plain]. */
            uint32_t has_cp=pr_int(r,1); int cp_cfb=0; uint32_t cp_cc=0;
            const unsigned char *cp_name=NULL,*cp_caller=NULL,*cp_prefix=NULL,*cp_suffix=NULL,*cp_plain=NULL,*cp_nonce=NULL;
            const unsigned char *cp_key=NULL;
            uint32_t cp_name_len=0,cp_key_len=0,cp_caller_len=0,cp_prefix_len=0,cp_suffix_len=0,cp_plain_len=0,cp_nonce_len=0;
            unsigned char cp_key_buffer[64+1024];
            if (has_cp==1) {
                cp_cc=pr_int(r,4);
                cp_name_len=pr_int(r,2); cp_caller_len=pr_int(r,2);
                cp_prefix_len=pr_int(r,2); cp_suffix_len=pr_int(r,2); cp_plain_len=pr_int(r,2);
                uint32_t mode=pr_int(r,1);
                if (mode>1) r->bad=1;
                cp_cfb=mode==1;
                if (cp_name_len>128 || cp_caller_len==0 || cp_caller_len>64 ||
                    cp_prefix_len>512 || cp_suffix_len>512 || cp_plain_len==0 || cp_plain_len>512 ||
                    (cp_cfb && n<32)) r->bad=1;
                cp_name=pr_take(r,cp_name_len);
                cp_key_len=program_cipher_key(r,steps,index,execute,name,n,&cp_key,cp_key_buffer);
                cp_caller=pr_take(r,cp_caller_len);
                cp_nonce=program_range(r,steps,index,execute,&cp_nonce_len);
                cp_prefix=pr_take(r,cp_prefix_len);
                cp_suffix=pr_take(r,cp_suffix_len);
                cp_plain=pr_take(r,cp_plain_len);
                if (cp_nonce_len==0 || cp_nonce_len>64 || cp_key==NULL) r->bad=1;
                if (cp_prefix_len+cp_plain_len+cp_suffix_len>MAX_COMMAND) r->bad=1;
            } else if (has_cp!=0) r->bad=1;
            if (message_len>MAX_COMMAND || extra_len>1024) r->bad=1;
            if (has_cp==1 && message2_len+n>MAX_COMMAND) r->bad=1;
            if (execute && !r->bad) {
                const void *(*md)(void)=NULL;
                unsigned char *(*hmac)(const void *,const void *,int,const unsigned char *,size_t,unsigned char *,unsigned int *)=NULL;
                *(void **)&md=dlsym(g_library,name); *(void **)&hmac=dlsym(g_library,"HMAC"); unsigned int result_len=0;
                if (md==NULL || hmac==NULL) r->bad=1;
                if (!r->bad && hmac(md(),kdf_key,(int)kdf_key_len,message,message_len,digest,&result_len)==NULL) r->bad=1;
                if (!r->bad && result_len != n) r->bad=1;
                if (has_cp==1 && !r->bad) {
                    /* cpHash = hash(cc || name || prefix || cipher || suffix);
                     * the cipher is exactly the request-masked parameter. */
                    unsigned char cp_msg[4+128+512+512+512]; uint32_t cp_len=0;
                    cp_msg[cp_len++]=(cp_cc>>24)&0xff; cp_msg[cp_len++]=(cp_cc>>16)&0xff;
                    cp_msg[cp_len++]=(cp_cc>>8)&0xff; cp_msg[cp_len++]=cp_cc&0xff;
                    memcpy(cp_msg+cp_len,cp_name,cp_name_len); cp_len+=cp_name_len;
                    memcpy(cp_msg+cp_len,cp_prefix,cp_prefix_len); cp_len+=cp_prefix_len;
                    unsigned char cipher[512];
                    if (!program_cipher(cipher,cp_cfb,n,cp_key,cp_key_len,cp_caller,cp_caller_len,cp_nonce,cp_nonce_len,cp_plain,cp_plain_len)) r->bad=1;
                    if (!r->bad) {
                        memcpy(cp_msg+cp_len,cipher,cp_plain_len); cp_len+=cp_plain_len;
                        memcpy(cp_msg+cp_len,cp_suffix,cp_suffix_len); cp_len+=cp_suffix_len;
                        unsigned char *(*sha_fn)(const unsigned char *,size_t,unsigned char *)=NULL;
                        *(void **)&sha_fn=dlsym(g_library,n==20?"SHA1":n==32?"SHA256":n==48?"SHA384":"SHA512");
                        if (sha_fn==NULL) r->bad=1;
                        else {
                            unsigned char cp_digest[64];
                            if (sha_fn(cp_msg,cp_len,cp_digest)==NULL) r->bad=1;
                            if (!r->bad) {
                                memmove(message2+n,message2,message2_len);
                                memcpy(message2,cp_digest,n);
                                message2_len+=n;
                            }
                        }
                    }
                }
                unsigned char session_key[64+1024];
                unsigned char digest2[64];
                if (n>64) r->bad=1;
                if (!r->bad) {
                    memcpy(session_key,digest,n); if (extra_len) memcpy(session_key+n,extra_key,extra_len);
                    if (hmac(md(),session_key,(int)(n+extra_len),message2,message2_len,digest2,&result_len)==NULL || result_len != n) r->bad=1;
                }
                if (!r->bad) memcpy(digest,digest2,n);
                source=digest;
            }
        } else if (kind == 3) {
            /* Request-parameter protection (mirrors program.rs Encrypt): the
             * request mask is KDFa(hash, key, "XOR"/"CFB", nonceCaller,
             * nonceTPM) with nonceTPM taken from a prior response; the key is
             * fixed bytes or a run-time session-key derivation, matching
             * CryptParameterDecryption for unbound and salted decrypt
             * sessions. */
            uint32_t hash=pr_int(r,2), cfb=pr_int(r,1), caller_len=pr_int(r,2),
                     plain_len=pr_int(r,2);
            uint32_t dsz=0;
            const char *name=NULL;
            switch (hash) { case 4: name="EVP_sha1"; dsz=20; break; case 11:name="EVP_sha256";dsz=32;break;case 12:name="EVP_sha384";dsz=48;break;case 13:name="EVP_sha512";dsz=64;break;default:r->bad=1; }
            if (cfb>1 || (cfb && dsz<32) || caller_len==0 || caller_len>64 || plain_len==0 || plain_len>MAX_COMMAND) r->bad=1;
            const unsigned char *caller=pr_take(r,caller_len);
            const unsigned char *key=NULL; uint32_t key_len=0;
            unsigned char key_buffer[64+1024];
            key_len=program_cipher_key(r,steps,index,execute,name,dsz,&key,key_buffer);
            uint32_t nonce_len=0;
            const unsigned char *nonce_tpmp=program_range(r,steps,index,execute,&nonce_len);
            const unsigned char *plain=pr_take(r,plain_len);
            if (nonce_len==0 || nonce_len>64 || key==NULL) r->bad=1;
            n=plain_len;
            if (execute && !r->bad) {
                if (!program_cipher(out,cfb,dsz,key,key_len,caller,caller_len,nonce_tpmp,nonce_len,plain,plain_len)) r->bad=1;
                if (!r->bad) { static const unsigned char zeros[MAX_COMMAND]; source=out; delta=zeros; }
            }
        } else r->bad=1;
        if (at<10 || at>s->command_len || n>s->command_len-at) r->bad=1;
        if (execute && !r->bad) for (uint32_t j=0;j<n;j++) work[at+j]=source[j]^delta[j];
    }
    return !r->bad;
}
static int program_decode(const unsigned char *command, uint32_t len, struct program_step *steps, uint32_t *count)
{
    if (len<9 || len>MAX_COMMAND || memcmp(command,"\xffTPG",4)!=0) return 0;
    struct program_reader r={command,len,4,0}; uint32_t version=pr_int(&r,1); *count=pr_int(&r,1);
    if (version!=1 || *count==0 || *count>PROGRAM_STEPS || pr_int(&r,2)!=len) return 0;
    uint32_t outcome=pr_int(&r,1);
    if (outcome!=255 && outcome>=*count) return 0;
    uint32_t transcript_len=16, consumed=0;
    for (uint32_t i=0; i<*count && !r.bad;i++) {
        struct program_step *s=&steps[i];
        s->command_len=pr_int(&r,2);s->slot=pr_int(&r,2);s->handles=pr_int(&r,1);s->auth_count=pr_int(&r,1);s->resource=pr_int(&r,1);
        s->consumes=pr_int(&r,1);s->patch_count=pr_int(&r,1);s->code=pr_int(&r,4);s->min=pr_int(&r,2);s->max=pr_int(&r,2);s->expected_len=pr_int(&r,2);
        s->command=pr_take(&r,s->command_len);s->expected=pr_take(&r,s->slot);s->mask=pr_take(&r,s->slot);
        transcript_len+=4+s->slot;
        if (r.bad || s->command_len<10 || s->handles>1 || s->auth_count>3 || s->resource>2 || s->patch_count>16 || s->min<10 || s->min>s->max || s->max>s->slot || s->expected_len>s->slot || transcript_len>SLOT_SIZE ||
            (s->expected_len && (s->expected_len!=s->min || s->min!=s->max)) || (s->code && i+1!=*count)) return 0;
        for (uint32_t k=s->expected_len;k<s->slot;k++) if (s->expected[k] || s->mask[k]) return 0;
        if (s->command[0]!=0x80 || (s->command[1]!=1 && s->command[1]!=2) || be32(s->command+2)!=s->command_len) return 0;
        if ((!s->code && ((s->command[1]==2)!=(s->auth_count>0))) || (s->code && s->auth_count)) return 0;
        uint32_t cc=be32(s->command+6);
        if (program_resource(cc)!=s->resource || (s->resource==1 && s->handles!=1)) return 0;
        if (s->consumes >= (1u<<i) || (consumed&s->consumes)) return 0;
        for (uint32_t j=0;j<i;j++) if (s->consumes&(1u<<j)) {
            if (s->code || !steps[j].resource ||
                (steps[j].resource==1 && cc!=0x13e && cc!=0x185 && cc!=0x165) ||
                (steps[j].resource==2 && cc!=0x15d && cc!=0x18d)) return 0;
        }
        consumed|=s->consumes;
        if (s->expected_len && !program_contract(s,s->expected,s->expected_len)) return 0;
        uint32_t at=r.at; s->patches=r.data+at;
        if (!program_patches(&r,steps,i,NULL)) return 0;
        s->patch_len=r.at-at;
    }
    for (uint32_t i=0;i<*count;i++) if (steps[i].resource==2 && !(consumed&(1u<<i))) return 0;
    return !r.bad && r.at==len;
}
/* Validate a consumption against the actual patched command, never merely trust
 * the candidate's resource bitmap. A counter is consumed only by its original
 * matching producer/consumer pair and a successful TPM response. */
static int program_consumption(struct program_step *steps, uint32_t i, const unsigned char *work)
{
    struct program_step *s=&steps[i]; uint32_t cc=be32(work+6);
    for (uint32_t j=0;j<i;j++) if (s->consumes&(1u<<j)) {
        struct program_step *p=&steps[j]; if (!p->live) return 0;
        if (p->resource==1) {
            uint32_t handle_at = cc == 0x185 ? 14 : 10;
            if (s->command_len < handle_at + 4 || be32(work + handle_at) != p->handle) return 0;
        }
        else {
            uint32_t producer=be32(p->command+6), at=14;
            if ((producer==0x18b && cc!=0x15d) || (producer==0x18e && cc!=0x18d) || work[1]!=2 || s->command_len<18 || p->param_len<2) return 0;
            uint32_t auth=be32(work+at); at+=4;
            if (auth>s->command_len-at) return 0;
            at+=auth;
            if (cc==0x15d) {
                if (s->command_len-at<2) return 0;
                uint32_t digest=(uint32_t)work[at]<<8|work[at+1]; at+=2;
                if (digest>s->command_len-at) return 0;
                at+=digest;
                if (s->command_len-at<6 || work[at]!=0 || work[at+1]!=0x1a) return 0;
                at+=4;
            } else {
                for (int k=0;k<2;k++) { if (s->command_len-at<2) return 0; uint32_t n=(uint32_t)work[at]<<8|work[at+1]; at+=2; if (n>s->command_len-at) return 0; at+=n; }
                if (s->command_len-at<4) return 0;
                at+=2;
            }
            if (memcmp(work+at,p->response+p->param_at+p->param_len-2,2)!=0) return 0;
        }
    }
    return 1;
}
static TPM_RESULT program_fail(uint32_t step, uint32_t *len, int preserve)
{
    g_poisoned=1; if (!preserve) *len=0;
    fprintf(stderr,"command-program failure step=%u; worker poisoned; original response preserved=%d response=",step,preserve);
    if (preserve) for (uint32_t i=0; i<*len && i<SLOT_SIZE; i++) fprintf(stderr,"%02x",g_response[i]);
    fprintf(stderr,"\n");
    return PROGRAM_FAILED;
}
static TPM_RESULT dispatch_command(unsigned char *command, uint32_t len, uint32_t *response_len)
{
    *response_len=0;
    if (g_poisoned) return PROGRAM_FAILED;
    if (len >= 4 && memcmp(command, "\xff" "DR1", 4) == 0) {
        if (g_kind != BACKEND_TPM || g_drbg_hook == NULL) {
            fprintf(stderr, "DRBG timing hook TPMS_TIMING_DRBG_v1 missing; build Rust with --features timing-test-hooks or use the instrumented C reference build\n");
            fail("missing-drbg-timing-hook");
        }
        TPM_RESULT rc = g_drbg_hook(command + 4, len - 4, g_response,
                                    g_response_capacity, response_len);
        if (rc != TPM_SUCCESS || *response_len > g_response_capacity) {
            *response_len = 0;
            return rc != TPM_SUCCESS ? rc : TPM_FAIL;
        }
        return rc;
    }
    if (len<4 || memcmp(command,"\xffTPG",4)!=0) return g_process(&g_response,response_len,&g_response_capacity,command,len);
    struct program_step steps[PROGRAM_STEPS]; memset(steps,0,sizeof(steps)); uint32_t count=0;
    if (g_kind!=BACKEND_TPM || !program_decode(command,len,steps,&count)) return program_fail(0,response_len,0);
    unsigned char work[MAX_COMMAND], transcript[SLOT_SIZE]; memset(transcript,0,sizeof(transcript));
    transcript[0]=0x80;transcript[1]=1;memcpy(transcript+10,"TPTR\x01",5);transcript[15]=count;uint32_t out=16;
    for (uint32_t i=0;i<count;i++) {
        struct program_step *s=&steps[i]; memcpy(work,s->command,s->command_len);
        struct program_reader r={s->patches,s->patch_len,0,0};
        if (!program_patches(&r,steps,i,work) || !program_consumption(steps,i,work)) return program_fail(i,response_len,0);
        TPM_RESULT rc=g_process(&g_response,response_len,&g_response_capacity,work,s->command_len);
        if (rc!=TPM_SUCCESS || !program_contract(s,g_response,*response_len) || !program_ecdaa_response(s,work,g_response,*response_len)) return program_fail(i,response_len,1);
        s->response_len=*response_len;memcpy(s->response,g_response,*response_len);
        if (s->code==0) {
            s->live=s->resource!=0;
            if (s->resource==1) { s->handle=be32(g_response+10); uint32_t type=s->handle>>24; if (type!=0x80 && type!=2 && type!=3) return program_fail(i,response_len,1); }
            for (uint32_t j=0;j<i;j++) if (s->consumes&(1u<<j)) steps[j].live=0;
        }
        put_be16(transcript+out,*response_len);put_be16(transcript+out+2,s->slot);memcpy(transcript+out+4,g_response,*response_len);out+=4+s->slot;
    }
    for (uint32_t i=count;i>0;i--) {
        struct program_step *s=&steps[i-1]; if (!s->live) continue;
        if (s->resource!=1) return program_fail(i-1,response_len,0);
        unsigned char flush[14]={0x80,1,0,0,0,14,0,0,1,0x65};put_be32(flush+10,s->handle);
        TPM_RESULT rc=g_process(&g_response,response_len,&g_response_capacity,flush,14);uint32_t at=0,size=0,auth_count=0;
        if (rc!=TPM_SUCCESS || !program_frame(g_response,*response_len,0,&at,&size,&auth_count) || *response_len!=10 || be32(g_response+6)!=0) return program_fail(i-1,response_len,1);
    }
    put_be32(transcript+2,out);
    if (g_response_capacity<out) { unsigned char *p=realloc(g_response,out); if (!p) return program_fail(count,response_len,0);g_response=p;g_response_capacity=out; }
    memcpy(g_response,transcript,out);*response_len=out;return TPM_SUCCESS;
}

static int created_resource(TPM_RESULT rc, uint32_t len)
{
    return rc == TPM_SUCCESS && tpm_response_code(g_response, len) == 0;
}

static int run_post(const struct bytes *post, const struct bytes *post_expected)
{
    static unsigned char post_work[MAX_COMMAND];
    if (post == NULL || post->data == NULL)
        return 1;
    memcpy(post_work, post->data, post->len);
    uint32_t len = 0;
    TPM_RESULT rc = dispatch_command(post_work, post->len, &len);
    return response_matches(rc, len, post_expected);
}

static struct bytes optional_hex(const char *text)
{
    struct bytes none = {NULL, 0};
    if (text == NULL || strcmp(text, "-") == 0)
        return none;
    return parse_hex(text);
}

static uint64_t xorshift(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void serve_measure(char *arguments)
{
    char *saveptr = NULL;
    char *rounds_text = strtok_r(arguments, " ", &saveptr);
    char *seed_text = strtok_r(NULL, " ", &saveptr);
    char *warmup_text = strtok_r(NULL, " ", &saveptr);
    char *hex[4];
    for (int i = 0; i < 4; i++)
        hex[i] = strtok_r(NULL, " ", &saveptr);
    if (!rounds_text || !seed_text || !warmup_text || !hex[0] || !hex[1] || !hex[2] || !hex[3])
        fail("malformed-measure");
    size_t rounds = strtoull(rounds_text, NULL, 10);
    uint64_t seed = strtoull(seed_text, NULL, 16) | 1ull;
    size_t warmup = strtoull(warmup_text, NULL, 10);
    struct bytes command[2] = {parse_hex(hex[0]), parse_hex(hex[2])};
    struct bytes expected[2] = {parse_hex(hex[1]), parse_hex(hex[3])};
    struct bytes mask[2] = {{NULL, 0}, {NULL, 0}};
    struct bytes post[2] = {{NULL, 0}, {NULL, 0}};
    struct bytes post_expected[2] = {{NULL, 0}, {NULL, 0}};
    char *extra = strtok_r(NULL, " ", &saveptr);
    if (extra != NULL) {
        char *fields[6] = {extra, NULL, NULL, NULL, NULL, NULL};
        for (int i = 1; i < 6; i++)
            fields[i] = strtok_r(NULL, " ", &saveptr);
        for (int i = 0; i < 6; i++)
            if (fields[i] == NULL)
                fail("malformed-measure-extension");
        for (int c = 0; c < 2; c++) {
            mask[c] = optional_hex(fields[3 * c]);
            post[c] = optional_hex(fields[3 * c + 1]);
            post_expected[c] = optional_hex(fields[3 * c + 2]);
        }
    }
    int64_t *ticks[2] = {calloc(rounds ? rounds : 1, sizeof(int64_t)), calloc(rounds ? rounds : 1, sizeof(int64_t))};
    char *order = calloc(rounds + 1, 1);
    if (!ticks[0] || !ticks[1] || !order)
        fail("out-of-memory");
    unsigned long stores_before = g_nv_stores;
    int mismatch_class = -1;
    TPM_RESULT mismatch_rc = 0;
    uint32_t mismatch_len = 0;
    unsigned char mismatch_response[SLOT_SIZE];
    int cleanup_needed = 0;
    int cleanup_failed = 0;
    for (size_t w = 0; w < warmup && mismatch_class < 0; w++) {
        for (int c = 0; c < 2 && mismatch_class < 0; c++) {
            uint32_t len = 0;
            TPM_RESULT rc = run_command(command[c].data, command[c].len, &len);
            int matched = response_matches_masked(rc, len, &expected[c], &mask[c]);
            int created = created_resource(rc, len);
            if (!matched) {
                mismatch_class = c;
                mismatch_rc = rc;
                mismatch_len = len < SLOT_SIZE ? len : SLOT_SIZE;
                memcpy(mismatch_response, g_response, mismatch_len);
            }
            if (created && post[c].data != NULL) {
                cleanup_needed = 1;
                if (!run_post(&post[c], &post_expected[c])) {
                    cleanup_failed = 1;
                    if (mismatch_class < 0) {
                        mismatch_class = c;
                        mismatch_rc = POST_FAILED;
                        mismatch_len = 0;
                    }
                }
            }
        }
    }
    unsigned long stores_measured = g_nv_stores;
    for (size_t r = 0; r < rounds && mismatch_class < 0; r++) {
        int first = (int)(xorshift(&seed) & 1u);
        order[r] = first ? '1' : '0';
        for (int k = 0; k < 2 && mismatch_class < 0; k++) {
            int c = k == 0 ? first : 1 - first;
            static unsigned char work[MAX_COMMAND];
            memcpy(work, command[c].data, command[c].len);
            uint32_t len = 0;
            int64_t t0 = cpucycles();
            TPM_RESULT rc = dispatch_command(work, command[c].len, &len);
            int matched = response_matches_masked(rc, len, &expected[c], &mask[c]);
            int created = created_resource(rc, len);
            int post_ok = (matched && created) ? run_post(&post[c], &post_expected[c]) : 1;
            int64_t t1 = cpucycles();
            ticks[c][r] = t1 - t0;
            if (matched && created && post[c].data != NULL)
                cleanup_needed = 1;
            if (!matched) {
                mismatch_class = c;
                mismatch_rc = rc;
                mismatch_len = len < SLOT_SIZE ? len : SLOT_SIZE;
                memcpy(mismatch_response, g_response, mismatch_len);
                if (created && post[c].data != NULL) {
                    cleanup_needed = 1;
                    if (!run_post(&post[c], &post_expected[c]))
                        cleanup_failed = 1;
                }
            } else if (!post_ok) {
                cleanup_failed = 1;
                mismatch_class = c;
                mismatch_rc = POST_FAILED;
                mismatch_len = 0;
            }
        }
    }
    unsigned long stores_after = g_nv_stores;
    printf("measure-begin\n");
    printf("nvstores_warmup %lu\n", stores_measured - stores_before);
    printf("nvstores_measured %lu\n", stores_after - stores_measured);
    printf("cleanup %s\n", cleanup_failed ? "failed" : (cleanup_needed ? "ok" : "not-needed"));
    if (mismatch_class >= 0) {
        printf("mismatch %d %08x ", mismatch_class, mismatch_rc);
        print_hex(mismatch_response, mismatch_len);
        printf("\n");
    } else {
        printf("order %s\n", rounds ? order : "-");
        for (int c = 0; c < 2; c++) {
            printf("class%d", c);
            for (size_t r = 0; r < rounds; r++)
                printf("%c%" PRId64, r == 0 ? ' ' : ',', ticks[c][r]);
            if (rounds == 0)
                printf(" -");
            printf("\n");
        }
    }
    printf("measure-end\n");
    free(ticks[0]);
    free(ticks[1]);
    free(order);
    for (int c = 0; c < 2; c++) {
        free(command[c].data);
        free(expected[c].data);
        free(mask[c].data);
        free(post[c].data);
        free(post_expected[c].data);
    }
}

static int serve(void)
{
    char *line = NULL;
    size_t capacity = 0;
    ssize_t n;
    printf("ready %d\n", WORKER_PROTOCOL);
    fflush(stdout);
    while ((n = getline(&line, &capacity, stdin)) > 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (strncmp(line, "init ", 5) == 0) {
            char kind[16], argument[4096];
            int cpu = -1;
            if (sscanf(line + 5, "%15s %4095s %d", kind, argument, &cpu) != 3)
                fail("malformed-init");
            init_backend("info ", kind, argument, cpu);
            printf("ok\n");
        } else if (strncmp(line, "exec ", 5) == 0) {
            if (g_kind == BACKEND_NONE)
                fail("not-initialized");
            struct bytes command = parse_hex(line + 5);
            uint32_t len = 0;
            TPM_RESULT rc = run_command(command.data, command.len, &len);
            printf("resp %08x ", rc);
            print_hex(g_response, len);
            printf("\n");
            free(command.data);
        } else if (strncmp(line, "measure ", 8) == 0) {
            if (g_kind == BACKEND_NONE)
                fail("not-initialized");
            serve_measure(line + 8);
        } else if (strcmp(line, "quit") == 0) {
            printf("bye\n");
            fflush(stdout);
            break;
        } else {
            fail("unknown-request");
        }
        fflush(stdout);
    }
    free(line);
    return 0;
}

static struct bytes g_class_command[2];
static struct bytes g_class_expected[2];
static struct bytes g_class_mask[2];
static struct bytes g_class_post[2];
static struct bytes g_class_post_expected[2];

struct patch {
    int cls;
    size_t at;
    size_t setup_index;
    size_t from;
    size_t len;
    struct bytes xor;
};

static struct patch g_patches[MAX_PATCHES];
static size_t g_patch_count;
static struct patch g_setup_patches[MAX_SETUP * MAX_PATCHES];
static size_t g_setup_patch_count;
static uint32_t g_chunk;
static uint8_t *g_input_base;
static uint8_t *g_classes;
static size_t g_batch;
static unsigned char *g_slots;
static uint32_t *g_slot_len;
static TPM_RESULT *g_slot_rc;

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes)
{
    g_input_base = input_data;
    g_classes = classes;
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        memcpy(input_data + i * c->chunk_size, g_class_command[classes[i]].data, c->chunk_size);
        g_slot_len[i] = 0;
        g_slot_rc[i] = TPM_FAIL;
    }
}

uint8_t do_one_computation(uint8_t *data)
{
    size_t index = (size_t)(data - g_input_base) / g_chunk;
    uint32_t len = 0;
    TPM_RESULT rc = dispatch_command(data, g_chunk, &len);
    g_slot_len[index] = len;
    memcpy(g_slots + index * SLOT_SIZE, g_response, len < SLOT_SIZE ? len : SLOT_SIZE);
    uint8_t first = g_response[0];
    if (created_resource(rc, len) && g_class_post[g_classes[index]].data != NULL &&
        !run_post(&g_class_post[g_classes[index]], &g_class_post_expected[g_classes[index]]))
        rc = POST_FAILED;
    g_slot_rc[index] = rc;
    return first;
}

static size_t verify_batch(int *first_class, TPM_RESULT *first_rc)
{
    size_t mismatches = 0;
    for (size_t i = 0; i < g_batch; i++) {
        const struct bytes *expected = &g_class_expected[g_classes[i]];
        if (g_slot_rc[i] != TPM_SUCCESS ||
            !masked_equal(g_slots + i * SLOT_SIZE, g_slot_len[i], expected, &g_class_mask[g_classes[i]])) {
            if (mismatches == 0) {
                *first_class = g_classes[i];
                *first_rc = g_slot_rc[i];
            }
            mismatches++;
        }
    }
    return mismatches;
}

static void print_tstats(const dudect_ctx_t *ctx, size_t batch_index)
{
    double max_crop = 0.0;
    size_t max_crop_index = 0;
    for (size_t i = 1; i <= DUDECT_NUMBER_PERCENTILES; i++) {
        ttest_ctx_t *t = ctx->ttest_ctxs[i];
        if (t->n[0] > 1 && t->n[1] > 1) {
            double v = fabs(t_compute(t));
            if (v > max_crop) {
                max_crop = v;
                max_crop_index = i;
            }
        }
    }
    ttest_ctx_t *raw = ctx->ttest_ctxs[0];
    ttest_ctx_t *second = ctx->ttest_ctxs[1 + DUDECT_NUMBER_PERCENTILES];
    printf("tpms-timing batch index=%zu raw_n0=%.0f raw_n1=%.0f raw_t=%.4f max_cropped_abs_t=%.4f max_cropped_test=%zu "
           "second_order_n=%.0f second_order_t=%.4f\n",
           batch_index, raw->n[0], raw->n[1], (raw->n[0] > 1 && raw->n[1] > 1) ? t_compute(raw) : 0.0,
           max_crop, max_crop_index, second->n[0] + second->n[1],
           (second->n[0] > 1 && second->n[1] > 1) ? t_compute(second) : 0.0);
}

static void print_all_tests(const dudect_ctx_t *ctx)
{
    for (size_t i = 0; i < DUDECT_TESTS; i++) {
        ttest_ctx_t *t = ctx->ttest_ctxs[i];
        const char *kind = i == 0 ? "raw" : (i == DUDECT_TESTS - 1 ? "second-order" : "cropped");
        printf("tpms-timing test index=%zu kind=%s n0=%.0f n1=%.0f t=%.6f eligible=%s\n", i, kind, t->n[0], t->n[1],
               (t->n[0] > 1 && t->n[1] > 1) ? t_compute(t) : 0.0,
               t->n[0] > DUDECT_ENOUGH_MEASUREMENTS ? "yes" : "no");
    }
}

static int apply_setup_patch(struct bytes *command, const struct patch *p,
                             const struct bytes *responses, size_t available)
{
    if (p->setup_index >= available || p->len == 0 || p->xor.len != p->len ||
        p->at > command->len || p->len > command->len - p->at)
        return 0;
    const struct bytes *source = &responses[p->setup_index];
    if (p->from > source->len || p->len > source->len - p->from)
        return 0;
    for (size_t k = 0; k < p->len; k++)
        command->data[p->at + k] = source->data[p->from + k] ^ p->xor.data[k];
    return 1;
}

static int dudect_run(const char *plan_path)
{
    FILE *plan = fopen(plan_path, "r");
    if (plan == NULL)
        fail("plan-unreadable");
    char kind[16] = "", argument[4096] = "";
    int cpu = -1;
    size_t warmup = 0, batch = 0, budget = 0;
    double time_limit = 0;
    struct bytes setup[MAX_SETUP];
    size_t setup_count = 0;
    int have[4] = {0, 0, 0, 0};
    char *line = NULL;
    size_t capacity = 0;
    ssize_t n;
    while ((n = getline(&line, &capacity, plan)) > 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        char *space = strchr(line, ' ');
        if (space == NULL)
            fail("malformed-plan");
        *space = '\0';
        const char *value = space + 1;
        if (strcmp(line, "backend") == 0) {
            if (sscanf(value, "%15s %4095s", kind, argument) != 2)
                fail("malformed-plan-backend");
        } else if (strcmp(line, "cpu") == 0) {
            cpu = atoi(value);
        } else if (strcmp(line, "setup") == 0) {
            if (setup_count == MAX_SETUP)
                fail("too-many-setup-commands");
            setup[setup_count++] = parse_hex(value);
        } else if (strcmp(line, "class0") == 0) {
            g_class_command[0] = parse_hex(value);
            have[0] = 1;
        } else if (strcmp(line, "class1") == 0) {
            g_class_command[1] = parse_hex(value);
            have[1] = 1;
        } else if (strcmp(line, "expect0") == 0) {
            g_class_expected[0] = parse_hex(value);
            have[2] = 1;
        } else if (strcmp(line, "expect1") == 0) {
            g_class_expected[1] = parse_hex(value);
            have[3] = 1;
        } else if (strcmp(line, "mask0") == 0 || strcmp(line, "mask1") == 0) {
            g_class_mask[line[4] - '0'] = parse_hex(value);
        } else if (strcmp(line, "post0") == 0 || strcmp(line, "post1") == 0) {
            g_class_post[line[4] - '0'] = parse_hex(value);
        } else if (strcmp(line, "postexpect0") == 0 || strcmp(line, "postexpect1") == 0) {
            g_class_post_expected[line[10] - '0'] = parse_hex(value);
        } else if (strcmp(line, "setup-patch") == 0) {
            if (g_setup_patch_count == MAX_SETUP * MAX_PATCHES)
                fail("too-many-setup-patches");
            struct patch *p = &g_setup_patches[g_setup_patch_count];
            char xor_hex[2 * MAX_COMMAND + 1];
            if (sscanf(value, "%d %zu %zu %zu %zu %8192s", &p->cls, &p->at, &p->setup_index, &p->from, &p->len,
                       xor_hex) != 6 || p->cls < 0 || p->cls >= MAX_SETUP)
                fail("malformed-setup-patch");
            p->xor = parse_hex(xor_hex);
            if (p->xor.len != p->len || p->len == 0)
                fail("malformed-setup-patch");
            g_setup_patch_count++;
        } else if (strcmp(line, "patch") == 0) {
            if (g_patch_count == MAX_PATCHES)
                fail("too-many-patches");
            struct patch *p = &g_patches[g_patch_count];
            char xor_hex[2 * MAX_COMMAND + 1];
            if (sscanf(value, "%d %zu %zu %zu %zu %8192s", &p->cls, &p->at, &p->setup_index, &p->from, &p->len,
                       xor_hex) != 6 || p->cls < 0 || p->cls > 1)
                fail("malformed-patch");
            p->xor = parse_hex(xor_hex);
            if (p->xor.len != p->len)
                fail("malformed-patch");
            g_patch_count++;
        } else if (strcmp(line, "warmup") == 0) {
            warmup = strtoull(value, NULL, 10);
        } else if (strcmp(line, "batch") == 0) {
            batch = strtoull(value, NULL, 10);
        } else if (strcmp(line, "budget") == 0) {
            budget = strtoull(value, NULL, 10);
        } else if (strcmp(line, "time_limit_s") == 0) {
            time_limit = strtod(value, NULL);
        } else {
            fail("unknown-plan-key");
        }
    }
    free(line);
    fclose(plan);
    if (!kind[0] || !have[0] || !have[1] || !have[2] || !have[3] || batch < 32 || budget < batch || time_limit <= 0)
        fail("incomplete-plan");
    if (g_class_command[0].len != g_class_command[1].len)
        fail("class-command-length-differs");
    if (g_class_expected[0].len > SLOT_SIZE || g_class_expected[1].len > SLOT_SIZE)
        fail("expected-response-too-large");
    for (int c = 0; c < 2; c++)
        if ((g_class_post[c].data == NULL) != (g_class_post_expected[c].data == NULL))
            fail("post-without-expectation");
    for (size_t i = 0; i < g_setup_patch_count; i++) {
        const struct patch *p = &g_setup_patches[i];
        if ((size_t)p->cls >= setup_count || p->setup_index >= (size_t)p->cls ||
            p->at > setup[p->cls].len || p->len > setup[p->cls].len - p->at)
            fail("invalid-setup-patch-dependency-or-bounds");
    }
    struct bytes setup_response[MAX_SETUP];
    memset(setup_response, 0, sizeof(setup_response));
    init_backend("tpms-timing info ", kind, argument, cpu);
    for (size_t i = 0; i < setup_count; i++) {
        for (size_t j = 0; j < g_setup_patch_count; j++) {
            const struct patch *p = &g_setup_patches[j];
            if ((size_t)p->cls == i && !apply_setup_patch(&setup[i], p, setup_response, i)) {
                printf("tpms-timing result status=setup-failure measurements=0 batches=0 nvstores=0 mismatches=0\n");
                return 4;
            }
        }
        uint32_t len = 0;
        TPM_RESULT rc = run_command(setup[i].data, setup[i].len, &len);
        uint32_t tpm_rc = len >= 10 ? ((uint32_t)g_response[6] << 24 | (uint32_t)g_response[7] << 16 |
                                       (uint32_t)g_response[8] << 8 | g_response[9])
                                    : 0xffffffffu;
        printf("tpms-timing setup index=%zu tpmlib_rc=%08x tpm_rc=%08x\n", i, rc, tpm_rc);
        if (rc != TPM_SUCCESS || tpm_rc != 0) {
            printf("tpms-timing result status=setup-failure measurements=0 batches=0 nvstores=0 mismatches=0\n");
            return 4;
        }
        setup_response[i].data = malloc(len ? len : 1);
        if (setup_response[i].data == NULL)
            fail("out-of-memory");
        memcpy(setup_response[i].data, g_response, len);
        setup_response[i].len = len;
    }
    for (size_t i = 0; i < g_patch_count; i++) {
        struct patch *p = &g_patches[i];
        struct bytes *command = &g_class_command[p->cls];
        if (!apply_setup_patch(command, p, setup_response, setup_count)) {
            printf("tpms-timing result status=setup-failure measurements=0 batches=0 nvstores=0 mismatches=0\n");
            return 4;
        }
    }
    printf("tpms-timing patches applied=%zu\n", g_patch_count);
    for (size_t w = 0; w < warmup; w++) {
        for (int c = 0; c < 2; c++) {
            uint32_t len = 0;
            TPM_RESULT rc = run_command(g_class_command[c].data, g_class_command[c].len, &len);
            int ok = response_matches_masked(rc, len, &g_class_expected[c], &g_class_mask[c]);
            if (created_resource(rc, len) && g_class_post[c].data != NULL &&
                !run_post(&g_class_post[c], &g_class_post_expected[c])) {
                ok = 0;
                rc = POST_FAILED;
            }
            if (!ok) {
                printf("tpms-timing mismatch phase=warmup class=%d tpmlib_rc=%08x len=%u\n", c, rc, len);
                printf("tpms-timing result status=functional-failure measurements=0 batches=0 nvstores=0 mismatches=1\n");
                return 4;
            }
        }
    }
    printf("tpms-timing warmup completed=%zu\n", warmup);
    g_chunk = g_class_command[0].len;
    g_batch = batch;
    g_slots = calloc(batch, SLOT_SIZE);
    g_slot_len = calloc(batch, sizeof(uint32_t));
    g_slot_rc = calloc(batch, sizeof(TPM_RESULT));
    if (!g_slots || !g_slot_len || !g_slot_rc)
        fail("out-of-memory");
    dudect_config_t config = {.chunk_size = g_chunk, .number_measurements = batch};
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    printf("tpms-timing dudect chunk_size=%u batch=%zu budget=%zu time_limit_s=%.1f enough_measurements=%d "
           "t_threshold_moderate=%d t_threshold_bananas=%d\n",
           g_chunk, batch, budget, time_limit, DUDECT_ENOUGH_MEASUREMENTS, t_threshold_moderate,
           t_threshold_bananas);
    fflush(stdout);
    uint64_t started = monotonic_ns();
    size_t measurements = 0, batches = 0;
    unsigned long stores_before = g_nv_stores;
    const char *status = NULL;
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (status == NULL) {
        if (g_interrupted) {
            status = "interrupted";
            break;
        }
        if (measurements + batch > budget) {
            status = ctx.ttest_ctxs[0]->n[0] > DUDECT_ENOUGH_MEASUREMENTS ? "budget-exhausted"
                                                                          : "insufficient-measurements";
            break;
        }
        if ((double)(monotonic_ns() - started) / 1e9 > time_limit) {
            status = "time-limit";
            break;
        }
        state = dudect_main(&ctx);
        measurements += batch;
        batches++;
        int mismatch_class = -1;
        TPM_RESULT mismatch_rc = 0;
        size_t mismatches = verify_batch(&mismatch_class, &mismatch_rc);
        print_tstats(&ctx, batches);
        if (mismatches != 0) {
            printf("tpms-timing mismatch phase=measurement batch=%zu count=%zu class=%d tpmlib_rc=%08x\n", batches,
                   mismatches, mismatch_class, mismatch_rc);
            status = "functional-failure";
            break;
        }
        if (g_nv_stores != stores_before) {
            status = "nv-store-during-measurement";
            break;
        }
        if (state == DUDECT_LEAKAGE_FOUND)
            status = "leakage-found";
        fflush(stdout);
    }
    print_all_tests(&ctx);
    printf("tpms-timing result status=%s measurements=%zu batches=%zu nvstores=%lu mismatches=%d elapsed_s=%.3f\n",
           status, measurements, batches, g_nv_stores - stores_before,
           strcmp(status, "functional-failure") == 0 ? 1 : 0, (double)(monotonic_ns() - started) / 1e9);
    fflush(stdout);
    dudect_free(&ctx);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && strcmp(argv[1], "serve") == 0)
        return serve();
    if (argc == 3 && strcmp(argv[1], "dudect") == 0)
        return dudect_run(argv[2]);
    fprintf(stderr, "usage: %s serve | dudect PLAN\n", argv[0]);
    return 2;
}
