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
#define SLOT_SIZE 512
#define MAX_COMMAND 4096
#define MAX_SETUP 16
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

static TPM_RESULT run_command(const unsigned char *command, uint32_t len, uint32_t *response_len)
{
    static unsigned char work[MAX_COMMAND];
    memcpy(work, command, len);
    *response_len = 0;
    return g_process(&g_response, response_len, &g_response_capacity, work, len);
}

static int response_matches(TPM_RESULT rc, uint32_t len, const struct bytes *expected)
{
    return rc == TPM_SUCCESS && len == expected->len && memcmp(g_response, expected->data, len) == 0;
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
    int64_t *ticks[2] = {calloc(rounds ? rounds : 1, sizeof(int64_t)), calloc(rounds ? rounds : 1, sizeof(int64_t))};
    char *order = calloc(rounds + 1, 1);
    if (!ticks[0] || !ticks[1] || !order)
        fail("out-of-memory");
    unsigned long stores_before = g_nv_stores;
    int mismatch_class = -1;
    TPM_RESULT mismatch_rc = 0;
    uint32_t mismatch_len = 0;
    unsigned char mismatch_response[SLOT_SIZE];
    for (size_t w = 0; w < warmup && mismatch_class < 0; w++) {
        for (int c = 0; c < 2 && mismatch_class < 0; c++) {
            uint32_t len = 0;
            TPM_RESULT rc = run_command(command[c].data, command[c].len, &len);
            if (!response_matches(rc, len, &expected[c])) {
                mismatch_class = c;
                mismatch_rc = rc;
                mismatch_len = len < SLOT_SIZE ? len : SLOT_SIZE;
                memcpy(mismatch_response, g_response, mismatch_len);
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
            TPM_RESULT rc = g_process(&g_response, &len, &g_response_capacity, work, command[c].len);
            int64_t t1 = cpucycles();
            ticks[c][r] = t1 - t0;
            if (!response_matches(rc, len, &expected[c])) {
                mismatch_class = c;
                mismatch_rc = rc;
                mismatch_len = len < SLOT_SIZE ? len : SLOT_SIZE;
                memcpy(mismatch_response, g_response, mismatch_len);
            }
        }
    }
    unsigned long stores_after = g_nv_stores;
    printf("measure-begin\n");
    printf("nvstores_warmup %lu\n", stores_measured - stores_before);
    printf("nvstores_measured %lu\n", stores_after - stores_measured);
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
    free(command[0].data);
    free(command[1].data);
    free(expected[0].data);
    free(expected[1].data);
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
    g_slot_rc[index] = g_process(&g_response, &len, &g_response_capacity, data, g_chunk);
    g_slot_len[index] = len;
    memcpy(g_slots + index * SLOT_SIZE, g_response, len < SLOT_SIZE ? len : SLOT_SIZE);
    return g_response[0];
}

static size_t verify_batch(int *first_class, TPM_RESULT *first_rc)
{
    size_t mismatches = 0;
    for (size_t i = 0; i < g_batch; i++) {
        const struct bytes *expected = &g_class_expected[g_classes[i]];
        if (g_slot_rc[i] != TPM_SUCCESS || g_slot_len[i] != expected->len ||
            memcmp(g_slots + i * SLOT_SIZE, expected->data, expected->len) != 0) {
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
    init_backend("tpms-timing info ", kind, argument, cpu);
    for (size_t i = 0; i < setup_count; i++) {
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
    }
    for (size_t w = 0; w < warmup; w++) {
        for (int c = 0; c < 2; c++) {
            uint32_t len = 0;
            TPM_RESULT rc = run_command(g_class_command[c].data, g_class_command[c].len, &len);
            if (!response_matches(rc, len, &g_class_expected[c])) {
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
