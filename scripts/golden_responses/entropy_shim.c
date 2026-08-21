#define _GNU_SOURCE

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t g_generator_state;
static pthread_once_t g_seed_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_generator_lock = PTHREAD_MUTEX_INITIALIZER;

static int hex_digit_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void fail_bad_seed(const char *reason)
{
    fprintf(stderr, "entropy_shim: GOLDEN_ENTROPY_SEED %s; set it to a hex u64\n",
            reason);
    abort();
}

static void initialize_seed_from_env(void)
{
    const char *seed_text = getenv("GOLDEN_ENTROPY_SEED");
    uint64_t seed_value = 0;
    int digit_count = 0;

    if (seed_text == NULL || seed_text[0] == '\0')
        fail_bad_seed("is unset or empty");
    for (; *seed_text != '\0'; seed_text++) {
        int digit = hex_digit_value(*seed_text);
        if (digit < 0)
            fail_bad_seed("contains a non-hex character");
        if (digit_count >= 16)
            fail_bad_seed("has more than 16 hex digits");
        seed_value = (seed_value << 4) | (uint64_t)digit;
        digit_count++;
    }
    g_generator_state = seed_value;
}

static uint64_t splitmix64_next_locked(void)
{
    uint64_t mixed;

    g_generator_state += UINT64_C(0x9e3779b97f4a7c15);
    mixed = g_generator_state;
    mixed = (mixed ^ (mixed >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27)) * UINT64_C(0x94d049bb133111eb);
    return mixed ^ (mixed >> 31);
}

int RAND_bytes(unsigned char *buf, int num)
{
    size_t requested;
    size_t index;
    uint64_t word = 0;

    if (num < 0)
        return 0;
    if (num == 0)
        return 1;
    requested = (size_t)num;
    pthread_once(&g_seed_once, initialize_seed_from_env);
    pthread_mutex_lock(&g_generator_lock);
    for (index = 0; index < requested; index++) {
        if (index % 8 == 0)
            word = splitmix64_next_locked();
        buf[index] = (unsigned char)(word & 0xff);
        word >>= 8;
    }
    pthread_mutex_unlock(&g_generator_lock);
    return 1;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_bytes(buf, num);
}

int RAND_status(void)
{
    return 1;
}

typedef int (*clock_gettime_function)(clockid_t, struct timespec *);

static clock_gettime_function g_next_clock_gettime;
static pthread_once_t g_clock_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_monotonic_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_monotonic_nanoseconds = UINT64_C(1000000000000);

static void initialize_next_clock_gettime(void)
{
    void *next_symbol = dlsym(RTLD_NEXT, "clock_gettime");

    if (next_symbol == NULL) {
        fprintf(stderr, "entropy_shim: dlsym(RTLD_NEXT, clock_gettime) failed\n");
        abort();
    }
    g_next_clock_gettime = (clock_gettime_function)next_symbol;
}

static int is_monotonic_family(clockid_t clock_id)
{
    return clock_id == CLOCK_MONOTONIC
        || clock_id == CLOCK_MONOTONIC_RAW
        || clock_id == CLOCK_MONOTONIC_COARSE
        || clock_id == CLOCK_BOOTTIME
        || clock_id == CLOCK_PROCESS_CPUTIME_ID
        || clock_id == CLOCK_THREAD_CPUTIME_ID;
}

void golden_advance_monotonic_ms(uint64_t milliseconds)
{
    pthread_mutex_lock(&g_monotonic_lock);
    g_monotonic_nanoseconds += milliseconds * UINT64_C(1000000);
    pthread_mutex_unlock(&g_monotonic_lock);
}

int clock_gettime(clockid_t clock_id, struct timespec *result)
{
    uint64_t now_nanoseconds;

    if (is_monotonic_family(clock_id)) {
        pthread_mutex_lock(&g_monotonic_lock);
        now_nanoseconds = g_monotonic_nanoseconds;
        pthread_mutex_unlock(&g_monotonic_lock);
        result->tv_sec = (time_t)(now_nanoseconds / UINT64_C(1000000000));
        result->tv_nsec = (long)(now_nanoseconds % UINT64_C(1000000000));
        return 0;
    }
    pthread_once(&g_clock_once, initialize_next_clock_gettime);
    return g_next_clock_gettime(clock_id, result);
}
