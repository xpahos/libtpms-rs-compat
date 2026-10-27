/* Test-build-only additions to CryptRand.c. drbg_reference.py places the
 * declarations after Tpm.h and the implementation at the end of that file.
 * State restore, generation, state serialization, and restoration of the
 * caller's default state all run within the timed adapter. */
static _Thread_local int timing_drbg_active;
static _Thread_local int timing_drbg_continuous;
static _Thread_local int timing_drbg_failed;
static _Thread_local BYTE timing_drbg_entropy[48];
static _Thread_local UINT32 timing_drbg_draws;

__attribute__((visibility("default")))
UINT32 TPMS_TIMING_DRBG_v1(const BYTE *input, UINT32 input_len,
                          BYTE *output, UINT32 output_capacity, UINT32 *output_len);

/* TPMS_TIMING_DRBG_IMPLEMENTATION */
static UINT64 timing_drbg_read_be(const BYTE *p, unsigned size)
{
    UINT64 value = 0;
    for (unsigned i = 0; i < size; i++)
        value = (value << 8) | p[i];
    return value;
}

static void timing_drbg_write_be(BYTE *p, UINT64 value, unsigned size)
{
    for (unsigned i = size; i != 0; i--) {
        p[i - 1] = (BYTE)value;
        value >>= 8;
    }
}

/* Input and output are caller-owned; output_len is a separate aligned UINT32.
 * Like the libtpms API, calls using global TPM state must be serialized. */
__attribute__((visibility("default")))
UINT32 TPMS_TIMING_DRBG_v1(const BYTE *input, UINT32 input_len,
                          BYTE *output, UINT32 output_capacity, UINT32 *output_len)
{
    BYTE payload[123], response[152] = {0};
    if (output_len == NULL)
        return 1;
    *output_len = 0;
    if (input == NULL || output == NULL || input_len != sizeof(payload) || timing_drbg_active)
        return 1;
    memcpy(payload, input, sizeof(payload));
    UINT64 counter = timing_drbg_read_be(payload + 48, 8);
    UINT16 requested = (UINT16)timing_drbg_read_be(payload + 121, 2);
    UINT32 response_len = 88u + requested;
    if (counter < 1 || counter > CTR_DRBG_MAX_REQUESTS_PER_RESEED + 7 ||
        payload[120] > 1 || requested > 64 || output_capacity < response_len)
        return 1;

    DRBG_STATE saved = drbgDefault;
    UINT32 saved_rng = g_cryptoSelfTestState.rng;
    memcpy(drbgDefault.seed.bytes, payload, 48);
    drbgDefault.reseedCounter = counter;
    drbgDefault.magic = DRBG_MAGIC;
    for (unsigned i = 0; i < 4; i++) {
        const BYTE *p = payload + 56 + i * 4;
        drbgDefault.lastValue[i] = (UINT32)p[0] | (UINT32)p[1] << 8 |
                                  (UINT32)p[2] << 16 | (UINT32)p[3] << 24;
    }
    memcpy(timing_drbg_entropy, payload + 72, 48);
    timing_drbg_draws = 0;
    timing_drbg_failed = 0;
    timing_drbg_continuous = payload[120];
    ClearEntropyBad();
    ClearSelfTest();
    timing_drbg_active = 1;
    UINT16 generated = DRBG_Generate(NULL, response + 12, requested);
    timing_drbg_active = 0;
    int failed = timing_drbg_failed || generated != requested || IsEntropyBad();
    if (!failed) {
        response[0] = 0x80;
        response[1] = 1;
        timing_drbg_write_be(response + 2, response_len, 4);
        timing_drbg_write_be(response + 10, requested, 2);
        BYTE *state = response + 12 + requested;
        memcpy(state, drbgDefault.seed.bytes, 48);
        timing_drbg_write_be(state + 48, drbgDefault.reseedCounter, 8);
        for (unsigned i = 0; i < 4; i++) {
            UINT32 word = drbgDefault.lastValue[i];
            for (unsigned j = 0; j < 4; j++) {
                state[56 + 4 * i + j] = (BYTE)word;
                word >>= 8;
            }
        }
        timing_drbg_write_be(state + 72, timing_drbg_draws, 4);
    }
    drbgDefault = saved;
    g_cryptoSelfTestState.rng = saved_rng;
    memset(timing_drbg_entropy, 0, sizeof(timing_drbg_entropy));
    if (failed)
        return 1;
    memcpy(output, response, response_len);
    *output_len = response_len;
    return 0;
}
