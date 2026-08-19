#include "Platform.h"

#define CLOCK_NOMINAL       30000
#define CLOCK_ADJUST_COARSE 300
#define CLOCK_ADJUST_MEDIUM 30
#define CLOCK_ADJUST_FINE   1
#define CLOCK_ADJUST_LIMIT  5000

#define FAKE_REALTIME_OFFSET_MS 1600000000000ULL

static uint64_t fake_monotonic_ms = 5000000ULL;

static uint64_t fake_ticks(void)
{
    fake_monotonic_ms += 10;
    return fake_monotonic_ms;
}

uint64_t ClockGetTime(clockid_t clk_id)
{
    uint64_t now = fake_ticks();
    if (clk_id == CLOCK_REALTIME)
        return FAKE_REALTIME_OFFSET_MS + now;
    return now;
}

void ClockAdjustPostResume(UINT64 backthen, BOOL timesAreRealtime)
{
    UINT64 now = ClockGetTime(CLOCK_REALTIME);
    INT64 timediff = now - backthen;

    if (timesAreRealtime) {
        s_suspendedElapsedTime = now;
        s_hostMonotonicAdjustTime = -ClockGetTime(CLOCK_MONOTONIC);
        s_lastSystemTime = now;
        s_lastReportedTime = now;
    } else if (timediff >= 0) {
        s_suspendedElapsedTime += timediff;
    }
}

LIB_EXPORT void _plat__TimerReset(void)
{
    s_lastSystemTime = 0;
    s_tpmTime = 0;
    s_adjustRate = CLOCK_NOMINAL;
    s_timerReset = TRUE;
    s_timerStopped = TRUE;
    s_hostMonotonicAdjustTime = 0;
    s_suspendedElapsedTime = 0;
}

LIB_EXPORT void _plat__TimerRestart(void)
{
    s_timerStopped = TRUE;
}

LIB_EXPORT uint64_t _plat__RealTime(void)
{
    return fake_ticks() + s_hostMonotonicAdjustTime + s_suspendedElapsedTime;
}

LIB_EXPORT uint64_t _plat__TimerRead(void)
{
    clock64_t timeDiff;
    clock64_t adjustedTimeDiff;
    clock64_t timeNow;
    clock64_t readjustedTimeDiff;

    timeNow = _plat__RealTime();
    if (s_lastSystemTime == 0) {
        s_lastSystemTime = timeNow;
        s_lastReportedTime = 0;
        s_realTimePrevious = 0;
    }
    if (timeNow < s_lastReportedTime)
        s_lastSystemTime = timeNow;
    s_lastReportedTime = s_lastReportedTime + timeNow - s_lastSystemTime;
    s_lastSystemTime = timeNow;
    timeNow = s_lastReportedTime;

    if (s_realTimePrevious >= timeNow)
        return s_tpmTime;
    timeDiff = timeNow - s_realTimePrevious;
    adjustedTimeDiff = (timeDiff * CLOCK_NOMINAL) / ((uint64_t)s_adjustRate);
    s_tpmTime += (clock64_t)adjustedTimeDiff;
    readjustedTimeDiff = (adjustedTimeDiff * (uint64_t)s_adjustRate) / CLOCK_NOMINAL;
    s_realTimePrevious = s_realTimePrevious + readjustedTimeDiff;
    return s_tpmTime;
}

LIB_EXPORT int _plat__TimerWasReset(void)
{
    int retVal = s_timerReset;
    s_timerReset = FALSE;
    return retVal;
}

LIB_EXPORT int _plat__TimerWasStopped(void)
{
    int retVal = s_timerStopped;
    s_timerStopped = FALSE;
    return retVal;
}

LIB_EXPORT void _plat__ClockRateAdjust(_plat__ClockAdjustStep adjust)
{
    switch (adjust) {
      case PLAT_TPM_CLOCK_ADJUST_COARSE_SLOWER:
        s_adjustRate += CLOCK_ADJUST_COARSE;
        break;
      case PLAT_TPM_CLOCK_ADJUST_MEDIUM_SLOWER:
        s_adjustRate += CLOCK_ADJUST_MEDIUM;
        break;
      case PLAT_TPM_CLOCK_ADJUST_FINE_SLOWER:
        s_adjustRate += CLOCK_ADJUST_FINE;
        break;
      case PLAT_TPM_CLOCK_ADJUST_FINE_FASTER:
        s_adjustRate -= CLOCK_ADJUST_FINE;
        break;
      case PLAT_TPM_CLOCK_ADJUST_MEDIUM_FASTER:
        s_adjustRate -= CLOCK_ADJUST_MEDIUM;
        break;
      case PLAT_TPM_CLOCK_ADJUST_COARSE_FASTER:
        s_adjustRate -= CLOCK_ADJUST_COARSE;
        break;
    }
    if (s_adjustRate > (CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT))
        s_adjustRate = CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT;
    if (s_adjustRate < (CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT))
        s_adjustRate = CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT;
}

LIB_EXPORT int32_t _plat__GetEntropy(unsigned char *entropy, uint32_t amount)
{
    static uint64_t lcg_state;
    uint32_t index;

    if (entropy == NULL || amount == 0) {
        lcg_state = 0;
        return 0;
    }
    for (index = 0; index < amount; index++) {
        lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
        entropy[index] = (unsigned char)(lcg_state >> 33);
    }
    return (int32_t)amount;
}
