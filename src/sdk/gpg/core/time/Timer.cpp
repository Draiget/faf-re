#include "Timer.h"
using namespace gpg;

LARGE_INTEGER sPerformanceFrequency; // 0x00F8ED58
float sTimerCycleToSeconds; // 0x00F8ED60
volatile LONGLONG cycle; // 0x00F8ED68
time::Timer systemTimer; // 0x00F8ED78, first set at 0x00BEAB90

/**
 * Address: 0x00955480 (FUN_00955480)
 *
 * What it does:
 * Caches QueryPerformanceFrequency and precomputes cycle-to-seconds scale.
 */
[[maybe_unused]] BOOL InitializePerformanceFrequencyCache()
{
    const BOOL result = QueryPerformanceFrequency(&sPerformanceFrequency);
    sTimerCycleToSeconds = 1.0f / static_cast<float>(sPerformanceFrequency.QuadPart);
    return result;
}

inline void EnsurePerformanceFrequencyInitialized() {
    if (!sPerformanceFrequency.QuadPart) {
        (void)InitializePerformanceFrequencyCache();
    }
}

/**
 * Address: 0x009556D0 (FUN_009556D0, gpg::time::Timer::Timer)
 *
 * What it does:
 * Captures the current monotonic cycle counter as the timer baseline.
 */
time::Timer::Timer() :
    mTime{ GetCycle() }
{
}

/**
 * Address: 0x009556F0 (FUN_009556F0, gpg::time::Timer::Reset)
 *
 * What it does:
 * Replaces the timer baseline with the current monotonic cycle counter.
 */
void time::Timer::Reset() {
    this->mTime = GetCycle();
}

/**
 * Address: 0x00955710 (FUN_00955710)
 *
 * What it does:
 * Returns elapsed cycle count since last stored timestamp and updates the timer baseline.
 */
LONGLONG time::Timer::ElapsedCyclesAndReset() {
	const LONGLONG curTime = GetCycle();
	const LONGLONG diff = curTime - this->mTime;
    this->mTime = curTime;
    return diff;
}

/**
 * Address: 0x00955700 (FUN_00955700)
 *
 * What it does:
 * Returns elapsed cycle count since the timer baseline without mutating state.
 */
LONGLONG time::Timer::ElapsedCycles() const {
    return GetCycle() - this->mTime;
}

/**
 * Address: 0x00485A40 (FUN_00485A40)
 *
 * What it does:
 * Converts elapsed cycle delta to microseconds.
 */
LONGLONG time::Timer::ElapsedMicroseconds() const {
    return CyclesToMicroseconds(this->ElapsedCycles());
}

/**
 * Address: 0x004A3560 (FUN_004A3560, ?ElapsedSeconds@Timer@time@gpg@@QBEMXZ)
 *
 * What it does:
 * Converts elapsed cycle delta to seconds.
 */
float time::Timer::ElapsedSeconds() const {
    return CyclesToSeconds(this->ElapsedCycles());
}

/**
 * Address: 0x00461A90 (FUN_00461A90, ?ElapsedMilliseconds@Timer@time@gpg@@QBEMXZ)
 *
 * What it does:
 * Returns elapsed wall-clock time in milliseconds since the timer baseline.
 */
float time::Timer::ElapsedMilliseconds() const {
    return CyclesToMilliseconds(this->ElapsedCycles());
}

/**
 * Address: 0x00955400 (FUN_00955400, gpg::time::GetCycle)
 *
 * What it does:
 * Returns a monotonic process cycle value derived from
 * `QueryPerformanceCounter`, clamped to never move backward.
 */
LONGLONG time::GetCycle() {
    LARGE_INTEGER PerformanceCount;
    QueryPerformanceCounter(&PerformanceCount);
    while (true) {
        const LONGLONG current = cycle;
        LONGLONG next = PerformanceCount.QuadPart;
        if (next < current) {
            next = current + 1;
            PerformanceCount.QuadPart = next;
        }

        const LONGLONG observed = InterlockedCompareExchange64(&cycle, next, current);
        if (observed == current) {
            return PerformanceCount.QuadPart;
        }
    }
}

/**
 * Address: 0x00955520 (FUN_00955520, gpg::time::CyclesToMicroseconds)
 *
 * What it does:
 * Converts performance-counter cycles to microseconds using cached frequency.
 */
LONGLONG time::CyclesToMicroseconds(const LONGLONG cycles) {
    EnsurePerformanceFrequencyInitialized();
    const LONGLONG freq = sPerformanceFrequency.QuadPart;
    const LONGLONG seconds = cycles / freq;
    const LONGLONG remainder = cycles % freq;
    return (seconds * 1000000LL) + ((remainder * 1000000LL) / freq);
}

/**
 * Address: 0x009554E0 (FUN_009554E0, gpg::time::CyclesToMilliseconds)
 *
 * What it does:
 * Converts performance-counter cycles to milliseconds.
 */
float time::CyclesToMilliseconds(const LONGLONG cycles) {
    EnsurePerformanceFrequencyInitialized();
    return static_cast<float>(cycles) * sTimerCycleToSeconds * 1000.0f;
}

/**
 * Address: 0x009554A0 (FUN_009554A0, gpg::time::CyclesToSeconds)
 *
 * What it does:
 * Converts performance-counter cycles to seconds.
 */
float time::CyclesToSeconds(const LONGLONG cycles) {
    EnsurePerformanceFrequencyInitialized();
    return static_cast<float>(cycles) * sTimerCycleToSeconds;
}

/**
 * Address: 0x00955730 (FUN_00955730)
 *
 * What it does:
 * Returns process-wide system timer singleton with one-time baseline initialization.
 */
time::Timer const& time::GetSystemTimer() {
    static int guard = 0; // 0x00F8ED80
    if ((guard & 1) == 0) {
        guard |= 1;
        systemTimer = Timer{};
    }
    return systemTimer;
}

/**
 * Address: 0x00955630 (FUN_00955630, gpg::time::MicrosecondsToCycles)
 *
 * What it does:
 * Converts microseconds to performance-counter cycles using decomposed
 * quotient/remainder arithmetic to preserve 64-bit precision.
 */
LONGLONG time::MicrosecondsToCycles(const LONGLONG micro) {
    EnsurePerformanceFrequencyInitialized();
    const LONGLONG freq = sPerformanceFrequency.QuadPart;
    const LONGLONG seconds = micro / 1000000LL;
    const LONGLONG remainder = micro % 1000000LL;
    return (seconds * freq) + ((remainder * freq) / 1000000LL);
}

/**
 * Address: 0x009555F0 (FUN_009555F0, gpg::time::MillisecondsToCycles)
 *
 * What it does:
 * Converts milliseconds to performance-counter cycles.
 */
LONGLONG time::MillisecondsToCycles(const float milli) {
    EnsurePerformanceFrequencyInitialized();
    return static_cast<LONGLONG>(sPerformanceFrequency.QuadPart * milli * 0.001);
}

/**
 * Address: 0x009555B0 (FUN_009555B0, gpg::time::SecondsToCycles)
 *
 * What it does:
 * Converts seconds to performance-counter cycles.
 */
LONGLONG time::SecondsToCycles(const float sec) {
    EnsurePerformanceFrequencyInitialized();
    return static_cast<LONGLONG>(sPerformanceFrequency.QuadPart * sec);
}
