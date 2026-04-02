#include "Timer.h"
using namespace gpg;

LARGE_INTEGER PerformanceFrequency; // 0x00F8ED58
float TimerCycleToSeconds; // 0x00F8ED60
LONGLONG gpgTime; // 0x00F8ED68
time::Timer systemTimer; // 0x00F8ED78, first set at 0x00BEAB90

// inline
inline void initPerformanceCounters() {
    if (!PerformanceFrequency.QuadPart) {
        QueryPerformanceCounter(&PerformanceFrequency);
        TimerCycleToSeconds = 1.0f / PerformanceFrequency.QuadPart;
    }
}

// 0x009556F0 or 0x009556D0
time::Timer::Timer() :
    mTime{ GetTime() }
{
}

// 0x009556D0 or 0x009556F0
void time::Timer::Reset() {
    this->mTime = GetTime();
}

/**
 * Address: 0x00955710 (FUN_00955710)
 *
 * What it does:
 * Returns elapsed cycle count since last stored timestamp and updates the timer baseline.
 */
LONGLONG time::Timer::ElapsedCyclesAndReset() {
	const LONGLONG curTime = GetTime();
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
    return GetTime() - this->mTime;
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

// 0x00955400
LONGLONG time::GetTime() {
    LARGE_INTEGER PerformanceCount;
    QueryPerformanceCounter(&PerformanceCount);
    LONGLONG newVal = PerformanceCount.QuadPart;
    LONGLONG ex, cur;
    do {
        cur = gpgTime;
        if (newVal < cur) {
            newVal = gpgTime + 1;
        }
        ex = InterlockedCompareExchange64(&gpgTime, newVal, gpgTime);
    } while (ex != cur);
    return newVal;
}

// 0x00955520
LONGLONG time::CyclesToMicroseconds(const LONGLONG cycles) {
    initPerformanceCounters();
    const LONGLONG freq = PerformanceFrequency.QuadPart;
    return 1000000 * (cycles % freq + (cycles >> 32) / freq);
}

// 0x009554E0
float time::CyclesToMilliseconds(const LONGLONG cycles) {
    initPerformanceCounters();
    return cycles * TimerCycleToSeconds * 1000.0;
}

// 0x009554A0
float time::CyclesToSeconds(const LONGLONG cycles) {
    initPerformanceCounters();
    return cycles * TimerCycleToSeconds;
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

// 0x00955630
LONGLONG time::MicrosecondsToCycles(const LONGLONG micro) {
    initPerformanceCounters();
    const LONGLONG freq = PerformanceFrequency.QuadPart;
    return freq * (micro % 1000000 + (micro >> 32) / 1000000);
}

// 0x009555F0
LONGLONG time::MillisecondsToCycles(const float milli) {
    initPerformanceCounters();
    return static_cast<LONGLONG>(PerformanceFrequency.QuadPart * milli * 0.001);
}

// 0x009555B0
LONGLONG time::SecondsToCycles(const float sec) {
    initPerformanceCounters();
    return (LONGLONG)(PerformanceFrequency.QuadPart * sec);
}
