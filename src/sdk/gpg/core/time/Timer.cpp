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

// 0x00955710
LONGLONG time::Timer::ElapsedCyclesAndReset() {
	const LONGLONG curTime = GetTime();
	const LONGLONG diff = curTime - this->mTime;
    this->mTime = curTime;
    return diff;
}

// 0x00955700
LONGLONG time::Timer::ElapsedCycles() const {
    return GetTime() - this->mTime;
}

// 0x00485A40
LONGLONG time::Timer::ElapsedMicroseconds() const {
    return CyclesToMicroseconds(this->ElapsedCycles());
}

// 0x004A3560
LONGLONG time::Timer::ElapsedSeconds() const {
    return CyclesToSeconds(this->ElapsedCycles());
}

LONGLONG time::Timer::ElapsedMilliseconds() const {
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

// 0x00955730
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