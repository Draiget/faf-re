#pragma once

#include "platform/Platform.h"

namespace gpg::time
{
	class Timer
	{
	public:
		LONGLONG mTime;

    /**
     * Address: 0x009556D0 (FUN_009556D0, gpg::time::Timer::Timer)
     *
     * What it does:
     * Captures the current monotonic cycle counter as the timer baseline.
     */
		Timer();

    /**
     * Address: 0x009556F0 (FUN_009556F0, gpg::time::Timer::Reset)
     *
     * What it does:
     * Replaces the timer baseline with the current monotonic cycle counter.
     */
		void Reset();
		/**
		 * Address: 0x00955710 (FUN_00955710)
		 *
		 * What it does:
		 * Returns elapsed cycle count since last stored timestamp and updates the timer baseline.
		 */
		LONGLONG ElapsedCyclesAndReset();
		/**
		 * Address: 0x00955700 (FUN_00955700)
		 *
		 * What it does:
		 * Returns elapsed cycle count since the timer baseline without mutating state.
		 */
		LONGLONG ElapsedCycles() const;
		LONGLONG ElapsedMicroseconds() const; // 0x00485A40
		/**
		 * Address: 0x004A3560 (FUN_004A3560, ?ElapsedSeconds@Timer@time@gpg@@QBEMXZ)
		 *
		 * What it does:
		 * Returns elapsed wall-clock time in seconds since the timer baseline.
		 */
		float ElapsedSeconds() const;
		/**
		 * Address: 0x00461A90 (FUN_00461A90, ?ElapsedMilliseconds@Timer@time@gpg@@QBEMXZ)
		 *
		 * What it does:
		 * Returns elapsed wall-clock time in milliseconds since the timer baseline.
		 */
		float ElapsedMilliseconds() const;
	};

    /**
     * Address: 0x00955400 (FUN_00955400, gpg::time::GetCycle)
     *
     * What it does:
     * Returns a monotonic process cycle value derived from
     * `QueryPerformanceCounter`, clamped to never move backward.
     */
    LONGLONG GetCycle();

    /**
     * Address: 0x00955520 (FUN_00955520, gpg::time::CyclesToMicroseconds)
     *
     * What it does:
     * Converts performance-counter cycles to microseconds using cached
     * frequency state.
     */
    LONGLONG CyclesToMicroseconds(LONGLONG cycles);

    /**
     * Address: 0x009554E0 (FUN_009554E0, gpg::time::CyclesToMilliseconds)
     *
     * What it does:
     * Converts performance-counter cycles to milliseconds.
     */
    float CyclesToMilliseconds(LONGLONG cycles);

    /**
     * Address: 0x009554A0 (FUN_009554A0, gpg::time::CyclesToSeconds)
     *
     * What it does:
     * Converts performance-counter cycles to seconds.
     */
    float CyclesToSeconds(LONGLONG cycles);
    /**
     * Address: 0x00955730 (FUN_00955730)
     *
     * What it does:
     * Returns process-wide system timer singleton with one-time baseline initialization.
     */
    Timer const& GetSystemTimer();

    /**
     * Address: 0x00955630 (FUN_00955630, gpg::time::MicrosecondsToCycles)
     *
     * What it does:
     * Converts microseconds to performance-counter cycles.
     */
    LONGLONG MicrosecondsToCycles(LONGLONG microseconds);

    /**
     * Address: 0x009555F0 (FUN_009555F0, gpg::time::MillisecondsToCycles)
     *
     * What it does:
     * Converts milliseconds to performance-counter cycles.
     */
    LONGLONG MillisecondsToCycles(float milliseconds);

    /**
     * Address: 0x009555B0 (FUN_009555B0, gpg::time::SecondsToCycles)
     *
     * What it does:
     * Converts seconds to performance-counter cycles.
     */
    LONGLONG SecondsToCycles(float seconds);
}

