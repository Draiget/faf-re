#pragma once

#include "platform/Platform.h"

namespace gpg::time
{
	class Timer
	{
	public:
		LONGLONG mTime;

		Timer();      // 0x009556F0 or 0x009556D0
		void Reset(); // 0x009556D0 or 0x009556F0
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
		LONGLONG ElapsedSeconds() const; // 0x004A3560
		LONGLONG ElapsedMilliseconds() const; // 0x00461A90
	};

    LONGLONG GetTime(); // 0x00955400
    LONGLONG CyclesToMicroseconds(LONGLONG); // 0x00955520
    float CyclesToMilliseconds(LONGLONG); // 0x009554E0
    float CyclesToSeconds(LONGLONG); // 0x009554A0
    /**
     * Address: 0x00955730 (FUN_00955730)
     *
     * What it does:
     * Returns process-wide system timer singleton with one-time baseline initialization.
     */
    Timer const& GetSystemTimer();
    LONGLONG MicrosecondsToCycles(LONGLONG); // 0x00955630
    LONGLONG MillisecondsToCycles(float); // 0x009555F0
    LONGLONG SecondsToCycles(float); // 0x009555B0
}

