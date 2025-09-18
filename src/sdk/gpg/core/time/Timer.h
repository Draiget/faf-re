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
		LONGLONG ElapsedCyclesAndReset(); // 0x00955710
		LONGLONG ElapsedCycles() const; // 0x00955700
		float ElapsedMicroseconds() const; // 0x00485A40
		float ElapsedSeconds() const; // 0x004A3560
		float ElapsedMilliSeconds() const; // 0x00461A90
	};

    LONGLONG GetTime(); // 0x00955400
    LONGLONG CyclesToMicroseconds(LONGLONG); // 0x00955520
    float CyclesToMilliseconds(LONGLONG); // 0x009554E0
    float CyclesToSeconds(LONGLONG); // 0x009554A0
    Timer const& GetSystemTimer(); // 0x00955730
    LONGLONG MicrosecondsToCycles(LONGLONG); // 0x00955630
    LONGLONG MillisecondsToCycles(float); // 0x009555F0
    LONGLONG SecondsToCycles(float); // 0x009555B0
}

