// FAF addition, not in the shipped binary: see XactClock.cpp.

#pragma once

namespace moho
{
  class IXACTEngine;

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Gives the DLL that implements `engine` (xactengine2_9.dll) a millisecond
   * clock that counts from process start instead of from Windows boot, by
   * pointing that module's QueryPerformanceCounter and GetTickCount imports at
   * engine functions. Call it right after the engine object is created and
   * before `IXACTEngine::Initialize`, so XACT never samples the system clock.
   *
   * Why:
   * XACT 2.9 reads `(DWORD)(QueryPerformanceCounter * 1000 / frequency)`
   * (x86 0x00407C14; inlined on x64), GetTickCount only when there is no
   * performance counter. Its worker-thread tick (x86 0x0040D34F, called from
   * the thread loop at 0x0040E001; x64 0x00411860) runs only while
   * `(LONG)now >= (LONG)(nextWork - 5)`, then sets `nextWork = now + 10`, and
   * the engine constructor zeroes `nextWork` (x86 0x0040D7FF). From 2^31 ms
   * (24.86 days) to 2^32 ms of uptime `now` is negative, that test never
   * passes, and the tick does nothing for the whole session: no per-cue
   * updates, no stream or notification work. That is the "sound partly
   * disappears after 24.8 days of uptime" bug. XACT 3.7 masks its clock to 31
   * bits for this reason (x86 0x100062AD).
   *
   * `/realtickcount` keeps the system clock. The environment variable
   * `FAF_TEST_TICK_OFFSET_DAYS` (test only) adds that many days to the clock
   * XACT would otherwise see, to reproduce the bug on a freshly booted machine.
   */
  void SND_InstallXactClock(const IXACTEngine& engine);
} // namespace moho
