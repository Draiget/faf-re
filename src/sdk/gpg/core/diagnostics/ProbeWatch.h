#ifndef GPG_CORE_DIAGNOSTICS_PROBEWATCH_H
#define GPG_CORE_DIAGNOSTICS_PROBEWATCH_H

#include <cstdio>

struct _EXCEPTION_POINTERS;

namespace gpg::diag
{

  struct CrashSectionInfo;

  /**
   * Memory watches (hardware, DR0-DR3) and code probes (software int3).
   * Dormant unless armed; one atomic load per debug exception otherwise.
   *
   * Watches: "addr" or "addr+offset" (hex). The first write by each
   * instruction to each watched address produces a full report (registers,
   * engine stack, Lua stack); later writes are counted per instruction.
   * Rounding: watch length is one dword (4 bytes), address rounded to the
   * dword it falls in - matching FADeepProbe's behaviour.
   *
   * Probes: any code address. Counts hits and collects the calling engine
   * function (stack symbol) per probe. A probe may carry a watch expression
   * ("addr:ecx+474" or "addr:[esp+4]+10"): on the probe's next hit the
   * expression is evaluated in the faulting register context and armed as a
   * watch - this reaches objects whose address only exists in registers.
   *
   * Arming: `/w <spec>` and `/p <spec>` command-line switches, console
   * commands `faf_watch` / `faf_probe`, and the FADeepProbe-compatible Lua
   * request strings handled in lua (pcall(error, "FADeepProbe ...")).
   */
  bool ParseWatchSpec(const char* spec);          // "1a2b3000+474"
  bool ParseProbeSpec(const char* spec);          // "438310" / "438310:ecx+474"
  bool ParseFadepProbeRequest(const char* text);  // "FADeepProbe watchaddr ..." / "... probe ..."

  /** Installs the vectored handler front-most. Safe to call more than once. */
  void InstallProbeWatchHandler();

  /** Crash-report section writer: the Watch/Probe log. */
  void WriteProbeWatchSection(std::FILE* sink, const CrashSectionInfo& info);

  /** Test hooks (used by /crashtest probe variants). */
  void ProbeWatchSelfTest();

} // namespace gpg::diag

#endif // GPG_CORE_DIAGNOSTICS_PROBEWATCH_H
