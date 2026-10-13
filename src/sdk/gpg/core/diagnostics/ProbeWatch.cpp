#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <tlhelp32.h>

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/diagnostics/ProbeWatch.h"

namespace gpg::diag
{
  namespace
  {

    // The Watch section is always registered (it writes nothing when no
    // probe or watch was ever armed).
    void WriteProbeWatchSectionAdapter(std::FILE* const sink, const CrashSectionInfo& info)
    {
      WriteProbeWatchSection(sink, info);
    }

    const bool sProbeWatchSectionRegistered =
      (AddCrashSection("Watch", &WriteProbeWatchSectionAdapter), true);

  } // namespace

  namespace
  {

    constexpr int kMaxWatches = 4;    // DR0-DR3
    constexpr int kMaxProbes = 16;
    constexpr int kMaxLogLines = 512;
    constexpr int kMaxReportsPerWatch = 8;

    struct Watch
    {
      std::uintptr_t address = 0;      // dword-rounded
      std::uintptr_t baseAddress = 0;  // spec base before "+offset" (0 if none)
      bool armed = false;
      int reportCount = 0;
    };

    struct Probe
    {
      std::uintptr_t address = 0;      // int3 site
      unsigned char originalByte = 0;
      char watchExpr[64] = {};         // optional "ecx+474", armed on next hit
      bool armed = false;
      bool waitingStepOver = false;    // single-stepping over the probe
      int hitCount = 0;
    };

    // All state lives here. The dormant fast path is one relaxed load of
    // sAnythingArmed inside the debug-exception branch of the vectored
    // handler - zero cost on any non-debug exception.
    struct ProbeWatchState
    {
      Watch watches[kMaxWatches] = {};
      Probe probes[kMaxProbes] = {};

      // Ring log, mirrored into the crash report and faf_diag.log.
      char log[kMaxLogLines][160] = {};
      int logCount = 0;
      int logHead = 0;

      volatile LONG anythingArmed = 0;
    };

    ProbeWatchState& PwState()
    {
      static ProbeWatchState state;
      return state;
    }

    void PwLog(const char* const format, ...)
    {
      ProbeWatchState& s = PwState();
      va_list args;
      va_start(args, format);
      char* const slot = s.log[s.logHead];
      (void)::vsnprintf_s(slot, sizeof(s.log[0]), _TRUNCATE, format, args);
      va_end(args);
      s.logHead = (s.logHead + 1) % kMaxLogLines;
      if (s.logCount < kMaxLogLines) {
        ++s.logCount;
      }
      DiagLine("[WATCH] %s", slot);
    }

    // ---- DR7 computation ----

    std::uintptr_t ComputeDr7(const Watch watches[kMaxWatches])
    {
      std::uintptr_t dr7 = 0;
      for (int i = 0; i < kMaxWatches; ++i) {
        if (watches[i].armed) {
          dr7 |= (1ull << (2 * i));                          // local enable i
          dr7 |= (0x1ull << (16 + 4 * i));                   // RW=01 (write)
          dr7 |= (0x3ull << (18 + 4 * i));                   // LEN=11 (dword)
        }
      }
      return dr7;
    }

    void ApplyDebugRegsToThread(HANDLE thread, const Watch watches[kMaxWatches])
    {
      CONTEXT context{};
      context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
      if (::GetThreadContext(thread, &context) == FALSE) {
        return;
      }
      context.Dr0 = watches[0].armed ? watches[0].address : 0;
      context.Dr1 = watches[1].armed ? watches[1].address : 0;
      context.Dr2 = watches[2].armed ? watches[2].address : 0;
      context.Dr3 = watches[3].armed ? watches[3].address : 0;
      context.Dr6 = 0;
      context.Dr7 = ComputeDr7(watches);
      context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
      (void)::SetThreadContext(thread, &context);
    }


    // Arguments for the arming helper thread (namespace scope so the helper
    // function can reach them; single armer at a time - arming is a rare,
    // operator-driven event).
    struct HelperArgs
    {
      DWORD targetTid = 0;
      Watch watches[kMaxWatches] = {};
      HANDLE done = nullptr;
    };
    HelperArgs gArmingHelperArgs;

    DWORD WINAPI ArmingHelperThread(LPVOID)
    {
      HelperArgs& a = gArmingHelperArgs;
      HANDLE target =
        ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, a.targetTid);
      if (target == nullptr) {
        (void)::SetEvent(a.done);
        return 0;
      }
      if (::SuspendThread(target) != static_cast<DWORD>(-1)) {
        ApplyDebugRegsToThread(target, a.watches);
        (void)::ResumeThread(target);
      }
      (void)::CloseHandle(target);
      (void)::SetEvent(a.done);
      return 0;
    }

    void WriteDebugRegsCurrent(const Watch watches[kMaxWatches])
    {
      // `mov drX` is privileged (ring 0); the only user-mode route is
      // SuspendThread + SetThreadContext, and a thread cannot suspend
      // itself. A short-lived helper suspends us, writes the registers and
      // resumes - the standard in-process arming dance.
      HelperArgs& args = gArmingHelperArgs;
      args.targetTid = ::GetCurrentThreadId();
      for (int i = 0; i < kMaxWatches; ++i) {
        args.watches[i] = watches[i];
      }
      args.done = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (args.done == nullptr) {
        return;
      }

      HANDLE thread = ::CreateThread(nullptr, 0, &ArmingHelperThread, nullptr, 0, nullptr);
      if (thread != nullptr) {
        (void)::WaitForSingleObject(args.done, 2000);
        (void)::CloseHandle(thread);
      }
      (void)::CloseHandle(args.done);
    }

    void BroadcastDebugRegs()
    {
      ProbeWatchState& s = PwState();
      WriteDebugRegsCurrent(s.watches);

      const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
      if (snapshot == INVALID_HANDLE_VALUE) {
        return;
      }
      THREADENTRY32 entry{};
      entry.dwSize = sizeof(entry);
      const DWORD pid = ::GetCurrentProcessId();
      const DWORD currentTid = ::GetCurrentThreadId();
      if (::Thread32First(snapshot, &entry) != FALSE) {
        do {
          if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == currentTid) {
            continue;
          }
          HANDLE thread =
            ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
          if (thread == nullptr) {
            continue;
          }
          if (::SuspendThread(thread) != static_cast<DWORD>(-1)) {
            ApplyDebugRegsToThread(thread, s.watches);
            (void)::ResumeThread(thread);
          }
          (void)::CloseHandle(thread);
        } while (::Thread32Next(snapshot, &entry) != FALSE);
      }
      (void)::CloseHandle(snapshot);
    }

    // ---- software breakpoints ----

    bool InstallInt3(const std::uintptr_t address, unsigned char* const originalByte)
    {
      DWORD oldProtect = 0;
      if (::VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) {
        return false;
      }
      *originalByte = *reinterpret_cast<unsigned char*>(address);
      *reinterpret_cast<unsigned char*>(address) = 0xCC;
      (void)::VirtualProtect(reinterpret_cast<void*>(address), 1, oldProtect, &oldProtect);
      FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
      return true;
    }

    void RestoreInt3(const std::uintptr_t address, const unsigned char originalByte)
    {
      DWORD oldProtect = 0;
      if (::VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) {
        return;
      }
      *reinterpret_cast<unsigned char*>(address) = originalByte;
      (void)::VirtualProtect(reinterpret_cast<void*>(address), 1, oldProtect, &oldProtect);
      FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
    }

    void StepOverProbe(Probe& probe, CONTEXT& context)
    {
      // Restore the original byte, rewind to the instruction, trap after it.
      RestoreInt3(probe.address, probe.originalByte);
#if defined(_M_IX86)
      context.Eip = static_cast<DWORD>(probe.address);
#elif defined(_M_X64)
      context.Rip = probe.address;
#endif
      context.EFlags |= 0x100; // TF
      probe.waitingStepOver = true;
    }

    // ---- expression evaluation in a register context ----
    // Grammar (FADeepProbe subset): reg | reg+hex | [reg+hex]+hex.
    // reg: eax..edi/esp/ebp (x86) or rax..r15 (x64).

    bool EvalWatchExpr(const char* const expr, const CONTEXT& context, std::uintptr_t* const out)
    {
      if (expr == nullptr || out == nullptr || expr[0] == '\0') {
        return false;
      }
      char buffer[64] = {};
      (void)::strncpy_s(buffer, expr, _TRUNCATE);

      int length = 0;
      for (char* p = buffer; *p != '\0'; ++p) {
        if (*p != ' ') {
          buffer[length++] = *p;
        }
      }
      buffer[length] = '\0';

      auto regValue = [&](const char* const name, std::uintptr_t& value) -> bool {
#if defined(_M_IX86)
        struct
        {
          const char* name;
          std::uintptr_t value;
        } const regs[] = {
          {"eax", context.Eax}, {"ebx", context.Ebx}, {"ecx", context.Ecx}, {"edx", context.Edx},
          {"esi", context.Esi}, {"edi", context.Edi}, {"esp", context.Esp}, {"ebp", context.Ebp},
        };
#elif defined(_M_X64)
        struct
        {
          const char* name;
          std::uintptr_t value;
        } const regs[] = {
          {"rax", context.Rax}, {"rbx", context.Rbx}, {"rcx", context.Rcx}, {"rdx", context.Rdx},
          {"rsi", context.Rsi}, {"rdi", context.Rdi}, {"rsp", context.Rsp}, {"rbp", context.Rbp},
          {"r8", context.R8},   {"r9", context.R9},   {"r10", context.R10}, {"r11", context.R11},
          {"r12", context.R12}, {"r13", context.R13}, {"r14", context.R14}, {"r15", context.R15},
        };
#else
        struct
        {
          const char* name;
          std::uintptr_t value;
        } const regs[] = {};
#endif
        for (const auto& reg : regs) {
          if (::strcmp(name, reg.name) == 0) {
            value = reg.value;
            return true;
          }
        }
        return false;
      };

      std::uintptr_t address = 0;
      int index = 0;

      if (buffer[0] == '[') {
        int close = -1;
        for (int i = 1; buffer[i] != '\0'; ++i) {
          if (buffer[i] == ']') {
            close = i;
            break;
          }
        }
        if (close < 0) {
          return false;
        }
        char inner[48] = {};
        (void)::strncpy_s(inner, sizeof(inner), buffer + 1, close - 1);
        std::uintptr_t base = 0;
        char* const plus = std::strchr(inner, '+');
        if (plus != nullptr) {
          *plus = '\0';
          if (!regValue(inner, base)) {
            return false;
          }
          base += std::strtoull(plus + 1, nullptr, 16);
        } else if (!regValue(inner, base)) {
          return false;
        }
        if (::IsBadReadPtr(reinterpret_cast<void*>(base), sizeof(void*)) != FALSE) {
          return false;
        }
        address = *reinterpret_cast<std::uintptr_t*>(base);
        index = close + 1;
      } else {
        char regCopy[16] = {};
        char* const plus = std::strchr(buffer, '+');
        if (plus != nullptr) {
          (void)::strncpy_s(regCopy, sizeof(regCopy), buffer, plus - buffer);
          if (!regValue(regCopy, address)) {
            return false;
          }
          address += std::strtoull(plus + 1, nullptr, 16);
          index = length;
        } else {
          if (!regValue(buffer, address)) {
            return false;
          }
          index = length;
        }
      }

      if (buffer[index] == '+') {
        address += std::strtoull(buffer + index + 1, nullptr, 16);
      } else if (buffer[index] != '\0') {
        return false;
      }

      *out = address & ~static_cast<std::uintptr_t>(3); // dword rounding
      return true;
    }

    // ---- reports ----

    void EmitWatchReport(const int watchIndex, CONTEXT& context)
    {
      ProbeWatchState& s = PwState();
      const Watch& watch = s.watches[watchIndex];

      char addressText[40] = {};
      if (watch.baseAddress != 0 && watch.address != watch.baseAddress) {
        (void)::sprintf_s(addressText, sizeof(addressText), "%llX+%llX",
                         static_cast<unsigned long long>(watch.baseAddress),
                         static_cast<unsigned long long>(watch.address - watch.baseAddress));
      } else {
        (void)::sprintf_s(addressText, sizeof(addressText), "%llX",
                         static_cast<unsigned long long>(watch.address));
      }

      std::uintptr_t writtenValue = 0;
      if (::IsBadReadPtr(reinterpret_cast<void*>(watch.address), sizeof(void*)) == FALSE) {
        writtenValue = *reinterpret_cast<std::uintptr_t*>(watch.address);
      }

#if defined(_M_IX86)
      const std::uintptr_t pc = context.Eip;
#elif defined(_M_X64)
      const std::uintptr_t pc = context.Rip;
#else
      const std::uintptr_t pc = 0;
#endif

      PwLog("%s write by %llX, value %llX, report %d", addressText,
            static_cast<unsigned long long>(pc), static_cast<unsigned long long>(writtenValue),
            watch.reportCount);
      DiagLogStack("watch-write");
    }

    // ---- the vectored debug handler ----
    //
    // Handler discipline:
    //  * not armed (fast path): one relaxed load, continue search.
    //  * EXCEPTION_SINGLE_STEP with DR6 B0-B3: hardware watchpoint. Emit the
    //    report, then set RF (resume flag) so the faulting instruction
    //    executes without re-triggering; RF self-clears after one
    //    instruction, which re-arms the watchpoint exactly.
    //  * EXCEPTION_SINGLE_STEP with DR6 BS (bit 14): our step-over finished.
    //    Rewrite the int3, clear TF.
    //  * EXCEPTION_BREAKPOINT whose site is one of ours: count the hit,
    //    evaluate any pending probe watch expression, step over.
    //  * anything else: continue search.

    LONG CALLBACK ProbeWatchVectoredHandler(EXCEPTION_POINTERS* const info)
    {
      if (PwState().anythingArmed == 0) {
        return EXCEPTION_CONTINUE_SEARCH;
      }
      if (info == nullptr || info->ExceptionRecord == nullptr || info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
      }

      CONTEXT& context = *info->ContextRecord;
      const DWORD code = info->ExceptionRecord->ExceptionCode;
      ProbeWatchState& s = PwState();

      if (code == EXCEPTION_SINGLE_STEP) {
        const DWORD64 dr6 = context.Dr6;
        bool handled = false;

        // Watchpoint bits first: a stepped instruction may itself write a
        // watched address (the FADeepProbe #3 collision case).
        if ((dr6 & 0xF) != 0) {
          for (int i = 0; i < kMaxWatches; ++i) {
            if ((dr6 & (1ull << i)) == 0 || !s.watches[i].armed) {
              continue;
            }
            Watch& watch = s.watches[i];
            if (watch.reportCount < kMaxReportsPerWatch) {
              ++watch.reportCount;
              EmitWatchReport(i, context);
            }
          }
          context.Dr6 = 0;
          context.EFlags |= 0x10000; // RF: execute without re-trigger
          handled = true;
        }

        // Our step-over trap (BS, bit 14)?
        if ((dr6 & 0x4000) != 0) {
          for (int i = 0; i < kMaxProbes; ++i) {
            if (s.probes[i].armed && s.probes[i].waitingStepOver) {
              s.probes[i].waitingStepOver = false;
              // The original byte was restored before the step; re-trap.
              if (InstallInt3(s.probes[i].address, &s.probes[i].originalByte)) {
                // keep originalByte accurate for future restores
              }
              break;
            }
          }
          context.Dr6 = 0;
          context.EFlags &= ~0x100u; // clear TF
          handled = true;
        }

        return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
      }

      if (code == EXCEPTION_BREAKPOINT) {
#if defined(_M_IX86)
        const std::uintptr_t site = context.Eip - 1;
#elif defined(_M_X64)
        const std::uintptr_t site = context.Rip - 1;
#else
        const std::uintptr_t site = 0;
#endif
        for (int i = 0; i < kMaxProbes; ++i) {
          if (!s.probes[i].armed || s.probes[i].address != site) {
            continue;
          }
          Probe& probe = s.probes[i];
          ++probe.hitCount;
          PwLog("probe %llX hit %d", static_cast<unsigned long long>(site), probe.hitCount);
          DiagLogStack("probe-hit");

          // Arm the probe's watch expression now, in this register context -
          // this reaches objects whose address only exists at this callsite.
          if (probe.watchExpr[0] != '\0') {
            std::uintptr_t watched = 0;
            if (EvalWatchExpr(probe.watchExpr, context, &watched)) {
              // Take the first free watch slot (or 0).
              int slot = -1;
              for (int w = 0; w < kMaxWatches; ++w) {
                if (!s.watches[w].armed) {
                  slot = w;
                  break;
                }
              }
              if (slot < 0) {
                slot = 0;
              }
              s.watches[slot] = Watch{};
              s.watches[slot].armed = true;
              s.watches[slot].address = watched;
              s.watches[slot].baseAddress = 0;
              BroadcastDebugRegs();
              PwLog("%llX armed by probe %llX (%s)", static_cast<unsigned long long>(watched),
                    static_cast<unsigned long long>(site), probe.watchExpr);
            }
            probe.watchExpr[0] = '\0';
          }

          StepOverProbe(probe, context);
          return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH; // not one of ours
      }

      return EXCEPTION_CONTINUE_SEARCH;
    }

  } // namespace

  bool ParseWatchSpec(const char* const spec)
  {
    if (spec == nullptr || spec[0] == '\0') {
      return false;
    }
    ProbeWatchState& s = PwState();

    // A request replaces the whole watch set (FADeepProbe semantics).
    for (int i = 0; i < kMaxWatches; ++i) {
      s.watches[i] = Watch{};
    }

    int armedCount = 0;
    const char* p = spec;
    while (*p != '\0' && armedCount < kMaxWatches) {
      const char* const comma = std::strchr(p, ',');
      char one[64] = {};
      const std::size_t length = (comma != nullptr) ? static_cast<std::size_t>(comma - p) : std::strlen(p);
      if (length == 0 || length >= sizeof(one)) {
        break;
      }
      (void)::strncpy_s(one, sizeof(one), p, length);

      const std::uintptr_t base = std::strtoull(one, nullptr, 16);
      std::uintptr_t address = base;
      const char* const plus = std::strchr(one, '+');
      if (plus != nullptr) {
        address += std::strtoull(plus + 1, nullptr, 16);
      }
      address &= ~static_cast<std::uintptr_t>(3); // dword rounding

      s.watches[armedCount].armed = true;
      s.watches[armedCount].address = address;
      s.watches[armedCount].baseAddress = (plus != nullptr) ? base : 0;
      ++armedCount;

      if (comma == nullptr) {
        break;
      }
      p = comma + 1;
    }

    if (armedCount == 0) {
      return false;
    }

    BroadcastDebugRegs();
    ::InterlockedExchange(&s.anythingArmed, 1);
    for (int i = 0; i < armedCount; ++i) {
      PwLog("%llX armed (watch %d)", static_cast<unsigned long long>(s.watches[i].address), i);
    }
    return true;
  }

  bool ParseProbeSpec(const char* const spec)
  {
    if (spec == nullptr || spec[0] == '\0') {
      return false;
    }
    ProbeWatchState& s = PwState();

    char addressText[32] = {};
    const char* const colon = std::strchr(spec, ':');
    const std::size_t addressLength =
      (colon != nullptr) ? static_cast<std::size_t>(colon - spec) : std::strlen(spec);
    if (addressLength == 0 || addressLength >= sizeof(addressText)) {
      return false;
    }
    (void)::strncpy_s(addressText, sizeof(addressText), spec, addressLength);
    const std::uintptr_t address = std::strtoull(addressText, nullptr, 16);
    if (address == 0) {
      return false;
    }

    for (int i = 0; i < kMaxProbes; ++i) {
      if (s.probes[i].armed) {
        continue;
      }
      s.probes[i].armed = true;
      s.probes[i].address = address;
      if (colon != nullptr) {
        (void)::strncpy_s(s.probes[i].watchExpr, sizeof(s.probes[i].watchExpr), colon + 1, _TRUNCATE);
      }
      if (InstallInt3(address, &s.probes[i].originalByte)) {
        ::InterlockedExchange(&s.anythingArmed, 1);
        PwLog("probe %llX armed%s", static_cast<unsigned long long>(address),
              (colon != nullptr) ? " with watch expression" : "");
        return true;
      }
      s.probes[i].armed = false;
      return false;
    }
    return false;
  }

  bool ParseFadepProbeRequest(const char* const text)
  {
    if (text == nullptr) {
      return false;
    }
    if (::strncmp(text, "FADeepProbe watchaddr ", 22) == 0) {
      return ParseWatchSpec(text + 22);
    }
    if (::strncmp(text, "FADeepProbe probe ", 18) == 0) {
      return ParseProbeSpec(text + 18);
    }
    return false;
  }

  void InstallProbeWatchHandler()
  {
    (void)::AddVectoredExceptionHandler(0, &ProbeWatchVectoredHandler); // behind the fault logger
  }

  void WriteProbeWatchSection(std::FILE* const sink, const CrashSectionInfo& info)
  {
    (void)info;
    ProbeWatchState& s = PwState();
    if (s.anythingArmed == 0) {
      return;
    }

    (void)std::fprintf(sink, "probe/watch log (%d events):\n", s.logCount);
    for (int i = 0; i < s.logCount && i < kMaxLogLines; ++i) {
      const int index = (s.logHead + kMaxLogLines - s.logCount + i) % kMaxLogLines;
      (void)std::fprintf(sink, "%s\n", s.log[index]);
    }

    for (int i = 0; i < kMaxProbes; ++i) {
      if (s.probes[i].armed) {
        (void)std::fprintf(sink, "probe %llX: %d hit(s)\n", static_cast<unsigned long long>(s.probes[i].address),
                          s.probes[i].hitCount);
      }
    }
    for (int i = 0; i < kMaxWatches; ++i) {
      if (s.watches[i].armed) {
        (void)std::fprintf(sink, "watch %llX: %d report(s)\n", static_cast<unsigned long long>(s.watches[i].address),
                          s.watches[i].reportCount);
      }
    }
    (void)std::fflush(sink);
  }

  void ProbeWatchSelfTest()
  {
    // Arm a watch on a local, write it, and let the handler report. Used by
    // /crashtest watch to verify the whole DR0-DR3 path end to end.
    volatile std::uint32_t scratch = 0;
    char spec[64] = {};
    (void)::sprintf_s(spec, sizeof(spec), "%llX", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(&scratch)));
    PwLog("selftest: arming watch on %s", spec);
    if (!ParseWatchSpec(spec)) {
      PwLog("selftest: arm failed");
      return;
    }
    PwLog("selftest: writing 0x42");
    scratch = 0x42; // must produce one watch-write report
    PwLog("selftest: wrote, scratch=%X", static_cast<unsigned>(scratch));
  }

} // namespace gpg::diag
