#include "replay/ReplayFpuReport.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <utility>
#include <vector>

// Engine addition, server mode: see ReplayFpuReport.h. Windows only (as faf-replay v1 is).

namespace faf::replay
{
  namespace
  {
    struct SThreadSamples
    {
      DWORD id = 0;
      std::map<std::pair<unsigned, unsigned>, int> values; // (x87 control word, MXCSR) -> count
      ULONGLONG cpu100ns = 0;
    };

    [[nodiscard]] std::vector<DWORD> OtherThreadIds()
    {
      std::vector<DWORD> ids;
      const DWORD process = ::GetCurrentProcessId();
      const DWORD self = ::GetCurrentThreadId();
      const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
      if (snapshot == INVALID_HANDLE_VALUE) {
        return ids;
      }
      THREADENTRY32 entry{};
      entry.dwSize = sizeof(entry);
      for (BOOL more = ::Thread32First(snapshot, &entry); more; more = ::Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID == process && entry.th32ThreadID != self) {
          ids.push_back(entry.th32ThreadID);
        }
      }
      ::CloseHandle(snapshot);
      return ids;
    }

    /** Suspends, reads the floating-point context, resumes; nothing allocates in between. */
    [[nodiscard]] bool SampleThread(const HANDLE thread, unsigned& controlWord, unsigned& mxcsr)
    {
      if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
        return false;
      }
      CONTEXT context{};
      context.ContextFlags = CONTEXT_FLOATING_POINT;
      const BOOL ok = ::GetThreadContext(thread, &context);
      ::ResumeThread(thread);
      if (!ok) {
        return false;
      }
#if defined(_M_X64)
      controlWord = context.FltSave.ControlWord;
      mxcsr = context.MxCsr;
#else
      controlWord = context.FloatSave.ControlWord & 0xFFFFu;
      mxcsr = 0; // the x86 CONTEXT has no MXCSR outside the extended registers
#endif
      return true;
    }
  } // namespace

  std::string ReportThreadFloatingPointState(const int samples, const int intervalMs)
  {
    std::map<DWORD, SThreadSamples> threads;
    for (int round = 0; round < samples; ++round) {
      for (const DWORD id : OtherThreadIds()) {
        const HANDLE thread =
          ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, id);
        if (thread == nullptr) {
          continue;
        }
        unsigned controlWord = 0;
        unsigned mxcsr = 0;
        if (SampleThread(thread, controlWord, mxcsr)) {
          SThreadSamples& entry = threads[id];
          entry.id = id;
          ++entry.values[{controlWord, mxcsr}];
          FILETIME created{}, exited{}, kernel{}, user{};
          if (::GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
            entry.cpu100ns = (static_cast<ULONGLONG>(user.dwHighDateTime) << 32) | user.dwLowDateTime;
          }
        }
        ::CloseHandle(thread);
      }
      ::Sleep(static_cast<DWORD>(intervalMs));
    }

    std::vector<SThreadSamples> sorted;
    for (auto& [id, entry] : threads) {
      sorted.push_back(std::move(entry));
    }
    std::sort(sorted.begin(), sorted.end(), [](const SThreadSamples& a, const SThreadSamples& b) {
      return a.cpu100ns > b.cpu100ns;
    });
    std::string text;
    char line[256];
    for (const SThreadSamples& entry : sorted) {
      std::snprintf(line, sizeof(line), "thread %lu user cpu %.2fs:", entry.id, entry.cpu100ns / 1.0e7);
      text += line;
      for (const auto& [value, count] : entry.values) {
        std::snprintf(line, sizeof(line), " fcw=0x%04X mxcsr=0x%04X x%d", value.first, value.second, count);
        text += line;
      }
      text += "\n";
    }
    return text;
  }
} // namespace faf::replay
