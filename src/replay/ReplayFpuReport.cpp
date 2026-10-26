#include "replay/ReplayFpuReport.h"

#if defined(_WIN32)
#include <Windows.h>
#include <TlHelp32.h>
#else
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include <csignal>
#include <dirent.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstdio>
#include <map>
#include <utility>
#include <vector>

// Engine addition, server mode: see ReplayFpuReport.h. Windows suspends each thread and reads
// its context; Linux (plan WPL.9) sends each thread a real-time signal and reads the x87
// control word and MXCSR the kernel saved in the signal frame (the handler's own registers
// are reset, the interrupted thread's are in ucontext's fpregs).

#if !defined(_WIN32)
namespace faf::replay
{
  namespace
  {
    std::atomic<int> gSampleDone{0};
    unsigned gSampledControlWord = 0;
    unsigned gSampledMxcsr = 0;

    void OnSampleSignal(int, siginfo_t*, void* const rawContext)
    {
      const auto* const context = static_cast<const ucontext_t*>(rawContext);
      if (context != nullptr && context->uc_mcontext.fpregs != nullptr) {
        gSampledControlWord = context->uc_mcontext.fpregs->cwd;
        gSampledMxcsr = context->uc_mcontext.fpregs->mxcsr;
        gSampleDone.store(1, std::memory_order_release);
      } else {
        gSampleDone.store(2, std::memory_order_release);
      }
    }

    struct SThreadSamples
    {
      long id = 0;
      std::map<std::pair<unsigned, unsigned>, int> values; // (x87 control word, MXCSR) -> count
      double userSeconds = 0.0;
    };

    [[nodiscard]] std::vector<long> OtherThreadIds()
    {
      std::vector<long> ids;
      const long self = static_cast<long>(::syscall(SYS_gettid));
      if (DIR* const tasks = ::opendir("/proc/self/task")) {
        while (const dirent* const entry = ::readdir(tasks)) {
          const long id = std::strtol(entry->d_name, nullptr, 10);
          if (id > 0 && id != self) {
            ids.push_back(id);
          }
        }
        (void)::closedir(tasks);
      }
      return ids;
    }

    [[nodiscard]] double ThreadUserSeconds(const long id)
    {
      char path[64];
      std::snprintf(path, sizeof(path), "/proc/self/task/%ld/stat", id);
      std::FILE* const file = std::fopen(path, "r");
      if (file == nullptr) {
        return 0.0;
      }
      char line[1024] = {};
      const bool read = std::fgets(line, sizeof(line), file) != nullptr;
      std::fclose(file);
      // Field 14 (utime) counts clock ticks; the name in field 2 may hold spaces, so count
      // from its closing parenthesis.
      const char* cursor = read ? std::strrchr(line, ')') : nullptr;
      for (int field = 2; cursor != nullptr && field < 14; ++field) {
        cursor = std::strchr(cursor + 1, ' ');
      }
      return cursor != nullptr ? std::strtod(cursor + 1, nullptr) / static_cast<double>(::sysconf(_SC_CLK_TCK)) : 0.0;
    }
  } // namespace

  std::string ReportThreadFloatingPointState(const int samples, const int intervalMs)
  {
    const int signalNumber = SIGRTMIN + 3;
    struct sigaction action{};
    struct sigaction previous{};
    action.sa_sigaction = &OnSampleSignal;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&action.sa_mask);
    (void)::sigaction(signalNumber, &action, &previous);

    std::map<long, SThreadSamples> threads;
    for (int round = 0; round < samples; ++round) {
      for (const long id : OtherThreadIds()) {
        gSampleDone.store(0, std::memory_order_release);
        if (::syscall(SYS_tgkill, static_cast<long>(::getpid()), id, signalNumber) != 0) {
          continue;
        }
        // A thread that blocks the signal is skipped after 100 ms.
        for (int wait = 0; wait < 100 && gSampleDone.load(std::memory_order_acquire) == 0; ++wait) {
          const timespec pause{0, 1000000};
          (void)::nanosleep(&pause, nullptr);
        }
        if (gSampleDone.load(std::memory_order_acquire) == 1) {
          SThreadSamples& entry = threads[id];
          entry.id = id;
          ++entry.values[{gSampledControlWord, gSampledMxcsr}];
          entry.userSeconds = ThreadUserSeconds(id);
        }
      }
      const timespec interval{intervalMs / 1000, static_cast<long>(intervalMs % 1000) * 1000000L};
      (void)::nanosleep(&interval, nullptr);
    }
    (void)::sigaction(signalNumber, &previous, nullptr);

    std::vector<SThreadSamples> sorted;
    for (auto& [id, entry] : threads) {
      sorted.push_back(std::move(entry));
    }
    std::sort(sorted.begin(), sorted.end(), [](const SThreadSamples& a, const SThreadSamples& b) {
      return a.userSeconds > b.userSeconds;
    });
    std::string text;
    char line[256];
    for (const SThreadSamples& entry : sorted) {
      std::snprintf(line, sizeof(line), "thread %ld user cpu %.2fs:", entry.id, entry.userSeconds);
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
#else
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
#endif // _WIN32
