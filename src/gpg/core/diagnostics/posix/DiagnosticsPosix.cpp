// Engine addition (dedicated-server plan WPL.5): the crash diagnostics of
// gpg/core/diagnostics (CrashHooks.h, CrashReport.h, ProbeWatch.h) for the Linux build, in
// place of CrashHooks.cpp, CrashReport.cpp and ProbeWatch.cpp, which are built on dbghelp,
// vectored exception handlers, minidumps and the debug registers.
//
// What is kept: faf_diag.log beside the executable, fatal signals and std::terminate written
// as a text report (reason, the faulting thread's stack, the registered sections) to
// faf_crash_<time>.txt and faf_crash_latest.txt beside the executable, and the report's path
// on stderr. Minidumps are the system's core dumps; memory watches and code probes are not
// available.

#if !defined(_WIN32)

#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/diagnostics/ProbeWatch.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>

#include <csignal>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>

namespace
{
  constexpr std::size_t kPathBytes = 4096;
  constexpr int kMaxFrames = 64;

  struct CrashSection
  {
    const char* name = nullptr;
    gpg::diag::CrashSectionWriter writer = nullptr;
    int priority = 0;
  };

  std::array<CrashSection, 8> gSections{};
  int gSectionCount = 0;
  std::atomic<bool> gWritingReport{false};

  char gExeDir[kPathBytes]{};
  char gDiagLogPath[kPathBytes]{};
  char gReportPath[kPathBytes]{};
  char gLatestReportPath[kPathBytes]{};
  char gDumpPath[kPathBytes]{};

  /// The directory of the running executable, with a trailing '/'.
  const char* ExeDir()
  {
    if (gExeDir[0] == '\0') {
      char exe[kPathBytes]{};
      const ssize_t length = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
      if (length > 0) {
        exe[length] = '\0';
        char* const slash = std::strrchr(exe, '/');
        if (slash != nullptr) {
          slash[1] = '\0';
        }
        std::snprintf(gExeDir, sizeof(gExeDir), "%s", exe);
      } else {
        std::snprintf(gExeDir, sizeof(gExeDir), "./");
      }
    }
    return gExeDir;
  }

  void AppendToFile(const char* const path, const char* const text, const std::size_t length)
  {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
      return;
    }
    std::size_t written = 0;
    while (written < length) {
      const ssize_t put = ::write(fd, text + written, length - written);
      if (put <= 0) {
        break;
      }
      written += static_cast<std::size_t>(put);
    }
    (void)::close(fd);
  }

  void WriteStack(std::FILE* const sink, const int skipFrames)
  {
    void* frames[kMaxFrames]{};
    const int count = ::backtrace(frames, kMaxFrames);
    for (int index = skipFrames; index < count; ++index) {
      char line[1024]{};
      gpg::diag::DiagDescribeAddress(frames[index], line, sizeof(line));
      std::fprintf(sink, "  #%02d %p %s\n", index - skipFrames, frames[index], line);
    }
  }

  const char* SignalName(const int signalNumber)
  {
    switch (signalNumber) {
    case SIGSEGV:
      return "SIGSEGV (segmentation fault)";
    case SIGBUS:
      return "SIGBUS (bus error)";
    case SIGFPE:
      return "SIGFPE (arithmetic exception)";
    case SIGILL:
      return "SIGILL (illegal instruction)";
    case SIGABRT:
      return "SIGABRT (abort)";
    default:
      return "fatal signal";
    }
  }

  void OnFatalSignal(const int signalNumber, siginfo_t* const info, void*)
  {
    char reason[256]{};
    std::snprintf(
      reason, sizeof(reason), "%s at address %p", SignalName(signalNumber), info != nullptr ? info->si_addr : nullptr
    );
    gpg::diag::CrashReportContext context{};
    context.reason = reason;
    gpg::diag::HandleFatalPath(context);

    // The default action (terminate, core dump where enabled) follows.
    std::signal(signalNumber, SIG_DFL);
    (void)::raise(signalNumber);
  }

  void OnTerminate()
  {
    gpg::diag::CrashReportContext context{};
    context.reason = "std::terminate";
    gpg::diag::HandleFatalPath(context);
    std::abort();
  }
} // namespace

namespace gpg::diag
{
  void InstallCrtDiagnosticHooks(const CrtDiagOptions& options)
  {
    (void)options; // CRT heap validation is MSVC's.

    // An alternate stack, so a stack overflow can still be reported.
    static std::array<char, 64 * 1024> sAlternateStack{};
    stack_t alternate{};
    alternate.ss_sp = sAlternateStack.data();
    alternate.ss_size = sAlternateStack.size();
    (void)::sigaltstack(&alternate, nullptr);

    struct sigaction action{};
    action.sa_sigaction = &OnFatalSignal;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&action.sa_mask);
    for (const int signalNumber : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT}) {
      (void)::sigaction(signalNumber, &action, nullptr);
    }
    std::set_terminate(&OnTerminate);
    DiagLine("diagnostic hooks installed (POSIX: fatal signals, std::terminate)");
  }

  const char* DiagLogPath()
  {
    if (gDiagLogPath[0] == '\0') {
      std::snprintf(gDiagLogPath, sizeof(gDiagLogPath), "%sfaf_diag.log", ExeDir());
    }
    return gDiagLogPath;
  }

  void DiagLine(const char* const format, ...)
  {
    char line[2048]{};
    const std::time_t now = std::time(nullptr);
    std::tm parts{};
    (void)::localtime_r(&now, &parts);
    int length = static_cast<int>(std::strftime(line, sizeof(line), "%Y-%m-%d %H:%M:%S ", &parts));

    va_list arguments;
    va_start(arguments, format);
    const int body = std::vsnprintf(line + length, sizeof(line) - static_cast<std::size_t>(length) - 1, format, arguments);
    va_end(arguments);
    if (body > 0) {
      length = std::min<int>(length + body, static_cast<int>(sizeof(line)) - 2);
    }
    line[length++] = '\n';
    AppendToFile(DiagLogPath(), line, static_cast<std::size_t>(length));
  }

  void DiagLogStack(const char* const tag)
  {
    DiagLine("stack (%s):", tag != nullptr ? tag : "");
    void* frames[kMaxFrames]{};
    const int count = ::backtrace(frames, kMaxFrames);
    for (int index = 1; index < count; ++index) {
      char line[1024]{};
      DiagDescribeAddress(frames[index], line, sizeof(line));
      DiagLine("  #%02d %s", index - 1, line);
    }
  }

  void DiagDescribeAddress(const void* const address, char* const out, const std::size_t outBytes)
  {
    if (out == nullptr || outBytes == 0) {
      return;
    }
    Dl_info info{};
    if (::dladdr(address, &info) == 0 || info.dli_fname == nullptr) {
      std::snprintf(out, outBytes, "%p", address);
      return;
    }
    const char* const slash = std::strrchr(info.dli_fname, '/');
    const char* const module = slash != nullptr ? slash + 1 : info.dli_fname;
    const auto offset = reinterpret_cast<std::uintptr_t>(address) - reinterpret_cast<std::uintptr_t>(info.dli_fbase);
    if (info.dli_sname != nullptr) {
      const auto symbolOffset =
        reinterpret_cast<std::uintptr_t>(address) - reinterpret_cast<std::uintptr_t>(info.dli_saddr);
      std::snprintf(out, outBytes, "%s+0x%zx [%s+0x%zx]", module, static_cast<std::size_t>(offset), info.dli_sname,
                    static_cast<std::size_t>(symbolOffset));
    } else {
      std::snprintf(out, outBytes, "%s+0x%zx", module, static_cast<std::size_t>(offset));
    }
  }

  bool DiagSymbolsReady()
  {
    return true;
  }

  void AddCrashSection(const char* const name, const CrashSectionWriter writer, const int priority)
  {
    if (name == nullptr || writer == nullptr || gSectionCount >= static_cast<int>(gSections.size())) {
      return;
    }
    int at = gSectionCount;
    while (at > 0 && gSections[at - 1].priority > priority) {
      gSections[at] = gSections[at - 1];
      --at;
    }
    gSections[at] = CrashSection{name, writer, priority};
    ++gSectionCount;
  }

  const char* CrashReportPath()
  {
    if (gReportPath[0] == '\0') {
      const std::time_t now = std::time(nullptr);
      std::tm parts{};
      (void)::localtime_r(&now, &parts);
      char stamp[32]{};
      (void)std::strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &parts);
      std::snprintf(gReportPath, sizeof(gReportPath), "%sfaf_crash_%s.txt", ExeDir(), stamp);
    }
    return gReportPath;
  }

  const char* CrashLatestReportPath()
  {
    if (gLatestReportPath[0] == '\0') {
      std::snprintf(gLatestReportPath, sizeof(gLatestReportPath), "%sfaf_crash_latest.txt", ExeDir());
    }
    return gLatestReportPath;
  }

  const char* CrashDumpPath()
  {
    if (gDumpPath[0] == '\0') {
      std::snprintf(gDumpPath, sizeof(gDumpPath), "%s", CrashReportPath());
      char* const dot = std::strrchr(gDumpPath, '.');
      if (dot != nullptr) {
        std::snprintf(dot, sizeof(gDumpPath) - static_cast<std::size_t>(dot - gDumpPath), ".dmp");
      }
    }
    return gDumpPath;
  }

  bool WriteCrashReport(const CrashReportContext& context)
  {
    bool expected = false;
    if (!gWritingReport.compare_exchange_strong(expected, true)) {
      return false;
    }

    const char* const reportPath = CrashReportPath();
    std::FILE* const sink = std::fopen(reportPath, "w");
    if (sink == nullptr) {
      return false;
    }
    std::setvbuf(sink, nullptr, _IOLBF, 0);

    const std::time_t now = std::time(nullptr);
    std::fprintf(sink, "FAF crash report (POSIX)\n");
    std::fprintf(sink, "time: %s", std::ctime(&now));
    std::fprintf(sink, "process: %d\n", static_cast<int>(::getpid()));
    std::fprintf(sink, "reason: %s\n", context.reason != nullptr ? context.reason : "(unknown)");

    const CrashSectionInfo info{};
    int section = 0;
    for (; section < gSectionCount && gSections[section].priority < kAfterModulesPriority; ++section) {
      std::fprintf(sink, "\n== %s ==\n", gSections[section].name);
      gSections[section].writer(sink, info);
    }
    std::fprintf(sink, "\n== Stack ==\n");
    WriteStack(sink, 1);
    for (; section < gSectionCount; ++section) {
      std::fprintf(sink, "\n== %s ==\n", gSections[section].name);
      gSections[section].writer(sink, info);
    }
    std::fclose(sink);

    // The stable copy of the newest report.
    if (std::FILE* const source = std::fopen(reportPath, "r")) {
      if (std::FILE* const latest = std::fopen(CrashLatestReportPath(), "w")) {
        char buffer[4096];
        std::size_t got = 0;
        while ((got = std::fread(buffer, 1, sizeof(buffer), source)) > 0) {
          (void)std::fwrite(buffer, 1, got, latest);
        }
        std::fclose(latest);
      }
      std::fclose(source);
    }
    DiagLine("crash report written: %s (%s)", reportPath, context.reason != nullptr ? context.reason : "");
    return true;
  }

  void HandleFatalPath(const CrashReportContext& context)
  {
    if (WriteCrashReport(context)) {
      ShowCrashReportDialog(CrashReportPath());
    }
  }

  bool WriteCrashMinidump(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    (void)exceptionInfo;
    return false;
  }

  void NoteSimLuaError(const char* const message)
  {
    (void)message; // The minidump-on-Lua-error aid is Windows only.
  }

  void CopyCrashReportToClipboard() {}

  void ShowCrashReportDialog(const char* const reportPath)
  {
    std::fprintf(stderr, "FAF crashed; report: %s\n", reportPath != nullptr ? reportPath : "(none)");
  }

  bool ParseWatchSpec(const char* const spec)
  {
    DiagLine("memory watch \"%s\" ignored: not available on this platform", spec != nullptr ? spec : "");
    return false;
  }

  bool ParseProbeSpec(const char* const spec)
  {
    DiagLine("code probe \"%s\" ignored: not available on this platform", spec != nullptr ? spec : "");
    return false;
  }

  bool ParseFadepProbeRequest(const char* const text)
  {
    (void)text;
    return false;
  }

  void InstallProbeWatchHandler() {}

  void WriteProbeWatchSection(std::FILE* const sink, const CrashSectionInfo& info)
  {
    (void)info;
    std::fprintf(sink, "(memory watches and code probes are not available on this platform)\n");
  }

  void ProbeWatchSelfTest() {}
} // namespace gpg::diag

#endif // !defined(_WIN32)
