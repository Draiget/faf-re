#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <dbghelp.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gpg/core/diagnostics/CrashHooks.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"

namespace gpg::diag
{
  namespace
  {

    constexpr std::size_t kMaxSections = 8;
    constexpr std::uint32_t kMaxFramesPerThread = 64;
    constexpr std::size_t kMaxSuspendedThreads = 64;

    struct SectionRegistry
    {
      const char* names[kMaxSections] = {};
      CrashSectionWriter writers[kMaxSections] = {};
      std::size_t count = 0;
    };

    SectionRegistry& SectionRegistryInstance()
    {
      static SectionRegistry registry;
      return registry;
    }

    // Re-entry guard: the first fatal path to arrive writes the report; any
    // nested fault inside the writer must not try to write a second one.
    volatile LONG sReportInProgress = 0;

    // One fprintf + flush per line. If the process dies mid-report, every
    // completed line is already on disk.
    void ReportLine(std::FILE* const sink, const char* const format, ...)
    {
      if (sink == nullptr) {
        return;
      }
      std::va_list args;
      va_start(args, format);
      (void)std::vfprintf(sink, format, args);
      va_end(args);
      (void)std::fputc('\n', sink);
      (void)std::fflush(sink);
    }

    // ------------------------------------------------------------------
    // Path resolution (beside the executable, like faf_diag.log)
    // ------------------------------------------------------------------

    void ResolveExeDir(char* outDir, const std::size_t bytes)
    {
      char exePath[MAX_PATH * 2] = {};
      const DWORD written = ::GetModuleFileNameA(nullptr, exePath, static_cast<DWORD>(sizeof(exePath)));
      if (written == 0u || written >= sizeof(exePath)) {
        (void)::strcpy_s(outDir, bytes, ".");
        return;
      }
      char* lastSlash = std::strrchr(exePath, '\\');
      if (lastSlash == nullptr) {
        (void)::strcpy_s(outDir, bytes, ".");
        return;
      }
      *(lastSlash + 1) = '\0';
      (void)::strcpy_s(outDir, bytes, exePath);
    }

  } // namespace

  const char* CrashReportPath()
  {
    static char sPath[MAX_PATH * 2] = {};
    static bool sResolved = false;
    if (!sResolved) {
      sResolved = true;
      char exeDir[MAX_PATH * 2] = {};
      ResolveExeDir(exeDir, sizeof(exeDir));
      (void)::sprintf_s(sPath, sizeof(sPath), "%sfaf_crash.txt", exeDir);
    }
    return sPath;
  }

  const char* CrashDumpPath()
  {
    static char sPath[MAX_PATH * 2] = {};
    static bool sResolved = false;
    if (!sResolved) {
      sResolved = true;
      char exeDir[MAX_PATH * 2] = {};
      ResolveExeDir(exeDir, sizeof(exeDir));
      (void)::sprintf_s(sPath, sizeof(sPath), "%sfaf_crash.dmp", exeDir);
    }
    return sPath;
  }

  namespace
  {

    // ------------------------------------------------------------------
    // Header sections
    // ------------------------------------------------------------------

    void WriteBuildSection(std::FILE* const sink)
    {
      ReportLine(sink, "=== FAF crash report ===");
#if defined(_M_IX86)
      ReportLine(sink, "Arch      : x86");
#elif defined(_M_X64)
      ReportLine(sink, "Arch      : x64");
#else
      ReportLine(sink, "Arch      : unknown");
#endif
#ifdef NDEBUG
      ReportLine(sink, "Config    : Release");
#else
      ReportLine(sink, "Config    : Debug");
#endif
      ReportLine(sink, "Built     : %s %s", __DATE__, __TIME__);
#ifdef _MSC_VER
      ReportLine(sink, "Compiler  : MSVC %d", _MSC_VER);
#endif
    }

    void WriteProcessSection(std::FILE* const sink)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- Process ---");
      ReportLine(sink, "pid=%lu faulting tid=%lu", ::GetCurrentProcessId(), ::GetCurrentThreadId());

      char exePath[MAX_PATH * 2] = {};
      const DWORD exeLen = ::GetModuleFileNameA(nullptr, exePath, static_cast<DWORD>(sizeof(exePath)));
      ReportLine(sink, "exe       : %s", (exeLen != 0u) ? exePath : "(unknown)");

      if (exeLen != 0u) {
        HANDLE exeFile = ::CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                       OPEN_EXISTING, 0, nullptr);
        if (exeFile != INVALID_HANDLE_VALUE) {
          FILETIME mtime{};
          SYSTEMTIME st{};
          if (::GetFileTime(exeFile, nullptr, nullptr, &mtime) != FALSE
              && ::FileTimeToSystemTime(&mtime, &st) != FALSE) {
            ReportLine(sink, "exe stamp : %04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour,
                       st.wMinute, st.wSecond);
          }
          LARGE_INTEGER size{};
          if (::GetFileSizeEx(exeFile, &size) != FALSE) {
            ReportLine(sink, "exe bytes : %lld", static_cast<long long>(size.QuadPart));
          }
          (void)::CloseHandle(exeFile);
        }
      }

      const char* const cmd = ::GetCommandLineA();
      ReportLine(sink, "cmdline   : %s", (cmd != nullptr) ? cmd : "(null)");
    }

    void WriteSystemSection(std::FILE* const sink)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- System ---");

      using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
      const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        ::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "RtlGetVersion"));
      if (rtlGetVersion != nullptr) {
        RTL_OSVERSIONINFOW info{};
        info.dwOSVersionInfoSize = sizeof(info);
        if (rtlGetVersion(&info) == 0) {
          ReportLine(sink, "OS        : Windows %lu.%lu.%lu", info.dwMajorVersion, info.dwMinorVersion,
                     info.dwBuildNumber);
        }
      }

      SYSTEM_INFO sysInfo{};
      ::GetNativeSystemInfo(&sysInfo);
      ReportLine(sink, "CPUs      : %lu logical", sysInfo.dwNumberOfProcessors);

      MEMORYSTATUSEX mem{};
      mem.dwLength = sizeof(mem);
      if (::GlobalMemoryStatusEx(&mem) != FALSE) {
        ReportLine(sink, "RAM       : %llu MB total / %llu MB available", mem.ullTotalPhys / (1024ULL * 1024ULL),
                   mem.ullAvailPhys / (1024ULL * 1024ULL));
      }
    }

    // ------------------------------------------------------------------
    // Exception + registers
    // ------------------------------------------------------------------

    const char* ExceptionName(const DWORD code)
    {
      switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
        case EXCEPTION_SINGLE_STEP: return "EXCEPTION_SINGLE_STEP";
        case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
        case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
        case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
        default: return "Unknown";
      }
    }

    void WriteExceptionSection(std::FILE* const sink, const CrashReportContext& context)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- Exception ---");
      if (context.reason != nullptr) {
        ReportLine(sink, "Reason    : %s", context.reason);
      }
      if (context.exceptionInfo == nullptr || context.exceptionInfo->ExceptionRecord == nullptr) {
        ReportLine(sink, "No SEH record (engine Die path, CRT fatal or abort).");
        return;
      }

      const EXCEPTION_RECORD& record = *context.exceptionInfo->ExceptionRecord;
      const auto faultAddress = reinterpret_cast<std::uintptr_t>(record.ExceptionAddress);
      ReportLine(sink, "Code      : 0x%08lX %s", record.ExceptionCode, ExceptionName(record.ExceptionCode));
      ReportLine(sink, "Address   : 0x%016llX", static_cast<unsigned long long>(faultAddress));

      HMODULE module = nullptr;
      if (::GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            static_cast<LPCSTR>(record.ExceptionAddress), &module
          ) != FALSE
          && module != nullptr) {
        char modulePath[MAX_PATH * 2] = {};
        if (::GetModuleFileNameA(module, modulePath, static_cast<DWORD>(sizeof(modulePath))) != 0u) {
          const auto base = reinterpret_cast<std::uintptr_t>(module);
          ReportLine(sink, "Module    : %s + 0x%llX (base 0x%016llX)", modulePath,
                     static_cast<unsigned long long>(faultAddress - base),
                     static_cast<unsigned long long>(base));
        }
      }

      if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record.NumberParameters >= 2) {
        static const char* const kAccessKinds[] = {"read", "write", "execute"};
        const ULONG_PTR kind = record.ExceptionInformation[0];
        ReportLine(sink, "AV target : 0x%016llX (%s)", static_cast<unsigned long long>(record.ExceptionInformation[1]),
                   (kind < 3) ? kAccessKinds[kind] : "unknown kind");
      }
    }

    void WriteRegistersSection(std::FILE* const sink, const CrashReportContext& context)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- Registers (faulting thread) ---");
      if (context.exceptionInfo == nullptr || context.exceptionInfo->ContextRecord == nullptr) {
        ReportLine(sink, "unavailable (no context record)");
        return;
      }
#if defined(_M_IX86)
      const CONTEXT* const c = context.exceptionInfo->ContextRecord;
      ReportLine(sink, "EAX=%08lX EBX=%08lX ECX=%08lX EDX=%08lX", c->Eax, c->Ebx, c->Ecx, c->Edx);
      ReportLine(sink, "ESI=%08lX EDI=%08lX EBP=%08lX ESP=%08lX", c->Esi, c->Edi, c->Ebp, c->Esp);
      ReportLine(sink, "EIP=%08lX EFLAGS=%08lX", c->Eip, c->EFlags);
#elif defined(_M_X64)
      const CONTEXT* const c = context.exceptionInfo->ContextRecord;
      ReportLine(sink, "RAX=%016llX RBX=%016llX RCX=%016llX RDX=%016llX", c->Rax, c->Rbx, c->Rcx, c->Rdx);
      ReportLine(sink, "RSI=%016llX RDI=%016llX RBP=%016llX RSP=%016llX", c->Rsi, c->Rdi, c->Rbp, c->Rsp);
      ReportLine(sink, "R8 =%016llX R9 =%016llX R10=%016llX R11=%016llX", c->R8, c->R9, c->R10, c->R11);
      ReportLine(sink, "R12=%016llX R13=%016llX R14=%016llX R15=%016llX", c->R12, c->R13, c->R14, c->R15);
      ReportLine(sink, "RIP=%016llX EFLAGS=%08lX", c->Rip, c->EFlags);
#else
      ReportLine(sink, "unsupported architecture");
#endif
    }

    // ------------------------------------------------------------------
    // Symbolised stacks for every thread
    // ------------------------------------------------------------------

    std::uint32_t CaptureThreadFrames(HANDLE thread, CONTEXT& context, std::uintptr_t* frames)
    {
      std::uint32_t count = 0;
      STACKFRAME64 frame{};
#if defined(_M_IX86)
      const DWORD machine = IMAGE_FILE_MACHINE_I386;
      frame.AddrPC.Offset = context.Eip;
      frame.AddrStack.Offset = context.Esp;
      frame.AddrFrame.Offset = context.Ebp;
#elif defined(_M_X64)
      const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
      frame.AddrPC.Offset = context.Rip;
      frame.AddrStack.Offset = context.Rsp;
      frame.AddrFrame.Offset = context.Rbp;
#else
      const DWORD machine = 0;
      (void)frame;
      (void)context;
#endif
      frame.AddrPC.Mode = AddrModeFlat;
      frame.AddrStack.Mode = AddrModeFlat;
      frame.AddrFrame.Mode = AddrModeFlat;

      while (count < kMaxFramesPerThread && machine != 0) {
        if (::StackWalk64(
              machine, ::GetCurrentProcess(), thread, &frame, &context, nullptr, ::SymFunctionTableAccess64,
              ::SymGetModuleBase64, nullptr
            ) == FALSE) {
          break;
        }
        if (frame.AddrPC.Offset == 0) {
          break;
        }
        frames[count] = static_cast<std::uintptr_t>(frame.AddrPC.Offset) - ((count != 0u) ? 1u : 0u);
        ++count;
      }
      return count;
    }

    void WriteThreadStackLines(std::FILE* const sink, const char* const tag, const std::uint32_t threadId,
                               const std::uintptr_t* frames, const std::uint32_t frameCount)
    {
      ReportLine(sink, "[%s] tid=%lu frames=%u", tag, threadId, frameCount);
      for (std::uint32_t i = 0; i < frameCount; ++i) {
        char described[420] = {};
        DiagDescribeAddress(reinterpret_cast<void*>(frames[i]), described, sizeof(described));
        ReportLine(sink, "[%s]   #%02u %s", tag, i, described);
      }
    }

    struct SuspendedThread
    {
      DWORD id = 0;
      HANDLE handle = nullptr;
    };

    void WriteFaultingThreadStack(std::FILE* const sink, const CrashReportContext& context)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- Threads ---");
      if (context.exceptionInfo != nullptr && context.exceptionInfo->ContextRecord != nullptr) {
        // Walk the faulting thread first, seeded from the exception context:
        // its frames are the ones that name the bug. No suspension needed -
        // this IS the faulting thread.
        CONTEXT contextCopy = *context.exceptionInfo->ContextRecord;
        std::uintptr_t frames[kMaxFramesPerThread] = {};
        const std::uint32_t frameCount =
          CaptureThreadFrames(::GetCurrentThread(), contextCopy, frames);
        WriteThreadStackLines(sink, "fault", ::GetCurrentThreadId(), frames, frameCount);
      } else {
        ReportLine(sink, "[fault] no SEH context; see faf_diag.log [STACK] records");
      }
    }

    void WriteThreadsSection(std::FILE* const sink, const CrashReportContext& context)
    {
      WriteFaultingThreadStack(sink, context);

      const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
      if (snapshot == INVALID_HANDLE_VALUE) {
        ReportLine(sink, "snapshot failed: %lu", ::GetLastError());
        return;
      }

      THREADENTRY32 entry{};
      entry.dwSize = sizeof(entry);
      if (::Thread32First(snapshot, &entry) == FALSE) {
        ReportLine(sink, "thread enumeration failed: %lu", ::GetLastError());
        (void)::CloseHandle(snapshot);
        return;
      }

      const DWORD pid = ::GetCurrentProcessId();
      const DWORD currentTid = ::GetCurrentThreadId();
      do {
        if (entry.th32OwnerProcessID != pid) {
          continue;
        }
        if (entry.th32ThreadID == currentTid) {
          continue;
        }

        HANDLE thread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE,
                                     entry.th32ThreadID);
        if (thread == nullptr) {
          continue;
        }
        if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
          (void)::CloseHandle(thread);
          continue;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        std::uintptr_t frames[kMaxFramesPerThread];
        std::uint32_t frameCount = 0;
        if (::GetThreadContext(thread, &context) != FALSE) {
          frameCount = CaptureThreadFrames(thread, context, frames);
        }
        (void)::ResumeThread(thread);
        (void)::CloseHandle(thread);

        WriteThreadStackLines(sink, "thread", entry.th32ThreadID, frames, frameCount);
      } while (::Thread32Next(snapshot, &entry) != FALSE);

      (void)::CloseHandle(snapshot);
    }

    // ------------------------------------------------------------------
    // Module list
    // ------------------------------------------------------------------

    void WriteModulesSection(std::FILE* const sink)
    {
      ReportLine(sink, "");
      ReportLine(sink, "--- Modules ---");
      HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ::GetCurrentProcessId());
      if (snapshot == INVALID_HANDLE_VALUE) {
        ReportLine(sink, "snapshot failed: %lu", ::GetLastError());
        return;
      }

      MODULEENTRY32 module{};
      module.dwSize = sizeof(module);
      if (::Module32First(snapshot, &module) == FALSE) {
        ReportLine(sink, "module enumeration failed: %lu", ::GetLastError());
        (void)::CloseHandle(snapshot);
        return;
      }

      do {
        ReportLine(sink, "%016llX %8lu %s", static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(module.modBaseAddr)
                                        ),
                   module.modBaseSize, module.szModule);
      } while (::Module32Next(snapshot, &module) != FALSE);
      (void)::CloseHandle(snapshot);
    }

    // Recent log tail: one line per history entry, flushed as we go. The
    // gpg log ring is the engine's own; reading it needs no lock on the
    // crash path (the process is dying; a torn line is acceptable).
    void WriteRecentLogTail(std::FILE* const sink)
    {
      // gpg::GetRecentLogLines returns one UTF-8 blob; split it into lines so
      // each gets its own flush (the blob can be a few hundred KB).
      const msvc8::string recent = gpg::GetRecentLogLines();
      const char* text = recent.c_str();
      std::size_t lineStart = 0;
      for (std::size_t i = 0;; ++i) {
        const char ch = text[i];
        if (ch != '\n' && ch != '\0') {
          continue;
        }
        const std::size_t lineLength = i - lineStart;
        if (lineLength != 0 && lineLength < 4096) {
          ReportLine(sink, "%.*s", static_cast<int>(lineLength), text + lineStart);
        }
        if (ch == '\0') {
          break;
        }
        lineStart = i + 1;
      }
    }

  } // namespace

  void AddCrashSection(const char* const name, const CrashSectionWriter writer)
  {
    SectionRegistry& registry = SectionRegistryInstance();
    if (name == nullptr || writer == nullptr || registry.count >= kMaxSections) {
      return;
    }
    registry.names[registry.count] = name;
    registry.writers[registry.count] = writer;
    ++registry.count;
  }

  bool WriteCrashReport(const CrashReportContext& context)
  {
    if (::InterlockedCompareExchange(&sReportInProgress, 1, 0) != 0) {
      return false; // a nested fault while a report is already being written
    }

    std::FILE* sink = std::fopen(CrashReportPath(), "w");
    if (sink == nullptr) {
      return false;
    }

    WriteBuildSection(sink);
    WriteProcessSection(sink);
    WriteSystemSection(sink);
    WriteExceptionSection(sink, context);
    WriteRegistersSection(sink, context);
    WriteThreadsSection(sink, context);
    WriteModulesSection(sink);

    const SectionRegistry& registry = SectionRegistryInstance();
    for (std::size_t i = 0; i < registry.count; ++i) {
      ReportLine(sink, "");
      ReportLine(sink, "--- %s ---", registry.names[i]);
      registry.writers[i](sink);
      (void)std::fflush(sink);
    }

    ReportLine(sink, "");
    ReportLine(sink, "--- Log (recent) ---");
    WriteRecentLogTail(sink);

    (void)std::fclose(sink);
    return true;
  }

  bool WriteCrashMinidump(_EXCEPTION_POINTERS* const exceptionInfo)
  {
    if (::GetEnvironmentVariableA("FAF_MINIDUMP", nullptr, 0) == 0u) {
      return false;
    }

    HANDLE file = ::CreateFileA(
      CrashDumpPath(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
      return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION dumpInfo{};
    dumpInfo.ThreadId = ::GetCurrentThreadId();
    dumpInfo.ExceptionPointers = exceptionInfo;
    dumpInfo.ClientPointers = FALSE;

    BOOL written = FALSE;
    if (exceptionInfo != nullptr) {
      written = ::MiniDumpWriteDump(
        ::GetCurrentProcess(), ::GetCurrentProcessId(), file, MiniDumpNormal, &dumpInfo, nullptr, nullptr
      );
    } else {
      // Non-SEH fatal path: capture this thread's context so the dump still
      // names the reporting frame.
      CONTEXT context{};
      ::RtlCaptureContext(&context);
      EXCEPTION_RECORD record{};
      record.ExceptionCode = 0xE0000001; // synthetic: engine fatal
#if defined(_M_IX86)
      record.ExceptionAddress = reinterpret_cast<PVOID>(context.Eip);
#elif defined(_M_X64)
      record.ExceptionAddress = reinterpret_cast<PVOID>(context.Rip);
#else
      record.ExceptionAddress = nullptr;
#endif
      EXCEPTION_POINTERS pointers{};
      pointers.ExceptionRecord = &record;
      pointers.ContextRecord = &context;
      dumpInfo.ExceptionPointers = &pointers;
      written = ::MiniDumpWriteDump(
        ::GetCurrentProcess(), ::GetCurrentProcessId(), file, MiniDumpNormal, &dumpInfo, nullptr, nullptr
      );
    }

    (void)::CloseHandle(file);
    return written != FALSE;
  }

  void CopyCrashReportToClipboard()
  {
    // Read the whole report; if it is missing, still clear-ish-fail quietly.
    std::FILE* const source = std::fopen(CrashReportPath(), "rb");
    if (source == nullptr) {
      return;
    }
    (void)std::fseek(source, 0, SEEK_END);
    const long bytes = std::ftell(source);
    (void)std::fseek(source, 0, SEEK_SET);
    if (bytes <= 0 || bytes > 8 * 1024 * 1024) {
      (void)std::fclose(source);
      return;
    }

    const std::size_t textBytes = static_cast<std::size_t>(bytes);
    char* const utf8 = static_cast<char*>(::HeapAlloc(::GetProcessHeap(), 0, textBytes + 1));
    if (utf8 == nullptr) {
      (void)std::fclose(source);
      return;
    }
    const std::size_t read = std::fread(utf8, 1, textBytes, source);
    (void)std::fclose(source);
    utf8[read] = '\0';

    // UTF-8 -> UTF-16 (report text is ASCII-dominated; use the system helper
    // and fall back to a truncation when conversion fails).
    const int wideChars = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    bool ok = false;
    if (wideChars > 0) {
      const std::size_t wideBytes = static_cast<std::size_t>(wideChars) * sizeof(wchar_t);
      // GMEM_MOVEABLE is required by CF_UNICODETEXT.
      HGLOBAL global = ::GlobalAlloc(GMEM_MOVEABLE, wideBytes);
      if (global != nullptr) {
        wchar_t* const destination = static_cast<wchar_t*>(::GlobalLock(global));
        if (destination != nullptr) {
          if (::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, destination, wideChars) != 0) {
            if (::OpenClipboard(nullptr) != FALSE) {
              if (::EmptyClipboard() != FALSE) {
                ok = ::SetClipboardData(CF_UNICODETEXT, global) != nullptr;
              }
              (void)::CloseClipboard();
            }
          }
          (void)::GlobalUnlock(global);
        }
        if (!ok) {
          (void)::GlobalFree(global);
        }
      }
    }
    (void)::HeapFree(::GetProcessHeap(), 0, utf8);
  }

  namespace
  {

    // Report text handed to the dialog (owned by ShowCrashReportDialog's
    // frame; the dialog only runs inside its DialogBoxIndirectParam call).
    wchar_t* sCrashDialogText = nullptr;
    char sCrashDialogReportPath[MAX_PATH * 2] = {};

    // Control ids for the edit and the three buttons.
    constexpr int kCopyButtonId = 1065;
    constexpr int kOpenFolderButtonId = 1066;
    constexpr int kCloseButtonId = 1067;
    constexpr int kEditControlId = 1068;

    void CreateCrashDialogChildren(HWND dialog)
    {
      HFONT font = static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));

      HWND edit = ::CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", sCrashDialogText,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        8, 8, 600, 400, dialog, reinterpret_cast<HMENU>(static_cast<std::uintptr_t>(kEditControlId)),
        nullptr, nullptr
      );
      if (edit != nullptr) {
        (void)::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        // Keep the selection at the top: the most useful lines are first.
        (void)::SendMessageW(edit, EM_SETSEL, 0, 0);
        (void)::SendMessageW(edit, EM_SCROLLCARET, 0, 0);
      }

      const wchar_t* const labels[] = {L"Copy report", L"Open report folder", L"Close"};
      const int ids[] = {kCopyButtonId, kOpenFolderButtonId, kCloseButtonId};
      int x = 8;
      for (int i = 0; i < 3; ++i) {
        HWND button = ::CreateWindowExW(
          0, L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, x, 440, 170, 30, dialog,
          reinterpret_cast<HMENU>(static_cast<std::uintptr_t>(ids[i])), nullptr, nullptr
        );
        if (button != nullptr) {
          (void)::SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        }
        x += 180;
      }
    }

    void LayoutCrashDialogChildren(HWND dialog, const int clientWidth, const int clientHeight)
    {
      const int margin = 8;
      const int buttonHeight = 32;
      const int buttonWidth = 170;
      const int buttonGap = 12;

      int x = margin;
      for (int i = 0; i < 3; ++i) {
        const int id = (i == 0) ? kCopyButtonId : ((i == 1) ? kOpenFolderButtonId : kCloseButtonId);
        (void)::SetWindowPos(
          ::GetDlgItem(dialog, id), nullptr, x, clientHeight - buttonHeight - margin, buttonWidth, buttonHeight,
          SWP_NOZORDER
        );
        x += buttonWidth + buttonGap;
      }

      HWND edit = ::GetDlgItem(dialog, kEditControlId);
      if (edit != nullptr) {
        (void)::SetWindowPos(
          edit, nullptr, margin, margin, clientWidth - 2 * margin,
          clientHeight - buttonHeight - 3 * margin, SWP_NOZORDER
        );
      }
    }

    INT_PTR CALLBACK CrashReportDialogProc(HWND dialog, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      switch (message) {
        case WM_INITDIALOG: {
          (void)lParam;
          CreateCrashDialogChildren(dialog);
          return TRUE;
        }
        case WM_SIZE:
          LayoutCrashDialogChildren(dialog, LOWORD(lParam), HIWORD(lParam));
          return TRUE;
        case WM_COMMAND: {
          const int id = LOWORD(wParam);
          if (id == kCopyButtonId) {
            CopyCrashReportToClipboard();
            ::SetDlgItemTextW(dialog, kCopyButtonId, L"Copied!");
            return TRUE;
          }
          if (id == kOpenFolderButtonId) {
            wchar_t widePath[MAX_PATH * 2] = {};
            if (::MultiByteToWideChar(CP_UTF8, 0, sCrashDialogReportPath, -1, widePath, MAX_PATH * 2) != 0) {
              wchar_t* lastSlash = std::wcsrchr(widePath, L'\\');
              if (lastSlash != nullptr) {
                *(lastSlash + 1) = L'\0';
                (void)::ShellExecuteW(nullptr, L"open", widePath, nullptr, nullptr, SW_SHOWNORMAL);
              }
            }
            return TRUE;
          }
          if (id == kCloseButtonId || id == IDCANCEL) {
            (void)::EndDialog(dialog, 0);
            return TRUE;
          }
          break;
        }
        case WM_CLOSE:
          (void)::EndDialog(dialog, 0);
          return TRUE;
        default:
          break;
      }
      return FALSE;
    }

    // DLGTEMPLATE with zero children (children are created in WM_INITDIALOG).
    // Fixed static buffer, DWORD-aligned (DLGTEMPLATE requirement),
    // WORD-aligned field writes.
    const DLGTEMPLATE* BuildCrashDialogTemplate()
    {
      alignas(DWORD) static unsigned char templateBytes[512];
      unsigned char* p = templateBytes;
      auto putWord = [&p](const unsigned short value) {
        *reinterpret_cast<unsigned short*>(p) = value;
        p += 2;
      };
      auto putDword = [&p](const unsigned long value) {
        *reinterpret_cast<unsigned long*>(p) = value;
        p += 4;
      };
      auto putString = [&p](const wchar_t* const text) {
        for (const wchar_t* c = text; *c != L'\0'; ++c) {
          *reinterpret_cast<unsigned short*>(p) = static_cast<unsigned short>(*c);
          p += 2;
        }
        *reinterpret_cast<unsigned short*>(p) = 0;
        p += 2;
      };

      // DLGTEMPLATE
      putDword(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER | DS_MODALFRAME | WS_SIZEBOX | WS_MINIMIZEBOX);
      putDword(0);   // dwExtendedStyle
      putWord(0);    // cdit (children created manually)
      putWord(10);   // x
      putWord(10);   // y
      putWord(500);  // cx, dialog units
      putWord(350);  // cy, dialog units
      putString(L""); // menu: none
      putString(L""); // class: default dialog
      putString(L"FAF crash report");

      return reinterpret_cast<const DLGTEMPLATE*>(templateBytes);
    }

  } // namespace

  void ShowCrashReportDialog(const char* const reportPath)
  {
    const char* const path = (reportPath != nullptr) ? reportPath : CrashReportPath();

    // Read the report text (bounded) into a wide buffer for the edit control.
    std::FILE* const source = std::fopen(path, "rb");
    if (source == nullptr) {
      ::MessageBoxW(nullptr, L"FAF crashed. The report file could not be read.", L"FAF crash", MB_ICONERROR | MB_OK);
      return;
    }
    (void)std::fseek(source, 0, SEEK_END);
    long bytes = std::ftell(source);
    (void)std::fseek(source, 0, SEEK_SET);
    if (bytes <= 0) {
      bytes = 0;
    }
    if (bytes > 512 * 1024) {
      bytes = 512 * 1024; // the edit control caps here; the clipboard copy takes the whole file
    }
    const std::size_t textBytes = static_cast<std::size_t>(bytes);

    wchar_t* wide = nullptr;
    char* utf8 = static_cast<char*>(::HeapAlloc(::GetProcessHeap(), 0, textBytes + 1));
    if (utf8 != nullptr) {
      const std::size_t read = std::fread(utf8, 1, textBytes, source);
      utf8[read] = '\0';
      const int wideChars = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
      if (wideChars > 0) {
        wide = static_cast<wchar_t*>(
          ::HeapAlloc(::GetProcessHeap(), 0, static_cast<std::size_t>(wideChars) * sizeof(wchar_t))
        );
        if (wide != nullptr) {
          (void)::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, wideChars);
        }
      }
      (void)::HeapFree(::GetProcessHeap(), 0, utf8);
    }
    (void)std::fclose(source);

    if (wide == nullptr) {
      ::MessageBoxW(
        nullptr, L"FAF crashed. The report file is too large or unreadable; find faf_crash.txt beside the game exe.",
        L"FAF crash", MB_ICONERROR | MB_OK
      );
      return;
    }

    (void)::strcpy_s(sCrashDialogReportPath, sizeof(sCrashDialogReportPath), path);
    sCrashDialogText = wide;

    (void)::DialogBoxIndirectParamW(
      ::GetModuleHandleW(nullptr), BuildCrashDialogTemplate(), nullptr, &CrashReportDialogProc, 0
    );

    sCrashDialogText = nullptr;
    (void)::HeapFree(::GetProcessHeap(), 0, wide);
  }
} // namespace gpg::diag