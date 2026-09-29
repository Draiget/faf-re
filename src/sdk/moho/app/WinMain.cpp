#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <array>
#include <algorithm>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <shellapi.h>

#include <crtdbg.h> // DIAGNOSTIC PROBE -- remove before committing
#include <csignal>  // DIAGNOSTIC PROBE -- remove before committing
#include <dbghelp.h> // DIAGNOSTIC PROBE -- remove before committing

#include "CScApp.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Error.hpp"
#include "legacy/containers/HashMap.h"
#include "WinApp.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  /**
   * The shipped exe's CRT (VS2005 msvcr80, `__tmainCRTStartup`) calls
   * GetStartupInfo before it runs any initializer; today's CRT asks only in
   * `invoke_main`, after them. The order matters under FAF's install: its ASI
   * loader (bin\dsound.dll) loads `scripts\UptimeFaker32.asi` on the first call
   * the exe makes to one of the kernel32 functions it hooks, and UptimeFaker
   * rebases QueryPerformanceCounter and GetTickCount to a one-day uptime. The
   * static `gpg::time::Timer`s (wakeupTimer, startTime, ...) must sample the
   * rebased counter too: one real sample stored first leaves
   * `gpg::time::GetCycle`'s never-backwards clamp ahead of every later reading,
   * so the frame clock stops and the intro movie never starts. Asking first, as
   * the old CRT did, keeps every sample on one timeline.
   */
  int __cdecl QueryStartupInfoBeforeInitializers()
  {
    STARTUPINFOW startupInfo{};
    ::GetStartupInfoW(&startupInfo);
    return 0;
  }
} // namespace

// `.CRT$XI*` entries run from `_initterm_e`, ahead of every C++ initializer.
#pragma section(".CRT$XIB", read)
extern "C" __declspec(allocate(".CRT$XIB")) int(__cdecl* const gQueryStartupInfoBeforeInitializers)() =
  &QueryStartupInfoBeforeInitializers;

namespace
{
  // The allocation log (`/alloclog`, `SC_StartMemoryLog`): the open file
  // (0x010A648C), the lock every hook call takes (0x010A6344), the re-entry
  // guard that keeps the log's own allocations out of it (0x010A6490), and the
  // return addresses whose symbol line is already in the file - `MemHookAddr`
  // (0x010C6264), built by its dynamic initializer 0x00BE8FA0.
  std::FILE* sAllocLogFile = nullptr;
  CRITICAL_SECTION sAllocLogLock{};
  bool sInMemHook = false;
  msvc8::hash_set<std::uint32_t> sMemHookAddr;

  STICKYKEYS sSavedStickyKeys{};
  TOGGLEKEYS sSavedToggleKeys{};
  FILTERKEYS sSavedFilterKeys{};

  /**
   * Address: 0x008D2140 (FUN_008D2140, func_CleanupAllocLoc)
   *
   * What it does:
   * Removes the allocation hook, closes the log file and deletes its lock.
   */
  void func_CleanupAllocLoc()
  {
    gpg::SetMemHook(nullptr);
    std::fclose(sAllocLogFile);
    sAllocLogFile = nullptr;
    ::DeleteCriticalSection(&sAllocLogLock);
  }

  /**
   * Address: 0x008D1E50 (FUN_008D1E50, func_MemHook)
   *
   * int isFreeing, int size, ...
   *
   * What it does:
   * Appends one record under the lock, unless the hook is already running on
   * this thread's record: thread id, performance counter, the operation, size
   * and pointer, then up to 64 return addresses and a 0 terminator. An address
   * seen for the first time also gets its resolved symbol line, NUL included.
   */
  void func_MemHook(const int isFreeing, const int size, ...)
  {
    va_list args;
    va_start(args, size);
    const void* const pointer = va_arg(args, const void*);
    va_end(args);

    ::EnterCriticalSection(&sAllocLogLock);
    if (!sInMemHook) {
      sInMemHook = true;

      const DWORD threadId = ::GetCurrentThreadId();
      std::fwrite(&threadId, sizeof(threadId), 1, sAllocLogFile);
      LARGE_INTEGER counter;
      ::QueryPerformanceCounter(&counter);
      std::fwrite(&counter, sizeof(counter), 1, sAllocLogFile);
      std::fwrite(&isFreeing, sizeof(isFreeing), 1, sAllocLogFile);
      std::fwrite(&size, sizeof(size), 1, sAllocLogFile);
      std::fwrite(&pointer, sizeof(pointer), 1, sAllocLogFile);

      std::uint32_t frames[64];
      const std::uint32_t frameCount = moho::PLAT_GetCallStack(nullptr, 64, frames);
      for (std::uint32_t index = 0; index < frameCount; ++index) {
        std::fwrite(&frames[index], sizeof(frames[index]), 1, sAllocLogFile);
        if (sMemHookAddr.insert(frames[index]).second) {
          moho::SPlatSymbolInfo symbolInfo{};
          if (moho::PLAT_GetSymbolInfo(frames[index], &symbolInfo)) {
            const msvc8::string symbolLine = symbolInfo.FormatResolvedLine();
            std::fwrite(symbolLine.c_str(), 1, symbolLine.size() + 1U, sAllocLogFile);
          }
        }
      }

      const std::uint32_t terminator = 0;
      std::fwrite(&terminator, sizeof(terminator), 1, sAllocLogFile);
      sInMemHook = false;
    }
    ::LeaveCriticalSection(&sAllocLogLock);
  }

  /**
   * Address: 0x008D2170 (FUN_008D2170)
   *
   * What it does:
   * Opens the log file for binary write; if that works, writes the
   * performance-counter frequency as its header, sets up the lock, registers
   * the cleanup for exit and installs the hook.
   */
  void InitializeAllocationLog(const char* const path)
  {
    std::FILE* const file = std::fopen(path, "wb");
    if (file == nullptr) {
      return;
    }

    LARGE_INTEGER frequency;
    ::QueryPerformanceFrequency(&frequency);
    std::fwrite(&frequency, sizeof(frequency), 1, file);
    ::InitializeCriticalSection(&sAllocLogLock);
    sAllocLogFile = file;
    (void)std::atexit(&func_CleanupAllocLoc);
    gpg::SetMemHook(&func_MemHook);
  }

  /**
   * Address: 0x008D4260 (FUN_008D4260, sub_8D4260)
   *
   * void*
   *
   * What it does:
   * `SC_StartMemoryLog <filename>` console command. Forwards the filename
   * argument straight to `InitializeAllocationLog` above.
   *
   * Registrar: FUN_00BE9700 (`__xc_a` lane), data-xref
   * `dword_F5BEFC = offset sub_8D4260` is the callsite evidence.
   */
  void SC_StartMemoryLog(const msvc8::vector<msvc8::string>& args)
  {
    if (args.size() != 2u) {
      return;
    }

    const msvc8::string* const pathToken = moho::ConCommandArg(args, 1u);
    if (pathToken == nullptr) {
      return;
    }

    InitializeAllocationLog(pathToken->c_str());
  }

  /**
   * Address: 0x008D42B0 (FUN_008D42B0, sub_8D42B0)
   *
   * What it does:
   * `SC_StopMemoryLog` console command. `func_CleanupAllocLoc` above already
   * reproduces the binary's exact teardown sequence (clear the mem hook,
   * close the alloc-log runtime) - this command just runs it on demand
   * instead of only at process exit.
   *
   * Registrar: FUN_00BE9740 (`__xc_a` lane), data-xref
   * `dword_F5BF0C = offset sub_8D42B0` is the callsite evidence.
   */
  void SC_StopMemoryLog(const msvc8::vector<msvc8::string>& args)
  {
    (void)args;
    func_CleanupAllocLoc();
  }

  /// 0x00E4F23C, the `.data` initializer of `Moho::CConFunc_SC_StartMemoryLog`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCStartMemoryLogDescription = "Start up memory logging to filename";

  /**
   * Address: 0x00BE9700 (FUN_00BE9700, dynamic initializer for `gCConFunc_SC_StartMemoryLog`)
   * Address: 0x00C08F10 (FUN_00C08F10, dynamic atexit destructor for `gCConFunc_SC_StartMemoryLog`)
   */
  moho::CConFunc gCConFunc_SC_StartMemoryLog("SC_StartMemoryLog", kConsoleStartupSCStartMemoryLogDescription, &SC_StartMemoryLog);

  /// 0x00E4F274, the `.data` initializer of `Moho::CConFunc_SC_StopMemoryLog`
  /// (+0x08), read directly from the shipped PE.
  constexpr const char* kConsoleStartupSCStopMemoryLogDescription = "Stop memory logging";

  /**
   * Address: 0x00BE9740 (FUN_00BE9740, dynamic initializer for `gCConFunc_SC_StopMemoryLog`)
   * Address: 0x00C08F40 (FUN_00C08F40, dynamic atexit destructor for `gCConFunc_SC_StopMemoryLog`)
   */
  moho::CConFunc gCConFunc_SC_StopMemoryLog("SC_StopMemoryLog", kConsoleStartupSCStopMemoryLogDescription, &SC_StopMemoryLog);

  // The binary runs these registrars from the CRT static-initializer array;
  // this file-scope bootstrap object reproduces that, matching the
  // `ResolutionConsoleRegistrations`/`FrameDumpConsoleRegistrations` pattern
  // established in moho/app/ResolutionCommands.cpp / FrameDumpCommands.cpp.
  /**
   * Address: 0x004F1500 (FUN_004F1500)
   *
   * What it does:
   * Fatal die-handler callback registered by WinMain.
   */
  void FatalErrorDieHandler(const char* const message)
  {
    moho::WIN_ShowCrashDialog(2, nullptr, "Fatal Error", message != nullptr ? message : "");
  }

  /**
   * Address: 0x008D4320 (FUN_008D4320)
   *
   * What it does:
   * Applies startup accessibility tweaks or restores previously captured values.
   */
  void ConfigureAccessibilitySystemParameters(const bool restoreOriginalValues)
  {
    if (restoreOriginalValues) {
      (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &sSavedStickyKeys, 0);
      (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &sSavedToggleKeys, 0);
      (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &sSavedFilterKeys, 0);
      return;
    }

    STICKYKEYS nextStickyKeys = sSavedStickyKeys;
    if ((sSavedStickyKeys.dwFlags & SKF_STICKYKEYSON) == 0) {
      nextStickyKeys.dwFlags = sSavedStickyKeys.dwFlags & ~(SKF_HOTKEYACTIVE | SKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(STICKYKEYS), &nextStickyKeys, 0);
    }

    TOGGLEKEYS nextToggleKeys = sSavedToggleKeys;
    if ((sSavedToggleKeys.dwFlags & TKF_TOGGLEKEYSON) == 0) {
      nextToggleKeys.dwFlags = sSavedToggleKeys.dwFlags & ~(TKF_HOTKEYACTIVE | TKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(TOGGLEKEYS), &nextToggleKeys, 0);
    }

    FILTERKEYS nextFilterKeys = sSavedFilterKeys;
    if ((sSavedFilterKeys.dwFlags & FKF_FILTERKEYSON) == 0) {
      nextFilterKeys.dwFlags = sSavedFilterKeys.dwFlags & ~(FKF_HOTKEYACTIVE | FKF_CONFIRMHOTKEY);
      (void)::SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(FILTERKEYS), &nextFilterKeys, 0);
    }
  }

  /**
   * Address: 0x008D4410 (FUN_008D4410)
   *
   * What it does:
   * Launches Windows Media Center shell when `/mediacenter` is requested.
   */
  [[nodiscard]]
  bool TryLaunchMediaCenterIfRequested()
  {
    if (!moho::CFG_GetArgOption("/mediacenter", 0, nullptr)) {
      return false;
    }

    if (::GetSystemMetrics(SM_MEDIACENTER) == 0) {
      return false;
    }

    std::array<wchar_t, MAX_PATH> ehomePath{};
    const DWORD expandedLength = ::ExpandEnvironmentStringsW(
      L"%SystemRoot%\\ehome\\ehshell.exe", ehomePath.data(), static_cast<DWORD>(ehomePath.size())
    );
    if (expandedLength == 0 || expandedLength > ehomePath.size()) {
      return false;
    }

    if (::GetFileAttributesW(ehomePath.data()) == INVALID_FILE_ATTRIBUTES) {
      return false;
    }

    const HINSTANCE result = ::ShellExecuteW(nullptr, L"open", ehomePath.data(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<std::uintptr_t>(result) > 32U;
  }

  // ---------------------------------------------------------------------
  // DIAGNOSTIC PROBE -- NOT PART OF THE RECOVERY. Remove before committing.
  //
  // The debug CRT aborts inside ucrtbased with a stack the debugger cannot
  // walk (every frame resolves to data or to a non-return address), so the
  // one thing that actually names the fault -- the CRT's own report text,
  // e.g. "HEAP CORRUPTION DETECTED: after Normal block (#NNNN)" or an
  // invalid-parameter expression -- is discarded. These two hooks copy it
  // into faf_diag.log beside the other probes.
  //
  // `/heapcheck` additionally turns on _CRTDBG_CHECK_ALWAYS_DF, which
  // validates the whole CRT heap on every allocation and free.
  //
  // Note this only covers the *CRT* heap. `gpg/core/utils/Global.cpp` replaces
  // `malloc`/`free` with the engine's own small-block allocator, so most engine
  // allocations never reach the CRT heap at all. The switch for that one is the
  // environment variable FAF_HEAPWATCH=1, which makes the allocator's existing
  // stamp/validate probe watch every size class instead of the single stale
  // class it was pinned to. For an engine-side corruption that is the switch
  // that matters; this one is the backstop for whatever does reach the CRT.
  // ---------------------------------------------------------------------
  // The log sits beside the executable, not in whatever the process happened to
  // make its working directory, so it can actually be found and handed over.
  const char* DiagLogPath()
  {
    static char sPath[MAX_PATH * 2] = {};
    static bool sResolved = false;
    if (!sResolved) {
      sResolved = true;
      char exePath[MAX_PATH] = {};
      const DWORD written = ::GetModuleFileNameA(nullptr, exePath, static_cast<DWORD>(sizeof(exePath)));
      if (written == 0u || written >= sizeof(exePath)) {
        (void)::strcpy_s(sPath, sizeof(sPath), "faf_diag.log");
      } else {
        char* const lastSlash = std::strrchr(exePath, '\\');
        if (lastSlash != nullptr) {
          *(lastSlash + 1) = '\0';
        } else {
          exePath[0] = '\0';
        }
        (void)::sprintf_s(sPath, sizeof(sPath), "%sfaf_diag.log", exePath);
      }
    }
    return sPath;
  }

  void DiagLine(const char* const format, ...)
  {
    std::FILE* sink = nullptr;
    if (::fopen_s(&sink, DiagLogPath(), "a") != 0 || sink == nullptr) {
      return;
    }

    std::va_list args;
    va_start(args, format);
    (void)std::vfprintf(sink, format, args);
    va_end(args);

    (void)std::fputc(0x0A, sink);
    (void)std::fclose(sink);
  }

  // ---------------------------------------------------------------------
  // DIAGNOSTIC PROBE -- self-symbolising backtrace.
  //
  // The reported fault is an abort raised on the sim thread from inside
  // ucrtbased, and the debugger cannot walk out of it: ucrtbased ships no
  // symbols here, so every frame above the break resolves to data or to a
  // non-return address and the one useful thing -- which engine call asked the
  // CRT to do something illegal -- is lost.
  //
  // The process does not need the debugger for that. main.exe is built with a
  // PDB and dbghelp.lib is already linked, so it can resolve its own return
  // addresses to function + file:line. Capturing the stack *inside* the handler
  // also beats reading it afterwards: the handler runs on the faulting thread
  // before any unwinding, so the frames above it are the real ones.
  // ---------------------------------------------------------------------
  bool DiagSymbolsReady()
  {
    static bool sReady = false;
    static bool sTried = false;
    if (!sTried) {
      sTried = true;
      (void)::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
      // WinApp.cpp already initialises dbghelp for the crash reporter. A second
      // call fails with ERROR_INVALID_PARAMETER and that is fine - the handle is
      // already usable, so treat "already initialised" as success.
      sReady = ::SymInitialize(::GetCurrentProcess(), nullptr, TRUE) != FALSE
        || ::GetLastError() == ERROR_INVALID_PARAMETER;
    }
    return sReady;
  }

  void DiagDescribeAddress(const void* const address, char* const out, const std::size_t outBytes)
  {
    const auto raw = reinterpret_cast<DWORD64>(address);

    // Module + RVA always works, even with no symbols, and is what makes an
    // unresolved frame decodable offline against the map file.
    char moduleName[MAX_PATH] = "?";
    DWORD64 moduleBase = 0;
    HMODULE module = nullptr;
    if (::GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          static_cast<LPCSTR>(address),
          &module
        ) != FALSE
        && module != nullptr) {
      moduleBase = reinterpret_cast<DWORD64>(module);
      char fullPath[MAX_PATH] = {};
      if (::GetModuleFileNameA(module, fullPath, static_cast<DWORD>(sizeof(fullPath))) != 0u) {
        const char* const slash = std::strrchr(fullPath, '\\');
        (void)::strcpy_s(moduleName, sizeof(moduleName), (slash != nullptr) ? (slash + 1) : fullPath);
      }
    }

    char symbolText[300] = {};
    if (DiagSymbolsReady()) {
      alignas(SYMBOL_INFO) unsigned char storage[sizeof(SYMBOL_INFO) + 256] = {};
      auto* const symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
      symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
      symbol->MaxNameLen = 255;

      DWORD64 symbolOffset = 0;
      if (::SymFromAddr(::GetCurrentProcess(), raw, &symbolOffset, symbol) != FALSE) {
        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineOffset = 0;
        // `_TRUNCATE`, never `sprintf_s`: a decorated template name runs to
        // `MaxNameLen` (255) and `line.FileName` is a full source path, so the
        // two of them overflow `symbolText` routinely. `sprintf_s` treats that
        // as an invalid parameter and aborts the process -- which is how a
        // perfectly loggable access violation turned into a CRT assertion box
        // with the real fault's stack already discarded.
        if (::SymGetLineFromAddr64(::GetCurrentProcess(), raw, &lineOffset, &line) != FALSE) {
          (void)::_snprintf_s(
            symbolText, sizeof(symbolText), _TRUNCATE, " %s+0x%llX (%s:%lu)",
            symbol->Name, symbolOffset, (line.FileName != nullptr) ? line.FileName : "?", line.LineNumber
          );
        } else {
          (void)::_snprintf_s(symbolText, sizeof(symbolText), _TRUNCATE, " %s+0x%llX", symbol->Name, symbolOffset);
        }
      }
    }

    (void)::_snprintf_s(
      out, outBytes, _TRUNCATE, "%08llX %s+0x%llX%s",
      raw, moduleName, (moduleBase != 0) ? (raw - moduleBase) : 0ull, symbolText
    );
  }

  void DiagLogStack(const char* const tag)
  {
    void* frames[40] = {};
    const USHORT captured = ::RtlCaptureStackBackTrace(1, 40, frames, nullptr);

    DiagLine("[STACK] %s tid=%lu frames=%u", tag, ::GetCurrentThreadId(), static_cast<unsigned>(captured));
    for (USHORT i = 0; i < captured; ++i) {
      char described[420] = {};
      DiagDescribeAddress(frames[i], described, sizeof(described));
      DiagLine("[STACK]   #%02u %s", static_cast<unsigned>(i), described);
    }
  }

  int CrtReportToDiagLog(const int reportType, char* const message, int* const returnValue)
  {
    static const char* const kKind[] = {"WARN", "ERROR", "ASSERT"};
    const char* const kind =
      (reportType >= 0 && reportType < 3) ? kKind[reportType] : "?";
    DiagLine("[CRTDIAG] %s: %s", kind, (message != nullptr) ? message : "(null)");
    DiagLogStack("crt-report");

    if (returnValue != nullptr) {
      *returnValue = 0; // do not force a breakpoint; let the CRT proceed
    }
    return 0; // fall through to the CRT's own reporting too
  }

  void DiagAbortSignalHandler(int)
  {
    DiagLine("[CRTDIAG] abort() raised");
    DiagLogStack("abort");
  }

  void DiagTerminateHandler()
  {
    DiagLine("[CRTDIAG] std::terminate (uncaught exception or noexcept violation)");
    DiagLogStack("terminate");
    // Let the CRT's own terminate run so behaviour is unchanged.
    (void)std::signal(SIGABRT, SIG_DFL);
    std::abort();
  }

  void DiagPureCallHandler()
  {
    DiagLine("[CRTDIAG] pure virtual call");
    DiagLogStack("purecall");
  }

  // First-chance, log-only. Always continues the search, so the debugger still
  // receives every exception exactly as before.
  LONG CALLBACK DiagVectoredHandler(EXCEPTION_POINTERS* const info)
  {
    if (info == nullptr || info->ExceptionRecord == nullptr) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    constexpr DWORD kCppException = 0xE06D7363u;

    // A C++ throw is an ordinary control-flow event in this engine, so it is
    // opt-in (FAF_LOGTHROW=1) - useful for pinning the bad_alloc, far too noisy
    // by default.
    static int sThrowBudget = 0;
    static const bool sLogThrows = ::GetEnvironmentVariableA("FAF_LOGTHROW", nullptr, 0) != 0u;

    static int sFaultBudget = 0;

    if (code == kCppException) {
      if (!sLogThrows || sThrowBudget >= 40) {
        return EXCEPTION_CONTINUE_SEARCH;
      }
      ++sThrowBudget;
      DiagLine("[FAULT] C++ throw");
      DiagLogStack("throw");
      return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_ACCESS_VIOLATION
        && code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_INT_DIVIDE_BY_ZERO
        && code != EXCEPTION_STACK_OVERFLOW) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    if (sFaultBudget >= 12) {
      return EXCEPTION_CONTINUE_SEARCH;
    }
    ++sFaultBudget;

    char detail[160] = {};
    if (code == EXCEPTION_ACCESS_VIOLATION && info->ExceptionRecord->NumberParameters >= 2) {
      const ULONG_PTR kind = info->ExceptionRecord->ExceptionInformation[0];
      const ULONG_PTR target = info->ExceptionRecord->ExceptionInformation[1];
      (void)::sprintf_s(
        detail, sizeof(detail), " %s address %08IX",
        (kind == 0) ? "reading" : ((kind == 1) ? "writing" : "executing"), target
      );
    }

    DiagLine(
      "[FAULT] code=0x%08lX at %08IX%s",
      code, reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress), detail
    );
    DiagLogStack("fault");
    return EXCEPTION_CONTINUE_SEARCH;
  }

  void CrtInvalidParameterToDiagLog(
    const wchar_t* const expression,
    const wchar_t* const function,
    const wchar_t* const file,
    const unsigned int line,
    const std::uintptr_t
  )
  {
    DiagLine(
      "[CRTDIAG] invalid parameter: expr=%ls function=%ls file=%ls line=%u",
      (expression != nullptr) ? expression : L"(none)",
      (function != nullptr) ? function : L"(none)",
      (file != nullptr) ? file : L"(none)",
      line
    );
  }

  void InstallCrtDiagnosticHooks()
  {
    (void)_CrtSetReportHook(&CrtReportToDiagLog);
    (void)_set_invalid_parameter_handler(&CrtInvalidParameterToDiagLog);

    // Every route the CRT can take to kill the process, each one logging the
    // stack of whoever asked for it. The vectored handler is first-chance and
    // always continues the search, so a debugger still sees everything.
    (void)::AddVectoredExceptionHandler(1UL, &DiagVectoredHandler);
    (void)std::signal(SIGABRT, &DiagAbortSignalHandler);
    (void)std::set_terminate(&DiagTerminateHandler);
    (void)_set_purecall_handler(&DiagPureCallHandler);
    (void)_set_abort_behavior(0U, _WRITE_ABORT_MSG); // no modal box on abort

    DiagLine("[CRTDIAG] ==== run start, pid=%lu ====", ::GetCurrentProcessId());

    if (moho::CFG_GetArgOption("/heapcheck", 0, nullptr)) {
      // _CRTDBG_CHECK_ALWAYS_DF walks every live block on every alloc and free.
      // On this engine that never gets past mounting the archives, so the
      // interval is selectable: FAF_HEAPCHECK_EVERY=1/16/128/1024 (default
      // 1024) still narrows an overrun to the allocations either side of it,
      // at a cost the run survives.
      char interval[16]{};
      const DWORD intervalLen = ::GetEnvironmentVariableA("FAF_HEAPCHECK_EVERY", interval, sizeof(interval));
      int checkFlag = _CRTDBG_CHECK_EVERY_1024_DF;
      const char* checkName = "every 1024 allocations";
      if (intervalLen != 0U && intervalLen < sizeof(interval)) {
        if (std::strcmp(interval, "1") == 0) {
          checkFlag = _CRTDBG_CHECK_ALWAYS_DF;
          checkName = "on every alloc/free";
        } else if (std::strcmp(interval, "16") == 0) {
          checkFlag = _CRTDBG_CHECK_EVERY_16_DF;
          checkName = "every 16 allocations";
        } else if (std::strcmp(interval, "128") == 0) {
          checkFlag = _CRTDBG_CHECK_EVERY_128_DF;
          checkName = "every 128 allocations";
        }
      }

      int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
      flags |= _CRTDBG_ALLOC_MEM_DF | checkFlag;
      (void)_CrtSetDbgFlag(flags);
      DiagLine("[CRTDIAG] /heapcheck on: validating the heap %s", checkName);
    }
  }

} // namespace

/**
 * Address: 0x008D44A0 (FUN_008D44A0)
 * Mangled: _WinMain@16
 *
 * HINSTANCE,HINSTANCE,LPSTR,int
 *
 * What it does:
 * Applies startup command-line behavior, executes CScApp through WIN_AppExecute,
 * restores input system settings, and returns IWinApp::exitValue.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nShowCmd;

  gpg::time::Timer runTimer{};

  InstallCrtDiagnosticHooks(); // DIAGNOSTIC PROBE -- remove before committing

  if (moho::CFG_GetArgOption("/waitfordebugger", 0, nullptr)) {
    ::MessageBoxW(nullptr, L"Attach the debugger and click OK.", L"Waiting", 0);
  }

  if (moho::CFG_GetArgOption("/aqtime", 0, nullptr)) {
    moho::APP_SetAqtimeInstrumentationMode(0);
  }

  msvc8::vector<msvc8::string> allocLogArgs;
  if (moho::CFG_GetArgOption("/alloclog", 1, &allocLogArgs) && !allocLogArgs.empty()) {
    InitializeAllocationLog(allocLogArgs[0].c_str());
  }

  gpg::SetDieHandler(&FatalErrorDieHandler);

  if (moho::CFG_GetArgOption("/singleproc", 0, nullptr)) {
    DWORD_PTR processAffinityMask = 0;
    DWORD_PTR systemAffinityMask = 0;
    (void)::GetProcessAffinityMask(::GetCurrentProcess(), &processAffinityMask, &systemAffinityMask);

    DWORD_PTR selectedMask = 1;
    if (processAffinityMask != 0) {
      unsigned long bitIndex = 0;
      const unsigned long maxBits = static_cast<unsigned long>(sizeof(DWORD_PTR) * 8U);
      while (bitIndex + 1 < maxBits && ((processAffinityMask >> bitIndex) & 1U) == 0U) {
        ++bitIndex;
      }
      selectedMask = static_cast<DWORD_PTR>(1ULL << bitIndex);
    }
    (void)::SetProcessAffinityMask(::GetCurrentProcess(), selectedMask);
  }

  if (moho::CFG_GetArgOption("/purgecache", 0, nullptr)) {
    moho::USER_PurgeAppCacheDir();
  }

  (void)::SystemParametersInfoW(SPI_GETSTICKYKEYS, sizeof(STICKYKEYS), &sSavedStickyKeys, 0);
  (void)::SystemParametersInfoW(SPI_GETTOGGLEKEYS, sizeof(TOGGLEKEYS), &sSavedToggleKeys, 0);
  (void)::SystemParametersInfoW(SPI_GETFILTERKEYS, sizeof(FILTERKEYS), &sSavedFilterKeys, 0);
  ConfigureAccessibilitySystemParameters(false);

  int exitCode = 0;
  try {
    {
      CScApp app;
      moho::WIN_AppExecute(&app);
      exitCode = app.GetExitValue();
      app.framerates.Reset();
    }

    const int totalSeconds = static_cast<int>(runTimer.ElapsedSeconds());
    gpg::Logf("Run time: %dh%02dm%02ds", totalSeconds / 3600, (totalSeconds % 3600) / 60, totalSeconds % 60);
  } catch (const gpg::gal::Error& galError) {
    std::ostringstream formatted;
    formatted << "file : " << galError.GetRuntimeMessage() << "(" << galError.GetRuntimeLine() << ")\n";
    formatted << "error: " << galError.what();
    gpg::Die("GAL Exception: %s", formatted.str().c_str());
  } catch (const std::exception& ex) {
    gpg::Die("Unhandled exception:\n\n%s", ex.what());
  }

  ConfigureAccessibilitySystemParameters(true);
  (void)TryLaunchMediaCenterIfRequested();
  return exitCode;
}
