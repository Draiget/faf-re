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

#include "CScApp.h"
#include "gpg/core/diagnostics/CrashHooks.h"
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
  msvc8::hash_set<std::uintptr_t> sMemHookAddr;

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

      std::uintptr_t frames[64];
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

      const std::uintptr_t terminator = 0;
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

  gpg::diag::CrtDiagOptions diagOptions{};
  diagOptions.enableHeapCheck = moho::CFG_GetArgOption("/heapcheck", 0, nullptr);
  gpg::diag::InstallCrtDiagnosticHooks(diagOptions);

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
    formatted << "file : " << galError.GetFile() << "(" << galError.GetLine() << ")\n";
    formatted << "error: " << galError.what();
    gpg::Die("GAL Exception: %s", formatted.str().c_str());
  } catch (const std::exception& ex) {
    gpg::Die("Unhandled exception:\n\n%s", ex.what());
  }

  ConfigureAccessibilitySystemParameters(true);
  (void)TryLaunchMediaCenterIfRequested();
  return exitCode;
}
