#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <ws2tcpip.h>
#include <Windows.h>
#include <winsock2.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

#include <shellapi.h>
#include <shlobj.h>

#include "CScApp.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "WinApp.h"

extern int __argc;
extern char** __argv;

namespace
{
  /**
   * Address: 0x008D2170 (FUN_008D2170)
   *
   * What it does:
   * Opens the `/alloclog` target file, writes the QPC frequency header,
   * and keeps the stream open for the process lifetime.
   */
  void InitializeAllocationLog(const char* const path)
  {
    if (path == nullptr || path[0] == '\0') {
      return;
    }

    static std::FILE* sAllocationLogFile = nullptr;
    if (sAllocationLogFile != nullptr) {
      return;
    }

    std::FILE* file = nullptr;
    if (::fopen_s(&file, path, "wb") != 0 || file == nullptr) {
      return;
    }

    LARGE_INTEGER frequency{};
    ::QueryPerformanceFrequency(&frequency);
    (void)::fwrite(&frequency, sizeof(frequency), 1, file);
    sAllocationLogFile = file;

    (void)::atexit([] {
      if (sAllocationLogFile != nullptr) {
        (void)::fclose(sAllocationLogFile);
        sAllocationLogFile = nullptr;
      }
    });
  }

  /**
   * Address: 0x004F1500 (FUN_004F1500)
   *
   * What it does:
   * Fatal die-handler callback registered by WinMain.
   */
  void FatalErrorDieHandler(const char* const message)
  {
    ::MessageBoxA(nullptr, message != nullptr ? message : "", "Fatal Error", MB_OK | MB_ICONERROR);
  }

  /**
   * Address: 0x0041B560 (FUN_0041B560)
   *
   * What it does:
   * Looks up command-line switches case-insensitively and optionally
   * requires one following argument.
   */
  [[nodiscard]]
  bool TryFindCommandSwitch(const char* const name, const int requiredFollowingArgs, const char** const firstArgOut)
  {
    if (name == nullptr || requiredFollowingArgs < 0) {
      return false;
    }

    for (int index = 1; index < __argc; ++index) {
      const char* const argument = __argv[index];
      if (argument == nullptr || ::_stricmp(argument, name) != 0) {
        continue;
      }

      if ((index + requiredFollowingArgs) >= __argc) {
        continue;
      }

      if (firstArgOut != nullptr) {
        *firstArgOut = requiredFollowingArgs > 0 ? __argv[index + 1] : nullptr;
      }
      return true;
    }

    return false;
  }

  /**
   * Address: 0x008C9D10 (FUN_008C9D10)
   *
   * What it does:
   * Builds the local-appdata root folder for FA user files.
   */
  [[nodiscard]]
  std::string GetFaLocalAppDataRoot()
  {
    std::array<wchar_t, MAX_PATH> localAppDataPath{};
    if (::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppDataPath.data()) < 0) {
      return {};
    }

    std::filesystem::path root(localAppDataPath.data());
    root /= "Gas Powered Games";
    root /= "Supreme Commander Forged Alliance";
    return root.generic_string();
  }

  /**
   * Address: 0x008C9F90 (FUN_008C9F90)
   *
   * What it does:
   * Resolves the FA cache directory and ensures it exists.
   */
  [[nodiscard]]
  std::string GetFaCachePath()
  {
    std::filesystem::path cachePath(GetFaLocalAppDataRoot());
    if (cachePath.empty()) {
      return {};
    }

    cachePath /= "cache";
    std::error_code createDirectoryError;
    std::filesystem::create_directories(cachePath, createDirectoryError);
    return cachePath.generic_string();
  }

  /**
   * Address: 0x008CA070 (FUN_008CA070)
   *
   * What it does:
   * Deletes contents of the cache directory using shell file operation flags.
   */
  void PurgeCacheDirectory()
  {
    std::string deletePattern = GetFaCachePath();
    if (deletePattern.empty()) {
      return;
    }

    deletePattern += "/*";
    for (char& character : deletePattern) {
      if (character == '/') {
        character = '\\';
      }
    }

    // SHFileOperation expects a double-null terminated multi-string.
    deletePattern.push_back('\0');

    SHFILEOPSTRUCTA operation{};
    operation.wFunc = FO_DELETE;
    operation.pFrom = deletePattern.c_str();
    operation.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI;

    if (::SHFileOperationA(&operation) != 0) {
      gpg::Warnf("Cache purge failed for \"%s\".", deletePattern.c_str());
    }
  }

  /**
   * Address: 0x008D4320 (FUN_008D4320)
   *
   * What it does:
   * Applies startup accessibility tweaks and restores original values on exit.
   */
  void ConfigureMouseSystemParameters(const bool restoreOriginalValues)
  {
    constexpr UINT kGetActionA = 0x3A;
    constexpr UINT kSetActionA = 0x3B;
    constexpr UINT kGetActionB = 0x34;
    constexpr UINT kSetActionB = 0x35;
    constexpr UINT kGetActionC = 0x32;
    constexpr UINT kSetActionC = 0x33;

    struct IntPair
    {
      std::uint32_t values[2]{};
    };
    struct IntSextet
    {
      std::uint32_t values[6]{};
    };

    static IntPair sSavedA{};
    static IntPair sSavedB{};
    static IntSextet sSavedC{};

    if (restoreOriginalValues) {
      (void)::SystemParametersInfoW(kSetActionA, sizeof(sSavedA), &sSavedA, 0);
      (void)::SystemParametersInfoW(kSetActionB, sizeof(sSavedB), &sSavedB, 0);
      (void)::SystemParametersInfoW(kSetActionC, sizeof(sSavedC), &sSavedC, 0);
      return;
    }

    (void)::SystemParametersInfoW(kGetActionA, sizeof(sSavedA), &sSavedA, 0);
    (void)::SystemParametersInfoW(kGetActionB, sizeof(sSavedB), &sSavedB, 0);
    (void)::SystemParametersInfoW(kGetActionC, sizeof(sSavedC), &sSavedC, 0);

    IntPair nextA = sSavedA;
    if ((sSavedA.values[1] & 1U) == 0U) {
      nextA.values[1] &= 0xFFFFFFF3U;
      (void)::SystemParametersInfoW(kSetActionA, sizeof(nextA), &nextA, 0);
    }

    IntPair nextB = sSavedB;
    if ((sSavedB.values[1] & 1U) == 0U) {
      nextB.values[1] &= 0xFFFFFFF3U;
      (void)::SystemParametersInfoW(kSetActionB, sizeof(nextB), &nextB, 0);
    }

    IntSextet nextC = sSavedC;
    if ((sSavedC.values[1] & 1U) == 0U) {
      nextC.values[1] &= 0xFFFFFFF3U;
      (void)::SystemParametersInfoW(kSetActionC, sizeof(nextC), &nextC, 0);
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
    if (!TryFindCommandSwitch("/mediacenter", 0, nullptr)) {
      return false;
    }

    if (::GetSystemMetrics(0x57) == 0) {
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

  /**
   * Address: 0x009071C0 (FUN_009071C0)
   *
   * What it does:
   * AQtime instrumentation gate used by `/aqtime` startup switch.
   */
  void EnableAqtimeInstrumentation([[maybe_unused]] const int mode)
  {
    // This helper is currently a no-op until AQtime integration is reconstructed.
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

  if (TryFindCommandSwitch("/waitfordebugger", 0, nullptr)) {
    ::MessageBoxW(nullptr, L"Attach the debugger and click OK.", L"Waiting", 0);
  }

  if (TryFindCommandSwitch("/aqtime", 0, nullptr)) {
    EnableAqtimeInstrumentation(0);
  }

  const char* allocLogPath = nullptr;
  if (TryFindCommandSwitch("/alloclog", 1, &allocLogPath)) {
    InitializeAllocationLog(allocLogPath);
  }

  gpg::SetDieHandler(&FatalErrorDieHandler);

  if (TryFindCommandSwitch("/singleproc", 0, nullptr)) {
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

  if (TryFindCommandSwitch("/purgecache", 0, nullptr)) {
    PurgeCacheDirectory();
  }

  ConfigureMouseSystemParameters(false);

  int exitCode = 0;
  {
    CScApp app;
    moho::WIN_AppExecute(&app);
    exitCode = app.exitValue;
    app.framerates.Reset();
  }

  const int totalSeconds = static_cast<int>(gpg::time::CyclesToSeconds(runTimer.ElapsedCycles()));
  gpg::Logf("Run time: %dh%02dm%02ds", totalSeconds / 3600, (totalSeconds % 3600) / 60, totalSeconds % 60);

  ConfigureMouseSystemParameters(true);
  (void)TryLaunchMediaCenterIfRequested();
  return exitCode;
}
