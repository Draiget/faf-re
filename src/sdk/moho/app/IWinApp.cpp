#include "IWinApp.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
#include <new>
#include <type_traits>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/ResourceManager.h"

using namespace moho;

extern char** __argv;

namespace
{
  std::uint32_t sInitThreadId = 0;
  std::uint32_t sStreamLogBootstrapFlags = 0;
  gpg::StreamLogTarget* sStreamLogTargetInstance = nullptr;
  std::aligned_storage_t<sizeof(gpg::StreamLogTarget), alignof(gpg::StreamLogTarget)> sStreamLogTargetStorage{};

  [[nodiscard]]
  gpg::StreamLogTarget* GetStartupLogTargetStorage()
  {
    return reinterpret_cast<gpg::StreamLogTarget*>(&sStreamLogTargetStorage);
  }

  /**
   * Address: 0x00BF1840 (FUN_00BF1840, sub_BF1840)
   *
   * What it does:
   * `atexit` callback that tears down the startup stream-log target singleton.
   */
  void DestroyStartupLogTargetAtProcessExit()
  {
    if ((sStreamLogBootstrapFlags & 1U) == 0U || sStreamLogTargetInstance == nullptr) {
      return;
    }

    sStreamLogTargetInstance->~StreamLogTarget();
    sStreamLogTargetInstance = nullptr;
    sStreamLogBootstrapFlags &= ~1U;
  }

  void TryInitializeStartupLogTarget()
  {
    if ((sStreamLogBootstrapFlags & 1U) != 0U) {
      return;
    }

    msvc8::vector<msvc8::string> logArgs;
    if (!CFG_GetArgOption("/log", 1, &logArgs) || logArgs.empty()) {
      return;
    }

    const msvc8::string logFileName = FILE_SuggestedExt(logArgs[0].c_str(), "sclog");
    std::ofstream* const logStream = new std::ofstream(logFileName.c_str(), std::ios::out | std::ios::trunc);
    const auto streamState = logStream->rdstate();
    if ((streamState & (std::ios::failbit | std::ios::badbit)) != 0) {
      delete logStream;
      return;
    }

    if ((sStreamLogBootstrapFlags & 1U) != 0U) {
      delete logStream;
      return;
    }

    sStreamLogTargetInstance = new (GetStartupLogTargetStorage()) gpg::StreamLogTarget(*logStream, 3U);
    sStreamLogBootstrapFlags |= 1U;
    std::atexit(&DestroyStartupLogTargetAtProcessExit);
  }

  [[nodiscard]]
  std::filesystem::path ResolveLaunchDirectory()
  {
    std::array<char, MAX_PATH> fullPathBuffer{};
    const char* const argv0 = (__argv != nullptr && __argv[0] != nullptr) ? __argv[0] : ".";
    if (_fullpath(fullPathBuffer.data(), argv0, fullPathBuffer.size()) == nullptr) {
      return std::filesystem::current_path();
    }

    std::filesystem::path launchPath(fullPathBuffer.data());
    if (launchPath.has_parent_path()) {
      return launchPath.parent_path();
    }

    return std::filesystem::current_path();
  }
}

/**
 * Address: 0x008CD360 (FUN_008CD360)
 * Mangled: ??0IWinApp@Moho@@QAE@VStrArg@gpg@@0@Z
 *
 * gpg::StrArg,gpg::StrArg
 *
 * What it does:
 * Initializes app identity strings used by startup/logging flows.
 */
IWinApp::IWinApp(const gpg::StrArg shortNameArg, const gpg::StrArg longNameArg)
{
  const char* const shortNameText = shortNameArg ? shortNameArg : "";
  const char* const longNameText = longNameArg ? longNameArg : "";
  shortName.assign_owned(shortNameText);
  longName.assign_owned(longNameText);
  exitValue = 0;
}

/**
 * Address: 0x008CD400 (FUN_008CD400)
 * Mangled: ??1IWinApp@Moho@@UAE@XZ
 *
 * What it does:
 * Releases owned string buffers and resets base app identity state.
 */
IWinApp::~IWinApp()
{
  longName.tidy(true, 0U);
  shortName.tidy(true, 0U);
}

/**
 * Address: 0x008CD460 (FUN_008CD460)
 * Mangled: ?AppGetHelpText@IWinApp@Moho@@UAE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z
 *
 * std::basic_string<char,...>&, bool
 *
 * What it does:
 * Default command-line help text provider.
 * FA retail default is a false/nullsub return.
 */
bool IWinApp::AppGetHelpText(msvc8::string& outHelpText, const bool shortMode)
{
  (void)shortMode;
  outHelpText.assign_owned("");
  return false;
}

/**
 * Address: 0x004F1BA0 (FUN_004F1BA0)
 * Mangled: ?AppInitCommonServices@IWinApp@Moho@@UAE_NXZ
 *
 * What it does:
 * Performs shared app service bootstrap before concrete app init.
 */
bool IWinApp::AppInitCommonServices()
{
  sInitThreadId = ::GetCurrentThreadId();
  gpg::EnableLogHistory(100);
  TryInitializeStartupLogTarget();

  gpg::REF_RegisterAllTypes();
  RES_EnsureResourceManager();
  RES_ActivatePendingFactories();

  const std::filesystem::path launchDirectory = ResolveLaunchDirectory();
  const msvc8::string dataPathScriptName("SupComDataPath.lua");
  if (!DISK_SetupDataAndSearchPaths(dataPathScriptName, launchDirectory)) {
    gpg::Die("Failed to setup initial search path.");
  }

  return true;
}

/**
 * Address: 0x008CD470 (FUN_008CD470)
 * Mangled: ?AppDoSuppressWindowsKeys@IWinApp@Moho@@UBE_NXZ
 *
 * What it does:
 * Low-level keyboard-hook gating probe (default false).
 */
bool IWinApp::AppDoSuppressWindowsKeys() const
{
  return false;
}
