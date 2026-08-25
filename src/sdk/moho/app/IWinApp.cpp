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
    // This construction is the real source-level trigger for a chain of
    // Dinkumware iostream/CRT internals, none of which need a hand-written
    // body -- they're satisfied automatically once this expression compiles:
    //   Address: 0x004F2B50 (FUN_004F2B50, std::basic_ofstream<char,
    //   std::char_traits<char>>::basic_ofstream(const char*, ios_base::openmode))
    //   Address: 0x004C54A0 (FUN_004C54A0, std::basic_filebuf<char,
    //   std::char_traits<char>>::open) -- called by the ofstream ctor above.
    //   Address: 0x004C5A10 (FUN_004C5A10, std::basic_streambuf<...>::getloc,
    //   IDA's own inferred name says the wchar_t instantiation, but the
    //   body only touches locale-refcounting state that isn't specialized
    //   per character type, so it's plausibly ICF-shared with the char
    //   version) -- called by basic_filebuf::open to read the ambient
    //   locale's codecvt facet.
    //   Address: 0x00ABFC0F (FUN_00ABFC0F, std::_Fiopen) -- called by
    //   basic_filebuf::open.
    //   Address: 0x00ABFB55 (FUN_00ABFB55, std::_Fiopen, a second calling-
    //   convention/argument-shape emission of the same CRT primitive).
    //   Address: 0x00ABFAA0 (FUN_00ABFAA0, std::_Xfsopen) -- the
    //   out-of-range-openmode exception path both _Fiopen emissions share.
    // DB-integrity fix: FUN_004F2B50 was marked `recovered` with a note
    // claiming this exact call site as its citation, but no `Address:`
    // annotation for it existed anywhere in src/sdk (fake-recovered-status
    // contamination, same shape documented elsewhere this session) -- this
    // comment is that citation, now real.
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
    return moho::DISK_GetLaunchDir();
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
 * Address: 0x008CD480 (FUN_008CD480)
 *
 * What it does:
 * Runs one deleting-destructor thunk for `IWinApp`, forwarding through
 * non-deleting teardown and optional storage release.
 */
[[nodiscard]] IWinApp* DestroyIWinAppDeleting(IWinApp* const app, const unsigned char deleteFlag)
{
  app->~IWinApp();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(app));
  }
  return app;
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

/**
 * Address: 0x008CD450 (FUN_008CD450)
 *
 * What it does:
 * Returns the cached process exit code lane stored in `exitValue`.
 */
std::int32_t IWinApp::GetExitValue() const
{
  return exitValue;
}
