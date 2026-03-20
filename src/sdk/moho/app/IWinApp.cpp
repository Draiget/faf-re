#include "IWinApp.h"

#include <Windows.h>

#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{
  std::uint32_t sInitThreadId = 0;
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
  // 0x004F1BA0 begins by capturing current thread id, then registers
  // reflection types before continuing with path/log bootstrap helpers.
  sInitThreadId = ::GetCurrentThreadId();
  gpg::REF_RegisterAllTypes();

  // Remaining 0x004F1BA0 phases depend on not-yet-lifted config/filesystem
  // bootstrap helpers (CFG_/DISK_/resource-manager chain).
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
