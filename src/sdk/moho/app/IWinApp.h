#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E4F408
   * COL: 0x00E9F9A0
   */
  class IWinApp
  {
  public:
    /**
     * Address: 0x008CD360 (FUN_008CD360)
     * Mangled: ??0IWinApp@Moho@@QAE@VStrArg@gpg@@0@Z
     *
     * gpg::StrArg,gpg::StrArg
     *
     * What it does:
     * Initializes app identity strings used by startup/logging flows.
     */
    IWinApp(gpg::StrArg shortNameArg, gpg::StrArg longNameArg);

    /**
     * Address: 0x008CD400 (FUN_008CD400)
     * Mangled: ??1IWinApp@Moho@@UAE@XZ
     *
     * What it does:
     * Releases owned string buffers and resets base app identity state.
     */
    virtual ~IWinApp();

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
    virtual bool AppGetHelpText(msvc8::string& outHelpText, bool shortMode);

    /**
     * Address: 0x004F1BA0 (FUN_004F1BA0)
     * Mangled: ?AppInitCommonServices@IWinApp@Moho@@UAE_NXZ
     *
     * What it does:
     * Performs shared app service bootstrap before concrete app init.
     */
    virtual bool AppInitCommonServices();

    /**
     * Address: 0x00A82547 (_purecall, slot 3 in IWinApp)
     *
     * What it does:
     * Concrete app startup phase.
     */
    virtual bool Init() = 0;

    /**
     * Address: 0x00A82547 (_purecall, slot 4 in IWinApp)
     *
     * What it does:
     * Concrete app main-frame phase.
     */
    virtual void Main() = 0;

    /**
     * Address: 0x00A82547 (_purecall, slot 5 in IWinApp)
     *
     * What it does:
     * Concrete app shutdown phase.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x008CD470 (FUN_008CD470)
     * Mangled: ?AppDoSuppressWindowsKeys@IWinApp@Moho@@UBE_NXZ
     *
     * What it does:
     * Low-level keyboard-hook gating probe (default false).
     */
    virtual bool AppDoSuppressWindowsKeys() const;

  public:
    // +0x04
    msvc8::string shortName;
    // +0x20
    msvc8::string longName;
    // +0x3C
    std::int32_t exitValue;
  };

  static_assert(offsetof(IWinApp, shortName) == 0x04, "IWinApp::shortName offset must be 0x04");
  static_assert(offsetof(IWinApp, longName) == 0x20, "IWinApp::longName offset must be 0x20");
  static_assert(offsetof(IWinApp, exitValue) == 0x3C, "IWinApp::exitValue offset must be 0x3C");
  static_assert(sizeof(IWinApp) == 0x40, "IWinApp size must be 0x40");
} // namespace moho
