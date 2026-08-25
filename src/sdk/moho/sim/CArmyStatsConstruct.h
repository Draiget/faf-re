#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E31288
   */
  class CArmyStatsConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA1D0 (FUN_00BDA1D0, dynamic initializer for the global
     * `CArmyStatsConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the construct/delete callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CArmyStatsConstruct@Moho@@6B@` -- no eager
     * `Init()` call exists here. The ctor's atexit target is a plain,
     * unmangled unlink thunk (not a mangled destructor symbol), so it is
     * modeled as the compiler's own implicit static-destructor
     * registration: this class declares a real destructor and relies on
     * the compiler to emit the matching registration.
     */
    CArmyStatsConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CArmyStatsConstruct();

    /**
     * Address: 0x0070F560 (FUN_0070F560, gpg::SerConstructHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CArmyStats RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(CArmyStatsConstruct, mConstructCallback) == 0x0C,
    "CArmyStatsConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatsConstruct, mDeleteCallback) == 0x10, "CArmyStatsConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatsConstruct) == 0x14, "CArmyStatsConstruct size must be 0x14");
} // namespace moho
