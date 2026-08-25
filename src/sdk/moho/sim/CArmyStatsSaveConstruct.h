#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E31278
   */
  class CArmyStatsSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA1A0 (FUN_00BDA1A0, dynamic initializer for the global
     * `CArmyStatsSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. Like `CArmyStatsConstruct`, the
     * ctor's atexit target is a plain unlink thunk, not a mangled
     * destructor, so it is modeled as the compiler's implicit
     * static-destructor registration rather than an explicit call.
     */
    CArmyStatsSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CArmyStatsSaveConstruct();

    /**
     * Address: 0x0070F4E0 (FUN_0070F4E0, gpg::SerSaveConstructHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds save-construct-args callback into CArmyStats RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CArmyStatsSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CArmyStatsSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CArmyStatsSaveConstruct) == 0x10, "CArmyStatsSaveConstruct size must be 0x10");
} // namespace moho
