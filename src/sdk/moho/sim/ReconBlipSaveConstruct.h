#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA44
   * COL:  0x00E73FF0
   */
  class ReconBlipSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDC70 (FUN_00BCDC70, register_ReconBlipSaveConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. The ctor's atexit target is a
     * plain unlink thunk, not a mangled destructor, so it is modeled as
     * the compiler's implicit static-destructor registration rather than
     * an explicit call.
     */
    ReconBlipSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~ReconBlipSaveConstruct();

    /**
     * Address: 0x005C42B0 (FUN_005C42B0, gpg::SerSaveConstructHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds save-construct-args callback into ReconBlip RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(ReconBlipSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "ReconBlipSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(ReconBlipSaveConstruct) == 0x10, "ReconBlipSaveConstruct size must be 0x10");
} // namespace moho
