#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2F4D4
   * COL: 0x00E8D908
   */
  class PropSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD98A0 (FUN_00BD98A0, dynamic initializer for the global
     * `PropSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the save-construct-args callback field. Plain unlink
     * atexit target, modeled as the compiler's implicit static-destructor
     * registration.
     */
    PropSaveConstruct();

    /**
     * Address: 0x00BFF1D0 (FUN_00BFF1D0, atexit target registered by the
     * real ctor above)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_006FA550`/
     * `FUN_006FA580` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneAS` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~PropSaveConstruct();

    /**
     * Address: 0x006FA960 (FUN_006FA960, gpg::SerSaveConstructHelper_Prop::Init)
     *
     * What it does:
     * Binds Prop save-construct-args callback into reflected RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(PropSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "PropSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(PropSaveConstruct) == 0x10, "PropSaveConstruct size must be 0x10");
} // namespace moho
