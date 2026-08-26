#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3176C
   */
  class CInfluenceMapConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA680 (FUN_00BDA680, dynamic initializer for the global
     * `CInfluenceMapConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. The ctor's atexit target is a
     * plain unlink thunk, not a mangled destructor, so it is modeled as
     * the compiler's implicit static-destructor registration rather than
     * an explicit call.
     */
    CInfluenceMapConstruct();

    /**
     * Address: 0x00BFFF10 (FUN_00BFFF10, atexit target registered by the
     * real ctor above)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_00717600`/
     * `FUN_00717630` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneAZ` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~CInfluenceMapConstruct();

    /**
     * Address: 0x00718AE0 (FUN_00718AE0, gpg::SerConstructHelper_CInfluenceMap::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CInfluenceMap RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(CInfluenceMapConstruct, mConstructCallback) == 0x0C,
    "CInfluenceMapConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CInfluenceMapConstruct, mDeleteCallback) == 0x10,
    "CInfluenceMapConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CInfluenceMapConstruct) == 0x14, "CInfluenceMapConstruct size must be 0x14");
} // namespace moho
