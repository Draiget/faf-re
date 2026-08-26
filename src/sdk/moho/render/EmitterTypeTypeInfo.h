#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/render/EmitterType.h"

namespace moho
{
  class EmitterTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
     */
    ~EmitterTypeTypeInfo() override;

    /**
     * Address: 0x0065DF30 (FUN_0065DF30)
     *
     * What it does:
     * Returns the reflection type name literal for EmitterType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0065DF10 (FUN_0065DF10)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EmitterTypeTypeInfo) == 0x78, "EmitterTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum moho::EmitterType,int>
   * VFTABLE: 0x00E2416C
   * COL: 0x00E7E4A8
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EmitterType@Moho@@H@gpg'`):
   * `FUN_00BD42B0` (real, `__xc_a`-reachable; no dead low-address duplicate
   * found for this instantiation). Previously modeled in this file as a
   * hand-rolled `{ void* mVtable; SerHelperBase* mHelperNext, mHelperPrev;
   * ... }` POD plus manual `InitializeHelperNode`/`UnlinkHelperNode`
   * splicing and an eager `register_EmitterTypePrimitiveSerializer()`
   * bootstrap call -- none of which the real binary does; `SerHelperBase`'s
   * own ctor performs the real self-registration onto the pending-helper
   * list.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BFBD20` (atexit target
   * pushed by the real ctor above); `FUN_0065DF80`/`FUN_0065DFB0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneX` and its two reset thunks; removed in
   * favor of this citation.
   */
  using EmitterTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EmitterType, int>;

  /**
   * Address: 0x0065DEB0 (FUN_0065DEB0, register_EmitterTypeTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::EmitterType`.
   */
  gpg::RType* register_EmitterTypeTypeInfo_00();

  /**
   * Address: 0x00BFBD10 (FUN_00BFBD10, cleanup_EmitterTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EmitterTypeTypeInfo` reflection storage.
   */
  void cleanup_EmitterTypeTypeInfo();

  /**
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo_AtExit)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_EmitterTypeTypeInfo_AtExit();
} // namespace moho
