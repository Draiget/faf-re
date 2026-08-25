#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EVisibilityMode : std::int32_t
  {
    VIZMODE_Never = 1,
    VIZMODE_Always = 2,
    VIZMODE_Intel = 4,
  };

  static_assert(sizeof(EVisibilityMode) == 0x04, "EVisibilityMode size must be 0x04");

  class EVisibilityModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF1F90 (FUN_00BF1F90, Moho::EVisibilityModeTypeInfo::dtr)
     */
    ~EVisibilityModeTypeInfo() override;

    /**
     * Address: 0x0050A0D0 (FUN_0050A0D0, Moho::EVisibilityModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A160 (FUN_0050A160, Moho::EVisibilityModeTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050A1C0 (FUN_0050A1C0, Moho::EVisibilityModeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EVisibilityModeTypeInfo) == 0x78, "EVisibilityModeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EVisibilityMode,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EVisibilityMode@Moho@@H@gpg'`):
   * `FUN_00BC7AF0` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0050A740` in the same instantiation family. Previously modeled
   * in this file as a hand-rolled `{ void* mVtable; SerHelperBase*
   * mHelperNext, mHelperPrev; ... }` POD plus manual
   * `InitializeSerializerNode`/`UnlinkSerializerNode` splicing and an eager
   * `register_EVisibilityModePrimitiveSerializer()` bootstrap call -- none
   * of which the real binary does; `SerHelperBase`'s own ctor performs the
   * real self-registration onto the pending-helper list.
   *
   * A second, unrelated writer shares this global's storage address
   * (`FUN_0050AA40`, demangled
   * `gpg::SerSaveLoadHelper<enum Moho::EVisibilityMode>`) but is itself
   * zero-xref/unreachable too -- a separate, still-unrecovered template
   * family, not modeled here.
   */
  using EVisibilityModePrimitiveSerializer = gpg::PrimitiveSerHelper<EVisibilityMode, int>;

  /**
   * Address: 0x0050A100 (FUN_0050A100, preregister_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `EVisibilityMode`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EVisibilityModeTypeInfo();

  /**
   * Address: 0x00BC7AD0 (FUN_00BC7AD0, register_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Runs `EVisibilityMode` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EVisibilityModeTypeInfo();
} // namespace moho

