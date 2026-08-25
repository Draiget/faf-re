#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Entity.h"

namespace moho
{
  class ELayerTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF2070 (FUN_00BF2070, Moho::ELayerTypeInfo::dtr)
     */
    ~ELayerTypeInfo() override;

    /**
     * Address: 0x0050BA70 (FUN_0050BA70, Moho::ELayerTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BA50 (FUN_0050BA50, Moho::ELayerTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050BAB0 (FUN_0050BAB0, Moho::ELayerTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ELayerTypeInfo) == 0x78, "ELayerTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ELayer,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ELayer@Moho@@H@gpg'`):
   * `FUN_00BC7C80` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_0050C660` in the same instantiation family. Previously modeled
   * in this file as a hand-rolled `{ void* mVtable; SerHelperBase*
   * mHelperNext, mHelperPrev; ... }` POD plus manual
   * `InitializeSerializerNode`/`UnlinkSerializerNode` splicing and an eager
   * `register_ELayerPrimitiveSerializer()` bootstrap call -- none of which
   * the real binary does; `SerHelperBase`'s own ctor performs the real
   * self-registration onto the pending-helper list.
   *
   * A second, unrelated writer shares this global's storage address
   * (`FUN_0050CA60`, demangled `gpg::SerSaveLoadHelper<enum Moho::ELayer>`)
   * but is itself zero-xref/unreachable too -- a separate, still-unrecovered
   * template family, not modeled here.
   */
  using ELayerPrimitiveSerializer = gpg::PrimitiveSerHelper<ELayer, int>;

  /**
   * Address: 0x0050B9F0 (FUN_0050B9F0, preregister_ELayerTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for `ELayer`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ELayerTypeInfo();

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   *
   * What it does:
   * Runs `ELayer` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_ELayerTypeInfo();
} // namespace moho
