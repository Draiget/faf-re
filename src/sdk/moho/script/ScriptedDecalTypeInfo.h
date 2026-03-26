#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E499D0
   * COL: 0x00E9C3D0
   */
  class ScriptedDecalTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0087F130 (FUN_0087F130, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~ScriptedDecalTypeInfo() override;

    /**
     * Address: 0x0087F120 (FUN_0087F120, ?GetName@ScriptedDecalTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0087F0F0 (FUN_0087F0F0, ?Init@ScriptedDecalTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(ScriptedDecalTypeInfo) == 0x64, "ScriptedDecalTypeInfo size must be 0x64");
} // namespace moho

