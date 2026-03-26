#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E06230
   * COL: 0x00E61580
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CParticleTextureTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0048EE40 (FUN_0048EE40, Moho::CParticleTextureTypeInfo::dtr)
     * Slot: 2
     */
    ~CParticleTextureTypeInfo() override;

    /**
     * Address: 0x0048EE30 (FUN_0048EE30, Moho::CParticleTextureTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `CParticleTexture`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048EE10 (FUN_0048EE10, Moho::CParticleTextureTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CParticleTexture` (`sizeof = 0x2C`)
     * and finalizes field/base indices.
     */
    void Init() override;
  };

  static_assert(sizeof(CParticleTextureTypeInfo) == 0x64, "CParticleTextureTypeInfo size must be 0x64");
} // namespace moho
