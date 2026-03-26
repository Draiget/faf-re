#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E06270
   * COL: 0x00E6143C
   */
  class CParticleTextureConstruct
  {
  public:
    /**
     * Address: 0x0048FA30 (FUN_0048FA30, gpg::SerConstructHelper_CParticleTexture::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CParticleTexture` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CParticleTextureConstruct, mHelperNext) == 0x04,
    "CParticleTextureConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CParticleTextureConstruct, mHelperPrev) == 0x08,
    "CParticleTextureConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CParticleTextureConstruct, mConstructCallback) == 0x0C,
    "CParticleTextureConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CParticleTextureConstruct, mDeleteCallback) == 0x10,
    "CParticleTextureConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CParticleTextureConstruct) == 0x14, "CParticleTextureConstruct size must be 0x14");
} // namespace moho
