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
   * VFTABLE: 0x00E06260
   * COL: 0x00E614E8
   */
  class CParticleTextureSaveConstruct
  {
  public:
    /**
     * Address: 0x0048F9B0 (FUN_0048F9B0, gpg::SerSaveConstructHelper_CParticleTexture::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CParticleTexture` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(CParticleTextureSaveConstruct, mHelperNext) == 0x04,
    "CParticleTextureSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CParticleTextureSaveConstruct, mHelperPrev) == 0x08,
    "CParticleTextureSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CParticleTextureSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CParticleTextureSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CParticleTextureSaveConstruct) == 0x10, "CParticleTextureSaveConstruct size must be 0x10");
} // namespace moho
