#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CParticleTexture;
}

namespace gpg
{
  /**
   * Address: 0x00490A60 (FUN_00490A60, gpg::RRef_CParticleTexture)
   *
   * What it does:
   * Builds one typed reflection reference for a `CParticleTexture*` lane,
   * resolving derived runtime type + base adjustment when needed.
   */
  gpg::RRef* RRef_CParticleTexture(gpg::RRef* outRef, moho::CParticleTexture* value);

} // namespace gpg
