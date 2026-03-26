#include "moho/resource/CParticleTextureConstruct.h"

#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x0048FA30 (FUN_0048FA30, gpg::SerConstructHelper_CParticleTexture::Init)
   *
   * What it does:
   * Resolves `CParticleTexture` RTTI and installs construct/delete callbacks.
   */
  void CParticleTextureConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }
} // namespace moho
