#include "moho/resource/CParticleTextureSaveConstruct.h"

#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x0048F9B0 (FUN_0048F9B0, gpg::SerSaveConstructHelper_CParticleTexture::Init)
   *
   * What it does:
   * Resolves `CParticleTexture` RTTI and installs save-construct-args callback.
   */
  void CParticleTextureSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }
} // namespace moho
