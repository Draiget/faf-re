#include "moho/resource/CParticleTextureTypeInfo.h"

#include "moho/resource/CParticleTexture.h"

namespace moho
{
  /**
   * Address: 0x0048EE40 (FUN_0048EE40, Moho::CParticleTextureTypeInfo::dtr)
   */
  CParticleTextureTypeInfo::~CParticleTextureTypeInfo() = default;

  /**
   * Address: 0x0048EE30 (FUN_0048EE30, Moho::CParticleTextureTypeInfo::GetName)
   */
  const char* CParticleTextureTypeInfo::GetName() const
  {
    return "CParticleTexture";
  }

  /**
   * Address: 0x0048EE10 (FUN_0048EE10, Moho::CParticleTextureTypeInfo::Init)
   */
  void CParticleTextureTypeInfo::Init()
  {
    size_ = sizeof(CParticleTexture);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
