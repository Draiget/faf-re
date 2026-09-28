#include "moho/resource/CParticleTextureTypeInfo.h"

#include <typeinfo>

#include "moho/resource/CParticleTexture.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CParticleTextureTypeInfo;

  /**
   * Address: 0x00BEFD70 (FUN_00BEFD70, atexit destructor of the CParticleTextureTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireCParticleTextureTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  struct CParticleTextureTypeInfoBootstrap
  {
    CParticleTextureTypeInfoBootstrap()
    {
      moho::register_CParticleTextureTypeInfo();
    }
  };

  CParticleTextureTypeInfoBootstrap gCParticleTextureTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0048EDB0 (FUN_0048EDB0, Moho::CParticleTextureTypeInfo::CParticleTextureTypeInfo)
   */
  CParticleTextureTypeInfo::CParticleTextureTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CParticleTexture), this);
  }

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

  /**
   * Address: 0x00BC5250 (FUN_00BC5250, register_CParticleTextureTypeInfo)
   */
  void register_CParticleTextureTypeInfo()
  {
    (void)AcquireCParticleTextureTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CParticleTextureTypeInfo_88240b, moho::register_CParticleTextureTypeInfo)
