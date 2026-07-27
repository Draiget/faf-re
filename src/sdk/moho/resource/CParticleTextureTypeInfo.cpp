#include "moho/resource/CParticleTextureTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/CParticleTexture.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CParticleTextureTypeInfo;

  alignas(TypeInfo) unsigned char gCParticleTextureTypeInfoStorage[sizeof(TypeInfo)];
  bool gCParticleTextureTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireCParticleTextureTypeInfo()
  {
    if (!gCParticleTextureTypeInfoConstructed) {
      new (gCParticleTextureTypeInfoStorage) TypeInfo();
      gCParticleTextureTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCParticleTextureTypeInfoStorage);
  }

  void cleanup_CParticleTextureTypeInfo_00BEFD70_Impl()
  {
    if (!gCParticleTextureTypeInfoConstructed) {
      return;
    }

    AcquireCParticleTextureTypeInfo().~TypeInfo();
    gCParticleTextureTypeInfoConstructed = false;
  }

  int register_CParticleTextureTypeInfo_00BC5250_Impl()
  {
    (void)AcquireCParticleTextureTypeInfo();
    return std::atexit(&cleanup_CParticleTextureTypeInfo_00BEFD70_Impl);
  }

  struct CParticleTextureTypeInfoBootstrap
  {
    CParticleTextureTypeInfoBootstrap()
    {
      (void)moho::register_CParticleTextureTypeInfo();
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
  int register_CParticleTextureTypeInfo()
  {
    return register_CParticleTextureTypeInfo_00BC5250_Impl();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CParticleTextureTypeInfo_88240b, moho::register_CParticleTextureTypeInfo)
