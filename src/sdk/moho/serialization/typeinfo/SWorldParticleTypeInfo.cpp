#include "moho/serialization/typeinfo/SWorldParticleTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using SWorldParticleBlendModeTypeInfo = moho::SWorldParticle_BlendModeTypeInfo;
  using SWorldParticleZModeTypeInfo = moho::SWorldParticle_ZModeTypeInfo;
  using SWorldParticleTypeInfo = moho::SWorldParticleTypeInfo;

  /**
   * Address: 0x00BEFF00 (FUN_00BEFF00, atexit destructor of the SWorldParticleBlendModeTypeInfo object)
   */
  [[nodiscard]] SWorldParticleBlendModeTypeInfo& AcquireSWorldParticleBlendModeTypeInfo()
  {
    static SWorldParticleBlendModeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BEFF40 (FUN_00BEFF40, atexit destructor of the SWorldParticleZModeTypeInfo object)
   */
  [[nodiscard]] SWorldParticleZModeTypeInfo& AcquireSWorldParticleZModeTypeInfo()
  {
    static SWorldParticleZModeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BEFF80 (FUN_00BEFF80, atexit destructor of the SWorldParticleTypeInfo object)
   */
  [[nodiscard]] SWorldParticleTypeInfo& AcquireSWorldParticleTypeInfo()
  {
    static SWorldParticleTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0048F530 (FUN_0048F530, Moho::SWorldParticle_BlendModeTypeInfo::SWorldParticle_BlendModeTypeInfo)
   */
  SWorldParticle_BlendModeTypeInfo::SWorldParticle_BlendModeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(SWorldParticle::BlendMode), this);
  }

  /**
   * Address: 0x0048F5C0 (FUN_0048F5C0, Moho::SWorldParticle_BlendModeTypeInfo::~SWorldParticle_BlendModeTypeInfo)
   */
  SWorldParticle_BlendModeTypeInfo::~SWorldParticle_BlendModeTypeInfo() = default;

  /**
   * Address: 0x0048F5B0 (FUN_0048F5B0, Moho::SWorldParticle_BlendModeTypeInfo::GetName)
   */
  const char* SWorldParticle_BlendModeTypeInfo::GetName() const
  {
    return "SWorldParticle_BlendMode";
  }

  /**
   * Address: 0x0048F590 (FUN_0048F590, Moho::SWorldParticle_BlendModeTypeInfo::Init)
   */
  void SWorldParticle_BlendModeTypeInfo::Init()
  {
    size_ = sizeof(SWorldParticle::BlendMode);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC53A0 (FUN_00BC53A0, register_SWorldParticle_BlendModeTypeInfo)
   */
  void register_SWorldParticle_BlendModeTypeInfo()
  {
    (void)AcquireSWorldParticleBlendModeTypeInfo();
  }

  /**
   * Address: 0x0048F660 (FUN_0048F660, Moho::SWorldParticle_ZModeTypeInfo::SWorldParticle_ZModeTypeInfo)
   */
  SWorldParticle_ZModeTypeInfo::SWorldParticle_ZModeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(SWorldParticle::ZMode), this);
  }

  /**
   * Address: 0x0048F6F0 (FUN_0048F6F0, Moho::SWorldParticle_ZModeTypeInfo::~SWorldParticle_ZModeTypeInfo)
   */
  SWorldParticle_ZModeTypeInfo::~SWorldParticle_ZModeTypeInfo() = default;

  /**
   * Address: 0x0048F6E0 (FUN_0048F6E0, Moho::SWorldParticle_ZModeTypeInfo::GetName)
   */
  const char* SWorldParticle_ZModeTypeInfo::GetName() const
  {
    return "SWorldParticle_ZMode";
  }

  /**
   * Address: 0x0048F6C0 (FUN_0048F6C0, Moho::SWorldParticle_ZModeTypeInfo::Init)
   */
  void SWorldParticle_ZModeTypeInfo::Init()
  {
    size_ = sizeof(SWorldParticle::ZMode);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC5400 (FUN_00BC5400, register_SWorldParticle_ZModeTypeInfo)
   */
  void register_SWorldParticle_ZModeTypeInfo()
  {
    (void)AcquireSWorldParticleZModeTypeInfo();
  }

  /**
   * Address: 0x0048F790 (FUN_0048F790, Moho::SWorldParticleTypeInfo::SWorldParticleTypeInfo)
   */
  SWorldParticleTypeInfo::SWorldParticleTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SWorldParticle), this);
  }

  /**
   * Address: 0x0048F820 (FUN_0048F820, Moho::SWorldParticleTypeInfo::~SWorldParticleTypeInfo)
   */
  SWorldParticleTypeInfo::~SWorldParticleTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x0048F810 (FUN_0048F810, Moho::SWorldParticleTypeInfo::GetName)
   */
  const char* SWorldParticleTypeInfo::GetName() const
  {
    return "SWorldParticle";
  }

  /**
   * Address: 0x0048F7F0 (FUN_0048F7F0, Moho::SWorldParticleTypeInfo::Init)
   */
  void SWorldParticleTypeInfo::Init()
  {
    size_ = sizeof(SWorldParticle);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC5460 (FUN_00BC5460, register_SWorldParticleTypeInfo)
   */
  void register_SWorldParticleTypeInfo()
  {
    (void)AcquireSWorldParticleTypeInfo();
  }
} // namespace moho

namespace
{
  struct SWorldParticleTypeInfoBootstrap
  {
    SWorldParticleTypeInfoBootstrap()
    {
      moho::register_SWorldParticle_BlendModeTypeInfo();
      moho::register_SWorldParticle_ZModeTypeInfo();
      (void)moho::register_SWorldParticleTypeInfo();
    }
  };

  SWorldParticleTypeInfoBootstrap gSWorldParticleTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SWorldParticle_BlendModeTypeInfo_eb7e20, moho::register_SWorldParticle_BlendModeTypeInfo)
GPG_PREREGISTER_INIT(register_SWorldParticle_ZModeTypeInfo_eb7e20, moho::register_SWorldParticle_ZModeTypeInfo)
GPG_PREREGISTER_INIT(register_SWorldParticleTypeInfo_eb7e20, moho::register_SWorldParticleTypeInfo)
