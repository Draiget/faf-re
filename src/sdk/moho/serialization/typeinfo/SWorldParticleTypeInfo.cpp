#include "moho/serialization/typeinfo/SWorldParticleTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  using SWorldParticleBlendModeTypeInfo = moho::SWorldParticle_BlendModeTypeInfo;
  using SWorldParticleZModeTypeInfo = moho::SWorldParticle_ZModeTypeInfo;
  using SWorldParticleTypeInfo = moho::SWorldParticleTypeInfo;

  alignas(SWorldParticleBlendModeTypeInfo)
    unsigned char gSWorldParticleBlendModeTypeInfoStorage[sizeof(SWorldParticleBlendModeTypeInfo)];
  alignas(SWorldParticleZModeTypeInfo)
    unsigned char gSWorldParticleZModeTypeInfoStorage[sizeof(SWorldParticleZModeTypeInfo)];
  alignas(SWorldParticleTypeInfo) unsigned char gSWorldParticleTypeInfoStorage[sizeof(SWorldParticleTypeInfo)];
  bool gSWorldParticleBlendModeTypeInfoConstructed = false;
  bool gSWorldParticleZModeTypeInfoConstructed = false;
  bool gSWorldParticleTypeInfoConstructed = false;

  [[nodiscard]] SWorldParticleBlendModeTypeInfo& AcquireSWorldParticleBlendModeTypeInfo()
  {
    if (!gSWorldParticleBlendModeTypeInfoConstructed) {
      new (gSWorldParticleBlendModeTypeInfoStorage) SWorldParticleBlendModeTypeInfo();
      gSWorldParticleBlendModeTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SWorldParticleBlendModeTypeInfo*>(gSWorldParticleBlendModeTypeInfoStorage);
  }

  [[nodiscard]] SWorldParticleZModeTypeInfo& AcquireSWorldParticleZModeTypeInfo()
  {
    if (!gSWorldParticleZModeTypeInfoConstructed) {
      new (gSWorldParticleZModeTypeInfoStorage) SWorldParticleZModeTypeInfo();
      gSWorldParticleZModeTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SWorldParticleZModeTypeInfo*>(gSWorldParticleZModeTypeInfoStorage);
  }

  [[nodiscard]] SWorldParticleTypeInfo& AcquireSWorldParticleTypeInfo()
  {
    if (!gSWorldParticleTypeInfoConstructed) {
      new (gSWorldParticleTypeInfoStorage) SWorldParticleTypeInfo();
      gSWorldParticleTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SWorldParticleTypeInfo*>(gSWorldParticleTypeInfoStorage);
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
   * Address: 0x00BEFF00 (FUN_00BEFF00, cleanup_SWorldParticle_BlendModeTypeInfo)
   */
  void cleanup_SWorldParticle_BlendModeTypeInfo()
  {
    if (!gSWorldParticleBlendModeTypeInfoConstructed) {
      return;
    }

    AcquireSWorldParticleBlendModeTypeInfo().~SWorldParticle_BlendModeTypeInfo();
    gSWorldParticleBlendModeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC53A0 (FUN_00BC53A0, register_SWorldParticle_BlendModeTypeInfo)
   */
  int register_SWorldParticle_BlendModeTypeInfo()
  {
    (void)AcquireSWorldParticleBlendModeTypeInfo();
    return std::atexit(&cleanup_SWorldParticle_BlendModeTypeInfo);
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
   * Address: 0x00BEFF40 (FUN_00BEFF40, cleanup_SWorldParticle_ZModeTypeInfo)
   */
  void cleanup_SWorldParticle_ZModeTypeInfo()
  {
    if (!gSWorldParticleZModeTypeInfoConstructed) {
      return;
    }

    AcquireSWorldParticleZModeTypeInfo().~SWorldParticle_ZModeTypeInfo();
    gSWorldParticleZModeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC5400 (FUN_00BC5400, register_SWorldParticle_ZModeTypeInfo)
   */
  void register_SWorldParticle_ZModeTypeInfo()
  {
    (void)AcquireSWorldParticleZModeTypeInfo();
    (void)std::atexit(&cleanup_SWorldParticle_ZModeTypeInfo);
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
   * Address: 0x00BEFF80 (FUN_00BEFF80, cleanup_SWorldParticleTypeInfo)
   */
  void cleanup_SWorldParticleTypeInfo()
  {
    if (!gSWorldParticleTypeInfoConstructed) {
      return;
    }

    AcquireSWorldParticleTypeInfo().~SWorldParticleTypeInfo();
    gSWorldParticleTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC5460 (FUN_00BC5460, register_SWorldParticleTypeInfo)
   */
  int register_SWorldParticleTypeInfo()
  {
    (void)AcquireSWorldParticleTypeInfo();
    return std::atexit(&cleanup_SWorldParticleTypeInfo);
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
