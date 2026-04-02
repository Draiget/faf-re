#include "moho/serialization/typeinfo/SWorldBeamTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  using SWorldBeamBlendModeTypeInfo = moho::SWorldBeam_BlendModeTypeInfo;
  using SWorldBeamTypeInfo = moho::SWorldBeamTypeInfo;

  alignas(SWorldBeamBlendModeTypeInfo)
    unsigned char gSWorldBeamBlendModeTypeInfoStorage[sizeof(SWorldBeamBlendModeTypeInfo)];
  alignas(SWorldBeamTypeInfo) unsigned char gSWorldBeamTypeInfoStorage[sizeof(SWorldBeamTypeInfo)];
  bool gSWorldBeamBlendModeTypeInfoConstructed = false;
  bool gSWorldBeamTypeInfoConstructed = false;

  [[nodiscard]] SWorldBeamBlendModeTypeInfo& AcquireSWorldBeamBlendModeTypeInfo()
  {
    if (!gSWorldBeamBlendModeTypeInfoConstructed) {
      new (gSWorldBeamBlendModeTypeInfoStorage) SWorldBeamBlendModeTypeInfo();
      gSWorldBeamBlendModeTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SWorldBeamBlendModeTypeInfo*>(gSWorldBeamBlendModeTypeInfoStorage);
  }

  [[nodiscard]] SWorldBeamTypeInfo& AcquireSWorldBeamTypeInfo()
  {
    if (!gSWorldBeamTypeInfoConstructed) {
      new (gSWorldBeamTypeInfoStorage) SWorldBeamTypeInfo();
      gSWorldBeamTypeInfoConstructed = true;
    }

    return *reinterpret_cast<SWorldBeamTypeInfo*>(gSWorldBeamTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0048F210 (FUN_0048F210, Moho::SWorldBeam_BlendModeTypeInfo::SWorldBeam_BlendModeTypeInfo)
   */
  SWorldBeam_BlendModeTypeInfo::SWorldBeam_BlendModeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(SWorldBeam::BlendMode), this);
  }

  /**
   * Address: 0x0048F2A0 (FUN_0048F2A0, Moho::SWorldBeam_BlendModeTypeInfo::~SWorldBeam_BlendModeTypeInfo)
   */
  SWorldBeam_BlendModeTypeInfo::~SWorldBeam_BlendModeTypeInfo() = default;

  /**
   * Address: 0x0048F290 (FUN_0048F290, Moho::SWorldBeam_BlendModeTypeInfo::GetName)
   */
  const char* SWorldBeam_BlendModeTypeInfo::GetName() const
  {
    return "SWorldBeam_BlendMode";
  }

  /**
   * Address: 0x0048F270 (FUN_0048F270, Moho::SWorldBeam_BlendModeTypeInfo::Init)
   */
  void SWorldBeam_BlendModeTypeInfo::Init()
  {
    size_ = sizeof(SWorldBeam::BlendMode);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BEFE30 (FUN_00BEFE30, cleanup_SWorldBeam_BlendModeTypeInfo)
   */
  void cleanup_SWorldBeam_BlendModeTypeInfo()
  {
    if (!gSWorldBeamBlendModeTypeInfoConstructed) {
      return;
    }

    AcquireSWorldBeamBlendModeTypeInfo().~SWorldBeam_BlendModeTypeInfo();
    gSWorldBeamBlendModeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC52E0 (FUN_00BC52E0, register_SWorldBeam_BlendModeTypeInfo)
   */
  void register_SWorldBeam_BlendModeTypeInfo()
  {
    (void)AcquireSWorldBeamBlendModeTypeInfo();
    (void)std::atexit(&cleanup_SWorldBeam_BlendModeTypeInfo);
  }

  /**
   * Address: 0x0048F340 (FUN_0048F340, Moho::SWorldBeamTypeInfo::SWorldBeamTypeInfo)
   */
  SWorldBeamTypeInfo::SWorldBeamTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SWorldBeam), this);
  }

  /**
   * Address: 0x0048F3D0 (FUN_0048F3D0, Moho::SWorldBeamTypeInfo::~SWorldBeamTypeInfo)
   */
  SWorldBeamTypeInfo::~SWorldBeamTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x0048F3C0 (FUN_0048F3C0, Moho::SWorldBeamTypeInfo::GetName)
   */
  const char* SWorldBeamTypeInfo::GetName() const
  {
    return "SWorldBeam";
  }

  /**
   * Address: 0x0048F3A0 (FUN_0048F3A0, Moho::SWorldBeamTypeInfo::Init)
   */
  void SWorldBeamTypeInfo::Init()
  {
    size_ = sizeof(SWorldBeam);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BEFE70 (FUN_00BEFE70, cleanup_SWorldBeamTypeInfo)
   */
  void cleanup_SWorldBeamTypeInfo()
  {
    if (!gSWorldBeamTypeInfoConstructed) {
      return;
    }

    AcquireSWorldBeamTypeInfo().~SWorldBeamTypeInfo();
    gSWorldBeamTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC5340 (FUN_00BC5340, register_SWorldBeamTypeInfo)
   */
  int register_SWorldBeamTypeInfo()
  {
    (void)AcquireSWorldBeamTypeInfo();
    return std::atexit(&cleanup_SWorldBeamTypeInfo);
  }
} // namespace moho

namespace
{
  struct SWorldBeamTypeInfoBootstrap
  {
    SWorldBeamTypeInfoBootstrap()
    {
      moho::register_SWorldBeam_BlendModeTypeInfo();
      (void)moho::register_SWorldBeamTypeInfo();
    }
  };

  SWorldBeamTypeInfoBootstrap gSWorldBeamTypeInfoBootstrap;
} // namespace
