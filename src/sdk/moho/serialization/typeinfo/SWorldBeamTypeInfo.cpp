#include "moho/serialization/typeinfo/SWorldBeamTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using SWorldBeamBlendModeTypeInfo = moho::SWorldBeam_BlendModeTypeInfo;
  using SWorldBeamTypeInfo = moho::SWorldBeamTypeInfo;

  /**
   * Address: 0x00BEFE30 (FUN_00BEFE30, atexit destructor of the SWorldBeamBlendModeTypeInfo object)
   */
  [[nodiscard]] SWorldBeamBlendModeTypeInfo& AcquireSWorldBeamBlendModeTypeInfo()
  {
    static SWorldBeamBlendModeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BEFE70 (FUN_00BEFE70, atexit destructor of the SWorldBeamTypeInfo object)
   */
  [[nodiscard]] SWorldBeamTypeInfo& AcquireSWorldBeamTypeInfo()
  {
    static SWorldBeamTypeInfo sInstance;
    return sInstance;
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
   * Address: 0x00BC52E0 (FUN_00BC52E0, register_SWorldBeam_BlendModeTypeInfo)
   */
  void register_SWorldBeam_BlendModeTypeInfo()
  {
    (void)AcquireSWorldBeamBlendModeTypeInfo();
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
   * Address: 0x00BC5340 (FUN_00BC5340, register_SWorldBeamTypeInfo)
   */
  void register_SWorldBeamTypeInfo()
  {
    (void)AcquireSWorldBeamTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SWorldBeam_BlendModeTypeInfo_3b975d, moho::register_SWorldBeam_BlendModeTypeInfo)
GPG_PREREGISTER_INIT(register_SWorldBeamTypeInfo_3b975d, moho::register_SWorldBeamTypeInfo)
