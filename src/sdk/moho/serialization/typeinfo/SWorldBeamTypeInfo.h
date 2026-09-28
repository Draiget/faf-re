#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/particles/SWorldBeam.h"

namespace moho
{
  /**
   * Address: 0x0048F210 (FUN_0048F210, Moho::SWorldBeam_BlendModeTypeInfo::SWorldBeam_BlendModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflection metadata for `SWorldBeam::BlendMode`.
   */
  class SWorldBeam_BlendModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0048F210 (FUN_0048F210, Moho::SWorldBeam_BlendModeTypeInfo::SWorldBeam_BlendModeTypeInfo)
     */
    SWorldBeam_BlendModeTypeInfo();

    /**
     * Address: 0x0048F2A0 (FUN_0048F2A0, Moho::SWorldBeam_BlendModeTypeInfo::~SWorldBeam_BlendModeTypeInfo)
     */
    ~SWorldBeam_BlendModeTypeInfo() override;

    /**
     * Address: 0x0048F290 (FUN_0048F290, Moho::SWorldBeam_BlendModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048F270 (FUN_0048F270, Moho::SWorldBeam_BlendModeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SWorldBeam_BlendModeTypeInfo) == 0x78, "SWorldBeam_BlendModeTypeInfo size must be 0x78");

  /**
   * Address: 0x00BC52E0 (FUN_00BC52E0, register_SWorldBeam_BlendModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the cached `SWorldBeam::BlendMode` reflection descriptor.
   */
  void register_SWorldBeam_BlendModeTypeInfo();

  /**
   * Address: 0x0048F340 (FUN_0048F340, Moho::SWorldBeamTypeInfo::SWorldBeamTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflection metadata for `SWorldBeam`.
   */
  class SWorldBeamTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0048F340 (FUN_0048F340, Moho::SWorldBeamTypeInfo::SWorldBeamTypeInfo)
     */
    SWorldBeamTypeInfo();

    /**
     * Address: 0x0048F3D0 (FUN_0048F3D0, Moho::SWorldBeamTypeInfo::~SWorldBeamTypeInfo)
     */
    ~SWorldBeamTypeInfo() override;

    /**
     * Address: 0x0048F3C0 (FUN_0048F3C0, Moho::SWorldBeamTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048F3A0 (FUN_0048F3A0, Moho::SWorldBeamTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SWorldBeamTypeInfo) == 0x64, "SWorldBeamTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC5340 (FUN_00BC5340, register_SWorldBeamTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the cached `SWorldBeam` reflection descriptor.
   */
  void register_SWorldBeamTypeInfo();
} // namespace moho
