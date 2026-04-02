#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/particles/SWorldParticle.h"

namespace moho
{
  /**
   * Address: 0x0048F530 (FUN_0048F530, Moho::SWorldParticle_BlendModeTypeInfo::SWorldParticle_BlendModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflection metadata for `SWorldParticle::BlendMode`.
   */
  class SWorldParticle_BlendModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0048F530 (FUN_0048F530, Moho::SWorldParticle_BlendModeTypeInfo::SWorldParticle_BlendModeTypeInfo)
     */
    SWorldParticle_BlendModeTypeInfo();

    /**
     * Address: 0x0048F5C0 (FUN_0048F5C0, Moho::SWorldParticle_BlendModeTypeInfo::~SWorldParticle_BlendModeTypeInfo)
     */
    ~SWorldParticle_BlendModeTypeInfo() override;

    /**
     * Address: 0x0048F5B0 (FUN_0048F5B0, Moho::SWorldParticle_BlendModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048F590 (FUN_0048F590, Moho::SWorldParticle_BlendModeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SWorldParticle_BlendModeTypeInfo) == 0x78, "SWorldParticle_BlendModeTypeInfo size must be 0x78");

  /**
   * Address: 0x00BEFF00 (FUN_00BEFF00, cleanup_SWorldParticle_BlendModeTypeInfo)
   *
   * What it does:
   * Tears down the cached `SWorldParticle::BlendMode` reflection descriptor at process exit.
   */
  void cleanup_SWorldParticle_BlendModeTypeInfo();

  /**
   * Address: 0x00BC53A0 (FUN_00BC53A0, register_SWorldParticle_BlendModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the cached `SWorldParticle::BlendMode` reflection descriptor.
   */
  int register_SWorldParticle_BlendModeTypeInfo();

  /**
   * Address: 0x0048F660 (FUN_0048F660, Moho::SWorldParticle_ZModeTypeInfo::SWorldParticle_ZModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflection metadata for `SWorldParticle::ZMode`.
   */
  class SWorldParticle_ZModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0048F660 (FUN_0048F660, Moho::SWorldParticle_ZModeTypeInfo::SWorldParticle_ZModeTypeInfo)
     */
    SWorldParticle_ZModeTypeInfo();

    /**
     * Address: 0x0048F6F0 (FUN_0048F6F0, Moho::SWorldParticle_ZModeTypeInfo::~SWorldParticle_ZModeTypeInfo)
     */
    ~SWorldParticle_ZModeTypeInfo() override;

    /**
     * Address: 0x0048F6E0 (FUN_0048F6E0, Moho::SWorldParticle_ZModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048F6C0 (FUN_0048F6C0, Moho::SWorldParticle_ZModeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SWorldParticle_ZModeTypeInfo) == 0x78, "SWorldParticle_ZModeTypeInfo size must be 0x78");

  /**
   * Address: 0x00BEFF40 (FUN_00BEFF40, cleanup_SWorldParticle_ZModeTypeInfo)
   *
   * What it does:
   * Tears down the cached `SWorldParticle::ZMode` reflection descriptor at process exit.
   */
  void cleanup_SWorldParticle_ZModeTypeInfo();

  /**
   * Address: 0x00BC5400 (FUN_00BC5400, register_SWorldParticle_ZModeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the cached `SWorldParticle::ZMode` reflection descriptor.
   */
  void register_SWorldParticle_ZModeTypeInfo();

  /**
   * Address: 0x0048F790 (FUN_0048F790, Moho::SWorldParticleTypeInfo::SWorldParticleTypeInfo)
   *
   * What it does:
   * Constructs and preregisters reflection metadata for `SWorldParticle`.
   */
  class SWorldParticleTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0048F790 (FUN_0048F790, Moho::SWorldParticleTypeInfo::SWorldParticleTypeInfo)
     */
    SWorldParticleTypeInfo();

    /**
     * Address: 0x0048F820 (FUN_0048F820, Moho::SWorldParticleTypeInfo::~SWorldParticleTypeInfo)
     */
    ~SWorldParticleTypeInfo() override;

    /**
     * Address: 0x0048F810 (FUN_0048F810, Moho::SWorldParticleTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0048F7F0 (FUN_0048F7F0, Moho::SWorldParticleTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SWorldParticleTypeInfo) == 0x64, "SWorldParticleTypeInfo size must be 0x64");

  /**
   * Address: 0x00BEFF80 (FUN_00BEFF80, cleanup_SWorldParticleTypeInfo)
   *
   * What it does:
   * Tears down the cached `SWorldParticle` reflection descriptor at process exit.
   */
  void cleanup_SWorldParticleTypeInfo();

  /**
   * Address: 0x00BC5460 (FUN_00BC5460, register_SWorldParticleTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the cached `SWorldParticle` reflection descriptor.
   */
  int register_SWorldParticleTypeInfo();
} // namespace moho
