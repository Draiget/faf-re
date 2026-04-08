#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class RUnitBlueprintGeneralTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00520530 (FUN_00520530, Moho::RUnitBlueprintGeneralTypeInfo::RUnitBlueprintGeneralTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintGeneral`.
     */
    RUnitBlueprintGeneralTypeInfo();

    /**
     * Address: 0x005205C0 (FUN_005205C0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintGeneralTypeInfo() override;

    /**
     * Address: 0x005205B0 (FUN_005205B0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520590 (FUN_00520590)
     *
     * What it does:
     * Sets `RUnitBlueprintGeneral` size and publishes general field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00520660 (FUN_00520660)
     *
     * What it does:
     * Registers `RUnitBlueprintGeneral` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x005252A0 (FUN_005252A0, gpg::RType::AddField_ERuleBPUnitCommandCaps_0x0CommandCaps)
     *
     * What it does:
     * Appends the `CommandCaps` reflected field entry (`+0x00`).
     */
    static gpg::RField* AddFieldCommandCaps(gpg::RType* typeInfo);

    /**
     * Address: 0x00525320 (FUN_00525320, gpg::RType::AddField_ERuleBPUnitToggleCaps_0x4ToggleCaps)
     *
     * What it does:
     * Appends the `ToggleCaps` reflected field entry (`+0x04`).
     */
    static gpg::RField* AddFieldToggleCaps(gpg::RType* typeInfo);
  };

  class RUnitBlueprintDisplayTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00520730 (FUN_00520730, Moho::RUnitBlueprintDisplayTypeInfo::RUnitBlueprintDisplayTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintDisplay`.
     */
    RUnitBlueprintDisplayTypeInfo();

    /**
     * Address: 0x005207C0 (FUN_005207C0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintDisplayTypeInfo() override;

    /**
     * Address: 0x005207B0 (FUN_005207B0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520790 (FUN_00520790)
     *
     * What it does:
     * Sets `RUnitBlueprintDisplay` size and publishes display field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00520860 (FUN_00520860)
     *
     * What it does:
     * Registers `RUnitBlueprintDisplay` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class RUnitBlueprintPhysicsTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00520910 (FUN_00520910, Moho::RUnitBlueprintPhysicsTypeInfo::RUnitBlueprintPhysicsTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintPhysics`.
     */
    RUnitBlueprintPhysicsTypeInfo();

    /**
     * Address: 0x005209A0 (FUN_005209A0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintPhysicsTypeInfo() override;

    /**
     * Address: 0x00520990 (FUN_00520990)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520970 (FUN_00520970)
     *
     * What it does:
     * Sets `RUnitBlueprintPhysics` size and publishes physics field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00520A40 (FUN_00520A40)
     *
     * What it does:
     * Registers `RUnitBlueprintPhysics` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x00525420 (FUN_00525420, gpg::RType::AddField_ELayer_0x7CBuildOnLayerCaps)
     *
     * What it does:
     * Appends the `BuildOnLayerCaps` reflected field entry (`+0x7C`).
     */
    static gpg::RField* AddFieldBuildOnLayerCaps(gpg::RType* typeInfo);

    /**
     * Address: 0x005253A0 (FUN_005253A0, gpg::RType::AddField_ERuleBPUnitMovementType)
     *
     * What it does:
     * Appends an `ERuleBPUnitMovementType` reflected field entry.
     */
    static gpg::RField* AddFieldMovementType(gpg::RType* typeInfo, const char* fieldName, int offset);

    /**
     * Address: 0x005254A0 (FUN_005254A0, gpg::RType::AddField_ERuleBPUnitBuildRestriction_0x80BuildRestriction)
     *
     * What it does:
     * Appends the `BuildRestriction` reflected field entry (`+0x80`).
     */
    static gpg::RField* AddFieldBuildRestriction(gpg::RType* typeInfo);

    /**
     * Address: 0x00525520 (FUN_00525520, gpg::RType::AddField_vector_float)
     *
     * What it does:
     * Appends a `vector<float>` reflected field entry.
     */
    static gpg::RField* AddFieldVectorFloat(gpg::RType* typeInfo, const char* fieldName, int offset);
  };

  class RUnitBlueprintAirTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00520E10 (FUN_00520E10, Moho::RUnitBlueprintAirTypeInfo::RUnitBlueprintAirTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintAir`.
     */
    RUnitBlueprintAirTypeInfo();

    /**
     * Address: 0x00520EA0 (FUN_00520EA0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintAirTypeInfo() override;

    /**
     * Address: 0x00520E90 (FUN_00520E90)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520E70 (FUN_00520E70)
     *
     * What it does:
     * Sets `RUnitBlueprintAir` size and publishes air field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00520F40 (FUN_00520F40)
     *
     * What it does:
     * Registers `RUnitBlueprintAir` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class RUnitBlueprintTransportTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00521300 (FUN_00521300, Moho::RUnitBlueprintTransportTypeInfo::RUnitBlueprintTransportTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintTransport`.
     */
    RUnitBlueprintTransportTypeInfo();

    /**
     * Address: 0x00521390 (FUN_00521390, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintTransportTypeInfo() override;

    /**
     * Address: 0x00521380 (FUN_00521380)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00521360 (FUN_00521360)
     *
     * What it does:
     * Sets `RUnitBlueprintTransport` size and publishes transport field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00521430 (FUN_00521430)
     *
     * What it does:
     * Registers `RUnitBlueprintTransport` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class RUnitBlueprintAITypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00521530 (FUN_00521530, Moho::RUnitBlueprintAITypeInfo::RUnitBlueprintAITypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintAI`.
     */
    RUnitBlueprintAITypeInfo();

    /**
     * Address: 0x005215C0 (FUN_005215C0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintAITypeInfo() override;

    /**
     * Address: 0x005215B0 (FUN_005215B0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00521590 (FUN_00521590)
     *
     * What it does:
     * Sets `RUnitBlueprintAI` size and publishes AI field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00521660 (FUN_00521660)
     *
     * What it does:
     * Registers `RUnitBlueprintAI` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class RUnitBlueprintDefenseTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00521980 (FUN_00521980, Moho::RUnitBlueprintDefenseTypeInfo::RUnitBlueprintDefenseTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintDefense`.
     */
    RUnitBlueprintDefenseTypeInfo();

    /**
     * Address: 0x00521A10 (FUN_00521A10, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintDefenseTypeInfo() override;

    /**
     * Address: 0x00521A00 (FUN_00521A00)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005219E0 (FUN_005219E0)
     *
     * What it does:
     * Sets `RUnitBlueprintDefense` size and publishes defense field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00521AB0 (FUN_00521AB0)
     *
     * What it does:
     * Registers `RUnitBlueprintDefense` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x005255A0 (FUN_005255A0, gpg::RType::AddField_RUnitBlueprintDefenseShield_0x38Shield)
     *
     * What it does:
     * Appends the `Shield` reflected field entry (`+0x38`).
     */
    static gpg::RField* AddFieldShield(gpg::RType* typeInfo);
  };

  class RUnitBlueprintIntelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00521B80 (FUN_00521B80, Moho::RUnitBlueprintIntelTypeInfo::RUnitBlueprintIntelTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintIntel`.
     */
    RUnitBlueprintIntelTypeInfo();

    /**
     * Address: 0x00521C10 (FUN_00521C10, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintIntelTypeInfo() override;

    /**
     * Address: 0x00521C00 (FUN_00521C00)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00521BE0 (FUN_00521BE0)
     *
     * What it does:
     * Sets `RUnitBlueprintIntel` size and publishes intel field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00521CB0 (FUN_00521CB0)
     *
     * What it does:
     * Registers `RUnitBlueprintIntel` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x00525620 (FUN_00525620, gpg::RType::AddFieldSMinMaxUint)
     *
     * What it does:
     * Appends an `SMinMax<uint32_t>` reflected field entry.
     */
    static gpg::RField* AddFieldSMinMaxUInt(gpg::RType* typeInfo, const char* fieldName, int offset);
  };

  class RUnitBlueprintEconomyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00521E10 (FUN_00521E10, Moho::RUnitBlueprintEconomyTypeInfo::RUnitBlueprintEconomyTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintEconomy`.
     */
    RUnitBlueprintEconomyTypeInfo();

    /**
     * Address: 0x00521EA0 (FUN_00521EA0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintEconomyTypeInfo() override;

    /**
     * Address: 0x00521E90 (FUN_00521E90)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00521E70 (FUN_00521E70)
     *
     * What it does:
     * Sets `RUnitBlueprintEconomy` size and publishes economy field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00521F40 (FUN_00521F40)
     *
     * What it does:
     * Registers `RUnitBlueprintEconomy` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  class RUnitBlueprintWeaponTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00522210 (FUN_00522210, Moho::RUnitBlueprintWeaponTypeInfo::RUnitBlueprintWeaponTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RUnitBlueprintWeapon`.
     */
    RUnitBlueprintWeaponTypeInfo();

    /**
     * Address: 0x005222A0 (FUN_005222A0, scalar deleting destructor thunk)
     */
    ~RUnitBlueprintWeaponTypeInfo() override;

    /**
     * Address: 0x00522290 (FUN_00522290)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00522270 (FUN_00522270)
     *
     * What it does:
     * Sets `RUnitBlueprintWeapon` size and publishes weapon field metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00522340 (FUN_00522340)
     *
     * What it does:
     * Registers `RUnitBlueprintWeapon` field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x005256A0 (FUN_005256A0, gpg::RType::AddField_UnitWeaponRangeCategory_0x40RangeCategory)
     *
     * What it does:
     * Appends the `RangeCategory` reflected field entry (`+0x40`).
     */
    static gpg::RField* AddFieldRangeCategory(gpg::RType* typeInfo);

    /**
     * Address: 0x00525720 (FUN_00525720, gpg::RType::AddField_ERuleBPUnitWeaponBallisticArc_0xE4BallisticArc)
     *
     * What it does:
     * Appends the `BallisticArc` reflected field entry (`+0xE4`).
     */
    static gpg::RField* AddFieldBallisticArc(gpg::RType* typeInfo);

    /**
     * Address: 0x005257A0 (FUN_005257A0, gpg::RType::AddField_ERuleBPUnitWeaponTargetType_0x130TargetType)
     *
     * What it does:
     * Appends the `TargetType` reflected field entry (`+0x130`).
     */
    static gpg::RField* AddFieldTargetType(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8A90 (FUN_00BC8A90, register_RUnitBlueprintGeneralTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintGeneralTypeInfo`.
   */
  int register_RUnitBlueprintGeneralTypeInfo();

  /**
   * Address: 0x00BC8AB0 (FUN_00BC8AB0, register_RUnitBlueprintDisplayTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintDisplayTypeInfo`.
   */
  int register_RUnitBlueprintDisplayTypeInfo();

  /**
   * Address: 0x00BC8AD0 (FUN_00BC8AD0, register_RUnitBlueprintPhysicsTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintPhysicsTypeInfo`.
   */
  int register_RUnitBlueprintPhysicsTypeInfo();

  /**
   * Address: 0x00BC8AF0 (FUN_00BC8AF0, register_RUnitBlueprintAirTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintAirTypeInfo`.
   */
  int register_RUnitBlueprintAirTypeInfo();

  /**
   * Address: 0x00BC8B10 (FUN_00BC8B10, register_RUnitBlueprintTransportTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintTransportTypeInfo`.
   */
  int register_RUnitBlueprintTransportTypeInfo();

  /**
   * Address: 0x00BC8B30 (FUN_00BC8B30, register_RUnitBlueprintAITypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintAITypeInfo`.
   */
  int register_RUnitBlueprintAITypeInfo();

  /**
   * Address: 0x00BC8B70 (FUN_00BC8B70, register_RUnitBlueprintDefenseTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintDefenseTypeInfo`.
   */
  int register_RUnitBlueprintDefenseTypeInfo();

  /**
   * Address: 0x00BC8B90 (FUN_00BC8B90, register_RUnitBlueprintIntelTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintIntelTypeInfo`.
   */
  int register_RUnitBlueprintIntelTypeInfo();

  /**
   * Address: 0x00BC8BB0 (FUN_00BC8BB0, register_RUnitBlueprintEconomyTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintEconomyTypeInfo`.
   */
  int register_RUnitBlueprintEconomyTypeInfo();

  /**
   * Address: 0x00BC8BF0 (FUN_00BC8BF0, register_RUnitBlueprintWeaponTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RUnitBlueprintWeaponTypeInfo`.
   */
  int register_RUnitBlueprintWeaponTypeInfo();

  static_assert(sizeof(RUnitBlueprintGeneralTypeInfo) == 0x64, "RUnitBlueprintGeneralTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintDisplayTypeInfo) == 0x64, "RUnitBlueprintDisplayTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintPhysicsTypeInfo) == 0x64, "RUnitBlueprintPhysicsTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintAirTypeInfo) == 0x64, "RUnitBlueprintAirTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintTransportTypeInfo) == 0x64, "RUnitBlueprintTransportTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintAITypeInfo) == 0x64, "RUnitBlueprintAITypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintDefenseTypeInfo) == 0x64, "RUnitBlueprintDefenseTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintIntelTypeInfo) == 0x64, "RUnitBlueprintIntelTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintEconomyTypeInfo) == 0x64, "RUnitBlueprintEconomyTypeInfo size must be 0x64");
  static_assert(sizeof(RUnitBlueprintWeaponTypeInfo) == 0x64, "RUnitBlueprintWeaponTypeInfo size must be 0x64");
} // namespace moho
