#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E10D3C
   */
  class RProjectileBlueprintDisplayTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051B9A0 (FUN_0051B9A0, Moho::RProjectileBlueprintDisplayTypeInfo::RProjectileBlueprintDisplayTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RProjectileBlueprintDisplay`.
     */
    RProjectileBlueprintDisplayTypeInfo();

    /**
     * Address: 0x0051BA30 (FUN_0051BA30, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RProjectileBlueprintDisplayTypeInfo() override;

    /**
     * Address: 0x0051BA20 (FUN_0051BA20)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051BA00 (FUN_0051BA00)
     * Slot: 9
     *
     * What it does:
     * Sets `RProjectileBlueprintDisplay` size and publishes display field
     * metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051BAD0 (FUN_0051BAD0)
     *
     * What it does:
     * Registers projectile display field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * VFTABLE: 0x00E10D6C
   */
  class RProjectileBlueprintEconomyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051BBA0 (FUN_0051BBA0, Moho::RProjectileBlueprintEconomyTypeInfo::RProjectileBlueprintEconomyTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RProjectileBlueprintEconomy`.
     */
    RProjectileBlueprintEconomyTypeInfo();

    /**
     * Address: 0x0051BC30 (FUN_0051BC30, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RProjectileBlueprintEconomyTypeInfo() override;

    /**
     * Address: 0x0051BC20 (FUN_0051BC20)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051BC00 (FUN_0051BC00)
     * Slot: 9
     *
     * What it does:
     * Sets `RProjectileBlueprintEconomy` size and publishes economy field
     * metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051BCD0 (FUN_0051BCD0)
     *
     * What it does:
     * Registers projectile economy field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * VFTABLE: 0x00E10D9C
   */
  class RProjectileBlueprintPhysicsTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051BDC0 (FUN_0051BDC0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RProjectileBlueprintPhysicsTypeInfo() override;

    /**
     * Address: 0x0051BDB0 (FUN_0051BDB0, Moho::RProjectileBlueprintPhysicsTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051BD90 (FUN_0051BD90, Moho::RProjectileBlueprintPhysicsTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `RProjectileBlueprintPhysics` size and publishes physics field
     * metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051BE60 (FUN_0051BE60, Moho::RProjectileBlueprintPhysicsTypeInfo::AddFields)
     *
     * What it does:
     * Registers projectile physics field descriptors and descriptions.
     */
    static void AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x0051BD30 (FUN_0051BD30, preregister_RProjectileBlueprintPhysicsTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup-owned type-info storage for
   * `RProjectileBlueprintPhysics`.
   */
  [[nodiscard]] gpg::RType* preregister_RProjectileBlueprintPhysicsTypeInfo();

  /**
   * Address: 0x00BC8650 (FUN_00BC8650, register_RProjectileBlueprintDisplayTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RProjectileBlueprintDisplayTypeInfo`.
   */
  int register_RProjectileBlueprintDisplayTypeInfo();

  /**
   * Address: 0x00BC8670 (FUN_00BC8670, register_RProjectileBlueprintEconomyTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RProjectileBlueprintEconomyTypeInfo`.
   */
  int register_RProjectileBlueprintEconomyTypeInfo();

  /**
   * Address: 0x00BC8690 (FUN_00BC8690, register_RProjectileBlueprintPhysicsTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RProjectileBlueprintPhysicsTypeInfo`.
   */
  int register_RProjectileBlueprintPhysicsTypeInfo();

  static_assert(
    sizeof(RProjectileBlueprintDisplayTypeInfo) == 0x64, "RProjectileBlueprintDisplayTypeInfo size must be 0x64"
  );
  static_assert(
    sizeof(RProjectileBlueprintEconomyTypeInfo) == 0x64, "RProjectileBlueprintEconomyTypeInfo size must be 0x64"
  );
  static_assert(
    sizeof(RProjectileBlueprintPhysicsTypeInfo) == 0x64, "RProjectileBlueprintPhysicsTypeInfo size must be 0x64"
  );
} // namespace moho
