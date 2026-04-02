#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace moho
{
  /**
   * Address: 0x005201F0 (FUN_005201F0)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitBuildRestriction`.
   */
  class ERuleBPUnitBuildRestrictionTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00520280 (FUN_00520280, scalar deleting thunk)
     */
    ~ERuleBPUnitBuildRestrictionTypeInfo() override;

    /**
     * Address: 0x00520270 (FUN_00520270)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520250 (FUN_00520250)
     */
    void Init() override;

  private:
    /**
     * Address: 0x005202B0 (FUN_005202B0)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitBuildRestriction` token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(
    sizeof(ERuleBPUnitBuildRestrictionTypeInfo) == 0x78, "ERuleBPUnitBuildRestrictionTypeInfo size must be 0x78"
  );

  /**
   * Address: 0x00520310 (FUN_00520310)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitWeaponBallisticArc`.
   */
  class ERuleBPUnitWeaponBallisticArcTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005203A0 (FUN_005203A0, scalar deleting thunk)
     */
    ~ERuleBPUnitWeaponBallisticArcTypeInfo() override;

    /**
     * Address: 0x00520390 (FUN_00520390)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520370 (FUN_00520370)
     */
    void Init() override;

  private:
    /**
     * Address: 0x005203D0 (FUN_005203D0)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitWeaponBallisticArc`
     * token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(
    sizeof(ERuleBPUnitWeaponBallisticArcTypeInfo) == 0x78, "ERuleBPUnitWeaponBallisticArcTypeInfo size must be 0x78"
  );

  /**
   * Address: 0x00520420 (FUN_00520420)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitWeaponTargetType`.
   */
  class ERuleBPUnitWeaponTargetTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005204B0 (FUN_005204B0, scalar deleting thunk)
     */
    ~ERuleBPUnitWeaponTargetTypeTypeInfo() override;

    /**
     * Address: 0x005204A0 (FUN_005204A0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520480 (FUN_00520480)
     */
    void Init() override;

  private:
    /**
     * Address: 0x005204E0 (FUN_005204E0)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitWeaponTargetType` token/value
     * table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(
    sizeof(ERuleBPUnitWeaponTargetTypeTypeInfo) == 0x78, "ERuleBPUnitWeaponTargetTypeTypeInfo size must be 0x78"
  );

  /**
   * Address: 0x0051FA80 (FUN_0051FA80)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitMovementType`.
   */
  class ERuleBPUnitMovementTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0051FB10 (FUN_0051FB10, scalar deleting thunk)
     */
    ~ERuleBPUnitMovementTypeTypeInfo() override;

    /**
     * Address: 0x0051FB00 (FUN_0051FB00)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051FAE0 (FUN_0051FAE0)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051FB40 (FUN_0051FB40)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitMovementType` token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(ERuleBPUnitMovementTypeTypeInfo) == 0x78, "ERuleBPUnitMovementTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x0051FC80 (FUN_0051FC80)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitCommandCaps`.
   */
  class ERuleBPUnitCommandCapsTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0051FD10 (FUN_0051FD10, scalar deleting thunk)
     */
    ~ERuleBPUnitCommandCapsTypeInfo() override;

    /**
     * Address: 0x0051FD00 (FUN_0051FD00)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051FCE0 (FUN_0051FCE0)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051FD40 (FUN_0051FD40)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitCommandCaps` token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(ERuleBPUnitCommandCapsTypeInfo) == 0x78, "ERuleBPUnitCommandCapsTypeInfo size must be 0x78");

  /**
   * Address: 0x00520000 (FUN_00520000)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ERuleBPUnitToggleCaps`.
   */
  class ERuleBPUnitToggleCapsTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00520090 (FUN_00520090, scalar deleting thunk)
     */
    ~ERuleBPUnitToggleCapsTypeInfo() override;

    /**
     * Address: 0x00520080 (FUN_00520080)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00520060 (FUN_00520060)
     */
    void Init() override;

  private:
    /**
     * Address: 0x005200C0 (FUN_005200C0)
     *
     * What it does:
     * Registers the reflected `ERuleBPUnitToggleCaps` token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(ERuleBPUnitToggleCapsTypeInfo) == 0x78, "ERuleBPUnitToggleCapsTypeInfo size must be 0x78");

  /**
   * Address: 0x005220C0 (FUN_005220C0)
   *
   * What it does:
   * Owns the reflected enum descriptor for `UnitWeaponRangeCategory`.
   */
  class UnitWeaponRangeCategoryTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00522150 (FUN_00522150, scalar deleting thunk)
     */
    ~UnitWeaponRangeCategoryTypeInfo() override;

    /**
     * Address: 0x00522140 (FUN_00522140)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00522120 (FUN_00522120)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00522180 (FUN_00522180)
     *
     * What it does:
     * Registers the reflected `UnitWeaponRangeCategory` token/value table.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(UnitWeaponRangeCategoryTypeInfo) == 0x78, "UnitWeaponRangeCategoryTypeInfo size must be 0x78");

  /**
   * Address: 0x005201F0 (FUN_005201F0, construct_ERuleBPUnitBuildRestrictionTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitBuildRestriction`.
   */
  gpg::REnumType* construct_ERuleBPUnitBuildRestrictionTypeInfo();

  /**
   * Address: 0x00520310 (FUN_00520310, construct_ERuleBPUnitWeaponBallisticArcTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitWeaponBallisticArc`.
   */
  gpg::REnumType* construct_ERuleBPUnitWeaponBallisticArcTypeInfo();

  /**
   * Address: 0x00520420 (FUN_00520420, construct_ERuleBPUnitWeaponTargetTypeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitWeaponTargetType`.
   */
  gpg::REnumType* construct_ERuleBPUnitWeaponTargetTypeTypeInfo();

  /**
   * Address: 0x0051FA80 (FUN_0051FA80, construct_ERuleBPUnitMovementTypeTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitMovementType`.
   */
  gpg::REnumType* construct_ERuleBPUnitMovementTypeTypeInfo();

  /**
   * Address: 0x0051FC80 (FUN_0051FC80, construct_ERuleBPUnitCommandCapsTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitCommandCaps`.
   */
  gpg::REnumType* construct_ERuleBPUnitCommandCapsTypeInfo();

  /**
   * Address: 0x00520000 (FUN_00520000, construct_ERuleBPUnitToggleCapsTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `ERuleBPUnitToggleCaps`.
   */
  gpg::REnumType* construct_ERuleBPUnitToggleCapsTypeInfo();

  /**
   * Address: 0x005220C0 (FUN_005220C0, construct_UnitWeaponRangeCategoryTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the reflected enum descriptor for
   * `UnitWeaponRangeCategory`.
   */
  gpg::REnumType* construct_UnitWeaponRangeCategoryTypeInfo();

  /**
   * Address: 0x00BC8A30 (FUN_00BC8A30, register_ERuleBPUnitBuildRestrictionTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitBuildRestrictionTypeInfo` and
   * installs process-exit cleanup.
   */
  int register_ERuleBPUnitBuildRestrictionTypeInfo();

  /**
   * Address: 0x00BC8A50 (FUN_00BC8A50, register_ERuleBPUnitWeaponBallisticArcTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitWeaponBallisticArcTypeInfo` and
   * installs process-exit cleanup.
   */
  int register_ERuleBPUnitWeaponBallisticArcTypeInfo();

  /**
   * Address: 0x00BC8A70 (FUN_00BC8A70, register_ERuleBPUnitWeaponTargetTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitWeaponTargetTypeTypeInfo` and
   * installs process-exit cleanup.
   */
  int register_ERuleBPUnitWeaponTargetTypeTypeInfo();

  /**
   * Address: 0x00BC8910 (FUN_00BC8910, register_ERuleBPUnitMovementTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitMovementTypeTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_ERuleBPUnitMovementTypeTypeInfo();

  /**
   * Address: 0x00BC8930 (FUN_00BC8930, register_ERuleBPUnitMovementTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `ERuleBPUnitMovementType`
   * and installs process-exit helper unlink cleanup.
   */
  int register_ERuleBPUnitMovementTypePrimitiveSerializer();

  /**
   * Address: 0x00BC8970 (FUN_00BC8970, register_ERuleBPUnitCommandCapsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitCommandCapsTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_ERuleBPUnitCommandCapsTypeInfo();

  /**
   * Address: 0x00BC8990 (FUN_00BC8990, register_ERuleBPUnitCommandCapsPrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `ERuleBPUnitCommandCaps`
   * and installs process-exit helper unlink cleanup.
   */
  int register_ERuleBPUnitCommandCapsPrimitiveSerializer();

  /**
   * Address: 0x00BC89D0 (FUN_00BC89D0, register_ERuleBPUnitToggleCapsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ERuleBPUnitToggleCapsTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_ERuleBPUnitToggleCapsTypeInfo();

  /**
   * Address: 0x00BC89F0 (FUN_00BC89F0, register_ERuleBPUnitToggleCapsPrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `ERuleBPUnitToggleCaps`
   * and installs process-exit helper unlink cleanup.
   */
  int register_ERuleBPUnitToggleCapsPrimitiveSerializer();

  /**
   * Address: 0x00BC8BD0 (FUN_00BC8BD0, register_UnitWeaponRangeCategoryTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `UnitWeaponRangeCategoryTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_UnitWeaponRangeCategoryTypeInfo();
} // namespace moho
