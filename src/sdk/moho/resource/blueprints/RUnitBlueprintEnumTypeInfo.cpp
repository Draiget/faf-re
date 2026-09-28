#include "RUnitBlueprintEnumTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ERuleBPUnitMovementType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ERuleBPUnitMovementType@Moho@@H@gpg'`):
   * `FUN_00BC8930` (real, `__xc_a`-reachable, sole writer). Confirmed via raw
   * asm: default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_00523AB0`/`FUN_00523AD0`, installs the
   * `PrimitiveSerHelper<ERuleBPUnitMovementType,int>` vtable, and explicitly
   * registers `atexit(&sub_BF31E0)` -- confirmed bare unlink-then-self-link
   * shape matching the helper node's unlink (`gpg::DListItem::ListUnlink`). Two zero-xref duplicate
   * emissions of that unlink logic (`FUN_0051FC20`, `FUN_0051FC50`, formerly
   * `CleanupERuleBPUnitMovementTypePrimitiveSerializerNodePrimary/Secondary`)
   * are dead ICF twins (sha256-identical), never invoked.
   *
   * Previously modeled via a hand-rolled generic `EnumPrimitiveSerializer
   * <TEnum>` template mimicking `SerHelperBase` with a raw `{ mHelperNext,
   * mHelperPrev, mDeserialize, mSerialize }` layout, backed by a fabricated
   * eager `register_ERuleBPUnitMovementTypePrimitiveSerializer()` call
   * invoked a second time from this file's own
   * `RUnitBlueprintEnumTypeInfoBootstrap` constructor -- absent from the
   * real ctor's disassembly; removed.
   */
  using ERuleBPUnitMovementTypePrimitiveSerializer = gpg::PrimitiveSerHelper<moho::ERuleBPUnitMovementType, int>;

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ERuleBPUnitCommandCaps,int>
   *
   * Real ctor confirmed via `vtable_writers`
   * (`class_name='?$PrimitiveSerHelper@W4ERuleBPUnitCommandCaps@Moho@@H@gpg'`):
   * `FUN_00BC8990` (real, `__xc_a`-reachable, sole writer). Same shape as
   * `ERuleBPUnitMovementTypePrimitiveSerializer` above: binds
   * `FUN_00523B20`/`FUN_00523B40`, explicitly registers
   * `atexit(&sub_BF3220)`. Two zero-xref duplicate unlink emissions
   * (`FUN_0051FFA0`, `FUN_0051FFD0`) are dead ICF twins.
   */
  using ERuleBPUnitCommandCapsPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::ERuleBPUnitCommandCaps, int>;

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ERuleBPUnitToggleCaps,int>
   *
   * Real ctor confirmed via `vtable_writers`
   * (`class_name='?$PrimitiveSerHelper@W4ERuleBPUnitToggleCaps@Moho@@H@gpg'`):
   * `FUN_00BC89F0` (real, `__xc_a`-reachable, sole writer). Same shape as
   * `ERuleBPUnitMovementTypePrimitiveSerializer` above: binds
   * `FUN_00523B90`/`FUN_00523BB0`, explicitly registers
   * `atexit(&sub_BF3260)`. Two zero-xref duplicate unlink emissions
   * (`FUN_00520190`, `FUN_005201C0`) are dead ICF twins.
   */
  using ERuleBPUnitToggleCapsPrimitiveSerializer = gpg::PrimitiveSerHelper<moho::ERuleBPUnitToggleCaps, int>;

  // Address: 0x010AB05C -- process-global `PrimitiveSerHelper<
  // ERuleBPUnitMovementType,int>` singleton (constructed by FUN_00BC8930,
  // self-registering via `__xc_a`).
  ERuleBPUnitMovementTypePrimitiveSerializer gERuleBPUnitMovementTypePrimitiveSerializer;

  // Address: 0x010AB41C -- process-global `PrimitiveSerHelper<
  // ERuleBPUnitCommandCaps,int>` singleton (constructed by FUN_00BC8990,
  // self-registering via `__xc_a`).
  ERuleBPUnitCommandCapsPrimitiveSerializer gERuleBPUnitCommandCapsPrimitiveSerializer;

  // Address: 0x010AB1C4 -- process-global `PrimitiveSerHelper<
  // ERuleBPUnitToggleCaps,int>` singleton (constructed by FUN_00BC89F0,
  // self-registering via `__xc_a`).
  ERuleBPUnitToggleCapsPrimitiveSerializer gERuleBPUnitToggleCapsPrimitiveSerializer;

  void AddEnumEntry(gpg::REnumType* const typeInfo, const char* const token, const int value)
  {
    typeInfo->AddEnum(typeInfo->StripPrefix(token), value);
  }

  /**
   * Address: 0x00BF3290 (FUN_00BF3290, atexit destructor of the ERuleBPUnitBuildRestrictionTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitBuildRestrictionTypeInfo& GetERuleBPUnitBuildRestrictionTypeInfo()
  {
    static moho::ERuleBPUnitBuildRestrictionTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF32A0 (FUN_00BF32A0, atexit destructor of the ERuleBPUnitWeaponBallisticArcTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitWeaponBallisticArcTypeInfo& GetERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    static moho::ERuleBPUnitWeaponBallisticArcTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF32B0 (FUN_00BF32B0, atexit destructor of the ERuleBPUnitWeaponTargetTypeTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitWeaponTargetTypeTypeInfo& GetERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    static moho::ERuleBPUnitWeaponTargetTypeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF31D0 (FUN_00BF31D0, atexit destructor of the ERuleBPUnitMovementTypeTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitMovementTypeTypeInfo& GetERuleBPUnitMovementTypeTypeInfo()
  {
    static moho::ERuleBPUnitMovementTypeTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3210 (FUN_00BF3210, atexit destructor of the ERuleBPUnitCommandCapsTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitCommandCapsTypeInfo& GetERuleBPUnitCommandCapsTypeInfo()
  {
    static moho::ERuleBPUnitCommandCapsTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3250 (FUN_00BF3250, atexit destructor of the ERuleBPUnitToggleCapsTypeInfo object)
   */
  [[nodiscard]] moho::ERuleBPUnitToggleCapsTypeInfo& GetERuleBPUnitToggleCapsTypeInfo()
  {
    static moho::ERuleBPUnitToggleCapsTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3680 (FUN_00BF3680, atexit destructor of the UnitWeaponRangeCategoryTypeInfo object)
   */
  [[nodiscard]] moho::UnitWeaponRangeCategoryTypeInfo& GetUnitWeaponRangeCategoryTypeInfo()
  {
    static moho::UnitWeaponRangeCategoryTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005201F0 (FUN_005201F0, Moho::ERuleBPUnitBuildRestrictionTypeInfo::ERuleBPUnitBuildRestrictionTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitBuildRestriction` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitBuildRestrictionTypeInfo::ERuleBPUnitBuildRestrictionTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitBuildRestriction), this);
  }

  /**
   * Address: 0x00520280 (FUN_00520280, scalar deleting thunk)
   */
  ERuleBPUnitBuildRestrictionTypeInfo::~ERuleBPUnitBuildRestrictionTypeInfo() = default;

  /**
   * Address: 0x00520270 (FUN_00520270)
   */
  const char* ERuleBPUnitBuildRestrictionTypeInfo::GetName() const
  {
    return "ERuleBPUnitBuildRestriction";
  }

  /**
   * Address: 0x00520250 (FUN_00520250)
   */
  void ERuleBPUnitBuildRestrictionTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitBuildRestriction);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005202B0 (FUN_005202B0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitBuildRestriction` token/value table.
   */
  void ERuleBPUnitBuildRestrictionTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUBR_None", 0);
    AddEnumEntry(typeInfo, "RULEUBR_Bridge", 1);
    AddEnumEntry(typeInfo, "RULEUBR_OnMassDeposit", 2);
    AddEnumEntry(typeInfo, "RULEUBR_OnHydrocarbonDeposit", 3);
  }

  /**
   * Address: 0x00520310 (FUN_00520310, Moho::ERuleBPUnitWeaponBallisticArcTypeInfo::ERuleBPUnitWeaponBallisticArcTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitWeaponBallisticArc` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitWeaponBallisticArcTypeInfo::ERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitWeaponBallisticArc), this);
  }

  /**
   * Address: 0x005203A0 (FUN_005203A0, scalar deleting thunk)
   */
  ERuleBPUnitWeaponBallisticArcTypeInfo::~ERuleBPUnitWeaponBallisticArcTypeInfo() = default;

  /**
   * Address: 0x00520390 (FUN_00520390)
   */
  const char* ERuleBPUnitWeaponBallisticArcTypeInfo::GetName() const
  {
    return "ERuleBPUnitWeaponBallisticArc";
  }

  /**
   * Address: 0x00520370 (FUN_00520370)
   */
  void ERuleBPUnitWeaponBallisticArcTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitWeaponBallisticArc);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005203D0 (FUN_005203D0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitWeaponBallisticArc` token/value
   * table.
   */
  void ERuleBPUnitWeaponBallisticArcTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUBA_None", 0);
    AddEnumEntry(typeInfo, "RULEUBA_LowArc", 1);
    AddEnumEntry(typeInfo, "RULEUBA_HighArc", 2);
  }

  /**
   * Address: 0x00520420 (FUN_00520420, Moho::ERuleBPUnitWeaponTargetTypeTypeInfo::ERuleBPUnitWeaponTargetTypeTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitWeaponTargetType` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitWeaponTargetTypeTypeInfo::ERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitWeaponTargetType), this);
  }

  /**
   * Address: 0x005204B0 (FUN_005204B0, scalar deleting thunk)
   */
  ERuleBPUnitWeaponTargetTypeTypeInfo::~ERuleBPUnitWeaponTargetTypeTypeInfo() = default;

  /**
   * Address: 0x005204A0 (FUN_005204A0)
   */
  const char* ERuleBPUnitWeaponTargetTypeTypeInfo::GetName() const
  {
    return "ERuleBPUnitWeaponTargetType";
  }

  /**
   * Address: 0x00520480 (FUN_00520480)
   */
  void ERuleBPUnitWeaponTargetTypeTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitWeaponTargetType);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005204E0 (FUN_005204E0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitWeaponTargetType` token/value table.
   */
  void ERuleBPUnitWeaponTargetTypeTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEWTT_Unit", 0);
    AddEnumEntry(typeInfo, "RULEWTT_Projectile", 1);
    AddEnumEntry(typeInfo, "RULEWTT_Prop", 2);
  }

  /**
   * Address: 0x0051FA80 (FUN_0051FA80, Moho::ERuleBPUnitMovementTypeTypeInfo::ERuleBPUnitMovementTypeTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitMovementType` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitMovementTypeTypeInfo::ERuleBPUnitMovementTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitMovementType), this);
  }

  /**
   * Address: 0x0051FB10 (FUN_0051FB10, scalar deleting thunk)
   */
  ERuleBPUnitMovementTypeTypeInfo::~ERuleBPUnitMovementTypeTypeInfo() = default;

  /**
   * Address: 0x0051FB00 (FUN_0051FB00)
   */
  const char* ERuleBPUnitMovementTypeTypeInfo::GetName() const
  {
    return "ERuleBPUnitMovementType";
  }

  /**
   * Address: 0x0051FAE0 (FUN_0051FAE0)
   */
  void ERuleBPUnitMovementTypeTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitMovementType);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x0051FB40 (FUN_0051FB40)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitMovementType` token/value table.
   */
  void ERuleBPUnitMovementTypeTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUMT_None", 0);
    AddEnumEntry(typeInfo, "RULEUMT_Land", 1);
    AddEnumEntry(typeInfo, "RULEUMT_Air", 2);
    AddEnumEntry(typeInfo, "RULEUMT_Water", 3);
    AddEnumEntry(typeInfo, "RULEUMT_Biped", 4);
    AddEnumEntry(typeInfo, "RULEUMT_SurfacingSub", 5);
    AddEnumEntry(typeInfo, "RULEUMT_Amphibious", 6);
    AddEnumEntry(typeInfo, "RULEUMT_Hover", 7);
    AddEnumEntry(typeInfo, "RULEUMT_AmphibiousFloating", 8);
    AddEnumEntry(typeInfo, "RULEUMT_Special", 9);
  }

  /**
   * Address: 0x0051FC80 (FUN_0051FC80, Moho::ERuleBPUnitCommandCapsTypeInfo::ERuleBPUnitCommandCapsTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitCommandCaps` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitCommandCapsTypeInfo::ERuleBPUnitCommandCapsTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitCommandCaps), this);
  }

  /**
   * Address: 0x0051FD10 (FUN_0051FD10, scalar deleting thunk)
   */
  ERuleBPUnitCommandCapsTypeInfo::~ERuleBPUnitCommandCapsTypeInfo() = default;

  /**
   * Address: 0x0051FD00 (FUN_0051FD00)
   */
  const char* ERuleBPUnitCommandCapsTypeInfo::GetName() const
  {
    return "ERuleBPUnitCommandCaps";
  }

  /**
   * Address: 0x0051FCE0 (FUN_0051FCE0)
   */
  void ERuleBPUnitCommandCapsTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitCommandCaps);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x0051FD40 (FUN_0051FD40)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitCommandCaps` token/value table.
   */
  void ERuleBPUnitCommandCapsTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUCC_Move", 1);
    AddEnumEntry(typeInfo, "RULEUCC_Stop", 2);
    AddEnumEntry(typeInfo, "RULEUCC_Attack", 4);
    AddEnumEntry(typeInfo, "RULEUCC_Guard", 8);
    AddEnumEntry(typeInfo, "RULEUCC_Patrol", 16);
    AddEnumEntry(typeInfo, "RULEUCC_RetaliateToggle", 32);
    AddEnumEntry(typeInfo, "RULEUCC_Repair", 64);
    AddEnumEntry(typeInfo, "RULEUCC_Capture", 128);
    AddEnumEntry(typeInfo, "RULEUCC_Transport", 256);
    AddEnumEntry(typeInfo, "RULEUCC_CallTransport", 512);
    AddEnumEntry(typeInfo, "RULEUCC_Nuke", 1024);
    AddEnumEntry(typeInfo, "RULEUCC_Tactical", 2048);
    AddEnumEntry(typeInfo, "RULEUCC_Teleport", 4096);
    AddEnumEntry(typeInfo, "RULEUCC_Ferry", 0x2000);
    AddEnumEntry(typeInfo, "RULEUCC_SiloBuildTactical", 0x4000);
    AddEnumEntry(typeInfo, "RULEUCC_SiloBuildNuke", 0x8000);
    AddEnumEntry(typeInfo, "RULEUCC_Sacrifice", 0x10000);
    AddEnumEntry(typeInfo, "RULEUCC_Pause", 0x20000);
    AddEnumEntry(typeInfo, "RULEUCC_Overcharge", 0x40000);
    AddEnumEntry(typeInfo, "RULEUCC_Dive", 0x80000);
    AddEnumEntry(typeInfo, "RULEUCC_Reclaim", 0x100000);
    AddEnumEntry(typeInfo, "RULEUCC_SpecialAction", 0x200000);
    AddEnumEntry(typeInfo, "RULEUCC_Dock", 0x400000);
    AddEnumEntry(typeInfo, "RULEUCC_Script", 0x800000);
    AddEnumEntry(typeInfo, "RULEUCC_Invalid", 0x1000000);
  }

  /**
   * Address: 0x00520000 (FUN_00520000, Moho::ERuleBPUnitToggleCapsTypeInfo::ERuleBPUnitToggleCapsTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitToggleCaps` enum type descriptor and
   * preregisters RTTI.
   */
  ERuleBPUnitToggleCapsTypeInfo::ERuleBPUnitToggleCapsTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ERuleBPUnitToggleCaps), this);
  }

  /**
   * Address: 0x00520090 (FUN_00520090, scalar deleting thunk)
   */
  ERuleBPUnitToggleCapsTypeInfo::~ERuleBPUnitToggleCapsTypeInfo() = default;

  /**
   * Address: 0x00520080 (FUN_00520080)
   */
  const char* ERuleBPUnitToggleCapsTypeInfo::GetName() const
  {
    return "ERuleBPUnitToggleCaps";
  }

  /**
   * Address: 0x00520060 (FUN_00520060)
   */
  void ERuleBPUnitToggleCapsTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitToggleCaps);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005200C0 (FUN_005200C0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitToggleCaps` token/value table.
   */
  void ERuleBPUnitToggleCapsTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUTC_ShieldToggle", 1);
    AddEnumEntry(typeInfo, "RULEUTC_WeaponToggle", 2);
    AddEnumEntry(typeInfo, "RULEUTC_JammingToggle", 4);
    AddEnumEntry(typeInfo, "RULEUTC_IntelToggle", 8);
    AddEnumEntry(typeInfo, "RULEUTC_ProductionToggle", 16);
    AddEnumEntry(typeInfo, "RULEUTC_StealthToggle", 32);
    AddEnumEntry(typeInfo, "RULEUTC_GenericToggle", 64);
    AddEnumEntry(typeInfo, "RULEUTC_SpecialToggle", 128);
    AddEnumEntry(typeInfo, "RULEUTC_CloakToggle", 256);
  }

  /**
   * Address: 0x005220C0 (FUN_005220C0, Moho::UnitWeaponRangeCategoryTypeInfo::UnitWeaponRangeCategoryTypeInfo)
   *
   * What it does:
   * Constructs the `UnitWeaponRangeCategory` enum type descriptor and
   * preregisters RTTI.
   */
  UnitWeaponRangeCategoryTypeInfo::UnitWeaponRangeCategoryTypeInfo()
  {
    gpg::PreRegisterRType(typeid(UnitWeaponRangeCategory), this);
  }

  /**
   * Address: 0x00522150 (FUN_00522150, scalar deleting thunk)
   */
  UnitWeaponRangeCategoryTypeInfo::~UnitWeaponRangeCategoryTypeInfo() = default;

  /**
   * Address: 0x00522140 (FUN_00522140)
   */
  const char* UnitWeaponRangeCategoryTypeInfo::GetName() const
  {
    return "UnitWeaponRangeCategory";
  }

  /**
   * Address: 0x00522120 (FUN_00522120)
   */
  void UnitWeaponRangeCategoryTypeInfo::Init()
  {
    size_ = sizeof(UnitWeaponRangeCategory);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x00522180 (FUN_00522180)
   *
   * What it does:
   * Registers the reflected `UnitWeaponRangeCategory` token/value table.
   */
  void UnitWeaponRangeCategoryTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "UWRC_Undefined", 0);
    AddEnumEntry(typeInfo, "UWRC_DirectFire", 1);
    AddEnumEntry(typeInfo, "UWRC_IndirectFire", 2);
    AddEnumEntry(typeInfo, "UWRC_AntiAir", 3);
    AddEnumEntry(typeInfo, "UWRC_AntiNavy", 4);
    AddEnumEntry(typeInfo, "UWRC_Countermeasure", 5);
  }

  /**
   * Address: 0x00BC8A30 (FUN_00BC8A30, register_ERuleBPUnitBuildRestrictionTypeInfo)
   */
  void register_ERuleBPUnitBuildRestrictionTypeInfo()
  {
    (void)GetERuleBPUnitBuildRestrictionTypeInfo();
  }

  /**
   * Address: 0x00BC8A50 (FUN_00BC8A50, register_ERuleBPUnitWeaponBallisticArcTypeInfo)
   */
  void register_ERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    (void)GetERuleBPUnitWeaponBallisticArcTypeInfo();
  }

  /**
   * Address: 0x00BC8A70 (FUN_00BC8A70, register_ERuleBPUnitWeaponTargetTypeTypeInfo)
   */
  void register_ERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    (void)GetERuleBPUnitWeaponTargetTypeTypeInfo();
  }

  /**
   * Address: 0x00BC8910 (FUN_00BC8910, register_ERuleBPUnitMovementTypeTypeInfo)
   */
  void register_ERuleBPUnitMovementTypeTypeInfo()
  {
    (void)GetERuleBPUnitMovementTypeTypeInfo();
  }

  /**
   * Address: 0x00BC8970 (FUN_00BC8970, register_ERuleBPUnitCommandCapsTypeInfo)
   */
  void register_ERuleBPUnitCommandCapsTypeInfo()
  {
    (void)GetERuleBPUnitCommandCapsTypeInfo();
  }

  /**
   * Address: 0x00BC89D0 (FUN_00BC89D0, register_ERuleBPUnitToggleCapsTypeInfo)
   */
  void register_ERuleBPUnitToggleCapsTypeInfo()
  {
    (void)GetERuleBPUnitToggleCapsTypeInfo();
  }

  /**
   * Address: 0x00BC8BD0 (FUN_00BC8BD0, register_UnitWeaponRangeCategoryTypeInfo)
   */
  void register_UnitWeaponRangeCategoryTypeInfo()
  {
    (void)GetUnitWeaponRangeCategoryTypeInfo();
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintEnumTypeInfoBootstrap
  {
    RUnitBlueprintEnumTypeInfoBootstrap()
    {
      moho::register_ERuleBPUnitBuildRestrictionTypeInfo();
      moho::register_ERuleBPUnitWeaponBallisticArcTypeInfo();
      moho::register_ERuleBPUnitWeaponTargetTypeTypeInfo();
      moho::register_ERuleBPUnitMovementTypeTypeInfo();
      moho::register_ERuleBPUnitCommandCapsTypeInfo();
      moho::register_ERuleBPUnitToggleCapsTypeInfo();
      moho::register_UnitWeaponRangeCategoryTypeInfo();
    }
  };

  RUnitBlueprintEnumTypeInfoBootstrap gRUnitBlueprintEnumTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ERuleBPUnitBuildRestrictionTypeInfo_8d2279, moho::register_ERuleBPUnitBuildRestrictionTypeInfo)
GPG_PREREGISTER_INIT(register_ERuleBPUnitWeaponBallisticArcTypeInfo_8d2279, moho::register_ERuleBPUnitWeaponBallisticArcTypeInfo)
GPG_PREREGISTER_INIT(register_ERuleBPUnitWeaponTargetTypeTypeInfo_8d2279, moho::register_ERuleBPUnitWeaponTargetTypeTypeInfo)
GPG_PREREGISTER_INIT(register_ERuleBPUnitMovementTypeTypeInfo_8d2279, moho::register_ERuleBPUnitMovementTypeTypeInfo)
GPG_PREREGISTER_INIT(register_ERuleBPUnitCommandCapsTypeInfo_8d2279, moho::register_ERuleBPUnitCommandCapsTypeInfo)
GPG_PREREGISTER_INIT(register_ERuleBPUnitToggleCapsTypeInfo_8d2279, moho::register_ERuleBPUnitToggleCapsTypeInfo)
GPG_PREREGISTER_INIT(register_UnitWeaponRangeCategoryTypeInfo_8d2279, moho::register_UnitWeaponRangeCategoryTypeInfo)
