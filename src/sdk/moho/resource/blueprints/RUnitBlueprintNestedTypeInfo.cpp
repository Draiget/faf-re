#include "RUnitBlueprintNestedTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  using GeneralTypeInfo = moho::RUnitBlueprintGeneralTypeInfo;
  using DisplayTypeInfo = moho::RUnitBlueprintDisplayTypeInfo;
  using PhysicsTypeInfo = moho::RUnitBlueprintPhysicsTypeInfo;
  using AirTypeInfo = moho::RUnitBlueprintAirTypeInfo;
  using TransportTypeInfo = moho::RUnitBlueprintTransportTypeInfo;
  using AITypeInfo = moho::RUnitBlueprintAITypeInfo;
  using DefenseTypeInfo = moho::RUnitBlueprintDefenseTypeInfo;
  using IntelTypeInfo = moho::RUnitBlueprintIntelTypeInfo;
  using EconomyTypeInfo = moho::RUnitBlueprintEconomyTypeInfo;
  using WeaponTypeInfo = moho::RUnitBlueprintWeaponTypeInfo;

  alignas(GeneralTypeInfo) unsigned char gRUnitBlueprintGeneralTypeInfoStorage[sizeof(GeneralTypeInfo)];
  bool gRUnitBlueprintGeneralTypeInfoConstructed = false;

  alignas(DisplayTypeInfo) unsigned char gRUnitBlueprintDisplayTypeInfoStorage[sizeof(DisplayTypeInfo)];
  bool gRUnitBlueprintDisplayTypeInfoConstructed = false;

  alignas(PhysicsTypeInfo) unsigned char gRUnitBlueprintPhysicsTypeInfoStorage[sizeof(PhysicsTypeInfo)];
  bool gRUnitBlueprintPhysicsTypeInfoConstructed = false;

  alignas(AirTypeInfo) unsigned char gRUnitBlueprintAirTypeInfoStorage[sizeof(AirTypeInfo)];
  bool gRUnitBlueprintAirTypeInfoConstructed = false;

  alignas(TransportTypeInfo) unsigned char gRUnitBlueprintTransportTypeInfoStorage[sizeof(TransportTypeInfo)];
  bool gRUnitBlueprintTransportTypeInfoConstructed = false;

  alignas(AITypeInfo) unsigned char gRUnitBlueprintAITypeInfoStorage[sizeof(AITypeInfo)];
  bool gRUnitBlueprintAITypeInfoConstructed = false;

  alignas(DefenseTypeInfo) unsigned char gRUnitBlueprintDefenseTypeInfoStorage[sizeof(DefenseTypeInfo)];
  bool gRUnitBlueprintDefenseTypeInfoConstructed = false;

  alignas(IntelTypeInfo) unsigned char gRUnitBlueprintIntelTypeInfoStorage[sizeof(IntelTypeInfo)];
  bool gRUnitBlueprintIntelTypeInfoConstructed = false;

  alignas(EconomyTypeInfo) unsigned char gRUnitBlueprintEconomyTypeInfoStorage[sizeof(EconomyTypeInfo)];
  bool gRUnitBlueprintEconomyTypeInfoConstructed = false;

  alignas(WeaponTypeInfo) unsigned char gRUnitBlueprintWeaponTypeInfoStorage[sizeof(WeaponTypeInfo)];
  bool gRUnitBlueprintWeaponTypeInfoConstructed = false;

  template <typename T>
  [[nodiscard]] T& AcquireTypeInfo(unsigned char* const storage, bool& constructed)
  {
    if (!constructed) {
      new (storage) T();
      constructed = true;
    }

    return *reinterpret_cast<T*>(storage);
  }

  template <typename T>
  void CleanupTypeInfo(unsigned char* const storage, bool& constructed)
  {
    if (!constructed) {
      return;
    }

    reinterpret_cast<T*>(storage)->~T();
    constructed = false;
  }

  [[nodiscard]] GeneralTypeInfo& AcquireRUnitBlueprintGeneralTypeInfo()
  {
    return AcquireTypeInfo<GeneralTypeInfo>(gRUnitBlueprintGeneralTypeInfoStorage, gRUnitBlueprintGeneralTypeInfoConstructed);
  }

  [[nodiscard]] DisplayTypeInfo& AcquireRUnitBlueprintDisplayTypeInfo()
  {
    return AcquireTypeInfo<DisplayTypeInfo>(gRUnitBlueprintDisplayTypeInfoStorage, gRUnitBlueprintDisplayTypeInfoConstructed);
  }

  [[nodiscard]] PhysicsTypeInfo& AcquireRUnitBlueprintPhysicsTypeInfo()
  {
    return AcquireTypeInfo<PhysicsTypeInfo>(gRUnitBlueprintPhysicsTypeInfoStorage, gRUnitBlueprintPhysicsTypeInfoConstructed);
  }

  [[nodiscard]] AirTypeInfo& AcquireRUnitBlueprintAirTypeInfo()
  {
    return AcquireTypeInfo<AirTypeInfo>(gRUnitBlueprintAirTypeInfoStorage, gRUnitBlueprintAirTypeInfoConstructed);
  }

  [[nodiscard]] TransportTypeInfo& AcquireRUnitBlueprintTransportTypeInfo()
  {
    return AcquireTypeInfo<TransportTypeInfo>(
      gRUnitBlueprintTransportTypeInfoStorage,
      gRUnitBlueprintTransportTypeInfoConstructed
    );
  }

  [[nodiscard]] AITypeInfo& AcquireRUnitBlueprintAITypeInfo()
  {
    return AcquireTypeInfo<AITypeInfo>(gRUnitBlueprintAITypeInfoStorage, gRUnitBlueprintAITypeInfoConstructed);
  }

  [[nodiscard]] DefenseTypeInfo& AcquireRUnitBlueprintDefenseTypeInfo()
  {
    return AcquireTypeInfo<DefenseTypeInfo>(gRUnitBlueprintDefenseTypeInfoStorage, gRUnitBlueprintDefenseTypeInfoConstructed);
  }

  [[nodiscard]] IntelTypeInfo& AcquireRUnitBlueprintIntelTypeInfo()
  {
    return AcquireTypeInfo<IntelTypeInfo>(gRUnitBlueprintIntelTypeInfoStorage, gRUnitBlueprintIntelTypeInfoConstructed);
  }

  [[nodiscard]] EconomyTypeInfo& AcquireRUnitBlueprintEconomyTypeInfo()
  {
    return AcquireTypeInfo<EconomyTypeInfo>(gRUnitBlueprintEconomyTypeInfoStorage, gRUnitBlueprintEconomyTypeInfoConstructed);
  }

  [[nodiscard]] WeaponTypeInfo& AcquireRUnitBlueprintWeaponTypeInfo()
  {
    return AcquireTypeInfo<WeaponTypeInfo>(gRUnitBlueprintWeaponTypeInfoStorage, gRUnitBlueprintWeaponTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintGeneralTypeInfo()
  {
    CleanupTypeInfo<GeneralTypeInfo>(gRUnitBlueprintGeneralTypeInfoStorage, gRUnitBlueprintGeneralTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintDisplayTypeInfo()
  {
    CleanupTypeInfo<DisplayTypeInfo>(gRUnitBlueprintDisplayTypeInfoStorage, gRUnitBlueprintDisplayTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintPhysicsTypeInfo()
  {
    CleanupTypeInfo<PhysicsTypeInfo>(gRUnitBlueprintPhysicsTypeInfoStorage, gRUnitBlueprintPhysicsTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintAirTypeInfo()
  {
    CleanupTypeInfo<AirTypeInfo>(gRUnitBlueprintAirTypeInfoStorage, gRUnitBlueprintAirTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintTransportTypeInfo()
  {
    CleanupTypeInfo<TransportTypeInfo>(gRUnitBlueprintTransportTypeInfoStorage, gRUnitBlueprintTransportTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintAITypeInfo()
  {
    CleanupTypeInfo<AITypeInfo>(gRUnitBlueprintAITypeInfoStorage, gRUnitBlueprintAITypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintDefenseTypeInfo()
  {
    CleanupTypeInfo<DefenseTypeInfo>(gRUnitBlueprintDefenseTypeInfoStorage, gRUnitBlueprintDefenseTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintIntelTypeInfo()
  {
    CleanupTypeInfo<IntelTypeInfo>(gRUnitBlueprintIntelTypeInfoStorage, gRUnitBlueprintIntelTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintEconomyTypeInfo()
  {
    CleanupTypeInfo<EconomyTypeInfo>(gRUnitBlueprintEconomyTypeInfoStorage, gRUnitBlueprintEconomyTypeInfoConstructed);
  }

  void cleanup_RUnitBlueprintWeaponTypeInfo()
  {
    CleanupTypeInfo<WeaponTypeInfo>(gRUnitBlueprintWeaponTypeInfoStorage, gRUnitBlueprintWeaponTypeInfoConstructed);
  }

  template <typename T>
  [[nodiscard]] gpg::RType* CachedType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedBoolType()
  {
    return CachedType<bool>();
  }

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    return CachedType<float>();
  }

  [[nodiscard]] gpg::RType* CachedInt32Type()
  {
    return CachedType<std::int32_t>();
  }

  [[nodiscard]] gpg::RType* CachedUInt32Type()
  {
    return CachedType<std::uint32_t>();
  }

  [[nodiscard]] gpg::RType* CachedUInt8Type()
  {
    return CachedType<std::uint8_t>();
  }

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    return CachedType<msvc8::string>();
  }

  [[nodiscard]] gpg::RType* CachedRResIdType()
  {
    return CachedType<moho::RResId>();
  }

  [[nodiscard]] gpg::RType* CachedVectorStringType()
  {
    return CachedType<msvc8::vector<msvc8::string>>();
  }

  [[nodiscard]] gpg::RType* CachedVectorOccupyRectType()
  {
    return CachedType<msvc8::vector<moho::RUnitBlueprintOccupyRect>>();
  }

  [[nodiscard]] gpg::RType* CachedVectorRaisedPlatformType()
  {
    return CachedType<msvc8::vector<moho::RUnitBlueprintRaisedPlatform>>();
  }

  [[nodiscard]] gpg::RType* CachedCommandCapsType()
  {
    return CachedType<moho::ERuleBPUnitCommandCaps>();
  }

  [[nodiscard]] gpg::RType* CachedToggleCapsType()
  {
    return CachedType<moho::ERuleBPUnitToggleCaps>();
  }

  [[nodiscard]] gpg::RType* CachedMovementType()
  {
    return CachedType<moho::ERuleBPUnitMovementType>();
  }

  [[nodiscard]] gpg::RType* CachedLayerType()
  {
    return CachedType<moho::ELayer>();
  }

  [[nodiscard]] gpg::RType* CachedBuildRestrictionType()
  {
    return CachedType<moho::ERuleBPUnitBuildRestriction>();
  }

  [[nodiscard]] gpg::RType* CachedDefenseShieldType()
  {
    return CachedType<moho::RUnitBlueprintDefenseShield>();
  }

  [[nodiscard]] gpg::RType* CachedSMinMaxUInt32Type()
  {
    return CachedType<moho::SMinMax<std::uint32_t>>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponRangeCategoryType()
  {
    return CachedType<moho::UnitWeaponRangeCategory>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponBallisticArcType()
  {
    return CachedType<moho::ERuleBPUnitWeaponBallisticArc>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponTargetType()
  {
    return CachedType<moho::ERuleBPUnitWeaponTargetType>();
  }

  [[nodiscard]] gpg::RField* AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
    return &typeInfo->fields_.back();
  }

  void SetLastFieldName(gpg::RType* const typeInfo, const char* const fieldName)
  {
    if (typeInfo->fields_.empty()) {
      return;
    }
    typeInfo->fields_.back().mName = fieldName;
  }

  struct RUnitBlueprintNestedTypeInfoBootstrap
  {
    RUnitBlueprintNestedTypeInfoBootstrap()
    {
      (void)moho::register_RUnitBlueprintGeneralTypeInfo();
      (void)moho::register_RUnitBlueprintDisplayTypeInfo();
      (void)moho::register_RUnitBlueprintPhysicsTypeInfo();
      (void)moho::register_RUnitBlueprintAirTypeInfo();
      (void)moho::register_RUnitBlueprintTransportTypeInfo();
      (void)moho::register_RUnitBlueprintAITypeInfo();
      (void)moho::register_RUnitBlueprintDefenseTypeInfo();
      (void)moho::register_RUnitBlueprintIntelTypeInfo();
      (void)moho::register_RUnitBlueprintEconomyTypeInfo();
      (void)moho::register_RUnitBlueprintWeaponTypeInfo();
    }
  };

  RUnitBlueprintNestedTypeInfoBootstrap gRUnitBlueprintNestedTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00520530 (FUN_00520530, Moho::RUnitBlueprintGeneralTypeInfo::RUnitBlueprintGeneralTypeInfo)
   */
  RUnitBlueprintGeneralTypeInfo::RUnitBlueprintGeneralTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintGeneral), this);
  }

  /**
   * Address: 0x005205C0 (FUN_005205C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintGeneralTypeInfo::~RUnitBlueprintGeneralTypeInfo() = default;

  /**
   * Address: 0x005205B0 (FUN_005205B0)
   */
  const char* RUnitBlueprintGeneralTypeInfo::GetName() const
  {
    return "RUnitBlueprintGeneral";
  }

  /**
   * Address: 0x00520660 (FUN_00520660)
   *
   * What it does:
   * Registers `RUnitBlueprintGeneral` field descriptors and descriptions.
   */
  void RUnitBlueprintGeneralTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "CommandCaps", CachedCommandCapsType(), 0x00, "Command capability flags for this unit");
    AddFieldWithDescription(typeInfo, "ToggleCaps", CachedToggleCapsType(), 0x04, "Command capability flags for this unit");
    AddFieldWithDescription(typeInfo, "UpgradesTo", CachedRResIdType(), 8, "What unit, if any, does this unit upgrade to.");
    AddFieldWithDescription(typeInfo, "UpgradesFrom", CachedRResIdType(), 36, "What unit, if any, was this unit upgrade from.");
    AddFieldWithDescription(
      typeInfo,
      "UpgradesFromBase",
      CachedRResIdType(),
      64,
      "What unit, if any, was this unit upgrade from base."
    );
    AddFieldWithDescription(typeInfo, "SeedUnit", CachedRResIdType(), 92, "What unit, if any, was this unit seeded from.");
    AddFieldWithDescription(
      typeInfo,
      "QuickSelectPriority",
      CachedInt32Type(),
      120,
      "Indicates unit has it's own avatar button in the quick select interface, and it's sorting priority"
    );
    AddFieldWithDescription(typeInfo, "CapCost", CachedFloatType(), 124, "Cost of unit towards unit cap");
    AddFieldWithDescription(
      typeInfo,
      "SelectionPriority",
      CachedInt32Type(),
      0x80,
      "Determines if a unit will be selected in a drag selection, only the highest priority units will get selected (1 is highest)"
    );
  }

  /**
   * Address: 0x00520590 (FUN_00520590)
   *
   * What it does:
   * Sets `RUnitBlueprintGeneral` size and publishes general field metadata.
   */
  void RUnitBlueprintGeneralTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintGeneral);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00520730 (FUN_00520730, Moho::RUnitBlueprintDisplayTypeInfo::RUnitBlueprintDisplayTypeInfo)
   */
  RUnitBlueprintDisplayTypeInfo::RUnitBlueprintDisplayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintDisplay), this);
  }

  /**
   * Address: 0x005207C0 (FUN_005207C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintDisplayTypeInfo::~RUnitBlueprintDisplayTypeInfo() = default;

  /**
   * Address: 0x005207B0 (FUN_005207B0)
   */
  const char* RUnitBlueprintDisplayTypeInfo::GetName() const
  {
    return "RUnitBlueprintDisplay";
  }

  /**
   * Address: 0x00520860 (FUN_00520860)
   *
   * What it does:
   * Registers `RUnitBlueprintDisplay` field descriptors and descriptions.
   */
  void RUnitBlueprintDisplayTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "DisplayName", CachedStringType(), 0, "Displayed name of unit");
    AddFieldWithDescription(typeInfo, "MeshBlueprint", CachedRResIdType(), 28, "Mesh blueprint we use for display");
    AddFieldWithDescription(
      typeInfo,
      "PlaceholderMeshName",
      CachedStringType(),
      56,
      "Name of placeholder mesh to use for the unit when normal mesh isn't available"
    );
    AddFieldWithDescription(typeInfo, "IconName", CachedRResIdType(), 84, "Name of icon to use for the unit");
    AddFieldWithDescription(typeInfo, "UniformScale", CachedFloatType(), 112, "Uniform scale to be applied to mesh");
    AddFieldWithDescription(typeInfo, "SpawnRandomRotation", CachedBoolType(), 116, "Spawn with a small random rotation");
    AddFieldWithDescription(typeInfo, "HideLifebars", CachedBoolType(), 0x75, "Hide lifebars if true");
  }

  /**
   * Address: 0x00520790 (FUN_00520790)
   *
   * What it does:
   * Sets `RUnitBlueprintDisplay` size and publishes display field metadata.
   */
  void RUnitBlueprintDisplayTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintDisplay);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00520910 (FUN_00520910, Moho::RUnitBlueprintPhysicsTypeInfo::RUnitBlueprintPhysicsTypeInfo)
   */
  RUnitBlueprintPhysicsTypeInfo::RUnitBlueprintPhysicsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintPhysics), this);
  }

  /**
   * Address: 0x005209A0 (FUN_005209A0, scalar deleting destructor thunk)
   */
  RUnitBlueprintPhysicsTypeInfo::~RUnitBlueprintPhysicsTypeInfo() = default;

  /**
   * Address: 0x00520990 (FUN_00520990)
   */
  const char* RUnitBlueprintPhysicsTypeInfo::GetName() const
  {
    return "RUnitBlueprintPhysics";
  }

  /**
   * Address: 0x00520A40 (FUN_00520A40)
   *
   * What it does:
   * Registers `RUnitBlueprintPhysics` field descriptors and descriptions.
   */
  void RUnitBlueprintPhysicsTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(
      typeInfo,
      "FlattenSkirt",
      CachedBoolType(),
      0,
      "If true, terrain under building's skirt will be flattened."
    );
    AddFieldWithDescription(
      typeInfo,
      "SkirtOffsetX",
      CachedFloatType(),
      4,
      "Offset of left edge of skirt from left edge of footprint. Should be <= 0."
    );
    AddFieldWithDescription(
      typeInfo,
      "SkirtOffsetZ",
      CachedFloatType(),
      0x08,
      "Offset of top edge of skirt from top edge of footprint. Should be <= 0."
    );
    AddFieldWithDescription(typeInfo, "SkirtSizeX", CachedFloatType(), 0x0C, "Unit construction pad Size X for building");
    AddFieldWithDescription(typeInfo, "SkirtSizeZ", CachedFloatType(), 0x10, "Unit construction pad Size Z for building");
    AddFieldWithDescription(
      typeInfo,
      "MaxGroundVariation",
      CachedFloatType(),
      0x14,
      "Maximum elevation difference across skirt for build site"
    );
    AddFieldWithDescription(typeInfo, "MotionType", CachedMovementType(), 0x18, "Method of locomotion");
    AddFieldWithDescription(typeInfo, "AltMotionType", CachedMovementType(), 0x1C, "Alternate method of locomotion");
    AddFieldWithDescription(typeInfo, "StandUpright", CachedBoolType(), 0x20, "Stands upright regardless of terrain");
    AddFieldWithDescription(typeInfo, "SinkLower", CachedBoolType(), 0x21, "Stands upright regardless of terrain");
    AddFieldWithDescription(
      typeInfo,
      "RotateBodyWhileMoving",
      CachedBoolType(),
      0x22,
      "Ability to rotate body to aim weapon slaved to body while in still in motion"
    );
    AddFieldWithDescription(typeInfo, "DiveSurfaceSpeed", CachedFloatType(), 0x24, "Dive/surface speed for the sub units");
    AddFieldWithDescription(typeInfo, "MaxSpeed", CachedFloatType(), 0x28, "Maximum speed for the unit");
    AddFieldWithDescription(typeInfo, "MaxSpeedReverse", CachedFloatType(), 0x2C, "Maximum speed for the unit in reverse");
    AddFieldWithDescription(typeInfo, "MaxAcceleration", CachedFloatType(), 0x30, "Maximum acceleration for the unit");
    AddFieldWithDescription(typeInfo, "MaxBrake", CachedFloatType(), 0x34, "Maximum braking acceleration for the unit");
    AddFieldWithDescription(
      typeInfo,
      "MaxSteerForce",
      CachedFloatType(),
      0x38,
      "Maximum steer force magnitude that can be applied to acceleration"
    );
    AddFieldWithDescription(
      typeInfo,
      "BankingSlope",
      CachedFloatType(),
      0x3C,
      "How much the unit banks in corners (negative to lean outwards)"
    );
    AddFieldWithDescription(
      typeInfo,
      "RollStability",
      CachedFloatType(),
      0x40,
      "How stable the unit is against rolling (0 to 1)"
    );
    AddFieldWithDescription(
      typeInfo,
      "RollDamping",
      CachedFloatType(),
      0x44,
      "How much damping there is against rolling motion (1 = no motion at all)"
    );
    AddFieldWithDescription(typeInfo, "WobbleFactor", CachedFloatType(), 0x48, "How much wobbling for the unit while hovering");
    AddFieldWithDescription(
      typeInfo,
      "WobbleSpeed",
      CachedFloatType(),
      0x4C,
      "How fast is the wobble. The faster the less stable looking"
    );
    AddFieldWithDescription(typeInfo, "TurnRadius", CachedFloatType(), 0x50, "Turn radius for the unit, in world units");
    AddFieldWithDescription(typeInfo, "TurnRate", CachedFloatType(), 0x54, "Turn rate for the unit, in degrees per second");
    AddFieldWithDescription(
      typeInfo,
      "TurnFacingRate",
      CachedFloatType(),
      0x58,
      "Turn facing damping for the unit, usually used for hover units only"
    );
    AddFieldWithDescription(typeInfo, "RotateOnSpot", CachedBoolType(), 0x5C, "This unit can tries to rotate on the spot.");
    AddFieldWithDescription(
      typeInfo,
      "RotateOnSpotThreshold",
      CachedFloatType(),
      0x60,
      "Threshold for rotate on spot to take effect when moving."
    );
    AddFieldWithDescription(
      typeInfo,
      "Elevation",
      CachedFloatType(),
      0x64,
      "Preferred height above (-below) land or water surface"
    );
    AddFieldWithDescription(
      typeInfo,
      "AttackElevation",
      CachedFloatType(),
      0x68,
      "Preferred attack height when attacking ground targets... used by dive bombers"
    );
    AddFieldWithDescription(
      typeInfo,
      "BuildOnLayerCaps",
      CachedLayerType(),
      0x7C,
      "Unit may be built on these layers (only applies to structures"
    );
    AddFieldWithDescription(
      typeInfo,
      "BuildRestriction",
      CachedBuildRestrictionType(),
      0x80,
      "Special build restrictions (mass deposit, thermal vent, etc)"
    );
    AddFieldWithDescription(
      typeInfo,
      "CatchUpAcc",
      CachedFloatType(),
      0x6C,
      "Acceleration to allow unit to catch up to the target when it starts to drift"
    );
    AddFieldWithDescription(
      typeInfo,
      "BackUpDistance",
      CachedFloatType(),
      0x70,
      "Distance that the unit will just back up if it's easier to do so"
    );
    AddFieldWithDescription(
      typeInfo,
      "LayerChangeOffsetHeight",
      CachedFloatType(),
      0x74,
      "An offset to the layer change height used during the transition between seabed/water and land"
    );
    AddFieldWithDescription(
      typeInfo,
      "LayerTransitionDuration",
      CachedFloatType(),
      0x78,
      "Transition time in seconds when going from water/land and land/water"
    );
    AddFieldWithDescription(typeInfo, "FuelUseTime", CachedFloatType(), 0x8C, "Unit has fuel for this number of seconds");
    AddFieldWithDescription(typeInfo, "FuelRechargeRate", CachedFloatType(), 0x90, "Unit fuels up at this rate per second");
    AddFieldWithDescription(typeInfo, "GroundCollisionOffset", CachedFloatType(), 0x94, "Collision with ground offset");

    AddFieldWithDescription(
      typeInfo,
      "RaisedPlatforms",
      CachedVectorRaisedPlatformType(),
      0xA8,
      "Raised platoform definition for ground units to move on"
    );
    SetLastFieldName(typeInfo, "RaisedPlatforms");

    AddFieldWithDescription(
      typeInfo,
      "OccupyRects",
      CachedVectorOccupyRectType(),
      0x98,
      "Set up the occupy rectangles of the unit that will override the footprint."
    );
    SetLastFieldName(typeInfo, "OccupyRects");
  }

  /**
   * Address: 0x00520970 (FUN_00520970)
   *
   * What it does:
   * Sets `RUnitBlueprintPhysics` size and publishes physics field metadata.
   */
  void RUnitBlueprintPhysicsTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintPhysics);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00520E10 (FUN_00520E10, Moho::RUnitBlueprintAirTypeInfo::RUnitBlueprintAirTypeInfo)
   */
  RUnitBlueprintAirTypeInfo::RUnitBlueprintAirTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintAir), this);
  }

  /**
   * Address: 0x00520EA0 (FUN_00520EA0, scalar deleting destructor thunk)
   */
  RUnitBlueprintAirTypeInfo::~RUnitBlueprintAirTypeInfo() = default;

  /**
   * Address: 0x00520E90 (FUN_00520E90)
   */
  const char* RUnitBlueprintAirTypeInfo::GetName() const
  {
    return "RUnitBlueprintAir";
  }

  /**
   * Address: 0x00520F40 (FUN_00520F40)
   *
   * What it does:
   * Registers `RUnitBlueprintAir` field descriptors and descriptions.
   */
  void RUnitBlueprintAirTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "CanFly", CachedBoolType(), 0, "Is the unit capable of flight?");
    AddFieldWithDescription(typeInfo, "Winged", CachedBoolType(), 1, "Does the unit use wings for forward flight?");
    AddFieldWithDescription(typeInfo, "FlyInWater", CachedBoolType(), 2, "Can this unit fly under water?");
    AddFieldWithDescription(typeInfo, "AutoLandTime", CachedFloatType(), 4, "Timer to automatically initate landing on ground if idle");
    AddFieldWithDescription(typeInfo, "MaxAirspeed", CachedFloatType(), 8, "Maximum airspeed");
    AddFieldWithDescription(typeInfo, "MinAirspeed", CachedFloatType(), 12, "Minimum combat airspeed");
    AddFieldWithDescription(typeInfo, "TurnSpeed", CachedFloatType(), 16, "Regular turn speed of the unit");
    AddFieldWithDescription(
      typeInfo,
      "CombatTurnSpeed",
      CachedFloatType(),
      20,
      "Maximum combat turn speed of the unit for special manuvers"
    );
    AddFieldWithDescription(
      typeInfo,
      "StartTurnDistance",
      CachedFloatType(),
      24,
      "Distance from target at which to start turning to align with it"
    );
    AddFieldWithDescription(
      typeInfo,
      "TightTurnMultiplier",
      CachedFloatType(),
      0x1C,
      "Additional turning multiplier ability during a tight turn manuver"
    );
    AddFieldWithDescription(
      typeInfo,
      "SustainedTurnThreshold",
      CachedFloatType(),
      32,
      "Length of time allowed for sustained turn before we re-try a different approach"
    );
    AddFieldWithDescription(typeInfo, "LiftFactor", CachedFloatType(), 36, "How much altitude the unit can gain/loose per second");
    AddFieldWithDescription(typeInfo, "BankFactor", CachedFloatType(), 40, "How much aircraft banks in turns; negative to lean out");
    AddFieldWithDescription(
      typeInfo,
      "BankForward",
      CachedBoolType(),
      44,
      "True if aircraft banks forward/back as well as sideways"
    );
    AddFieldWithDescription(
      typeInfo,
      "EngageDistance",
      CachedFloatType(),
      0x30,
      "Distance to being engaging enemy target in attack task"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffTrigger",
      CachedFloatType(),
      52,
      "Distance to target to trigger the breaking off attack"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffDistance",
      CachedFloatType(),
      56,
      "Distnace to break off before turning around for another attack run"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffIfNearNewTarget",
      CachedBoolType(),
      60,
      "If our new target is close by then perform break off first to increase distance between the 2"
    );
    AddFieldWithDescription(
      typeInfo,
      "KMove",
      CachedFloatType(),
      64,
      "Controller proportional parameter for horizontal motion"
    );
    AddFieldWithDescription(typeInfo, "KMoveDamping", CachedFloatType(), 68, "Controller damping parameter for horizontal motion");
    AddFieldWithDescription(typeInfo, "KLift", CachedFloatType(), 0x48, "Controller proportional parameter for vertical motion");
    AddFieldWithDescription(typeInfo, "KLiftDamping", CachedFloatType(), 76, "Controller damping parameter for vertical motion");
    AddFieldWithDescription(typeInfo, "KTurn", CachedFloatType(), 80, "Controller proportional parameter for heading changes");
    AddFieldWithDescription(typeInfo, "KTurnDamping", CachedFloatType(), 84, "Controller damping parameter for heading changes");
    AddFieldWithDescription(typeInfo, "KRoll", CachedFloatType(), 88, "Controller proportional parameter for roll changes");
    AddFieldWithDescription(typeInfo, "KRollDamping", CachedFloatType(), 92, "Controller damping parameter for roll changes");
    AddFieldWithDescription(typeInfo, "CirclingTurnMult", CachedFloatType(), 96, "Adjust turning ability when in circling mode");
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusChangeMinRatio",
      CachedFloatType(),
      100,
      "Min circling radius ratio for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusChangeMaxRatio",
      CachedFloatType(),
      104,
      "Max circling radius ratio for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusVsAirMult",
      CachedFloatType(),
      0x6C,
      "Multiplier to the circling radius when targetting another air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingElevationChangeRatio",
      CachedFloatType(),
      112,
      "Elevation change ratio of unit when circling"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingFlightChangeFrequency",
      CachedFloatType(),
      116,
      "Frequency of flight pattern change for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingDirChange",
      CachedBoolType(),
      120,
      "Whether unit should ever change flight direction while circling"
    );
    AddFieldWithDescription(
      typeInfo,
      "HoverOverAttack",
      CachedBoolType(),
      121,
      "Whether unit should hover over the target directly to attack... used for cases like the C.Z.A.R"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomBreakOffDistanceMult",
      CachedFloatType(),
      124,
      "Random multiplier applied to the break off distance for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomMinChangeCombatStateTime",
      CachedFloatType(),
      128,
      "Random min time to switch combat state in seconds for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomMaxChangeCombatStateTime",
      CachedFloatType(),
      132,
      "Random max time to switch combat state in seconds for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "TransportHoverHeight",
      CachedFloatType(),
      136,
      "This transport will stay at this height when picking up and dropping off units"
    );
    AddFieldWithDescription(typeInfo, "PredictAheadForBombDrop", CachedFloatType(), 0x8C, "Time to predict ahead for moving targets?");
  }

  /**
   * Address: 0x00520E70 (FUN_00520E70)
   *
   * What it does:
   * Sets `RUnitBlueprintAir` size and publishes air field metadata.
   */
  void RUnitBlueprintAirTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintAir);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521300 (FUN_00521300, Moho::RUnitBlueprintTransportTypeInfo::RUnitBlueprintTransportTypeInfo)
   */
  RUnitBlueprintTransportTypeInfo::RUnitBlueprintTransportTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintTransport), this);
  }

  /**
   * Address: 0x00521390 (FUN_00521390, scalar deleting destructor thunk)
   */
  RUnitBlueprintTransportTypeInfo::~RUnitBlueprintTransportTypeInfo() = default;

  /**
   * Address: 0x00521380 (FUN_00521380)
   */
  const char* RUnitBlueprintTransportTypeInfo::GetName() const
  {
    return "RUnitBlueprintTransport";
  }

  /**
   * Address: 0x00521430 (FUN_00521430)
   *
   * What it does:
   * Registers `RUnitBlueprintTransport` field descriptors and descriptions.
   */
  void RUnitBlueprintTransportTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "TransportClass", CachedInt32Type(), 0, "Type of attach points required on transports");
    AddFieldWithDescription(typeInfo, "ClassGenericUpTo", CachedInt32Type(), 4, "Generic slots up to the specified class");
    AddFieldWithDescription(typeInfo, "Class2AttachSize", CachedInt32Type(), 8, "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "Class3AttachSize", CachedInt32Type(), 12, "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "Class4AttachSize", CachedInt32Type(), 16, "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "ClassSAttachSize", CachedInt32Type(), 20, "Number of class 1 attach points this affects");
    AddFieldWithDescription(
      typeInfo,
      "AirClass",
      CachedBoolType(),
      24,
      "These define that the unit can only land on air staging platforms"
    );
    AddFieldWithDescription(
      typeInfo,
      "StorageSlots",
      CachedInt32Type(),
      28,
      "How many internal storage slots available for the transport on top of the attach points"
    );
    AddFieldWithDescription(
      typeInfo,
      "DockingSlots",
      CachedInt32Type(),
      32,
      "How many external docking slots available for air staging platforms"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairRate",
      CachedFloatType(),
      0x24,
      "Repairs units attached to me at this % of max health per second"
    );
  }

  /**
   * Address: 0x00521360 (FUN_00521360)
   *
   * What it does:
   * Sets `RUnitBlueprintTransport` size and publishes transport field metadata.
   */
  void RUnitBlueprintTransportTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintTransport);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521530 (FUN_00521530, Moho::RUnitBlueprintAITypeInfo::RUnitBlueprintAITypeInfo)
   */
  RUnitBlueprintAITypeInfo::RUnitBlueprintAITypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintAI), this);
  }

  /**
   * Address: 0x005215C0 (FUN_005215C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintAITypeInfo::~RUnitBlueprintAITypeInfo() = default;

  /**
   * Address: 0x005215B0 (FUN_005215B0)
   */
  const char* RUnitBlueprintAITypeInfo::GetName() const
  {
    return "RUnitBlueprintAI";
  }

  /**
   * Address: 0x00521660 (FUN_00521660)
   *
   * What it does:
   * Registers `RUnitBlueprintAI` field descriptors and descriptions.
   */
  void RUnitBlueprintAITypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "GuardScanRadius", CachedFloatType(), 0, "Guard range for the unit");
    AddFieldWithDescription(
      typeInfo,
      "GuardReturnRadius",
      CachedFloatType(),
      4,
      "Maximum range from the guarded unit before initiating return"
    );
    AddFieldWithDescription(
      typeInfo,
      "StagingPlatformScanRadius",
      CachedFloatType(),
      8,
      "Range for staging platforms to look for planes to repair and refuel when they are on patrol"
    );
    AddFieldWithDescription(
      typeInfo,
      "ShowAssistRangeOnSelect",
      CachedBoolType(),
      12,
      "Show assist range for the unit if selected"
    );
    AddFieldWithDescription(
      typeInfo,
      "GuardFormationName",
      CachedStringType(),
      16,
      "The formation name used for guarding this unit"
    );
    AddFieldWithDescription(typeInfo, "NeedUnpack", CachedBoolType(), 44, "Unit should unpack before firing weapon");
    AddFieldWithDescription(typeInfo, "InitialAutoMode", CachedBoolType(), 45, "Initial auto mode behavior for the unit");
    AddFieldWithDescription(
      typeInfo,
      "BeaconName",
      CachedStringType(),
      48,
      "Thie is the beacon that this unit will create under some circumstances"
    );
    AddFieldWithDescription(
      typeInfo,
      "TargetBones",
      CachedVectorStringType(),
      76,
      "Some target bones setup for other units to aim at instead of the default center pos"
    );
    AddFieldWithDescription(
      typeInfo,
      "RefuelingMultiplier",
      CachedFloatType(),
      92,
      "This multiplier is applied when a staging platform is refueling an air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "RefuelingRepairAmount",
      CachedFloatType(),
      0x60,
      "This amount of repair per second offered to refueling air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairConsumeEnergy",
      CachedFloatType(),
      100,
      "This amount of energy per second required to repair air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairConsumeMass",
      CachedFloatType(),
      104,
      "This amount of mass per second require to repair air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "AutoSurfaceToAttack",
      CachedBoolType(),
      108,
      "Automatically surface to attack ground targets"
    );
    AddFieldWithDescription(
      typeInfo,
      "AttackAngle",
      CachedFloatType(),
      0x70,
      "Desired angle to face target to maximize the number of guns able to hit the targets"
    );
  }

  /**
   * Address: 0x00521590 (FUN_00521590)
   *
   * What it does:
   * Sets `RUnitBlueprintAI` size and publishes AI field metadata.
   */
  void RUnitBlueprintAITypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintAI);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521980 (FUN_00521980, Moho::RUnitBlueprintDefenseTypeInfo::RUnitBlueprintDefenseTypeInfo)
   */
  RUnitBlueprintDefenseTypeInfo::RUnitBlueprintDefenseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintDefense), this);
  }

  /**
   * Address: 0x00521A10 (FUN_00521A10, scalar deleting destructor thunk)
   */
  RUnitBlueprintDefenseTypeInfo::~RUnitBlueprintDefenseTypeInfo() = default;

  /**
   * Address: 0x00521A00 (FUN_00521A00)
   */
  const char* RUnitBlueprintDefenseTypeInfo::GetName() const
  {
    return "RUnitBlueprintDefense";
  }

  /**
   * Address: 0x00521AB0 (FUN_00521AB0)
   *
   * What it does:
   * Registers `RUnitBlueprintDefense` field descriptors and descriptions.
   */
  void RUnitBlueprintDefenseTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "MaxHealth", CachedFloatType(), 0, "Max health value for the unit");
    AddFieldWithDescription(typeInfo, "Health", CachedFloatType(), 4, "Starting health value for the unit");
    AddFieldWithDescription(typeInfo, "RegenRate", CachedFloatType(), 8, "Amount of health to regenerate per second");
    AddFieldWithDescription(
      typeInfo,
      "AirThreatLevel",
      CachedFloatType(),
      12,
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "SurfaceThreatLevel",
      CachedFloatType(),
      16,
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "SubThreatLevel",
      CachedFloatType(),
      20,
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "EconomyThreatLevel",
      CachedFloatType(),
      24,
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(typeInfo, "ArmorType", CachedStringType(), 28, "The Armor type name");
    AddFieldWithDescription(typeInfo, "Shield", CachedDefenseShieldType(), 0x38, "Shield information");
  }

  /**
   * Address: 0x005219E0 (FUN_005219E0)
   *
   * What it does:
   * Sets `RUnitBlueprintDefense` size and publishes defense field metadata.
   */
  void RUnitBlueprintDefenseTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintDefense);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00521B80 (FUN_00521B80, Moho::RUnitBlueprintIntelTypeInfo::RUnitBlueprintIntelTypeInfo)
   */
  RUnitBlueprintIntelTypeInfo::RUnitBlueprintIntelTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintIntel), this);
  }

  /**
   * Address: 0x00521C10 (FUN_00521C10, scalar deleting destructor thunk)
   */
  RUnitBlueprintIntelTypeInfo::~RUnitBlueprintIntelTypeInfo() = default;

  /**
   * Address: 0x00521C00 (FUN_00521C00)
   */
  const char* RUnitBlueprintIntelTypeInfo::GetName() const
  {
    return "RUnitBlueprintIntel";
  }

  /**
   * Address: 0x00521CB0 (FUN_00521CB0)
   *
   * What it does:
   * Registers `RUnitBlueprintIntel` field descriptors and descriptions.
   */
  void RUnitBlueprintIntelTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "VisionRadius", CachedUInt32Type(), 0, "How far we can see above water");
    AddFieldWithDescription(typeInfo, "WaterVisionRadius", CachedUInt32Type(), 4, "How far we can see underwater");
    AddFieldWithDescription(typeInfo, "RadarRadius", CachedUInt32Type(), 8, "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "SonarRadius", CachedUInt32Type(), 12, "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "OmniRadius", CachedUInt32Type(), 16, "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "RadarStealth", CachedBoolType(), 20, "Single unit radar stealth");
    AddFieldWithDescription(typeInfo, "SonarStealth", CachedBoolType(), 21, "Single unit sonar stealth");
    AddFieldWithDescription(typeInfo, "Cloak", CachedBoolType(), 22, "Single unit cloaking");
    AddFieldWithDescription(typeInfo, "ShowIntelOnSelect", CachedBoolType(), 23, "Show intel radius of unit if selected");
    AddFieldWithDescription(
      typeInfo,
      "RadarStealthFieldRadius",
      CachedUInt32Type(),
      0x18,
      "How far our radar stealth goes"
    );
    AddFieldWithDescription(
      typeInfo,
      "SonarStealthFieldRadius",
      CachedUInt32Type(),
      28,
      "How far our sonar stealth goes"
    );
    AddFieldWithDescription(typeInfo, "CloakFieldRadius", CachedUInt32Type(), 0x20, "How far our cloaking goes");
    AddFieldWithDescription(typeInfo, "JamRadius", CachedSMinMaxUInt32Type(), 0x24, "How far we create fake blips");
    AddFieldWithDescription(typeInfo, "SpoofRadius", CachedSMinMaxUInt32Type(), 0x30, "How far off to displace blip");
    AddFieldWithDescription(typeInfo, "JammerBlips", CachedUInt8Type(), 0x2C, "How many blips does a jammer produce?");
  }

  /**
   * Address: 0x00521BE0 (FUN_00521BE0)
   *
   * What it does:
   * Sets `RUnitBlueprintIntel` size and publishes intel field metadata.
   */
  void RUnitBlueprintIntelTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintIntel);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521E10 (FUN_00521E10, Moho::RUnitBlueprintEconomyTypeInfo::RUnitBlueprintEconomyTypeInfo)
   */
  RUnitBlueprintEconomyTypeInfo::RUnitBlueprintEconomyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintEconomy), this);
  }

  /**
   * Address: 0x00521EA0 (FUN_00521EA0, scalar deleting destructor thunk)
   */
  RUnitBlueprintEconomyTypeInfo::~RUnitBlueprintEconomyTypeInfo() = default;

  /**
   * Address: 0x00521E90 (FUN_00521E90)
   */
  const char* RUnitBlueprintEconomyTypeInfo::GetName() const
  {
    return "RUnitBlueprintEconomy";
  }

  /**
   * Address: 0x00521F40 (FUN_00521F40)
   *
   * What it does:
   * Registers `RUnitBlueprintEconomy` field descriptors and descriptions.
   */
  void RUnitBlueprintEconomyTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BuildCostEnergy", CachedFloatType(), 0, "Energy cost to build this unit");
    AddFieldWithDescription(typeInfo, "BuildCostMass", CachedFloatType(), 4, "Mass cost to build this unit");
    AddFieldWithDescription(typeInfo, "BuildRate", CachedFloatType(), 8, "How efficient a unit is at building");
    AddFieldWithDescription(typeInfo, "BuildTime", CachedFloatType(), 0x0C, "How long it takes to build this unit (in seconds)");
    AddFieldWithDescription(
      typeInfo,
      "StorageEnergy",
      CachedFloatType(),
      0x10,
      "Energy storage capacity provided by this unit"
    );
    AddFieldWithDescription(typeInfo, "StorageMass", CachedFloatType(), 0x14, "Mass storage capacity provided by this unit");
    AddFieldWithDescription(
      typeInfo,
      "NaturalProducer",
      CachedBoolType(),
      0x18,
      "Produces resouce naturally and does not consume anything"
    );

    AddFieldWithDescription(
      typeInfo,
      "BuildableCategories",
      CachedVectorStringType(),
      0x1C,
      "One of the unit categories that can be built by this unit"
    );
    SetLastFieldName(typeInfo, "BuildableCategory");

    AddFieldWithDescription(
      typeInfo,
      "RebuildBonusIds",
      CachedVectorStringType(),
      0x2C,
      "You will get bonus if you rebuild this unit over the wreckage of these wreckages"
    );

    AddFieldWithDescription(typeInfo, "InitialRallyX", CachedFloatType(), 0x68, "default rally point Xfor the factory");
    AddFieldWithDescription(typeInfo, "InitialRallyZ", CachedFloatType(), 0x6C, "default rally point Z for the factory");
    AddFieldWithDescription(
      typeInfo,
      "NeedToFaceTargetToBuild",
      CachedBoolType(),
      0x70,
      "builder needs to face target before it can build/repair"
    );
    AddFieldWithDescription(
      typeInfo,
      "SacrificeMassMult",
      CachedFloatType(),
      0x74,
      "builder will kill self but provide this amount of mass based on builder's mass cost to the unit it is helping"
    );
    AddFieldWithDescription(
      typeInfo,
      "SacrificeEnergyMult",
      CachedFloatType(),
      0x78,
      "builder will kill self but provide this amount of energy based on the builder's energy cost to the unit it is helping"
    );
    AddFieldWithDescription(
      typeInfo,
      "MaxBuildDistance",
      CachedFloatType(),
      0x7C,
      "Maximum build range of the unit. The target must be within this range before the builder can perform operation"
    );
  }

  /**
   * Address: 0x00521E70 (FUN_00521E70)
   *
   * What it does:
   * Sets `RUnitBlueprintEconomy` size and publishes economy field metadata.
   */
  void RUnitBlueprintEconomyTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintEconomy);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00522210 (FUN_00522210, Moho::RUnitBlueprintWeaponTypeInfo::RUnitBlueprintWeaponTypeInfo)
   */
  RUnitBlueprintWeaponTypeInfo::RUnitBlueprintWeaponTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintWeapon), this);
  }

  /**
   * Address: 0x005222A0 (FUN_005222A0, scalar deleting destructor thunk)
   */
  RUnitBlueprintWeaponTypeInfo::~RUnitBlueprintWeaponTypeInfo() = default;

  /**
   * Address: 0x00522290 (FUN_00522290)
   */
  const char* RUnitBlueprintWeaponTypeInfo::GetName() const
  {
    return "RUnitBlueprintWeapon";
  }

  /**
   * Address: 0x00522340 (FUN_00522340)
   *
   * What it does:
   * Registers `RUnitBlueprintWeapon` field descriptors and descriptions.
   */
  void RUnitBlueprintWeaponTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "Label", CachedStringType(), 8, "The label to pass to scripts to id this weapon.");
    AddFieldWithDescription(typeInfo, "DisplayName", CachedStringType(), 0x24, "The display name of this weapon.");
    AddFieldWithDescription(typeInfo, "RangeCategory", CachedWeaponRangeCategoryType(), 0x40, "The range category this weapon satisfies.");
    AddFieldWithDescription(
      typeInfo,
      "DummyWeapon",
      CachedBoolType(),
      0x44,
      "True if the engine should not create an actual weapon for this blueprint. This is used for special damage like the Spiderbot's feet, where no real weapon exists, but we still want a consistent way to spec damage types etc."
    );
    AddFieldWithDescription(typeInfo, "TargetCheckInterval", CachedFloatType(), 0x50, "Interval between checks for a new weapon target. Default is three seconds.");
    AddFieldWithDescription(
      typeInfo,
      "AlwaysRecheckTarget",
      CachedBoolType(),
      0x54,
      "Always recheck for better target regardless of whether you already have one or not."
    );
    AddFieldWithDescription(
      typeInfo,
      "PrefersPrimaryWeaponTarget",
      CachedBoolType(),
      0x45,
      "Flag to specify if the weapon prefers to target what the primary weapon is currently targetting."
    );
    AddFieldWithDescription(
      typeInfo,
      "StopOnPrimaryWeaponBusy",
      CachedBoolType(),
      0x46,
      "Flag to specify to not make weapon active if the primary weapon has a current target."
    );
    AddFieldWithDescription(
      typeInfo,
      "SlavedToBody",
      CachedBoolType(),
      0x47,
      "Flag to specify if the weapon is slaved to the unit body, thus requiring unit to face target to fire."
    );
    AddFieldWithDescription(typeInfo, "SlavedToBodyArcRange", CachedFloatType(), 0x48, "Range of arc to be considered slaved to a target.");
    AddFieldWithDescription(
      typeInfo,
      "AutoInitiateAttackCommand",
      CachedBoolType(),
      0x4C,
      "Flag to specify if the unit will initate an attack command when idle if an enemy target comes within firing/tracking range."
    );
    AddFieldWithDescription(typeInfo, "MinRadius", CachedFloatType(), 0x58, "The minimum range we must be to fire at our target.");
    AddFieldWithDescription(typeInfo, "MaxRadius", CachedFloatType(), 0x5C, "The maximum range we can be to fire at our target.");
    AddFieldWithDescription(typeInfo, "EffectiveRadius", CachedFloatType(), 0x64, "The effective range that this weapon really is.");
    AddFieldWithDescription(
      typeInfo,
      "MaxHeightDiff",
      CachedFloatType(),
      0x68,
      "The maximum height diff range for the weapon. Keep in mind weapons are now cylinder in nature."
    );
    AddFieldWithDescription(
      typeInfo,
      "TrackingRadius",
      CachedFloatType(),
      0x6C,
      "The range where we begin tracking a unit but will not fire yet; multiplier of the weapon's MaxRadius"
    );
    AddFieldWithDescription(typeInfo, "HeadingArcCenter", CachedFloatType(), 0x70, "Center of firing arc for this weapon, in degrees. Default is 0");
    AddFieldWithDescription(
      typeInfo,
      "HeadingArcRange",
      CachedFloatType(),
      0x74,
      "Maximum angle from HeadingArcCenter, in degrees. Default is 180, meaning weapon can aim anywhere."
    );
    AddFieldWithDescription(typeInfo, "FiringTolerance", CachedFloatType(), 0x78, "How accurate do we have to be aimed before we take a shot.  In degrees.");
    AddFieldWithDescription(typeInfo, "FiringRandomness", CachedFloatType(), 0x7C, "How many degrees of arc can we randomly be off by (gaussian)");
    AddFieldWithDescription(typeInfo, "IgnoreIfDisabled", CachedBoolType(), 0x149, "Does not consider weapon when attacking targets if it is disabled");
    AddFieldWithDescription(typeInfo, "CannotAttackGround", CachedBoolType(), 0x14A, "Weapon cannot attack ground positions");
    AddFieldWithDescription(typeInfo, "RequiresEnergy", CachedFloatType(), 0x80, "Weapon requires this much available energy to fire");
    AddFieldWithDescription(typeInfo, "RequiresMass", CachedFloatType(), 0x84, "Weapon requires this much available mass to fire");
    AddFieldWithDescription(typeInfo, "MuzzleVelocity", CachedFloatType(), 0x88, "Weapon's muzzle velocity");
    AddFieldWithDescription(typeInfo, "MuzzleVelocityRandom", CachedFloatType(), 0x8C, "Random variation for muzzle velocity (gaussian)");
    AddFieldWithDescription(
      typeInfo,
      "MuzzleVelocityReduceDistance",
      CachedFloatType(),
      0x90,
      "Target distance at which weapon will start reducing muzzle velocity to maintain a higher firing arc."
    );
    AddFieldWithDescription(typeInfo, "LeadTarget", CachedBoolType(), 0x94, "True if weapon should lead its target when aiming.");
    AddFieldWithDescription(
      typeInfo,
      "ProjectileLifetime",
      CachedFloatType(),
      0x98,
      "Lifetime for projectile in seconds. If 0, the projectile will use the lifetime from its own blueprint."
    );
    AddFieldWithDescription(
      typeInfo,
      "ProjectileLifetimeUsesMultiplier",
      CachedFloatType(),
      0x9C,
      "Lifetime for projectile based on lifetime equation of Multiplier * (MaxRadius/MuzzleVelocity)"
    );
    AddFieldWithDescription(typeInfo, "Damage", CachedFloatType(), 0xA0, "How much damage to cause.");
    AddFieldWithDescription(typeInfo, "DamageRadius", CachedFloatType(), 0xA4, "Radius to inflict damage in.");
    AddFieldWithDescription(typeInfo, "DamageType", CachedStringType(), 0xA8, "Type of damage this weapon deals");
    AddFieldWithDescription(typeInfo, "RateOfFire", CachedFloatType(), 0xC4, "How many shots/second we can fire.");
    AddFieldWithDescription(typeInfo, "ProjectileId", CachedRResIdType(), 0xC8, "Blueprint Id for projectile, if any.");
    AddFieldWithDescription(typeInfo, "BallisticArc", CachedWeaponBallisticArcType(), 0xE4, "High or low arc for projectiles");
    AddFieldWithDescription(
      typeInfo,
      "TargetRestrictOnlyAllow",
      CachedStringType(),
      0xE8,
      "Comma separated list of Entity Category that are the only valid targets."
    );
    AddFieldWithDescription(
      typeInfo,
      "TargetRestrictDisallow",
      CachedStringType(),
      0x104,
      "Comma separated list of Entity Category that are always invalid targets."
    );
    AddFieldWithDescription(typeInfo, "TargetType", CachedWeaponTargetType(), 0x130, "The type of entity this unit can target.");
    AddFieldWithDescription(typeInfo, "ManualFire", CachedBoolType(), 0x120, "Never fires automaticly.");
    AddFieldWithDescription(typeInfo, "NukeWeapon", CachedBoolType(), 0x121, "Nuke weapon flag.");
    AddFieldWithDescription(typeInfo, "OverChargeWeapon", CachedBoolType(), 0x122, "Overcharge weapon flag.");
    AddFieldWithDescription(typeInfo, "NeedPrep", CachedBoolType(), 0x123, "Weapon needs prep time (applies to most Aeon units).");
    AddFieldWithDescription(typeInfo, "CountedProjectile", CachedBoolType(), 0x124, "This projectile needs to be built and stored before the weapon can fire");
    AddFieldWithDescription(typeInfo, "MaxProjectileStorage", CachedInt32Type(), 0x128, "This weapon can only hold this many counted projectiles");
    AddFieldWithDescription(typeInfo, "IgnoreIfDisabled", CachedBoolType(), 0x149, "Ignore trying to use the weapon if it's disabled.");
    AddFieldWithDescription(typeInfo, "IgnoresAlly", CachedBoolType(), 0x12C, "This determines whether the weapon affect ally units or not");
    AddFieldWithDescription(typeInfo, "AttackGroundTries", CachedInt32Type(), 0x134, "This determines the number of shots at a ground target before moving on to the enxt target");
    AddFieldWithDescription(typeInfo, "AimsStraightOnDisable", CachedBoolType(), 0x138, "This weapon will aim straight ahead when disabled");
    AddFieldWithDescription(typeInfo, "Turreted", CachedBoolType(), 0x139, "This weapon is on a turret");
    AddFieldWithDescription(typeInfo, "YawOnlyOnTarget", CachedBoolType(), 0x13A, "This weapon is considered on target if the yaw is facing the target");
    AddFieldWithDescription(typeInfo, "AboveWaterFireOnly", CachedBoolType(), 0x13B, "This weapon will only fire if it is above water");
    AddFieldWithDescription(typeInfo, "BelowWaterFireOnly", CachedBoolType(), 0x13C, "This weapon will only fire if it is below water");
    AddFieldWithDescription(typeInfo, "AboveWaterTargetsOnly", CachedBoolType(), 0x13D, "This weapon will only at targets above water");
    AddFieldWithDescription(typeInfo, "BelowWaterTargetsOnly", CachedBoolType(), 0x13E, "This weapon will only at targets below water");
    AddFieldWithDescription(typeInfo, "NeedToComputeBombDrop", CachedBoolType(), 0x140, "This to compute when to drop bomb?");
    AddFieldWithDescription(typeInfo, "BombDropThreshold", CachedFloatType(), 0x144, "Threshold to release point before releasing ordinance?");
    AddFieldWithDescription(typeInfo, "ReTargetOnMiss", CachedBoolType(), 0x13F, "This weapon will find new target on miss events");
    AddFieldWithDescription(
      typeInfo,
      "UseFiringSolutionInsteadOfAimBone",
      CachedBoolType(),
      0x148,
      "This weapon uses the recent firing solution to create projectile istead of the aim bone transform"
    );
    AddFieldWithDescription(
      typeInfo,
      "UIMinRangeVisualId",
      CachedStringType(),
      0x14C,
      "Allows the UI to know what kind of minimum range indicator to draw for this weapon."
    );
    AddFieldWithDescription(
      typeInfo,
      "UIMaxRangeVisualId",
      CachedStringType(),
      0x168,
      "Allows the UI to know what kind of maximum range indicator to draw for this weapon."
    );
    AddFieldWithDescription(
      typeInfo,
      "MaximumBeamLength",
      CachedFloatType(),
      0x60,
      "Allows the setting of the Maximum Beam length so beams and radius can be different. Default to MaxRadius."
    );
  }

  /**
   * Address: 0x00522270 (FUN_00522270)
   *
   * What it does:
   * Sets `RUnitBlueprintWeapon` size and publishes weapon field metadata.
   */
  void RUnitBlueprintWeaponTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintWeapon);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8A90 (FUN_00BC8A90, register_RUnitBlueprintGeneralTypeInfo)
   */
  int register_RUnitBlueprintGeneralTypeInfo()
  {
    (void)AcquireRUnitBlueprintGeneralTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintGeneralTypeInfo);
  }

  /**
   * Address: 0x00BC8AB0 (FUN_00BC8AB0, register_RUnitBlueprintDisplayTypeInfo)
   */
  int register_RUnitBlueprintDisplayTypeInfo()
  {
    (void)AcquireRUnitBlueprintDisplayTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintDisplayTypeInfo);
  }

  /**
   * Address: 0x00BC8AD0 (FUN_00BC8AD0, register_RUnitBlueprintPhysicsTypeInfo)
   */
  int register_RUnitBlueprintPhysicsTypeInfo()
  {
    (void)AcquireRUnitBlueprintPhysicsTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintPhysicsTypeInfo);
  }

  /**
   * Address: 0x00BC8AF0 (FUN_00BC8AF0, register_RUnitBlueprintAirTypeInfo)
   */
  int register_RUnitBlueprintAirTypeInfo()
  {
    (void)AcquireRUnitBlueprintAirTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintAirTypeInfo);
  }

  /**
   * Address: 0x00BC8B10 (FUN_00BC8B10, register_RUnitBlueprintTransportTypeInfo)
   */
  int register_RUnitBlueprintTransportTypeInfo()
  {
    (void)AcquireRUnitBlueprintTransportTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintTransportTypeInfo);
  }

  /**
   * Address: 0x00BC8B30 (FUN_00BC8B30, register_RUnitBlueprintAITypeInfo)
   */
  int register_RUnitBlueprintAITypeInfo()
  {
    (void)AcquireRUnitBlueprintAITypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintAITypeInfo);
  }

  /**
   * Address: 0x00BC8B70 (FUN_00BC8B70, register_RUnitBlueprintDefenseTypeInfo)
   */
  int register_RUnitBlueprintDefenseTypeInfo()
  {
    (void)AcquireRUnitBlueprintDefenseTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintDefenseTypeInfo);
  }

  /**
   * Address: 0x00BC8B90 (FUN_00BC8B90, register_RUnitBlueprintIntelTypeInfo)
   */
  int register_RUnitBlueprintIntelTypeInfo()
  {
    (void)AcquireRUnitBlueprintIntelTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintIntelTypeInfo);
  }

  /**
   * Address: 0x00BC8BB0 (FUN_00BC8BB0, register_RUnitBlueprintEconomyTypeInfo)
   */
  int register_RUnitBlueprintEconomyTypeInfo()
  {
    (void)AcquireRUnitBlueprintEconomyTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintEconomyTypeInfo);
  }

  /**
   * Address: 0x00BC8BF0 (FUN_00BC8BF0, register_RUnitBlueprintWeaponTypeInfo)
   */
  int register_RUnitBlueprintWeaponTypeInfo()
  {
    (void)AcquireRUnitBlueprintWeaponTypeInfo();
    return std::atexit(&cleanup_RUnitBlueprintWeaponTypeInfo);
  }
} // namespace moho
