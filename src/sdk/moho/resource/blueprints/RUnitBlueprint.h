#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/resource/RResId.h"
#include "moho/sim/SMinMax.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CRandomStream;
  class RRuleGameRules;
  class RRuleGameRulesImpl;
  struct RUnitBlueprint;
  struct SCoordsVec2;

  /**
   * Address: 0x00520590 (FUN_00520590)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintGeneral` (`sizeof = 0x84`).
   *
   * Evidence:
   * - 0x00520660 (FUN_00520660) registers `CommandCaps` at +0x00,
   *   `ToggleCaps` at +0x04, and `CapCost` at +0x7C.
   */
  struct RUnitBlueprintGeneral
  {
    /**
     * Address: 0x0051EE10 (FUN_0051EE10)
     * Mangled: ??0RUnitBlueprintGeneral@Moho@@QAE@XZ
     *
     * What it does:
     * Initializes capability bitmasks and upgrade-id defaults for new unit
     * blueprint records.
     */
    RUnitBlueprintGeneral();

    /**
     * Address: 0x0051E6F0 (FUN_0051E6F0, Moho::RUnitBlueprintGeneral::~RUnitBlueprintGeneral)
     * Mangled: ??1RUnitBlueprintGeneral@Moho@@QAE@XZ
     *
     * What it does:
     * Releases upgrade/seed string-id lanes owned by general blueprint
     * metadata.
     */
    ~RUnitBlueprintGeneral();

    ERuleBPUnitCommandCaps CommandCaps; // +0x00
    ERuleBPUnitToggleCaps ToggleCaps;   // +0x04
    RResId UpgradesTo;                  // +0x08
    RResId UpgradesFrom;                // +0x24
    RResId UpgradesFromBase;            // +0x40
    RResId SeedUnit;                    // +0x5C
    std::int32_t QuickSelectPriority;   // +0x78
    float CapCost;                      // +0x7C
    std::int32_t SelectionPriority;     // +0x80
  };

  /**
   * Address: 0x00520790 (FUN_00520790)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintDisplay` (`sizeof = 0x78`).
   *
   * Evidence:
   * - 0x00520860 (FUN_00520860) registers:
   *   - `DisplayName` at +0x00
   *   - `MeshBlueprint` at +0x1C
   *   - `PlaceholderMeshName` at +0x38
   *   - `IconName` at +0x54
   *   - `UniformScale` at +0x70
   *   - `SpawnRandomRotation` at +0x74
   *   - `HideLifebars` at +0x75
   */
  struct RUnitBlueprintDisplay
  {
    /**
     * Address: 0x0051E770 (FUN_0051E770, Moho::RUnitBlueprintDisplay::~RUnitBlueprintDisplay)
     * Mangled: ??1RUnitBlueprintDisplay@Moho@@QAE@XZ
     *
     * What it does:
     * Releases display-name, mesh, placeholder, and icon string-id lanes.
     */
    ~RUnitBlueprintDisplay();

    msvc8::string DisplayName;         // +0x00
    RResId MeshBlueprint;              // +0x1C
    msvc8::string PlaceholderMeshName; // +0x38
    RResId IconName;                   // +0x54
    float UniformScale;                // +0x70
    std::uint8_t SpawnRandomRotation;  // +0x74
    std::uint8_t HideLifebars;         // +0x75
    std::uint8_t pad_0076_0078[0x02];  // +0x76
  };

  enum ERuleBPUnitMovementType : std::int32_t
  {
    RULEUMT_None = 0,
    RULEUMT_Land = 1,
    RULEUMT_Air = 2,
    RULEUMT_Water = 3,
    RULEUMT_Biped = 4,
    RULEUMT_SurfacingSub = 5,
    RULEUMT_Amphibious = 6,
    RULEUMT_Hover = 7,
    RULEUMT_AmphibiousFloating = 8,
    RULEUMT_Special = 9,
  };

  enum ERuleBPUnitBuildRestriction : std::int32_t
  {
    RULEUBR_None = 0,
    RULEUBR_Bridge = 1,
    RULEUBR_OnMassDeposit = 2,
    RULEUBR_OnHydrocarbonDeposit = 3,
  };

  enum UnitWeaponRangeCategory : std::int32_t
  {
    UWRC_Undefined = 0,
    UWRC_DirectFire = 1,
    UWRC_IndirectFire = 2,
    UWRC_AntiAir = 3,
    UWRC_AntiNavy = 4,
    UWRC_Countermeasure = 5,
  };

  enum ERuleBPUnitWeaponBallisticArc : std::int32_t
  {
    RULEUBA_None = 0,
    RULEUBA_LowArc = 1,
    RULEUBA_HighArc = 2,
  };

  enum ERuleBPUnitWeaponTargetType : std::int32_t
  {
    RULEWTT_Unit = 0,
    RULEWTT_Projectile = 1,
    RULEWTT_Prop = 2,
  };

  /**
   * Occupy-rectangle entry used by `Physics.OccupyRects`.
   *
   * Evidence:
   * - `?ExecuteOccupyGround@Unit@Moho@@QAEXXZ` (0x10286F50) iterates
   *   `blueprint + 0x310` as 4-float entries and computes world rects:
   *   left/right from `offsetX +- halfSizeX`, top/bottom from `offsetZ +- halfSizeZ`.
   */
  struct RUnitBlueprintOccupyRect
  {
    float CenterOffsetX; // +0x00
    float CenterOffsetZ; // +0x04
    float HalfSizeX;     // +0x08
    float HalfSizeZ;     // +0x0C
  };

  /**
   * Raised platform quad entry used by `Physics.RaisedPlatforms`.
   *
   * Evidence:
   * - `?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ` (0x006AC600)
   *   iterates `blueprint->mPhysics.mRaisedPlatforms` as 12-float entries
   *   and renders four world-space vertices (p0..p3).
   */
  struct RUnitBlueprintRaisedPlatform
  {
    float Vertex0X; // +0x00
    float Vertex0Y; // +0x04
    float Vertex0Z; // +0x08
    float Vertex1X; // +0x0C
    float Vertex1Y; // +0x10
    float Vertex1Z; // +0x14
    float Vertex2X; // +0x18
    float Vertex2Y; // +0x1C
    float Vertex2Z; // +0x20
    float Vertex3X; // +0x24
    float Vertex3Y; // +0x28
    float Vertex3Z; // +0x2C
  };

  /**
   * Address: 0x00520970 (FUN_00520970)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintPhysics` (`sizeof = 0xB8`).
   *
   * Evidence:
   * - 0x00520A40 (FUN_00520A40) field registration for the full block.
   * - 0x1010D660 (`RUnitBlueprint::GetSkirtRect`) confirms:
   *   - `SkirtOffsetX` at absolute `+0x27C`
   *   - `SkirtOffsetZ` at absolute `+0x280`
   *   - `SkirtSizeX` at absolute `+0x284`
   *   - `SkirtSizeZ` at absolute `+0x288`
   * - 0x005AA060 / 0x005ABED0 (`CAiPathFinder` setup/load) copy
   *   blueprint absolute `+0x2FC` and `+0x300` into runtime pathfinder state.
   * - 0x1010C1A0 (`RUnitBlueprintPhysics` copy-ctor in MohoEngine) copies
   *   `+0x84` and `+0x88` as 32-bit words.
   * - 0x0051F260 (`RUnitBlueprintPhysics::ComputeDerivedQuantities`) writes
   *   `+0x84` / `+0x88` with `RRuleGameRules::FindFootprint` return pointers.
   * - 0x10286F50 (`Unit::ExecuteOccupyGround`) confirms `OccupyRects` at absolute `+0x310`.
   * - 0x006AC600 (`Unit::DebugShowRaisedPlatforms`) confirms `RaisedPlatforms` at absolute `+0x320`.
   */
  struct RUnitBlueprintPhysics
  {
    /**
     * Address: 0x0051F090 (FUN_0051F090, Moho::RUnitBlueprintPhysics::RUnitBlueprintPhysics)
     *
     * What it does:
     * Initializes movement/skirt/footprint defaults and clears occupancy/
     * raised-platform vector lanes.
     */
    RUnitBlueprintPhysics();

    /**
     * Address: 0x0051E7F0 (FUN_0051E7F0, Moho::RUnitBlueprintPhysics::~RUnitBlueprintPhysics)
     * Mangled: ??1RUnitBlueprintPhysics@Moho@@QAE@XZ
     *
     * What it does:
     * Releases occupancy and raised-platform vector storage lanes.
     */
    ~RUnitBlueprintPhysics();

    std::uint8_t FlattenSkirt;                                   // +0x00
    std::uint8_t pad_0001_0004[0x03];                            // +0x01
    float SkirtOffsetX;                                          // +0x04
    float SkirtOffsetZ;                                          // +0x08
    float SkirtSizeX;                                            // +0x0C
    float SkirtSizeZ;                                            // +0x10
    float MaxGroundVariation;                                    // +0x14
    ERuleBPUnitMovementType MotionType;                          // +0x18
    ERuleBPUnitMovementType AltMotionType;                       // +0x1C
    std::uint8_t StandUpright;                                   // +0x20
    std::uint8_t SinkLower;                                      // +0x21
    std::uint8_t RotateBodyWhileMoving;                          // +0x22
    std::uint8_t pad_0023_0024[0x01];                            // +0x23
    float DiveSurfaceSpeed;                                      // +0x24
    float MaxSpeed;                                              // +0x28
    float MaxSpeedReverse;                                       // +0x2C
    float MaxAcceleration;                                       // +0x30
    float MaxBrake;                                              // +0x34
    float MaxSteerForce;                                         // +0x38
    float BankingSlope;                                          // +0x3C
    float RollStability;                                         // +0x40
    float RollDamping;                                           // +0x44
    float WobbleFactor;                                          // +0x48
    float WobbleSpeed;                                           // +0x4C
    float TurnRadius;                                            // +0x50
    float TurnRate;                                              // +0x54
    float TurnFacingRate;                                        // +0x58
    std::uint8_t RotateOnSpot;                                   // +0x5C
    std::uint8_t pad_005D_0060[0x03];                            // +0x5D
    float RotateOnSpotThreshold;                                 // +0x60
    float Elevation;                                             // +0x64
    float AttackElevation;                                       // +0x68
    float CatchUpAcc;                                            // +0x6C
    float BackUpDistance;                                        // +0x70
    float LayerChangeOffsetHeight;                               // +0x74
    float LayerTransitionDuration;                               // +0x78
    std::int32_t BuildOnLayerCapsMask;                           // +0x7C (`ELayer` bitmask)
    ERuleBPUnitBuildRestriction BuildRestriction;                // +0x80
    const SFootprint* ResolvedFootprint;                         // +0x84
    const SFootprint* ResolvedAltFootprint;                      // +0x88
    float FuelUseTime;                                           // +0x8C
    float FuelRechargeRate;                                      // +0x90
    float GroundCollisionOffset;                                 // +0x94
    msvc8::vector<RUnitBlueprintOccupyRect> OccupyRects;         // +0x98
    msvc8::vector<RUnitBlueprintRaisedPlatform> RaisedPlatforms; // +0xA8

    /**
     * Address: 0x0051F260 (FUN_0051F260)
     * Mangled:
     * ?ComputeDerivedQuantities@RUnitBlueprintPhysics@Moho@@QAEXPAVRRuleGameRules@2@PBDAAVREntityBlueprint@2@@Z
     *
     * What it does:
     * Computes derived movement/footprint/skirt values and resolves runtime
     * footprint pointers using rule-game tables.
     */
    void ComputeDerivedQuantities(RRuleGameRules* gameRules, const char* blueprintName, REntityBlueprint& ownerEntity);
  };

  /**
   * Address: 0x00521BE0 (FUN_00521BE0)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintIntel` (`sizeof = 0x38`).
   *
   * Evidence:
   * - 0x00521CB0 (FUN_00521CB0) registers full Intel member set and offsets.
   * - Primitive helper mapping from type-info builders:
   *   - `FUN_0040E020` (`TypeDescriptor_00f5bf98`) => `unsigned int`
   *   - `FUN_00510DD0` (`TypeDescriptor_00f5f7c4`) => `bool`
   *   - `FUN_0050D010` (`TypeDescriptor_00f5f7b8`) => `unsigned char`
   * - `FUN_00525620` uses `Moho::SMinMax<>::RTTI_Type_Descriptor` at +0x24 and +0x30.
   */
  struct RUnitBlueprintIntel
  {
    std::uint32_t VisionRadius;            // +0x00
    std::uint32_t WaterVisionRadius;       // +0x04
    std::uint32_t RadarRadius;             // +0x08
    std::uint32_t SonarRadius;             // +0x0C
    std::uint32_t OmniRadius;              // +0x10
    std::uint8_t RadarStealth;             // +0x14
    std::uint8_t SonarStealth;             // +0x15
    std::uint8_t Cloak;                    // +0x16
    std::uint8_t ShowIntelOnSelect;        // +0x17
    std::uint32_t RadarStealthFieldRadius; // +0x18
    std::uint32_t SonarStealthFieldRadius; // +0x1C
    std::uint32_t CloakFieldRadius;        // +0x20
    SMinMax<std::uint32_t> JamRadius;      // +0x24
    std::uint8_t JammerBlips;              // +0x2C
    std::uint8_t pad_002D_0030[0x03];      // +0x2D
    SMinMax<std::uint32_t> SpoofRadius;    // +0x30
  };

  /**
   * Address: 0x00520E10 (FUN_00520E10)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintAir` (`sizeof = 0x90`).
   *
   * Evidence:
   * - 0x00520F40 (FUN_00520F40) registers full Air member set and offsets.
   * - Primitive helper mapping:
   *   - `FUN_00510DD0` => `bool` slots (`TypeDescriptor_00f5f7c4`)
   *   - `FUN_0040DFA0` => `float` slots (`TypeDescriptor_00f5c858`)
   */
  struct RUnitBlueprintAir
  {
    /**
     * Address: 0x0051EF00 (FUN_0051EF00, Moho::RUnitBlueprintAir::RUnitBlueprintAir)
     *
     * What it does:
     * Initializes air-movement tuning, circling heuristics, and engagement
     * defaults for unit blueprints.
     */
    RUnitBlueprintAir();

    std::uint8_t CanFly;                  // +0x00
    std::uint8_t Winged;                  // +0x01
    std::uint8_t FlyInWater;              // +0x02
    std::uint8_t pad_0003_0004[0x01];     // +0x03
    float AutoLandTime;                   // +0x04
    float MaxAirspeed;                    // +0x08
    float MinAirspeed;                    // +0x0C
    float TurnSpeed;                      // +0x10
    float CombatTurnSpeed;                // +0x14
    float StartTurnDistance;              // +0x18
    float TightTurnMultiplier;            // +0x1C
    float SustainedTurnThreshold;         // +0x20
    float LiftFactor;                     // +0x24
    float BankFactor;                     // +0x28
    std::uint8_t BankForward;             // +0x2C
    std::uint8_t pad_002D_0030[0x03];     // +0x2D
    float EngageDistance;                 // +0x30
    float BreakOffTrigger;                // +0x34
    float BreakOffDistance;               // +0x38
    std::uint8_t BreakOffIfNearNewTarget; // +0x3C
    std::uint8_t pad_003D_0040[0x03];     // +0x3D
    float KMove;                          // +0x40
    float KMoveDamping;                   // +0x44
    float KLift;                          // +0x48
    float KLiftDamping;                   // +0x4C
    float KTurn;                          // +0x50
    float KTurnDamping;                   // +0x54
    float KRoll;                          // +0x58
    float KRollDamping;                   // +0x5C
    float CirclingTurnMult;               // +0x60
    float CirclingRadiusChangeMinRatio;   // +0x64
    float CirclingRadiusChangeMaxRatio;   // +0x68
    float CirclingRadiusVsAirMult;        // +0x6C
    float CirclingElevationChangeRatio;   // +0x70
    float CirclingFlightChangeFrequency;  // +0x74
    std::uint8_t CirclingDirChange;       // +0x78
    std::uint8_t HoverOverAttack;         // +0x79
    std::uint8_t pad_007A_007C[0x02];     // +0x7A
    float RandomBreakOffDistanceMult;     // +0x7C
    float RandomMinChangeCombatStateTime; // +0x80
    float RandomMaxChangeCombatStateTime; // +0x84
    float TransportHoverHeight;           // +0x88
    float PredictAheadForBombDrop;        // +0x8C
  };

  /**
   * Address: 0x00521300 (FUN_00521300)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintTransport` (`sizeof = 0x28`).
   *
   * Evidence:
   * - 0x00521430 (FUN_00521430) registers full Transport member set and offsets.
   * - Primitive helper mapping:
   *   - `FUN_004EDC10` => `int` slots (`TypeDescriptor_00f5f794`)
   *   - `FUN_00510DD0` => `bool` slot (`TypeDescriptor_00f5f7c4`)
   *   - `FUN_0040DFA0` => `float` slot (`TypeDescriptor_00f5c858`)
   */
  struct RUnitBlueprintTransport
  {
    std::int32_t TransportClass;      // +0x00
    std::int32_t ClassGenericUpTo;    // +0x04
    std::int32_t Class2AttachSize;    // +0x08
    std::int32_t Class3AttachSize;    // +0x0C
    std::int32_t Class4AttachSize;    // +0x10
    std::int32_t ClassSAttachSize;    // +0x14
    std::uint8_t AirClass;            // +0x18
    std::uint8_t pad_0019_001C[0x03]; // +0x19
    std::int32_t StorageSlots;        // +0x1C
    std::int32_t DockingSlots;        // +0x20
    float RepairRate;                 // +0x24
  };

  /**
   * Address: 0x005217D0 (FUN_005217D0)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintDefenseShield` (`sizeof = 0x08`).
   *
   * Evidence:
   * - 0x00521830 (FUN_00521830) registers:
   *   - `ShieldSize` at +0x00
   *   - `RegenAssistMult` at +0x04
   */
  struct RUnitBlueprintDefenseShield
  {
    float ShieldSize;      // +0x00
    float RegenAssistMult; // +0x04
  };

  /**
   * Address: 0x00521980 (FUN_00521980)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintDefense` (`sizeof = 0x40`).
   *
   * Evidence:
   * - 0x00521AB0 (FUN_00521AB0) registers full Defense member set and offsets.
   * - Primitive helper mapping:
   *   - `FUN_0040DFA0` => `float` slots (`TypeDescriptor_00f5c858`)
   *   - `FUN_0050E1F0` => `msvc8::string` slot (`std::basic_string<>::RTTI_Type_Descriptor`)
   *   - `FUN_005255A0` => nested `RUnitBlueprintDefenseShield` at +0x38.
   */
  struct RUnitBlueprintDefense
  {
    float MaxHealth;                    // +0x00
    float Health;                       // +0x04
    float RegenRate;                    // +0x08
    float AirThreatLevel;               // +0x0C
    float SurfaceThreatLevel;           // +0x10
    float SubThreatLevel;               // +0x14
    float EconomyThreatLevel;           // +0x18
    msvc8::string ArmorType;            // +0x1C
    RUnitBlueprintDefenseShield Shield; // +0x38
  };

  /**
   * Address: 0x00521530 (FUN_00521530)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintAI` (`sizeof = 0x74`).
   *
   * Evidence:
   * - 0x00521660 (FUN_00521660) registers full AI member set and offsets.
   * - Primitive helper mapping:
   *   - `FUN_0040DFA0` => `float` slots (`TypeDescriptor_00f5c858`)
   *   - `FUN_00510DD0` => `bool` slots (`TypeDescriptor_00f5f7c4`)
   *   - `FUN_0050E1F0` => `msvc8::string` slots (`std::basic_string<>::RTTI_Type_Descriptor`)
   *   - `FUN_00513230` => `std::vector<>` slot (`std::vector<>::RTTI_Type_Descriptor`)
   */
  struct RUnitBlueprintAI
  {
    /**
     * Address: 0x0051F7D0 (FUN_0051F7D0, ??0RUnitBlueprintAI@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes AI blueprint defaults for guard behavior, refueling, and
     * transport/beacon metadata.
     */
    RUnitBlueprintAI();

    /**
     * Address: 0x0051E870 (FUN_0051E870, ??1RUnitBlueprintAI@Moho@@QAE@@Z)
     *
     * What it does:
     * Destroys target-bone strings, releases heap-backed bone storage, and
     * resets beacon/guard formation names to their legacy empty-state layout.
     */
    ~RUnitBlueprintAI();

    float GuardScanRadius;                    // +0x00
    float GuardReturnRadius;                  // +0x04
    float StagingPlatformScanRadius;          // +0x08
    std::uint8_t ShowAssistRangeOnSelect;     // +0x0C
    std::uint8_t pad_000D_0010[0x03];         // +0x0D
    msvc8::string GuardFormationName;         // +0x10
    std::uint8_t NeedUnpack;                  // +0x2C
    std::uint8_t InitialAutoMode;             // +0x2D
    std::uint8_t pad_002E_0030[0x02];         // +0x2E
    msvc8::string BeaconName;                 // +0x30
    msvc8::vector<msvc8::string> TargetBones; // +0x4C
    float RefuelingMultiplier;                // +0x5C
    float RefuelingRepairAmount;              // +0x60
    float RepairConsumeEnergy;                // +0x64
    float RepairConsumeMass;                  // +0x68
    std::uint8_t AutoSurfaceToAttack;         // +0x6C
    std::uint8_t pad_006D_0070[0x03];         // +0x6D
    float AttackAngle;                        // +0x70
  };

  /**
   * Address: 0x00522270 (FUN_00522270)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintWeapon` (`sizeof = 0x184`).
   *
   * Evidence:
   * - 0x00522340 (FUN_00522340) registers the reflected weapon fields.
   * - 0x0051E970 callsite family writes:
   *   - owner blueprint pointer at +0x00
   *   - stable weapon index at +0x04
   */
  struct RUnitBlueprintWeapon
  {
    RUnitBlueprint* OwnerBlueprint;                 // +0x00
    std::uint32_t WeaponIndex;                      // +0x04
    msvc8::string Label;                            // +0x08
    msvc8::string DisplayName;                      // +0x24
    UnitWeaponRangeCategory RangeCategory;          // +0x40
    std::uint8_t DummyWeapon;                       // +0x44
    std::uint8_t PrefersPrimaryWeaponTarget;        // +0x45
    std::uint8_t StopOnPrimaryWeaponBusy;           // +0x46
    std::uint8_t SlavedToBody;                      // +0x47
    float SlavedToBodyArcRange;                     // +0x48
    std::uint8_t AutoInitiateAttackCommand;         // +0x4C
    std::uint8_t pad_004D_0050[0x03];               // +0x4D
    float TargetCheckInterval;                      // +0x50
    std::uint8_t AlwaysRecheckTarget;               // +0x54
    std::uint8_t pad_0055_0058[0x03];               // +0x55
    float MinRadius;                                // +0x58
    float MaxRadius;                                // +0x5C
    float MaximumBeamLength;                        // +0x60
    float EffectiveRadius;                          // +0x64
    float MaxHeightDiff;                            // +0x68
    float TrackingRadius;                           // +0x6C
    float HeadingArcCenter;                         // +0x70
    float HeadingArcRange;                          // +0x74
    float FiringTolerance;                          // +0x78
    float FiringRandomness;                         // +0x7C
    float RequiresEnergy;                           // +0x80
    float RequiresMass;                             // +0x84
    float MuzzleVelocity;                           // +0x88
    float MuzzleVelocityRandom;                     // +0x8C
    float MuzzleVelocityReduceDistance;             // +0x90
    std::uint8_t LeadTarget;                        // +0x94
    std::uint8_t pad_0095_0098[0x03];               // +0x95
    float ProjectileLifetime;                       // +0x98
    float ProjectileLifetimeUsesMultiplier;         // +0x9C
    float Damage;                                   // +0xA0
    float DamageRadius;                             // +0xA4
    msvc8::string DamageType;                       // +0xA8
    float RateOfFire;                               // +0xC4
    RResId ProjectileId;                            // +0xC8
    ERuleBPUnitWeaponBallisticArc BallisticArc;     // +0xE4
    msvc8::string TargetRestrictOnlyAllow;          // +0xE8
    msvc8::string TargetRestrictDisallow;           // +0x104
    std::uint8_t ManualFire;                        // +0x120
    std::uint8_t NukeWeapon;                        // +0x121
    std::uint8_t OverChargeWeapon;                  // +0x122
    std::uint8_t NeedPrep;                          // +0x123
    std::uint8_t CountedProjectile;                 // +0x124
    std::uint8_t pad_0125_0128[0x03];               // +0x125
    std::int32_t MaxProjectileStorage;              // +0x128
    std::uint8_t IgnoresAlly;                       // +0x12C
    std::uint8_t pad_012D_0130[0x03];               // +0x12D
    ERuleBPUnitWeaponTargetType TargetType;         // +0x130
    std::int32_t AttackGroundTries;                 // +0x134
    std::uint8_t AimsStraightOnDisable;             // +0x138
    std::uint8_t Turreted;                          // +0x139
    std::uint8_t YawOnlyOnTarget;                   // +0x13A
    std::uint8_t AboveWaterFireOnly;                // +0x13B
    std::uint8_t BelowWaterFireOnly;                // +0x13C
    std::uint8_t AboveWaterTargetsOnly;             // +0x13D
    std::uint8_t BelowWaterTargetsOnly;             // +0x13E
    std::uint8_t ReTargetOnMiss;                    // +0x13F
    std::uint8_t NeedToComputeBombDrop;             // +0x140
    std::uint8_t pad_0141_0144[0x03];               // +0x141
    float BombDropThreshold;                        // +0x144
    std::uint8_t UseFiringSolutionInsteadOfAimBone; // +0x148
    std::uint8_t IgnoreIfDisabled;                  // +0x149
    std::uint8_t CannotAttackGround;                // +0x14A
    std::uint8_t pad_014B_014C[0x01];               // +0x14B
    msvc8::string UIMinRangeVisualId;               // +0x14C
    msvc8::string UIMaxRangeVisualId;               // +0x168

    /**
     * Address: 0x0051F4C0 (FUN_0051F4C0)
     *
     * What it does:
     * Restores default weapon-blueprint runtime state, including canonical
     * range, ballistic, and damage-profile defaults.
     */
    RUnitBlueprintWeapon();

    /**
     * Address: 0x00524E50 (FUN_00524E50, Moho::RUnitBlueprintWeapon::RUnitBlueprintWeapon)
     *
     * What it does:
     * Copy-constructs one weapon blueprint lane, including all resource-id,
     * string, and scalar gameplay fields.
     */
    RUnitBlueprintWeapon(const RUnitBlueprintWeapon& other);

    /**
     * Address: 0x00523F90 (FUN_00523F90, Moho::RUnitBlueprintWeapon::~RUnitBlueprintWeapon)
     *
     * What it does:
     * Releases owned string lanes in reverse declaration order.
     */
    ~RUnitBlueprintWeapon();

    /**
     * Address: 0x1010E1C0 (FUN_1010E1C0)
     *
     * What it does:
     * Stores runtime owner/index metadata after a weapon record is materialized.
     */
    void PostInit(RUnitBlueprint* ownerBlueprint, std::uint32_t weaponIndex) noexcept;

    /**
     * Address: 0x1010E150 (FUN_1010E150)
     * Mangled: ?GetMuzzleVelocity@RUnitBlueprintWeapon@Moho@@QBEMMPAVCRandomStream@2@@Z
     *
     * What it does:
     * Returns muzzle velocity with optional gaussian jitter and
     * short-range attenuation against `MuzzleVelocityReduceDistance`.
     */
    float GetMuzzleVelocity(float targetDistance, CRandomStream* randomStream) const noexcept;
  };

  /**
   * Address: 0x00525C80 (FUN_00525C80)
   *
   * What it does:
   * Registers the `Weapons` section at `RUnitBlueprint + 0x4D4`.
   *
   * Evidence:
   * - Runtime iteration reads weapon storage from +0x4D8/+0x4DC with element stride `0x184`.
   * - The section descriptor uses `std::vector<>` RTTI type.
   * - FA-side reconstruction has no direct read/write users of `+0x4E4`; modeled as unresolved FA-only dword.
   * - MohoEngine's module-local `RUnitBlueprint` (`sizeof=0x558`) places economy immediately after the vector (no
   * equivalent tail slot).
   */
  struct RUnitBlueprintWeapons
  {
    msvc8::vector<RUnitBlueprintWeapon> WeaponBlueprints; // +0x00
    std::uint32_t UnresolvedFaTailWord;                   // +0x10 (FA-only; semantics unresolved)
  };

  /**
   * Runtime category-resolution state nested in `RUnitBlueprintEconomy`.
   *
   * Evidence:
   * - 0x1010E390 (`RUnitBlueprintEconomy` ctor) initializes:
   *   - `RuleGameRules` at +0x00
   *   - inline category word buffer pointers at +0x10..+0x1C
   *   - inline storage window at +0x20..+0x27
   * - 0x1010CD70 (`RUnitBlueprintEconomy` dtor) and 0x1010CF40 helper
   *   manage the +0x10..+0x1C pointer window.
   */
  struct RUnitBlueprintEconomyCategoryCache
  {
    RRuleGameRules* RuleGameRules;   // +0x00
    std::uint32_t UnresolvedWord04;  // +0x04
    std::uint32_t RuntimeWord08;     // +0x08
    void* RuntimeVectorProxy;        // +0x0C
    std::uint32_t* First;            // +0x10
    std::uint32_t* Last;             // +0x14
    std::uint32_t* End;              // +0x18
    std::uint32_t* InlineStoragePtr; // +0x1C
    std::uint32_t InlineStorage[2];  // +0x20
  };

  /**
   * Address: 0x00521E70 (FUN_00521E70)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprintEconomy` (`sizeof = 0x80`).
   *
   * Evidence:
   * - 0x00521F40 (FUN_00521F40) registers reflected fields.
   * - 0x1010E390 / 0x1010CEB0 / 0x1010CD70 provide ctor/assign/dtor evidence
   *   for runtime-only category cache fields between +0x40 and +0x67.
   */
  struct RUnitBlueprintEconomy
  {
    /**
     * Address: 0x0051F990 (FUN_0051F990, Moho::RUnitBlueprintEconomy::RUnitBlueprintEconomy)
     * Mangled: ??0RUnitBlueprintEconomy@Moho@@QAE@PAVRRuleGameRules@1@@Z
     *
     * What it does:
     * Seeds economy defaults, clears category-string vectors, and initializes
     * runtime category-cache inline storage using one rules-owner lane.
     */
    RUnitBlueprintEconomy(RRuleGameRules* rules = nullptr);

    /**
     * Address: 0x0051E8F0 (FUN_0051E8F0, Moho::RUnitBlueprintEconomy::~RUnitBlueprintEconomy)
     * Mangled: ??1RUnitBlueprintEconomy@Moho@@QAE@@Z
     *
     * What it does:
     * Releases dynamic category-cache words and restores inline storage lanes
     * before member vector destructors run.
     */
    ~RUnitBlueprintEconomy();

    float BuildCostEnergy;                            // +0x00
    float BuildCostMass;                              // +0x04
    float BuildRate;                                  // +0x08
    float BuildTime;                                  // +0x0C
    float StorageEnergy;                              // +0x10
    float StorageMass;                                // +0x14
    std::uint8_t NaturalProducer;                     // +0x18
    std::uint8_t pad_0019_001C[0x03];                 // +0x19
    msvc8::vector<msvc8::string> BuildableCategories; // +0x1C
    msvc8::vector<msvc8::string> RebuildBonusIds;     // +0x2C
    std::uint32_t UnresolvedWord3C;                   // +0x3C
    RUnitBlueprintEconomyCategoryCache CategoryCache; // +0x40
    float InitialRallyX;                              // +0x68
    float InitialRallyZ;                              // +0x6C
    std::uint8_t NeedToFaceTargetToBuild;             // +0x70
    std::uint8_t pad_0071_0074[0x03];                 // +0x71
    float SacrificeMassMult;                          // +0x74
    float SacrificeEnergyMult;                        // +0x78
    float MaxBuildDistance;                           // +0x7C
  };

  /**
   * Address: 0x005229A0 (FUN_005229A0)
   *
   * What it does:
   * Reflection type init for `RUnitBlueprint` (`sizeof = 0x568`).
   *
   * Evidence:
   * - 0x00525820 (FUN_00525820) links `REntityBlueprint` as base.
   * - 0x00525880 (FUN_00525880) places `General` at +0x17C.
   * - 0x00525900 (FUN_00525900) places `Display` at +0x200.
   */
  struct RUnitBlueprint : public REntityBlueprint
  {
    static gpg::RType* sPointerType;

    RUnitBlueprintGeneral General;     // +0x17C
    RUnitBlueprintDisplay Display;     // +0x200
    RUnitBlueprintPhysics Physics;     // +0x278
    RUnitBlueprintIntel Intel;         // +0x330
    RUnitBlueprintAir Air;             // +0x368
    RUnitBlueprintTransport Transport; // +0x3F8
    RUnitBlueprintDefense Defense;     // +0x420
    RUnitBlueprintAI AI;               // +0x460
    RUnitBlueprintWeapons Weapons;     // +0x4D4
    RUnitBlueprintEconomy Economy;     // +0x4E8

    /**
     * Address: 0x0051E480 (FUN_0051E480, Moho::RUnitBlueprint::RUnitBlueprint)
     * Mangled: ??0RUnitBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Constructs unit-blueprint subsection lanes on top of
     * `REntityBlueprint`, seeds gameplay defaults, and enables life-bar
     * rendering.
     */
    RUnitBlueprint(RRuleGameRules* owner, const RResId& resId);

    /**
     * Address: 0x0051E980 (FUN_0051E980)
     * Mangled: ??1RUnitBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Destroys unit-blueprint subsection lanes in reverse order, then
     * tears down the `REntityBlueprint` base.
     */
    ~RUnitBlueprint();

    /**
     * Address: 0x0051EA40 (FUN_0051EA40)
     *
     * What it does:
     * Runs base entity-blueprint initialization, computes derived unit physics,
     * applies air/display defaults, and post-initializes weapon records.
     */
    void OnInitBlueprint();

    /**
     * Address: 0x00529E90 (FUN_00529E90, Moho::RUnitBlueprint::AddEconomyRestrictions)
     *
     * What it does:
     * Parses each `Economy.BuildableCategories` expression and unions the
     * resulting category bits into the runtime economy restriction cache.
     */
    void AddEconomyRestrictions(RRuleGameRulesImpl* rules);

    /**
     * Address: 0x005A1330 (FUN_005A1330, Moho::RUnitBlueprint::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `RUnitBlueprint*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x0051E400 (FUN_0051E400, ?StaticGetClass@RUnitBlueprint@Moho@@SAPAVRType@gpg@@XZ)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `RUnitBlueprint`.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0051E420 (FUN_0051E420, ?GetClass@RUnitBlueprint@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * What it does:
     * Returns the reflected runtime type descriptor for this
     * `RUnitBlueprint` instance.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0051E440 (FUN_0051E440, ?GetDerivedObjectRef@RUnitBlueprint@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflected object reference handle.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0051E460 (FUN_0051E460)
     * Mangled: ?IsMobile@RUnitBlueprint@Moho@@UBE_NXZ
     *
     * What it does:
     * Returns true when unit physics motion type is not `RULEUMT_None`.
     */
    [[nodiscard]] bool IsMobile() const;

    /**
     * Address: 0x0051E470 (FUN_0051E470)
     * Mangled: ?IsUnitBlueprint@RUnitBlueprint@Moho@@UBEPBV12@XZ
     *
     * What it does:
     * Returns `this` to mark the entity blueprint as a unit blueprint.
     */
    [[nodiscard]] const RUnitBlueprint* IsUnitBlueprint() const;

    /**
     * Address: 0x0051ED80 (FUN_0051ED80)
     * Mangled: ?GetFootprintRect@RUnitBlueprint@Moho@@QBE?AV?$Rect2@H@gpg@@ABUSCoordsVec2@2@@Z
     *
     * What it does:
     * Builds the grid-aligned footprint occupancy rectangle centered around
     * `position` using `mFootprint.{mSizeX,mSizeZ}` extents.
     */
    [[nodiscard]] gpg::Rect2i GetFootprintRect(const SCoordsVec2& position) const;

    /**
     * Address: 0x0051EC50 (FUN_0051EC50)
     * Mangled: ?GetSkirtRect@RUnitBlueprint@Moho@@QBE?AV?$Rect2@M@gpg@@ABUSCoordsVec2@2@@Z
     *
     * What it does:
     * Builds world-space XZ skirt occupancy bounds around `position`, using
     * explicit skirt offsets/sizes when present and falling back to footprint
     * extents otherwise.
     */
    [[nodiscard]] gpg::Rect2f GetSkirtRect(const SCoordsVec2& position) const;
  };

  /**
   * Address: 0x005267A0 (FUN_005267A0, Moho::CopyOccupyRects)
   *
   * What it does:
   * Rebuilds destination `vector<float>` runtime lanes from source occupancy
   * data and copies the full `[begin,end)` float range.
   */
  [[nodiscard]] msvc8::vector<float>* CopyOccupyRects(
    const msvc8::vector<float>& source,
    msvc8::vector<float>& destination
  );

  static_assert(
    offsetof(RUnitBlueprintGeneral, UpgradesTo) == 0x08, "RUnitBlueprintGeneral::UpgradesTo offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintGeneral, UpgradesFrom) == 0x24, "RUnitBlueprintGeneral::UpgradesFrom offset must be 0x24"
  );
  static_assert(
    offsetof(RUnitBlueprintGeneral, UpgradesFromBase) == 0x40,
    "RUnitBlueprintGeneral::UpgradesFromBase offset must be 0x40"
  );
  static_assert(
    offsetof(RUnitBlueprintGeneral, SeedUnit) == 0x5C, "RUnitBlueprintGeneral::SeedUnit offset must be 0x5C"
  );
  static_assert(
    offsetof(RUnitBlueprintGeneral, QuickSelectPriority) == 0x78,
    "RUnitBlueprintGeneral::QuickSelectPriority offset must be 0x78"
  );
  static_assert(offsetof(RUnitBlueprintGeneral, CapCost) == 0x7C, "RUnitBlueprintGeneral::CapCost offset must be 0x7C");
  static_assert(
    offsetof(RUnitBlueprintGeneral, SelectionPriority) == 0x80,
    "RUnitBlueprintGeneral::SelectionPriority offset must be 0x80"
  );
  static_assert(sizeof(RUnitBlueprintGeneral) == 0x84, "RUnitBlueprintGeneral size must be 0x84");
  static_assert(
    offsetof(RUnitBlueprintGeneral, CommandCaps) == 0x00, "RUnitBlueprintGeneral::CommandCaps offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintGeneral, ToggleCaps) == 0x04, "RUnitBlueprintGeneral::ToggleCaps offset must be 0x04"
  );

  static_assert(
    offsetof(RUnitBlueprintDisplay, DisplayName) == 0x00, "RUnitBlueprintDisplay::DisplayName offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, MeshBlueprint) == 0x1C, "RUnitBlueprintDisplay::MeshBlueprint offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, PlaceholderMeshName) == 0x38,
    "RUnitBlueprintDisplay::PlaceholderMeshName offset must be 0x38"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, IconName) == 0x54, "RUnitBlueprintDisplay::IconName offset must be 0x54"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, UniformScale) == 0x70, "RUnitBlueprintDisplay::UniformScale offset must be 0x70"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, SpawnRandomRotation) == 0x74,
    "RUnitBlueprintDisplay::SpawnRandomRotation offset must be 0x74"
  );
  static_assert(
    offsetof(RUnitBlueprintDisplay, HideLifebars) == 0x75, "RUnitBlueprintDisplay::HideLifebars offset must be 0x75"
  );
  static_assert(sizeof(RUnitBlueprintDisplay) == 0x78, "RUnitBlueprintDisplay size must be 0x78");

  static_assert(sizeof(ERuleBPUnitMovementType) == 0x04, "ERuleBPUnitMovementType size must be 0x04");
  static_assert(static_cast<std::int32_t>(RULEUMT_None) == 0, "RULEUMT_None must be 0");
  static_assert(static_cast<std::int32_t>(RULEUMT_Special) == 9, "RULEUMT_Special must be 9");
  static_assert(sizeof(ERuleBPUnitBuildRestriction) == 0x04, "ERuleBPUnitBuildRestriction size must be 0x04");
  static_assert(static_cast<std::int32_t>(RULEUBR_None) == 0, "RULEUBR_None must be 0");
  static_assert(static_cast<std::int32_t>(RULEUBR_OnHydrocarbonDeposit) == 3, "RULEUBR_OnHydrocarbonDeposit must be 3");
  static_assert(sizeof(UnitWeaponRangeCategory) == 0x04, "UnitWeaponRangeCategory size must be 0x04");
  static_assert(static_cast<std::int32_t>(UWRC_Undefined) == 0, "UWRC_Undefined must be 0");
  static_assert(static_cast<std::int32_t>(UWRC_Countermeasure) == 5, "UWRC_Countermeasure must be 5");
  static_assert(sizeof(ERuleBPUnitWeaponBallisticArc) == 0x04, "ERuleBPUnitWeaponBallisticArc size must be 0x04");
  static_assert(static_cast<std::int32_t>(RULEUBA_None) == 0, "RULEUBA_None must be 0");
  static_assert(static_cast<std::int32_t>(RULEUBA_HighArc) == 2, "RULEUBA_HighArc must be 2");
  static_assert(sizeof(ERuleBPUnitWeaponTargetType) == 0x04, "ERuleBPUnitWeaponTargetType size must be 0x04");
  static_assert(static_cast<std::int32_t>(RULEWTT_Unit) == 0, "RULEWTT_Unit must be 0");
  static_assert(static_cast<std::int32_t>(RULEWTT_Prop) == 2, "RULEWTT_Prop must be 2");

  static_assert(
    offsetof(RUnitBlueprintOccupyRect, CenterOffsetX) == 0x00,
    "RUnitBlueprintOccupyRect::CenterOffsetX offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintOccupyRect, CenterOffsetZ) == 0x04,
    "RUnitBlueprintOccupyRect::CenterOffsetZ offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintOccupyRect, HalfSizeX) == 0x08, "RUnitBlueprintOccupyRect::HalfSizeX offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintOccupyRect, HalfSizeZ) == 0x0C, "RUnitBlueprintOccupyRect::HalfSizeZ offset must be 0x0C"
  );
  static_assert(sizeof(RUnitBlueprintOccupyRect) == 0x10, "RUnitBlueprintOccupyRect size must be 0x10");

  static_assert(
    offsetof(RUnitBlueprintRaisedPlatform, Vertex0X) == 0x00,
    "RUnitBlueprintRaisedPlatform::Vertex0X offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintRaisedPlatform, Vertex1X) == 0x0C,
    "RUnitBlueprintRaisedPlatform::Vertex1X offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintRaisedPlatform, Vertex2X) == 0x18,
    "RUnitBlueprintRaisedPlatform::Vertex2X offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintRaisedPlatform, Vertex3X) == 0x24,
    "RUnitBlueprintRaisedPlatform::Vertex3X offset must be 0x24"
  );
  static_assert(sizeof(RUnitBlueprintRaisedPlatform) == 0x30, "RUnitBlueprintRaisedPlatform size must be 0x30");

  static_assert(
    offsetof(RUnitBlueprintPhysics, FlattenSkirt) == 0x00, "RUnitBlueprintPhysics::FlattenSkirt offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, SkirtOffsetX) == 0x04, "RUnitBlueprintPhysics::SkirtOffsetX offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, SkirtOffsetZ) == 0x08, "RUnitBlueprintPhysics::SkirtOffsetZ offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, SkirtSizeX) == 0x0C, "RUnitBlueprintPhysics::SkirtSizeX offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, SkirtSizeZ) == 0x10, "RUnitBlueprintPhysics::SkirtSizeZ offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, MaxGroundVariation) == 0x14,
    "RUnitBlueprintPhysics::MaxGroundVariation offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, MotionType) == 0x18, "RUnitBlueprintPhysics::MotionType offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, AltMotionType) == 0x1C, "RUnitBlueprintPhysics::AltMotionType offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, Elevation) == 0x64, "RUnitBlueprintPhysics::Elevation offset must be 0x64"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, BuildOnLayerCapsMask) == 0x7C,
    "RUnitBlueprintPhysics::BuildOnLayerCapsMask offset must be 0x7C"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, BuildRestriction) == 0x80,
    "RUnitBlueprintPhysics::BuildRestriction offset must be 0x80"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, ResolvedFootprint) == 0x84,
    "RUnitBlueprintPhysics::ResolvedFootprint offset must be 0x84"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, ResolvedAltFootprint) == 0x88,
    "RUnitBlueprintPhysics::ResolvedAltFootprint offset must be 0x88"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, FuelUseTime) == 0x8C, "RUnitBlueprintPhysics::FuelUseTime offset must be 0x8C"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, FuelRechargeRate) == 0x90,
    "RUnitBlueprintPhysics::FuelRechargeRate offset must be 0x90"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, GroundCollisionOffset) == 0x94,
    "RUnitBlueprintPhysics::GroundCollisionOffset offset must be 0x94"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, OccupyRects) == 0x98, "RUnitBlueprintPhysics::OccupyRects offset must be 0x98"
  );
  static_assert(
    offsetof(RUnitBlueprintPhysics, RaisedPlatforms) == 0xA8,
    "RUnitBlueprintPhysics::RaisedPlatforms offset must be 0xA8"
  );
  static_assert(sizeof(RUnitBlueprintPhysics) == 0xB8, "RUnitBlueprintPhysics size must be 0xB8");

  static_assert(
    offsetof(RUnitBlueprintIntel, VisionRadius) == 0x00, "RUnitBlueprintIntel::VisionRadius offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, WaterVisionRadius) == 0x04,
    "RUnitBlueprintIntel::WaterVisionRadius offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, RadarRadius) == 0x08, "RUnitBlueprintIntel::RadarRadius offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, SonarRadius) == 0x0C, "RUnitBlueprintIntel::SonarRadius offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, OmniRadius) == 0x10, "RUnitBlueprintIntel::OmniRadius offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, RadarStealth) == 0x14, "RUnitBlueprintIntel::RadarStealth offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, SonarStealth) == 0x15, "RUnitBlueprintIntel::SonarStealth offset must be 0x15"
  );
  static_assert(offsetof(RUnitBlueprintIntel, Cloak) == 0x16, "RUnitBlueprintIntel::Cloak offset must be 0x16");
  static_assert(
    offsetof(RUnitBlueprintIntel, ShowIntelOnSelect) == 0x17,
    "RUnitBlueprintIntel::ShowIntelOnSelect offset must be 0x17"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, RadarStealthFieldRadius) == 0x18,
    "RUnitBlueprintIntel::RadarStealthFieldRadius offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, SonarStealthFieldRadius) == 0x1C,
    "RUnitBlueprintIntel::SonarStealthFieldRadius offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, CloakFieldRadius) == 0x20, "RUnitBlueprintIntel::CloakFieldRadius offset must be 0x20"
  );
  static_assert(offsetof(RUnitBlueprintIntel, JamRadius) == 0x24, "RUnitBlueprintIntel::JamRadius offset must be 0x24");
  static_assert(
    offsetof(RUnitBlueprintIntel, JammerBlips) == 0x2C, "RUnitBlueprintIntel::JammerBlips offset must be 0x2C"
  );
  static_assert(
    offsetof(RUnitBlueprintIntel, SpoofRadius) == 0x30, "RUnitBlueprintIntel::SpoofRadius offset must be 0x30"
  );
  static_assert(sizeof(RUnitBlueprintIntel) == 0x38, "RUnitBlueprintIntel size must be 0x38");

  static_assert(offsetof(RUnitBlueprintAir, CanFly) == 0x00, "RUnitBlueprintAir::CanFly offset must be 0x00");
  static_assert(offsetof(RUnitBlueprintAir, Winged) == 0x01, "RUnitBlueprintAir::Winged offset must be 0x01");
  static_assert(offsetof(RUnitBlueprintAir, FlyInWater) == 0x02, "RUnitBlueprintAir::FlyInWater offset must be 0x02");
  static_assert(
    offsetof(RUnitBlueprintAir, AutoLandTime) == 0x04, "RUnitBlueprintAir::AutoLandTime offset must be 0x04"
  );
  static_assert(offsetof(RUnitBlueprintAir, MaxAirspeed) == 0x08, "RUnitBlueprintAir::MaxAirspeed offset must be 0x08");
  static_assert(offsetof(RUnitBlueprintAir, MinAirspeed) == 0x0C, "RUnitBlueprintAir::MinAirspeed offset must be 0x0C");
  static_assert(offsetof(RUnitBlueprintAir, TurnSpeed) == 0x10, "RUnitBlueprintAir::TurnSpeed offset must be 0x10");
  static_assert(
    offsetof(RUnitBlueprintAir, CombatTurnSpeed) == 0x14, "RUnitBlueprintAir::CombatTurnSpeed offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, StartTurnDistance) == 0x18, "RUnitBlueprintAir::StartTurnDistance offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, TightTurnMultiplier) == 0x1C,
    "RUnitBlueprintAir::TightTurnMultiplier offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, SustainedTurnThreshold) == 0x20,
    "RUnitBlueprintAir::SustainedTurnThreshold offset must be 0x20"
  );
  static_assert(offsetof(RUnitBlueprintAir, LiftFactor) == 0x24, "RUnitBlueprintAir::LiftFactor offset must be 0x24");
  static_assert(offsetof(RUnitBlueprintAir, BankFactor) == 0x28, "RUnitBlueprintAir::BankFactor offset must be 0x28");
  static_assert(offsetof(RUnitBlueprintAir, BankForward) == 0x2C, "RUnitBlueprintAir::BankForward offset must be 0x2C");
  static_assert(
    offsetof(RUnitBlueprintAir, EngageDistance) == 0x30, "RUnitBlueprintAir::EngageDistance offset must be 0x30"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, BreakOffTrigger) == 0x34, "RUnitBlueprintAir::BreakOffTrigger offset must be 0x34"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, BreakOffDistance) == 0x38, "RUnitBlueprintAir::BreakOffDistance offset must be 0x38"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, BreakOffIfNearNewTarget) == 0x3C,
    "RUnitBlueprintAir::BreakOffIfNearNewTarget offset must be 0x3C"
  );
  static_assert(offsetof(RUnitBlueprintAir, KMove) == 0x40, "RUnitBlueprintAir::KMove offset must be 0x40");
  static_assert(
    offsetof(RUnitBlueprintAir, KMoveDamping) == 0x44, "RUnitBlueprintAir::KMoveDamping offset must be 0x44"
  );
  static_assert(offsetof(RUnitBlueprintAir, KLift) == 0x48, "RUnitBlueprintAir::KLift offset must be 0x48");
  static_assert(
    offsetof(RUnitBlueprintAir, KLiftDamping) == 0x4C, "RUnitBlueprintAir::KLiftDamping offset must be 0x4C"
  );
  static_assert(offsetof(RUnitBlueprintAir, KTurn) == 0x50, "RUnitBlueprintAir::KTurn offset must be 0x50");
  static_assert(
    offsetof(RUnitBlueprintAir, KTurnDamping) == 0x54, "RUnitBlueprintAir::KTurnDamping offset must be 0x54"
  );
  static_assert(offsetof(RUnitBlueprintAir, KRoll) == 0x58, "RUnitBlueprintAir::KRoll offset must be 0x58");
  static_assert(
    offsetof(RUnitBlueprintAir, KRollDamping) == 0x5C, "RUnitBlueprintAir::KRollDamping offset must be 0x5C"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingTurnMult) == 0x60, "RUnitBlueprintAir::CirclingTurnMult offset must be 0x60"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingRadiusChangeMinRatio) == 0x64,
    "RUnitBlueprintAir::CirclingRadiusChangeMinRatio offset must be 0x64"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingRadiusChangeMaxRatio) == 0x68,
    "RUnitBlueprintAir::CirclingRadiusChangeMaxRatio offset must be 0x68"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingRadiusVsAirMult) == 0x6C,
    "RUnitBlueprintAir::CirclingRadiusVsAirMult offset must be 0x6C"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingElevationChangeRatio) == 0x70,
    "RUnitBlueprintAir::CirclingElevationChangeRatio offset must be 0x70"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingFlightChangeFrequency) == 0x74,
    "RUnitBlueprintAir::CirclingFlightChangeFrequency offset must be 0x74"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, CirclingDirChange) == 0x78, "RUnitBlueprintAir::CirclingDirChange offset must be 0x78"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, HoverOverAttack) == 0x79, "RUnitBlueprintAir::HoverOverAttack offset must be 0x79"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, RandomBreakOffDistanceMult) == 0x7C,
    "RUnitBlueprintAir::RandomBreakOffDistanceMult offset must be 0x7C"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, RandomMinChangeCombatStateTime) == 0x80,
    "RUnitBlueprintAir::RandomMinChangeCombatStateTime offset must be 0x80"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, RandomMaxChangeCombatStateTime) == 0x84,
    "RUnitBlueprintAir::RandomMaxChangeCombatStateTime offset must be 0x84"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, TransportHoverHeight) == 0x88,
    "RUnitBlueprintAir::TransportHoverHeight offset must be 0x88"
  );
  static_assert(
    offsetof(RUnitBlueprintAir, PredictAheadForBombDrop) == 0x8C,
    "RUnitBlueprintAir::PredictAheadForBombDrop offset must be 0x8C"
  );
  static_assert(sizeof(RUnitBlueprintAir) == 0x90, "RUnitBlueprintAir size must be 0x90");

  static_assert(
    offsetof(RUnitBlueprintTransport, TransportClass) == 0x00,
    "RUnitBlueprintTransport::TransportClass offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, ClassGenericUpTo) == 0x04,
    "RUnitBlueprintTransport::ClassGenericUpTo offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, Class2AttachSize) == 0x08,
    "RUnitBlueprintTransport::Class2AttachSize offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, Class3AttachSize) == 0x0C,
    "RUnitBlueprintTransport::Class3AttachSize offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, Class4AttachSize) == 0x10,
    "RUnitBlueprintTransport::Class4AttachSize offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, ClassSAttachSize) == 0x14,
    "RUnitBlueprintTransport::ClassSAttachSize offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, AirClass) == 0x18, "RUnitBlueprintTransport::AirClass offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, StorageSlots) == 0x1C, "RUnitBlueprintTransport::StorageSlots offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, DockingSlots) == 0x20, "RUnitBlueprintTransport::DockingSlots offset must be 0x20"
  );
  static_assert(
    offsetof(RUnitBlueprintTransport, RepairRate) == 0x24, "RUnitBlueprintTransport::RepairRate offset must be 0x24"
  );
  static_assert(sizeof(RUnitBlueprintTransport) == 0x28, "RUnitBlueprintTransport size must be 0x28");

  static_assert(
    offsetof(RUnitBlueprintDefenseShield, ShieldSize) == 0x00,
    "RUnitBlueprintDefenseShield::ShieldSize offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintDefenseShield, RegenAssistMult) == 0x04,
    "RUnitBlueprintDefenseShield::RegenAssistMult offset must be 0x04"
  );
  static_assert(sizeof(RUnitBlueprintDefenseShield) == 0x08, "RUnitBlueprintDefenseShield size must be 0x08");

  static_assert(
    offsetof(RUnitBlueprintDefense, MaxHealth) == 0x00, "RUnitBlueprintDefense::MaxHealth offset must be 0x00"
  );
  static_assert(offsetof(RUnitBlueprintDefense, Health) == 0x04, "RUnitBlueprintDefense::Health offset must be 0x04");
  static_assert(
    offsetof(RUnitBlueprintDefense, RegenRate) == 0x08, "RUnitBlueprintDefense::RegenRate offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintDefense, AirThreatLevel) == 0x0C, "RUnitBlueprintDefense::AirThreatLevel offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintDefense, SurfaceThreatLevel) == 0x10,
    "RUnitBlueprintDefense::SurfaceThreatLevel offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintDefense, SubThreatLevel) == 0x14, "RUnitBlueprintDefense::SubThreatLevel offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintDefense, EconomyThreatLevel) == 0x18,
    "RUnitBlueprintDefense::EconomyThreatLevel offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintDefense, ArmorType) == 0x1C, "RUnitBlueprintDefense::ArmorType offset must be 0x1C"
  );
  static_assert(offsetof(RUnitBlueprintDefense, Shield) == 0x38, "RUnitBlueprintDefense::Shield offset must be 0x38");
  static_assert(sizeof(RUnitBlueprintDefense) == 0x40, "RUnitBlueprintDefense size must be 0x40");

  static_assert(
    offsetof(RUnitBlueprintAI, GuardScanRadius) == 0x00, "RUnitBlueprintAI::GuardScanRadius offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, GuardReturnRadius) == 0x04, "RUnitBlueprintAI::GuardReturnRadius offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, StagingPlatformScanRadius) == 0x08,
    "RUnitBlueprintAI::StagingPlatformScanRadius offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, ShowAssistRangeOnSelect) == 0x0C,
    "RUnitBlueprintAI::ShowAssistRangeOnSelect offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, GuardFormationName) == 0x10, "RUnitBlueprintAI::GuardFormationName offset must be 0x10"
  );
  static_assert(offsetof(RUnitBlueprintAI, NeedUnpack) == 0x2C, "RUnitBlueprintAI::NeedUnpack offset must be 0x2C");
  static_assert(
    offsetof(RUnitBlueprintAI, InitialAutoMode) == 0x2D, "RUnitBlueprintAI::InitialAutoMode offset must be 0x2D"
  );
  static_assert(offsetof(RUnitBlueprintAI, BeaconName) == 0x30, "RUnitBlueprintAI::BeaconName offset must be 0x30");
  static_assert(offsetof(RUnitBlueprintAI, TargetBones) == 0x4C, "RUnitBlueprintAI::TargetBones offset must be 0x4C");
  static_assert(
    offsetof(RUnitBlueprintAI, RefuelingMultiplier) == 0x5C, "RUnitBlueprintAI::RefuelingMultiplier offset must be 0x5C"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, RefuelingRepairAmount) == 0x60,
    "RUnitBlueprintAI::RefuelingRepairAmount offset must be 0x60"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, RepairConsumeEnergy) == 0x64, "RUnitBlueprintAI::RepairConsumeEnergy offset must be 0x64"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, RepairConsumeMass) == 0x68, "RUnitBlueprintAI::RepairConsumeMass offset must be 0x68"
  );
  static_assert(
    offsetof(RUnitBlueprintAI, AutoSurfaceToAttack) == 0x6C, "RUnitBlueprintAI::AutoSurfaceToAttack offset must be 0x6C"
  );
  static_assert(offsetof(RUnitBlueprintAI, AttackAngle) == 0x70, "RUnitBlueprintAI::AttackAngle offset must be 0x70");
  static_assert(sizeof(RUnitBlueprintAI) == 0x74, "RUnitBlueprintAI size must be 0x74");

  static_assert(
    offsetof(RUnitBlueprintWeapon, OwnerBlueprint) == 0x00, "RUnitBlueprintWeapon::OwnerBlueprint offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, WeaponIndex) == 0x04, "RUnitBlueprintWeapon::WeaponIndex offset must be 0x04"
  );
  static_assert(offsetof(RUnitBlueprintWeapon, Label) == 0x08, "RUnitBlueprintWeapon::Label offset must be 0x08");
  static_assert(
    offsetof(RUnitBlueprintWeapon, DisplayName) == 0x24, "RUnitBlueprintWeapon::DisplayName offset must be 0x24"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, RangeCategory) == 0x40, "RUnitBlueprintWeapon::RangeCategory offset must be 0x40"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, TargetCheckInterval) == 0x50,
    "RUnitBlueprintWeapon::TargetCheckInterval offset must be 0x50"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, MinRadius) == 0x58, "RUnitBlueprintWeapon::MinRadius offset must be 0x58"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, MaxRadius) == 0x5C, "RUnitBlueprintWeapon::MaxRadius offset must be 0x5C"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, MaximumBeamLength) == 0x60,
    "RUnitBlueprintWeapon::MaximumBeamLength offset must be 0x60"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, EffectiveRadius) == 0x64, "RUnitBlueprintWeapon::EffectiveRadius offset must be 0x64"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, DamageType) == 0xA8, "RUnitBlueprintWeapon::DamageType offset must be 0xA8"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, ProjectileId) == 0xC8, "RUnitBlueprintWeapon::ProjectileId offset must be 0xC8"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, BallisticArc) == 0xE4, "RUnitBlueprintWeapon::BallisticArc offset must be 0xE4"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, TargetRestrictOnlyAllow) == 0xE8,
    "RUnitBlueprintWeapon::TargetRestrictOnlyAllow offset must be 0xE8"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, TargetRestrictDisallow) == 0x104,
    "RUnitBlueprintWeapon::TargetRestrictDisallow offset must be 0x104"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, TargetType) == 0x130, "RUnitBlueprintWeapon::TargetType offset must be 0x130"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, BombDropThreshold) == 0x144,
    "RUnitBlueprintWeapon::BombDropThreshold offset must be 0x144"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, UseFiringSolutionInsteadOfAimBone) == 0x148,
    "RUnitBlueprintWeapon::UseFiringSolutionInsteadOfAimBone offset must be 0x148"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, IgnoreIfDisabled) == 0x149,
    "RUnitBlueprintWeapon::IgnoreIfDisabled offset must be 0x149"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, CannotAttackGround) == 0x14A,
    "RUnitBlueprintWeapon::CannotAttackGround offset must be 0x14A"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, UIMinRangeVisualId) == 0x14C,
    "RUnitBlueprintWeapon::UIMinRangeVisualId offset must be 0x14C"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapon, UIMaxRangeVisualId) == 0x168,
    "RUnitBlueprintWeapon::UIMaxRangeVisualId offset must be 0x168"
  );
  static_assert(sizeof(RUnitBlueprintWeapon) == 0x184, "RUnitBlueprintWeapon size must be 0x184");

  static_assert(
    offsetof(RUnitBlueprintWeapons, WeaponBlueprints) == 0x00,
    "RUnitBlueprintWeapons::WeaponBlueprints offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintWeapons, UnresolvedFaTailWord) == 0x10,
    "RUnitBlueprintWeapons::UnresolvedFaTailWord offset must be 0x10"
  );
  static_assert(sizeof(RUnitBlueprintWeapons) == 0x14, "RUnitBlueprintWeapons size must be 0x14");

  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, RuleGameRules) == 0x00,
    "RUnitBlueprintEconomyCategoryCache::RuleGameRules offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, First) == 0x10,
    "RUnitBlueprintEconomyCategoryCache::First offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStoragePtr) == 0x1C,
    "RUnitBlueprintEconomyCategoryCache::InlineStoragePtr offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStorage) == 0x20,
    "RUnitBlueprintEconomyCategoryCache::InlineStorage offset must be 0x20"
  );
  static_assert(
    sizeof(RUnitBlueprintEconomyCategoryCache) == 0x28, "RUnitBlueprintEconomyCategoryCache size must be 0x28"
  );

  static_assert(
    offsetof(RUnitBlueprintEconomy, BuildCostEnergy) == 0x00,
    "RUnitBlueprintEconomy::BuildCostEnergy offset must be 0x00"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, BuildCostMass) == 0x04, "RUnitBlueprintEconomy::BuildCostMass offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, BuildRate) == 0x08, "RUnitBlueprintEconomy::BuildRate offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, BuildTime) == 0x0C, "RUnitBlueprintEconomy::BuildTime offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, StorageEnergy) == 0x10, "RUnitBlueprintEconomy::StorageEnergy offset must be 0x10"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, StorageMass) == 0x14, "RUnitBlueprintEconomy::StorageMass offset must be 0x14"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, NaturalProducer) == 0x18,
    "RUnitBlueprintEconomy::NaturalProducer offset must be 0x18"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, BuildableCategories) == 0x1C,
    "RUnitBlueprintEconomy::BuildableCategories offset must be 0x1C"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, RebuildBonusIds) == 0x2C,
    "RUnitBlueprintEconomy::RebuildBonusIds offset must be 0x2C"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, CategoryCache) == 0x40, "RUnitBlueprintEconomy::CategoryCache offset must be 0x40"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, InitialRallyX) == 0x68, "RUnitBlueprintEconomy::InitialRallyX offset must be 0x68"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, InitialRallyZ) == 0x6C, "RUnitBlueprintEconomy::InitialRallyZ offset must be 0x6C"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, NeedToFaceTargetToBuild) == 0x70,
    "RUnitBlueprintEconomy::NeedToFaceTargetToBuild offset must be 0x70"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, SacrificeMassMult) == 0x74,
    "RUnitBlueprintEconomy::SacrificeMassMult offset must be 0x74"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, SacrificeEnergyMult) == 0x78,
    "RUnitBlueprintEconomy::SacrificeEnergyMult offset must be 0x78"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomy, MaxBuildDistance) == 0x7C,
    "RUnitBlueprintEconomy::MaxBuildDistance offset must be 0x7C"
  );
  static_assert(sizeof(RUnitBlueprintEconomy) == 0x80, "RUnitBlueprintEconomy size must be 0x80");

  static_assert(offsetof(RUnitBlueprint, General) == 0x17C, "RUnitBlueprint::General offset must be 0x17C");
  static_assert(offsetof(RUnitBlueprint, Display) == 0x200, "RUnitBlueprint::Display offset must be 0x200");
  static_assert(offsetof(RUnitBlueprint, Physics) == 0x278, "RUnitBlueprint::Physics offset must be 0x278");
  static_assert(offsetof(RUnitBlueprint, Intel) == 0x330, "RUnitBlueprint::Intel offset must be 0x330");
  static_assert(offsetof(RUnitBlueprint, Air) == 0x368, "RUnitBlueprint::Air offset must be 0x368");
  static_assert(offsetof(RUnitBlueprint, Transport) == 0x3F8, "RUnitBlueprint::Transport offset must be 0x3F8");
  static_assert(offsetof(RUnitBlueprint, Defense) == 0x420, "RUnitBlueprint::Defense offset must be 0x420");
  static_assert(offsetof(RUnitBlueprint, AI) == 0x460, "RUnitBlueprint::AI offset must be 0x460");
  static_assert(offsetof(RUnitBlueprint, Weapons) == 0x4D4, "RUnitBlueprint::Weapons offset must be 0x4D4");
  static_assert(offsetof(RUnitBlueprint, Economy) == 0x4E8, "RUnitBlueprint::Economy offset must be 0x4E8");
  static_assert(
    (offsetof(RUnitBlueprint, General) + offsetof(RUnitBlueprintGeneral, CapCost)) == 0x1F8,
    "RUnitBlueprint::General.CapCost offset must be 0x1F8"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Display) + offsetof(RUnitBlueprintDisplay, UniformScale)) == 0x270,
    "RUnitBlueprint::Display.UniformScale offset must be 0x270"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, SkirtOffsetX)) == 0x27C,
    "RUnitBlueprint::Physics.SkirtOffsetX offset must be 0x27C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, SkirtSizeX)) == 0x284,
    "RUnitBlueprint::Physics.SkirtSizeX offset must be 0x284"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, Elevation)) == 0x2DC,
    "RUnitBlueprint::Physics.Elevation offset must be 0x2DC"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, ResolvedFootprint)) == 0x2FC,
    "RUnitBlueprint::Physics.ResolvedFootprint offset must be 0x2FC"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, ResolvedAltFootprint)) == 0x300,
    "RUnitBlueprint::Physics.ResolvedAltFootprint offset must be 0x300"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, OccupyRects)) == 0x310,
    "RUnitBlueprint::Physics.OccupyRects offset must be 0x310"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Physics) + offsetof(RUnitBlueprintPhysics, RaisedPlatforms)) == 0x320,
    "RUnitBlueprint::Physics.RaisedPlatforms offset must be 0x320"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, VisionRadius)) == 0x330,
    "RUnitBlueprint::Intel.VisionRadius offset must be 0x330"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, RadarRadius)) == 0x338,
    "RUnitBlueprint::Intel.RadarRadius offset must be 0x338"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, SonarRadius)) == 0x33C,
    "RUnitBlueprint::Intel.SonarRadius offset must be 0x33C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, OmniRadius)) == 0x340,
    "RUnitBlueprint::Intel.OmniRadius offset must be 0x340"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, RadarStealth)) == 0x344,
    "RUnitBlueprint::Intel.RadarStealth offset must be 0x344"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, SonarStealth)) == 0x345,
    "RUnitBlueprint::Intel.SonarStealth offset must be 0x345"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, Cloak)) == 0x346,
    "RUnitBlueprint::Intel.Cloak offset must be 0x346"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, RadarStealthFieldRadius)) == 0x348,
    "RUnitBlueprint::Intel.RadarStealthFieldRadius offset must be 0x348"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, JamRadius)) == 0x354,
    "RUnitBlueprint::Intel.JamRadius offset must be 0x354"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, JamRadius) +
     offsetof(SMinMax<std::uint32_t>, max)) == 0x358,
    "RUnitBlueprint::Intel.JamRadius.max offset must be 0x358"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, JammerBlips)) == 0x35C,
    "RUnitBlueprint::Intel.JammerBlips offset must be 0x35C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, SpoofRadius)) == 0x360,
    "RUnitBlueprint::Intel.SpoofRadius offset must be 0x360"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Intel) + offsetof(RUnitBlueprintIntel, SpoofRadius) +
     offsetof(SMinMax<std::uint32_t>, max)) == 0x364,
    "RUnitBlueprint::Intel.SpoofRadius.max offset must be 0x364"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, CanFly)) == 0x368,
    "RUnitBlueprint::Air.CanFly offset must be 0x368"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, AutoLandTime)) == 0x36C,
    "RUnitBlueprint::Air.AutoLandTime offset must be 0x36C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, BreakOffIfNearNewTarget)) == 0x3A4,
    "RUnitBlueprint::Air.BreakOffIfNearNewTarget offset must be 0x3A4"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, CirclingDirChange)) == 0x3E0,
    "RUnitBlueprint::Air.CirclingDirChange offset must be 0x3E0"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, HoverOverAttack)) == 0x3E1,
    "RUnitBlueprint::Air.HoverOverAttack offset must be 0x3E1"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Air) + offsetof(RUnitBlueprintAir, PredictAheadForBombDrop)) == 0x3F4,
    "RUnitBlueprint::Air.PredictAheadForBombDrop offset must be 0x3F4"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Transport) + offsetof(RUnitBlueprintTransport, TransportClass)) == 0x3F8,
    "RUnitBlueprint::Transport.TransportClass offset must be 0x3F8"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Transport) + offsetof(RUnitBlueprintTransport, AirClass)) == 0x410,
    "RUnitBlueprint::Transport.AirClass offset must be 0x410"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Transport) + offsetof(RUnitBlueprintTransport, StorageSlots)) == 0x414,
    "RUnitBlueprint::Transport.StorageSlots offset must be 0x414"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Transport) + offsetof(RUnitBlueprintTransport, RepairRate)) == 0x41C,
    "RUnitBlueprint::Transport.RepairRate offset must be 0x41C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Defense) + offsetof(RUnitBlueprintDefense, MaxHealth)) == 0x420,
    "RUnitBlueprint::Defense.MaxHealth offset must be 0x420"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Defense) + offsetof(RUnitBlueprintDefense, ArmorType)) == 0x43C,
    "RUnitBlueprint::Defense.ArmorType offset must be 0x43C"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Defense) + offsetof(RUnitBlueprintDefense, Shield)) == 0x458,
    "RUnitBlueprint::Defense.Shield offset must be 0x458"
  );
  static_assert(
    (offsetof(RUnitBlueprint, AI) + offsetof(RUnitBlueprintAI, GuardFormationName)) == 0x470,
    "RUnitBlueprint::AI.GuardFormationName offset must be 0x470"
  );
  static_assert(
    (offsetof(RUnitBlueprint, AI) + offsetof(RUnitBlueprintAI, BeaconName)) == 0x490,
    "RUnitBlueprint::AI.BeaconName offset must be 0x490"
  );
  static_assert(
    (offsetof(RUnitBlueprint, AI) + offsetof(RUnitBlueprintAI, TargetBones)) == 0x4AC,
    "RUnitBlueprint::AI.TargetBones offset must be 0x4AC"
  );
  static_assert(
    (offsetof(RUnitBlueprint, AI) + offsetof(RUnitBlueprintAI, AutoSurfaceToAttack)) == 0x4CC,
    "RUnitBlueprint::AI.AutoSurfaceToAttack offset must be 0x4CC"
  );
  static_assert(
    (offsetof(RUnitBlueprint, AI) + offsetof(RUnitBlueprintAI, AttackAngle)) == 0x4D0,
    "RUnitBlueprint::AI.AttackAngle offset must be 0x4D0"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Weapons) + offsetof(RUnitBlueprintWeapons, WeaponBlueprints)) == 0x4D4,
    "RUnitBlueprint::Weapons.WeaponBlueprints offset must be 0x4D4"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Weapons) + offsetof(RUnitBlueprintWeapons, UnresolvedFaTailWord)) == 0x4E4,
    "RUnitBlueprint::Weapons.UnresolvedFaTailWord offset must be 0x4E4"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, BuildCostEnergy)) == 0x4E8,
    "RUnitBlueprint::Economy.BuildCostEnergy offset must be 0x4E8"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, BuildableCategories)) == 0x504,
    "RUnitBlueprint::Economy.BuildableCategories offset must be 0x504"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, RebuildBonusIds)) == 0x514,
    "RUnitBlueprint::Economy.RebuildBonusIds offset must be 0x514"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, CategoryCache)) == 0x528,
    "RUnitBlueprint::Economy.CategoryCache offset must be 0x528"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, InitialRallyX)) == 0x550,
    "RUnitBlueprint::Economy.InitialRallyX offset must be 0x550"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, InitialRallyZ)) == 0x554,
    "RUnitBlueprint::Economy.InitialRallyZ offset must be 0x554"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, NeedToFaceTargetToBuild)) == 0x558,
    "RUnitBlueprint::Economy.NeedToFaceTargetToBuild offset must be 0x558"
  );
  static_assert(
    (offsetof(RUnitBlueprint, Economy) + offsetof(RUnitBlueprintEconomy, MaxBuildDistance)) == 0x564,
    "RUnitBlueprint::Economy.MaxBuildDistance offset must be 0x564"
  );
  static_assert(sizeof(RUnitBlueprint) == 0x568, "RUnitBlueprint size must be 0x568");
} // namespace moho
