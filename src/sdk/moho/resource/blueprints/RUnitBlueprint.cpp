#include "RUnitBlueprint.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/path/SNamedFootprint.h"
#include "moho/resource/RResId.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "gpg/core/containers/String.h"

namespace moho
{
  gpg::RType* RUnitBlueprint::sPointerType = nullptr;

  namespace
  {
    constexpr std::uint8_t kGroundOccupancyMask = 0x0F;
    constexpr float kBlueprintExtentMultiplier = 3.0f;
    constexpr std::int8_t kDefaultFootprintFlags = -1;

    constexpr EOccupancyCaps OccupancyMask(const std::uint8_t value) noexcept
    {
      return static_cast<EOccupancyCaps>(value);
    }

    constexpr std::array<EOccupancyCaps, static_cast<std::size_t>(RULEUMT_Special) + 1>
      kFootprintOccupancyCapsByMotion = {
        OccupancyMask(0x00), // RULEUMT_None
        EOccupancyCaps::OC_LAND, // RULEUMT_Land
        EOccupancyCaps::OC_AIR, // RULEUMT_Air
        EOccupancyCaps::OC_WATER, // RULEUMT_Water
        EOccupancyCaps::OC_LAND, // RULEUMT_Biped
        OccupancyMask(0x0C), // RULEUMT_SurfacingSub (OC_SUB | OC_WATER)
        OccupancyMask(0x03), // RULEUMT_Amphibious (OC_LAND | OC_SEABED)
        OccupancyMask(0x09), // RULEUMT_Hover (OC_LAND | OC_WATER)
        OccupancyMask(0x09), // RULEUMT_AmphibiousFloating (OC_LAND | OC_WATER)
        OccupancyMask(0x00), // RULEUMT_Special
    };

    constexpr std::array<std::int8_t, 10> kFootprintFlagsByMotion = {
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
      kDefaultFootprintFlags,
    };

    [[nodiscard]] std::size_t ToMotionIndex(const ERuleBPUnitMovementType motionType) noexcept
    {
      const auto rawValue = static_cast<std::int32_t>(motionType);
      if (rawValue < 0 || rawValue >= static_cast<std::int32_t>(kFootprintOccupancyCapsByMotion.size())) {
        return 0;
      }
      return static_cast<std::size_t>(rawValue);
    }

    [[nodiscard]] EOccupancyCaps LookupFootprintOccupancyCaps(const ERuleBPUnitMovementType motionType) noexcept
    {
      return kFootprintOccupancyCapsByMotion[ToMotionIndex(motionType)];
    }

    [[nodiscard]] EFootprintFlags LookupFootprintFlags(const ERuleBPUnitMovementType motionType) noexcept
    {
      return static_cast<EFootprintFlags>(kFootprintFlagsByMotion[ToMotionIndex(motionType)]);
    }

    void AssignNormalizedFilename(msvc8::string& destination, const std::string_view filename)
    {
      std::string normalized{filename};
      gpg::STR_NormalizeFilenameLowerSlash(normalized);
      destination.assign_owned(normalized);
    }

  } // namespace

  /**
   * Address: 0x0051EE10 (FUN_0051EE10)
   * Mangled: ??0RUnitBlueprintGeneral@Moho@@QAE@XZ
   *
   * What it does:
   * Initializes capability bitmasks, upgrade-id defaults, and command-priority
   * lanes for general unit-blueprint metadata.
   */
  RUnitBlueprintGeneral::RUnitBlueprintGeneral()
    : CommandCaps(RULEUCC_None),
      ToggleCaps(static_cast<ERuleBPUnitToggleCaps>(0)),
      QuickSelectPriority(0),
      CapCost(1.0f),
      SelectionPriority(1)
  {
    gpg::STR_InitFilename(&UpgradesTo.name, "");
    gpg::STR_InitFilename(&UpgradesFrom.name, "none");
    gpg::STR_InitFilename(&UpgradesFromBase.name, "none");
    gpg::STR_InitFilename(&SeedUnit.name, "");
  }

  /**
   * Address: 0x0051E6F0 (FUN_0051E6F0, Moho::RUnitBlueprintGeneral::~RUnitBlueprintGeneral)
   * Mangled: ??1RUnitBlueprintGeneral@Moho@@QAE@XZ
   *
   * What it does:
   * Tears down all general-lane string-id members (`UpgradesTo`,
   * `UpgradesFrom`, `UpgradesFromBase`, `SeedUnit`).
   */
  RUnitBlueprintGeneral::~RUnitBlueprintGeneral() = default;

  /**
   * Address: 0x0051E770 (FUN_0051E770, Moho::RUnitBlueprintDisplay::~RUnitBlueprintDisplay)
   * Mangled: ??1RUnitBlueprintDisplay@Moho@@QAE@XZ
   *
   * What it does:
   * Tears down display-lane string and string-id members.
   */
  RUnitBlueprintDisplay::~RUnitBlueprintDisplay() = default;

  /**
   * Address: 0x0051EF00 (FUN_0051EF00, Moho::RUnitBlueprintAir::RUnitBlueprintAir)
   *
   * What it does:
   * Seeds air blueprint defaults for turn/bank control, circling behavior,
   * and combat-state randomization lanes.
   */
  RUnitBlueprintAir::RUnitBlueprintAir()
    : CanFly(0)
    , Winged(0)
    , FlyInWater(0)
    , pad_0003_0004{0}
    , AutoLandTime(0.0f)
    , MaxAirspeed(0.0f)
    , MinAirspeed(0.0f)
    , TurnSpeed(1.0f)
    , CombatTurnSpeed(1.0f)
    , StartTurnDistance(0.0f)
    , TightTurnMultiplier(1.0f)
    , SustainedTurnThreshold(10.0f)
    , LiftFactor(5.0f)
    , BankFactor(0.5f)
    , BankForward(0)
    , pad_002D_0030{0, 0, 0}
    , EngageDistance(0.0f)
    , BreakOffTrigger(0.0f)
    , BreakOffDistance(0.0f)
    , BreakOffIfNearNewTarget(0)
    , pad_003D_0040{0, 0, 0}
    , KMove(1.0f)
    , KMoveDamping(1.0f)
    , KLift(1.0f)
    , KLiftDamping(1.0f)
    , KTurn(3.0f)
    , KTurnDamping(3.0f)
    , KRoll(3.0f)
    , KRollDamping(3.0f)
    , CirclingTurnMult(3.0f)
    , CirclingRadiusChangeMinRatio(0.60000002f)
    , CirclingRadiusChangeMaxRatio(0.89999998f)
    , CirclingRadiusVsAirMult(1.0f)
    , CirclingElevationChangeRatio(0.25f)
    , CirclingFlightChangeFrequency(2.0f)
    , CirclingDirChange(1)
    , HoverOverAttack(0)
    , pad_007A_007C{0, 0}
    , RandomBreakOffDistanceMult(1.5f)
    , RandomMinChangeCombatStateTime(3.0f)
    , RandomMaxChangeCombatStateTime(6.0f)
    , TransportHoverHeight(0.0f)
    , PredictAheadForBombDrop(0.0f)
  {}

  /**
   * Address: 0x0051F090 (FUN_0051F090, Moho::RUnitBlueprintPhysics::RUnitBlueprintPhysics)
   *
   * What it does:
   * Seeds movement/skirt defaults, clears runtime footprint pointers, and
   * starts occupancy/raised-platform vectors empty.
   */
  RUnitBlueprintPhysics::RUnitBlueprintPhysics()
    : FlattenSkirt(0)
    , pad_0001_0004{0, 0, 0}
    , SkirtOffsetX(0.0f)
    , SkirtOffsetZ(0.0f)
    , SkirtSizeX(0.0f)
    , SkirtSizeZ(0.0f)
    , MaxGroundVariation(1.0f)
    , MotionType(RULEUMT_None)
    , AltMotionType(RULEUMT_None)
    , StandUpright(0)
    , SinkLower(0)
    , RotateBodyWhileMoving(0)
    , pad_0023_0024{0}
    , DiveSurfaceSpeed(1.0f)
    , MaxSpeed(0.0f)
    , MaxSpeedReverse(-1.0f)
    , MaxAcceleration(0.0f)
    , MaxBrake(0.0f)
    , MaxSteerForce(0.0f)
    , BankingSlope(0.0f)
    , RollStability(0.2f)
    , RollDamping(0.5f)
    , WobbleFactor(0.0f)
    , WobbleSpeed(0.0f)
    , TurnRadius(5.0f)
    , TurnRate(0.0f)
    , TurnFacingRate(0.0f)
    , RotateOnSpot(0)
    , pad_005D_0060{0, 0, 0}
    , RotateOnSpotThreshold(0.5f)
    , Elevation(0.0f)
    , AttackElevation(0.0f)
    , CatchUpAcc(0.0f)
    , BackUpDistance(-1.0f)
    , LayerChangeOffsetHeight(-0.1f)
    , LayerTransitionDuration(0.0f)
    , BuildOnLayerCapsMask(static_cast<std::int32_t>(LAYER_Land))
    , BuildRestriction(RULEUBR_None)
    , ResolvedFootprint(nullptr)
    , ResolvedAltFootprint(nullptr)
    , FuelUseTime(0.0f)
    , FuelRechargeRate(0.0f)
    , GroundCollisionOffset(0.0f)
    , OccupyRects()
    , RaisedPlatforms()
  {}

  /**
   * Address: 0x0051E7F0 (FUN_0051E7F0, Moho::RUnitBlueprintPhysics::~RUnitBlueprintPhysics)
   * Mangled: ??1RUnitBlueprintPhysics@Moho@@QAE@XZ
   *
   * What it does:
   * Tears down occupancy and raised-platform vector storage.
   */
  RUnitBlueprintPhysics::~RUnitBlueprintPhysics() = default;

  /**
   * Address: 0x0051F7D0 (FUN_0051F7D0, ??0RUnitBlueprintAI@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes AI blueprint defaults for guard behavior, beacon metadata,
   * and refueling/repair tuning lanes.
   */
  RUnitBlueprintAI::RUnitBlueprintAI()
    : GuardScanRadius(25.0f)
    , GuardReturnRadius(50.0f)
    , StagingPlatformScanRadius(300.0f)
    , ShowAssistRangeOnSelect(0)
    , GuardFormationName("GuardFormation")
    , NeedUnpack(0)
    , InitialAutoMode(0)
    , BeaconName()
    , TargetBones()
    , RefuelingMultiplier(1.0f)
    , RefuelingRepairAmount(20.0f)
    , RepairConsumeEnergy(2.0f)
    , RepairConsumeMass(0.5f)
    , AutoSurfaceToAttack(1)
    , AttackAngle(0.0f)
  {}

  /**
   * Address: 0x0051E870 (FUN_0051E870, ??1RUnitBlueprintAI@Moho@@QAE@@Z)
   *
   * What it does:
   * Destroys target-bone strings, releases heap-backed bone storage, and
   * resets beacon/guard formation names to their legacy empty-state layout.
   */
  RUnitBlueprintAI::~RUnitBlueprintAI()
  {
    auto& targetBonesView = msvc8::AsVectorRuntimeView(TargetBones);
    if (targetBonesView.begin != nullptr) {
      for (msvc8::string* cursor = targetBonesView.begin; cursor != targetBonesView.end; ++cursor) {
        cursor->~string();
      }
      ::operator delete(targetBonesView.begin);
    }

    targetBonesView.begin = nullptr;
    targetBonesView.end = nullptr;
    targetBonesView.capacityEnd = nullptr;

    if (BeaconName.myRes >= 0x10U) {
      ::operator delete(BeaconName.bx.ptr);
    }
    BeaconName.myRes = 15U;
    BeaconName.mySize = 0U;
    BeaconName.bx.buf[0] = '\0';

    if (GuardFormationName.myRes >= 0x10U) {
      ::operator delete(GuardFormationName.bx.ptr);
    }
    GuardFormationName.mySize = 0U;
    GuardFormationName.myRes = 15U;
    GuardFormationName.bx.buf[0] = '\0';
  }

  /**
   * Address: 0x0051F990 (FUN_0051F990, Moho::RUnitBlueprintEconomy::RUnitBlueprintEconomy)
   * Mangled: ??0RUnitBlueprintEconomy@Moho@@QAE@PAVRRuleGameRules@1@@Z
   *
   * What it does:
   * Seeds economy defaults, clears category-string vectors, and initializes
   * runtime category-cache inline storage using one rules-owner lane.
   */
  RUnitBlueprintEconomy::RUnitBlueprintEconomy(RRuleGameRules* const rules)
    : BuildCostEnergy(0.0f)
    , BuildCostMass(0.0f)
    , BuildRate(1.0f)
    , BuildTime(0.0f)
    , StorageEnergy(0.0f)
    , StorageMass(0.0f)
    , NaturalProducer(0)
    , pad_0019_001C{0, 0, 0}
    , BuildableCategories()
    , RebuildBonusIds()
    , UnresolvedWord3C(0)
    , CategoryCache{}
    , InitialRallyX(0.0f)
    , InitialRallyZ(5.0f)
    , NeedToFaceTargetToBuild(0)
    , pad_0071_0074{0, 0, 0}
    , SacrificeMassMult(0.0f)
    , SacrificeEnergyMult(0.0f)
    , MaxBuildDistance(5.0f)
  {
    CategoryCache.RuleGameRules = rules;
    CategoryCache.UnresolvedWord04 = 0;
    CategoryCache.RuntimeWord08 = 0;
    CategoryCache.RuntimeVectorProxy = nullptr;
    CategoryCache.First = CategoryCache.InlineStorage;
    CategoryCache.Last = CategoryCache.InlineStorage;
    CategoryCache.End = reinterpret_cast<std::uint32_t*>(&InitialRallyX);
    CategoryCache.InlineStoragePtr = CategoryCache.InlineStorage;
  }

  /**
   * Address: 0x0051E8F0 (FUN_0051E8F0, Moho::RUnitBlueprintEconomy::~RUnitBlueprintEconomy)
   * Mangled: ??1RUnitBlueprintEconomy@Moho@@QAE@@Z
   *
   * What it does:
   * Frees dynamic category-cache storage when detached from inline lanes and
   * restores inline start/end pointers before member vector destruction.
   */
  RUnitBlueprintEconomy::~RUnitBlueprintEconomy()
  {
    if (CategoryCache.First != CategoryCache.InlineStoragePtr) {
      ::operator delete[](CategoryCache.First);
      CategoryCache.First = CategoryCache.InlineStoragePtr;
      CategoryCache.End =
        reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*CategoryCache.InlineStoragePtr));
    }

    CategoryCache.Last = CategoryCache.First;
  }

  /**
   * Address: 0x0051E480 (FUN_0051E480, Moho::RUnitBlueprint::RUnitBlueprint)
   * Mangled: ??0RUnitBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Constructs unit-blueprint subsection lanes on top of `REntityBlueprint`,
   * seeds gameplay defaults, and enables life-bar rendering.
   */
  RUnitBlueprint::RUnitBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : REntityBlueprint(owner, resId)
    , General()
    , Physics()
    , Air()
    , AI()
    , Economy(owner)
  {
    Display.UniformScale = 1.0f;
    Display.SpawnRandomRotation = 0;
    Display.HideLifebars = 0;

    Intel.VisionRadius = 10;
    Intel.WaterVisionRadius = 10;
    Intel.RadarRadius = 0;
    Intel.SonarRadius = 0;
    Intel.OmniRadius = 0;
    Intel.RadarStealth = 0;
    Intel.SonarStealth = 0;
    Intel.Cloak = 0;
    Intel.ShowIntelOnSelect = 0;
    Intel.RadarStealthFieldRadius = 0;
    Intel.SonarStealthFieldRadius = 0;
    Intel.CloakFieldRadius = 0;
    Intel.JamRadius.min = 0;
    Intel.JamRadius.max = 0;
    Intel.JammerBlips = 0;
    Intel.SpoofRadius.min = 0;
    Intel.SpoofRadius.max = 0;

    Transport.TransportClass = 1;
    Transport.ClassGenericUpTo = 0;
    Transport.Class2AttachSize = 2;
    Transport.Class3AttachSize = 6;
    Transport.Class4AttachSize = 1;
    Transport.ClassSAttachSize = 0;
    Transport.AirClass = 0;
    Transport.StorageSlots = 0;
    Transport.DockingSlots = 0;
    Transport.RepairRate = 0.0f;

    Defense.MaxHealth = 1.0f;
    Defense.Health = 1.0f;
    Defense.RegenRate = 0.0f;
    Defense.AirThreatLevel = 0.0f;
    Defense.SurfaceThreatLevel = 0.0f;
    Defense.SubThreatLevel = 0.0f;
    Defense.EconomyThreatLevel = 0.0f;
    Defense.ArmorType = "Default";
    Defense.Shield.ShieldSize = 0.0f;
    Defense.Shield.RegenAssistMult = 1.0f;

    auto& weaponBlueprintsView = msvc8::AsVectorRuntimeView(Weapons.WeaponBlueprints);
    weaponBlueprintsView.begin = nullptr;
    weaponBlueprintsView.end = nullptr;
    weaponBlueprintsView.capacityEnd = nullptr;

    mLifeBarRender = 1;
  }

  /**
   * Address: 0x0051F260 (FUN_0051F260)
   * Mangled: ?ComputeDerivedQuantities@RUnitBlueprintPhysics@Moho@@QAEXPAVRRuleGameRules@2@PBDAAVREntityBlueprint@2@@Z
   *
   * What it does:
   * Computes derived movement/footprint/skirt values and resolves runtime
   * footprint pointers using rule-game tables.
   */
  void RUnitBlueprintPhysics::ComputeDerivedQuantities(
    RRuleGameRules* const gameRules, const char* const blueprintName, REntityBlueprint& ownerEntity
  )
  {
    if (MaxSpeed == 0.0f) {
      MotionType = RULEUMT_None;
    } else if (MaxSpeedReverse < 0.0f) {
      MaxSpeedReverse = MaxSpeed;
    }

    if (AttackElevation == 0.0f) {
      AttackElevation = Elevation;
    }

    if (MotionType != RULEUMT_None) {
      const EOccupancyCaps occupancyCaps = LookupFootprintOccupancyCaps(MotionType);
      ownerEntity.mFootprint.mOccupancyCaps = occupancyCaps;
      ownerEntity.mFootprint.mFlags = LookupFootprintFlags(MotionType);

      if ((static_cast<std::uint8_t>(occupancyCaps) & kGroundOccupancyMask) != 0U) {
        const SNamedFootprint* const resolvedNamed = gameRules->FindFootprint(ownerEntity.mFootprint, blueprintName);
        ResolvedFootprint = resolvedNamed;
        if (ResolvedFootprint != nullptr) {
          ownerEntity.mFootprint = *ResolvedFootprint;
        }
      }

      if (AltMotionType != RULEUMT_None) {
        ownerEntity.mAltFootprint.mOccupancyCaps = LookupFootprintOccupancyCaps(AltMotionType);
        ownerEntity.mAltFootprint.mFlags = LookupFootprintFlags(AltMotionType);

        const bool hasGroundFootprint =
          (static_cast<std::uint8_t>(ownerEntity.mFootprint.mOccupancyCaps) & kGroundOccupancyMask) != 0U;
        if (hasGroundFootprint) {
          const SNamedFootprint* const resolvedAltNamed =
            gameRules->FindFootprint(ownerEntity.mAltFootprint, blueprintName);
          ResolvedAltFootprint = resolvedAltNamed;

          if (ResolvedAltFootprint != nullptr) {
            ownerEntity.mAltFootprint = *ResolvedAltFootprint;
          } else {
            ResolvedAltFootprint = ResolvedFootprint;
            ownerEntity.mAltFootprint = ownerEntity.mFootprint;
          }
        }
      } else {
        ResolvedAltFootprint = ResolvedFootprint;
        ownerEntity.mAltFootprint = ownerEntity.mFootprint;
      }
    } else {
      const std::uint8_t layerCapsLow = static_cast<std::uint8_t>(BuildOnLayerCapsMask);
      ownerEntity.mFootprint.mOccupancyCaps = static_cast<EOccupancyCaps>(layerCapsLow);

      if ((layerCapsLow & static_cast<std::uint8_t>(LAYER_Seabed)) != 0U &&
          ownerEntity.mFootprint.mMaxWaterDepth == 0.0f) {
        ownerEntity.mFootprint.mMaxWaterDepth = std::numeric_limits<float>::max();
      }
    }

    if (SkirtOffsetX > 0.0f) {
      SkirtOffsetX = 0.0f;
    }
    if (SkirtOffsetZ > 0.0f) {
      SkirtOffsetZ = 0.0f;
    }

    SkirtSizeX = std::max(SkirtSizeX, static_cast<float>(ownerEntity.mFootprint.mSizeX));
    SkirtSizeZ = std::max(SkirtSizeZ, static_cast<float>(ownerEntity.mFootprint.mSizeZ));

    if (CatchUpAcc == 0.0f) {
      CatchUpAcc = std::max(MaxAcceleration, MaxBrake);
    }

    if (BackUpDistance < 0.0f) {
      BackUpDistance = ownerEntity.mSizeZ * kBlueprintExtentMultiplier;
    }
  }

  /**
   * Address: 0x0051E980 (FUN_0051E980)
   * Mangled: ??1RUnitBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Destroys unit-blueprint subsection lanes in reverse order, then
   * tears down the `REntityBlueprint` base.
   */
  RUnitBlueprint::~RUnitBlueprint() = default;

  /**
   * Address: 0x0051EA40 (FUN_0051EA40)
   *
   * What it does:
   * Runs base entity-blueprint initialization, computes derived unit physics,
   * applies air/display defaults, and post-initializes weapon records.
   */
  void RUnitBlueprint::OnInitBlueprint()
  {
    REntityBlueprint::OnInitBlueprint();

    Physics.ComputeDerivedQuantities(mOwner, mBlueprintId.c_str(), *this);

    if (Air.CanFly == 0 && Physics.MotionType == RULEUMT_Air) {
      Air.CanFly = 1;
    }
    if (Air.MaxAirspeed == 0.0f && Air.CanFly != 0) {
      Air.MaxAirspeed = Physics.MaxSpeed;
    }
    if (Air.MinAirspeed == 0.0f) {
      Air.MinAirspeed = Air.MaxAirspeed;
    }
    if (Air.StartTurnDistance == 0.0f) {
      Air.StartTurnDistance = mSizeZ * kBlueprintExtentMultiplier;
    }

    if (!Display.MeshBlueprint.name.empty()) {
      msvc8::string meshPath = RES_CompletePath(Display.MeshBlueprint.name.c_str(), mSource.c_str());
      gpg::STR_NormalizeFilenameLowerSlash(meshPath);
      Display.MeshBlueprint.name.assign_owned(meshPath.view());
    }

    if (Display.IconName.name.empty()) {
      AssignNormalizedFilename(Display.IconName.name, mBlueprintId.view());
    }

    std::uint32_t weaponIndex = 0;
    for (auto* weapon = Weapons.WeaponBlueprints.begin(); weapon != Weapons.WeaponBlueprints.end(); ++weapon) {
      weapon->PostInit(this, weaponIndex++);
    }
  }

  /**
   * Address: 0x0051E400 (FUN_0051E400, ?StaticGetClass@RUnitBlueprint@Moho@@SAPAVRType@gpg@@XZ)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for
   * `RUnitBlueprint`.
   */
  gpg::RType* RUnitBlueprint::StaticGetClass()
  {
    gpg::RType* cached = RUnitBlueprint::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(RUnitBlueprint));
      RUnitBlueprint::sType = cached;
    }
    return cached;
  }

  /**
   * Address: 0x0051E420 (FUN_0051E420, ?GetClass@RUnitBlueprint@Moho@@UBEPAVRType@gpg@@XZ)
   *
   * What it does:
   * Returns the reflected runtime type descriptor for this
   * `RUnitBlueprint` instance.
   */
  gpg::RType* RUnitBlueprint::GetClass() const
  {
    return StaticGetClass();
  }

  /**
   * Address: 0x0051E440 (FUN_0051E440, ?GetDerivedObjectRef@RUnitBlueprint@Moho@@UAE?AVRRef@gpg@@XZ)
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflected object reference handle.
   */
  gpg::RRef RUnitBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x005A1330 (FUN_005A1330, Moho::RUnitBlueprint::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for
   * `RUnitBlueprint*`.
   */
  gpg::RType* RUnitBlueprint::GetPointerType()
  {
    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(RUnitBlueprint*));
      sPointerType = cached;
    }
    return cached;
  }

  /**
   * Address: 0x0051E460 (FUN_0051E460)
   * Mangled: ?IsMobile@RUnitBlueprint@Moho@@UBE_NXZ
   *
   * What it does:
   * Returns true when unit physics motion type is not `RULEUMT_None`.
   */
  bool RUnitBlueprint::IsMobile() const
  {
    return Physics.MotionType != RULEUMT_None;
  }

  /**
   * Address: 0x0051E470 (FUN_0051E470)
   * Mangled: ?IsUnitBlueprint@RUnitBlueprint@Moho@@UBEPBV12@XZ
   *
   * What it does:
   * Returns `this` to mark the entity blueprint as a unit blueprint.
   */
  const RUnitBlueprint* RUnitBlueprint::IsUnitBlueprint() const
  {
    return this;
  }

  /**
   * Address: 0x0051ED80 (FUN_0051ED80)
   * Mangled: ?GetFootprintRect@RUnitBlueprint@Moho@@QBE?AV?$Rect2@H@gpg@@ABUSCoordsVec2@2@@Z
   *
   * What it does:
   * Builds the integer occupancy footprint rectangle centered around
   * `position`.
   */
  gpg::Rect2i RUnitBlueprint::GetFootprintRect(const SCoordsVec2& position) const
  {
    const std::int32_t footprintSizeX = static_cast<std::int32_t>(mFootprint.mSizeX);
    const std::int32_t footprintSizeZ = static_cast<std::int32_t>(mFootprint.mSizeZ);

    const std::int32_t x0 =
      static_cast<std::int32_t>(position.x - (static_cast<float>(footprintSizeX) * 0.5f));
    const std::int32_t z0 =
      static_cast<std::int32_t>(position.z - (static_cast<float>(footprintSizeZ) * 0.5f));

    gpg::Rect2i footprintRect{};
    footprintRect.x0 = x0;
    footprintRect.z0 = z0;
    footprintRect.x1 = x0 + footprintSizeX;
    footprintRect.z1 = z0 + footprintSizeZ;
    return footprintRect;
  }

  /**
   * Address: 0x0051EC50 (FUN_0051EC50)
   * Mangled: ?GetSkirtRect@RUnitBlueprint@Moho@@QBE?AV?$Rect2@M@gpg@@ABUSCoordsVec2@2@@Z
   *
   * What it does:
   * Builds world-space XZ skirt occupancy bounds around `position`, using
   * explicit skirt offsets/sizes when present and falling back to footprint
   * extents otherwise.
   */
  gpg::Rect2f RUnitBlueprint::GetSkirtRect(const SCoordsVec2& position) const
  {
    const std::int16_t xLower = static_cast<std::int16_t>(
      static_cast<std::int32_t>(position.x - (static_cast<float>(mFootprint.mSizeX) * 0.5f))
    );
    const std::int16_t zLower = static_cast<std::int16_t>(
      static_cast<std::int32_t>(position.z - (static_cast<float>(mFootprint.mSizeZ) * 0.5f))
    );

    gpg::Rect2f skirtRect{};

    const float skirtSizeX = Physics.SkirtSizeX;
    if (skirtSizeX == 0.0f) {
      skirtRect.x0 = static_cast<float>(xLower);
      skirtRect.x1 = skirtRect.x0 + static_cast<float>(mFootprint.mSizeX);
    } else {
      skirtRect.x0 = Physics.SkirtOffsetX + static_cast<float>(xLower);
      skirtRect.x1 = skirtRect.x0 + skirtSizeX;
    }

    const float skirtSizeZ = Physics.SkirtSizeZ;
    if (skirtSizeZ == 0.0f) {
      skirtRect.z0 = static_cast<float>(zLower);
      skirtRect.z1 = skirtRect.z0 + static_cast<float>(mFootprint.mSizeZ);
    } else {
      skirtRect.z0 = Physics.SkirtOffsetZ + static_cast<float>(zLower);
      skirtRect.z1 = skirtRect.z0 + skirtSizeZ;
    }

    return skirtRect;
  }

  /**
   * Address: 0x00523F90 (FUN_00523F90, Moho::RUnitBlueprintWeapon::~RUnitBlueprintWeapon)
   *
   * What it does:
   * Releases owned string lanes in reverse declaration order.
   */
  RUnitBlueprintWeapon::~RUnitBlueprintWeapon() = default;

  /**
   * Address: 0x1010E1C0 (FUN_1010E1C0)
   *
   * What it does:
   * Stores runtime owner/index metadata after a weapon record is materialized.
   */
  void RUnitBlueprintWeapon::PostInit(RUnitBlueprint* ownerBlueprint, const std::uint32_t weaponIndex) noexcept
  {
    OwnerBlueprint = ownerBlueprint;
    WeaponIndex = weaponIndex;
  }

  /**
   * Address: 0x1010E150 (FUN_1010E150)
   * Mangled: ?GetMuzzleVelocity@RUnitBlueprintWeapon@Moho@@QBEMMPAVCRandomStream@2@@Z
   *
   * What it does:
   * Returns muzzle velocity with optional gaussian jitter and
   * short-range attenuation against `MuzzleVelocityReduceDistance`.
   */
  float
  RUnitBlueprintWeapon::GetMuzzleVelocity(const float targetDistance, CRandomStream* const randomStream) const noexcept
  {
    float velocity = MuzzleVelocity;
    if (randomStream != nullptr && MuzzleVelocityRandom != 0.0f) {
      velocity += randomStream->FRandGaussian() * MuzzleVelocityRandom;
    }

    if (MuzzleVelocityReduceDistance > targetDistance) {
      return velocity * std::sqrt(targetDistance / MuzzleVelocityReduceDistance);
    }

    return velocity;
  }
} // namespace moho
