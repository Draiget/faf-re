#include "RUnitBlueprint.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
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
    /**
     * Address: 0x005273B0 (FUN_005273B0, copy_RUnitBlueprintWeapon_counted_range_with_rollback)
     *
     * What it does:
     * Copy-constructs `count` contiguous `RUnitBlueprintWeapon` elements from
     * `source` into destination storage, then tears down constructed elements
     * before rethrowing if construction fails.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponCountedRangeWithRollback(
      int count,
      RUnitBlueprintWeapon* destination,
      const RUnitBlueprintWeapon* source
    )
    {
      RUnitBlueprintWeapon* destinationCursor = destination;
      try {
        while (count > 0) {
          if (destinationCursor != nullptr) {
            ::new (destinationCursor) RUnitBlueprintWeapon(*source);
          }
          --count;
          ++destinationCursor;
          ++source;
        }
        return destinationCursor;
      } catch (...) {
        for (RUnitBlueprintWeapon* destroyCursor = destination; destroyCursor != destinationCursor; ++destroyCursor) {
          destroyCursor->~RUnitBlueprintWeapon();
        }
        throw;
      }
    }

    /**
     * Address: 0x00524DD0 (FUN_00524DD0)
     *
     * What it does:
     * Adapts one register-lane caller shape into the canonical counted
     * `RUnitBlueprintWeapon` copy-with-rollback helper.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponCountedRangeRegisterAdapter(
      RUnitBlueprintWeapon* const destination,
      const int count,
      const RUnitBlueprintWeapon* const source
    )
    {
      return CopyRUnitBlueprintWeaponCountedRangeWithRollback(count, destination, source);
    }

    /**
     * Address: 0x00526220 (FUN_00526220)
     *
     * What it does:
     * Alternate register-shape adapter lane that forwards one counted
     * `RUnitBlueprintWeapon` copy-with-rollback request into the canonical
     * helper.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponCountedRangeRegisterAdapterAlt(
      RUnitBlueprintWeapon* const destination,
      const int count,
      const RUnitBlueprintWeapon* const source
    )
    {
      return CopyRUnitBlueprintWeaponCountedRangeWithRollback(count, destination, source);
    }

    /**
     * Address: 0x00527D30 (FUN_00527D30, copy_RUnitBlueprintWeapon_range_with_rollback)
     *
     * What it does:
     * Copy-constructs one contiguous source range into destination storage and
     * destroys already-built destination elements before rethrowing on failure.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponRangeWithRollback(
      RUnitBlueprintWeapon* destinationBegin,
      RUnitBlueprintWeapon* destinationEnd,
      const RUnitBlueprintWeapon* sourceBegin
    )
    {
      RUnitBlueprintWeapon* destinationCursor = destinationBegin;
      const RUnitBlueprintWeapon* sourceCursor = sourceBegin;
      try {
        while (destinationCursor != destinationEnd) {
          if (sourceCursor != nullptr) {
            ::new (destinationCursor) RUnitBlueprintWeapon(*sourceCursor);
          }
          ++destinationCursor;
          ++sourceCursor;
        }
        return destinationCursor;
      } catch (...) {
        for (RUnitBlueprintWeapon* destroyCursor = destinationBegin; destroyCursor != destinationCursor; ++destroyCursor) {
          destroyCursor->~RUnitBlueprintWeapon();
        }
        throw;
      }
    }

    /**
     * Address: 0x00527620 (FUN_00527620)
     *
     * What it does:
     * Register-shape adapter lane that forwards one range-copy request into
     * `CopyRUnitBlueprintWeaponRangeWithRollback`.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponRangeWithRollbackRegisterAdapter(
      const std::uintptr_t /*unusedLane*/,
      const RUnitBlueprintWeapon* const sourceBegin,
      RUnitBlueprintWeapon* const destinationBegin,
      RUnitBlueprintWeapon* const destinationEnd
    )
    {
      return CopyRUnitBlueprintWeaponRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    /**
     * Address: 0x00527B70 (FUN_00527B70)
     *
     * What it does:
     * Alternate register-shape adapter lane that forwards one range-copy
     * request into `CopyRUnitBlueprintWeaponRangeWithRollback`.
     */
    [[maybe_unused]] RUnitBlueprintWeapon* CopyRUnitBlueprintWeaponRangeWithRollbackRegisterAdapterAlt(
      const RUnitBlueprintWeapon* const sourceBegin,
      RUnitBlueprintWeapon* const destinationBegin,
      RUnitBlueprintWeapon* const destinationEnd
    )
    {
      return CopyRUnitBlueprintWeaponRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    [[nodiscard]] RUnitBlueprintWeapon* CopyConstructRUnitBlueprintWeaponIfPresent(
      RUnitBlueprintWeapon* const destination,
      const RUnitBlueprintWeapon* const source
    )
    {
      if (source == nullptr) {
        return nullptr;
      }

      return ::new (destination) RUnitBlueprintWeapon(*source);
    }

    /**
     * Address: 0x00527960 (FUN_00527960)
     *
     * What it does:
     * Primary register-shape adapter for nullable `RUnitBlueprintWeapon`
     * copy-construction into caller-provided storage.
     */
    [[maybe_unused]] [[nodiscard]] RUnitBlueprintWeapon* CopyConstructRUnitBlueprintWeaponIfPresentPrimary(
      RUnitBlueprintWeapon* const destination,
      const RUnitBlueprintWeapon* const source
    )
    {
      return CopyConstructRUnitBlueprintWeaponIfPresent(destination, source);
    }

    /**
     * Address: 0x00527BC0 (FUN_00527BC0)
     *
     * What it does:
     * Secondary register-shape adapter for nullable `RUnitBlueprintWeapon`
     * copy-construction into caller-provided storage.
     */
    [[maybe_unused]] [[nodiscard]] RUnitBlueprintWeapon* CopyConstructRUnitBlueprintWeaponIfPresentSecondary(
      RUnitBlueprintWeapon* const destination,
      const RUnitBlueprintWeapon* const source
    )
    {
      return CopyConstructRUnitBlueprintWeaponIfPresent(destination, source);
    }

    /**
     * Address: 0x0051E330 (FUN_0051E330)
     *
     * What it does:
     * Reinitializes one destination string lane and copies the full source
     * payload into it.
     */
    [[maybe_unused]] msvc8::string* CopyStringLane(
      msvc8::string* const destination,
      const msvc8::string* const source
    )
    {
      destination->assign_owned(source->view());
      return destination;
    }

    /**
     * Address: 0x0051E3F0 (FUN_0051E3F0)
     *
     * What it does:
     * Writes one 32-bit scalar lane into destination storage.
     */
    [[maybe_unused]] std::uint32_t* StoreU32Lane(
      std::uint32_t* const destination,
      const std::uint32_t value
    ) noexcept
    {
      *destination = value;
      return destination;
    }

    /**
     * Address: 0x0051F780 (FUN_0051F780)
     *
     * What it does:
     * Writes one two-dword payload pair into destination storage in
     * `(lane0,lane1)` order.
     */
    [[maybe_unused]] std::uint32_t* StoreU32PairLanes(
      std::uint32_t* const destination,
      const std::uint32_t lane1,
      const std::uint32_t lane0
    ) noexcept
    {
      destination[0] = lane0;
      destination[1] = lane1;
      return destination;
    }

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
   * Address: 0x005267A0 (FUN_005267A0, Moho::CopyOccupyRects)
   *
   * What it does:
   * Rebuilds destination float-vector runtime lanes from source occupancy
   * storage and copies the full `[begin,end)` float range.
   */
  msvc8::vector<float>* CopyOccupyRects(
    const msvc8::vector<float>& source,
    msvc8::vector<float>& destination
  )
  {
    const auto& sourceView = msvc8::AsVectorRuntimeView(source);
    auto& destinationView = msvc8::AsVectorRuntimeView(destination);

    const std::uint32_t sourceCount = (sourceView.begin != nullptr)
      ? static_cast<std::uint32_t>(sourceView.end - sourceView.begin)
      : 0u;

    destinationView.proxy = nullptr;
    destinationView.begin = nullptr;
    destinationView.end = nullptr;
    destinationView.capacityEnd = nullptr;

    if (sourceCount != 0u) {
      if (sourceCount > msvc8::vector<float>::max_elements_sentinel()) {
        msvc8::vector<float>::throw_too_long();
      }

      auto* const destinationBegin = static_cast<float*>(
        ::operator new(static_cast<std::size_t>(sourceCount) * sizeof(float))
      );
      destinationView.begin = destinationBegin;
      destinationView.end = destinationBegin;
      destinationView.capacityEnd = destinationBegin + sourceCount;
      destinationView.end = std::copy(sourceView.begin, sourceView.end, destinationBegin);
    }

    return &destination;
  }

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
   * Address: 0x00529E90 (FUN_00529E90, Moho::RUnitBlueprint::AddEconomyRestrictions)
   *
   * What it does:
   * Parses each buildable-category expression and unions the resulting
   * category bits into the runtime economy category cache.
   */
  void RUnitBlueprint::AddEconomyRestrictions(RRuleGameRulesImpl* const rules)
  {
    auto& buildableCategoriesView = msvc8::AsVectorRuntimeView(Economy.BuildableCategories);
    auto* const economyCategoryCache = reinterpret_cast<EntityCategorySet*>(&Economy.CategoryCache);

    for (msvc8::string* it = buildableCategoriesView.begin; it != buildableCategoriesView.end; ++it) {
      const CategoryWordRangeView parsedCategory = rules->ParseEntityCategory(it->c_str());
      CategoryWordRangeView mergedCategory{};
      (void)func_EntityCategoryAdd(&parsedCategory, &mergedCategory, economyCategoryCache);
      *economyCategoryCache = mergedCategory;
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
   * Address: 0x0051F4C0 (FUN_0051F4C0)
   *
   * What it does:
   * Restores default weapon-blueprint runtime state, including canonical
   * range, ballistic, and damage-profile defaults.
   */
  RUnitBlueprintWeapon::RUnitBlueprintWeapon() :
    OwnerBlueprint(nullptr),
    WeaponIndex(static_cast<std::uint32_t>(-1)),
    Label(),
    DisplayName(),
    RangeCategory(UWRC_Undefined),
    DummyWeapon(0),
    PrefersPrimaryWeaponTarget(0),
    StopOnPrimaryWeaponBusy(0),
    SlavedToBody(0),
    SlavedToBodyArcRange(1.0f),
    AutoInitiateAttackCommand(0),
    pad_004D_0050{},
    TargetCheckInterval(3.0f),
    AlwaysRecheckTarget(1),
    pad_0055_0058{},
    MinRadius(1.0f),
    MaxRadius(3.0f),
    MaximumBeamLength(0.0f),
    EffectiveRadius(-1.0f),
    MaxHeightDiff(std::numeric_limits<float>::infinity()),
    TrackingRadius(1.0f),
    HeadingArcCenter(0.0f),
    HeadingArcRange(180.0f),
    FiringTolerance(0.01f),
    FiringRandomness(0.0f),
    RequiresEnergy(0.0f),
    RequiresMass(0.0f),
    MuzzleVelocity(0.0f),
    MuzzleVelocityRandom(0.0f),
    MuzzleVelocityReduceDistance(0.0f),
    LeadTarget(1),
    pad_0095_0098{},
    ProjectileLifetime(0.0f),
    ProjectileLifetimeUsesMultiplier(0.0f),
    Damage(0.0f),
    DamageRadius(0.0f),
    DamageType("Normal"),
    RateOfFire(1.0f),
    ProjectileId(),
    BallisticArc(RULEUBA_None),
    TargetRestrictOnlyAllow(),
    TargetRestrictDisallow(),
    ManualFire(0),
    NukeWeapon(0),
    OverChargeWeapon(0),
    NeedPrep(0),
    CountedProjectile(0),
    pad_0125_0128{},
    MaxProjectileStorage(0),
    IgnoresAlly(1),
    pad_012D_0130{},
    TargetType(static_cast<ERuleBPUnitWeaponTargetType>(3)),
    AttackGroundTries(0),
    AimsStraightOnDisable(0),
    Turreted(0),
    YawOnlyOnTarget(0),
    AboveWaterFireOnly(0),
    BelowWaterFireOnly(0),
    AboveWaterTargetsOnly(0),
    BelowWaterTargetsOnly(0),
    ReTargetOnMiss(0),
    NeedToComputeBombDrop(0),
    pad_0141_0144{},
    BombDropThreshold(1.5f),
    UseFiringSolutionInsteadOfAimBone(0),
    IgnoreIfDisabled(0),
    CannotAttackGround(0),
    pad_014B_014C{},
    UIMinRangeVisualId(),
    UIMaxRangeVisualId()
  {}

  /**
   * Address: 0x00524E50 (FUN_00524E50, Moho::RUnitBlueprintWeapon::RUnitBlueprintWeapon)
   *
   * What it does:
   * Copy-constructs one weapon blueprint lane, preserving complete field
   * payload across ids, strings, and scalar gameplay properties.
   */
  RUnitBlueprintWeapon::RUnitBlueprintWeapon(const RUnitBlueprintWeapon& other) = default;

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
