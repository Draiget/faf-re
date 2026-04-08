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
