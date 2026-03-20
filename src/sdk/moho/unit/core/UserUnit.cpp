// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/UserUnit.h"

#include <cstddef>
#include <cstdint>
#include <limits>

#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitAttributes.h"

using namespace moho;

namespace
{
  enum class EIntel : std::int32_t
  {
    None = 0,
    Vision = 1,
    WaterVision = 2,
    Radar = 3,
    Sonar = 4,
    Omni = 5,
    RadarStealthField = 6,
    SonarStealthField = 7,
    CloakField = 8,
    Jammer = 9,
    Spoof = 10,
    Cloak = 11,
    RadarStealth = 12,
    SonarStealth = 13,
  };

  constexpr std::uint32_t kIntelRangeMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint8_t kToggleCapJamming = 0x04u;
  constexpr std::uint8_t kToggleCapIntel = 0x08u;
  constexpr std::uint8_t kToggleCapStealth = 0x20u;
  constexpr std::int32_t kRangeCategoryAll = 6;

  struct UserEntityUiFlagView
  {
    std::uint8_t pad_0000_0070[0x70];
    std::uint8_t isBeingBuilt; // +0x70
    std::uint8_t pad_0071;
    std::uint8_t requestRefreshUi; // +0x72
  };
  static_assert(
    offsetof(UserEntityUiFlagView, isBeingBuilt) == 0x70, "UserEntityUiFlagView::isBeingBuilt offset must be 0x70"
  );
  static_assert(
    offsetof(UserEntityUiFlagView, requestRefreshUi) == 0x72,
    "UserEntityUiFlagView::requestRefreshUi offset must be 0x72"
  );

  struct UserUnitIntelRangeView
  {
    std::uint8_t pad_0000_0100[0x100];
    std::uint32_t vision;       // +0x100
    std::uint32_t waterVision;  // +0x104
    std::uint32_t radar;        // +0x108
    std::uint32_t sonar;        // +0x10C
    std::uint32_t omni;         // +0x110
    std::uint32_t radarStealth; // +0x114
    std::uint32_t sonarStealth; // +0x118
    std::uint32_t cloak;        // +0x11C
  };
  static_assert(
    offsetof(UserUnitIntelRangeView, vision) == 0x100, "UserUnitIntelRangeView::vision offset must be 0x100"
  );
  static_assert(offsetof(UserUnitIntelRangeView, cloak) == 0x11C, "UserUnitIntelRangeView::cloak offset must be 0x11C");

  struct UserUnitWeaponRuntimeView
  {
    std::uint8_t pad_0000_0054[0x54];
    float minRange; // +0x54
    float maxRange; // +0x58
    std::uint8_t pad_005C_0098[0x98 - 0x5C];
  };
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, minRange) == 0x54, "UserUnitWeaponRuntimeView::minRange offset must be 0x54"
  );
  static_assert(
    offsetof(UserUnitWeaponRuntimeView, maxRange) == 0x58, "UserUnitWeaponRuntimeView::maxRange offset must be 0x58"
  );
  static_assert(sizeof(UserUnitWeaponRuntimeView) == 0x98, "UserUnitWeaponRuntimeView size must be 0x98");

  [[nodiscard]] const IUnit* GetIUnitBridge(const UserUnit* const self) noexcept
  {
    return reinterpret_cast<const IUnit*>(self->mIUnitAndScriptBridge);
  }

  [[nodiscard]] const UserUnitIntelRangeView& GetIntelRangeView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserUnitIntelRangeView*>(self);
  }

  [[nodiscard]] std::uint32_t GetIntelRangeMagnitude(const UserUnit* const self, const EIntel intel) noexcept
  {
    const auto& ranges = GetIntelRangeView(self);

    // Binary parity with 0x005BD530 (EntityAttributes::GetRange):
    // enum ordinals are shifted relative to stored lanes.
    switch (intel) {
    case EIntel::None:
      return ranges.vision & kIntelRangeMagnitudeMask;
    case EIntel::Vision:
      return ranges.waterVision & kIntelRangeMagnitudeMask;
    case EIntel::WaterVision:
      return ranges.radar & kIntelRangeMagnitudeMask;
    case EIntel::Radar:
      return ranges.sonar & kIntelRangeMagnitudeMask;
    case EIntel::Sonar:
      return ranges.omni & kIntelRangeMagnitudeMask;
    case EIntel::Spoof:
      return ranges.cloak & kIntelRangeMagnitudeMask;
    case EIntel::Cloak:
      return ranges.radarStealth & kIntelRangeMagnitudeMask;
    case EIntel::RadarStealth:
      return ranges.sonarStealth & kIntelRangeMagnitudeMask;
    case EIntel::Omni:
    case EIntel::RadarStealthField:
    case EIntel::SonarStealthField:
    case EIntel::CloakField:
    case EIntel::Jammer:
    case EIntel::SonarStealth:
      return 0u;
    }
    return 0u;
  }

  [[nodiscard]] float GetIntelRangeAsFloat(const UserUnit* const self, const EIntel intel) noexcept
  {
    return static_cast<float>(GetIntelRangeMagnitude(self, intel));
  }

  [[nodiscard]] const UserEntityUiFlagView& GetUiFlagView(const UserUnit* const self) noexcept
  {
    return *reinterpret_cast<const UserEntityUiFlagView*>(self);
  }
} // namespace

/**
 * Address: 0x008BF120 (FUN_008BF120)
 *
 * What it does:
 * Returns this object as the const UserUnit identity view.
 */
UserUnit const* UserUnit::IsUserUnit1() const
{
  return this;
}

/**
 * Address: 0x008BF110 (FUN_008BF110)
 *
 * What it does:
 * Returns this object as the mutable UserUnit identity view.
 */
UserUnit* UserUnit::IsUserUnit2()
{
  return this;
}

/**
 * Address: 0x008BF170 (FUN_008BF170)
 *
 * What it does:
 * Calls IUnit::GetBlueprint through the embedded +0x148 subobject and reads
 * blueprint uniform scale at +0x270.
 */
float UserUnit::GetUnitformScale() const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  return blueprint->Display.UniformScale;
}

/**
 * Address: 0x008BF150 (FUN_008BF150)
 *
 * What it does:
 * Returns the current user command-queue handle (mutable view slot).
 */
std::int32_t UserUnit::GetCommandQueue1()
{
  return mCommandQueueHandle;
}

/**
 * Address: 0x008BF130 (FUN_008BF130)
 *
 * What it does:
 * Returns the current user command-queue handle (const view slot).
 */
std::int32_t UserUnit::GetCommandQueue2() const
{
  return mCommandQueueHandle;
}

/**
 * Address: 0x008BF160 (FUN_008BF160)
 *
 * What it does:
 * Returns the current factory command-queue handle (mutable view slot).
 */
std::int32_t UserUnit::GetFactoryCommandQueue1()
{
  return mFactoryCommandQueueHandle;
}

/**
 * Address: 0x008BF140 (FUN_008BF140)
 *
 * What it does:
 * Returns the current factory command-queue handle (const view slot).
 */
std::int32_t UserUnit::GetFactoryCommandQueue2() const
{
  return mFactoryCommandQueueHandle;
}

/**
 * Address: 0x008B8530 (FUN_008B8530)
 *
 * What it does:
 * Returns replicated UI-dirty state from UserEntity variable-data bytes.
 */
bool UserUnit::RequiresUIRefresh() const
{
  return GetUiFlagView(this).requestRefreshUi != 0;
}

/**
 * Address: 0x008BEFB0 (FUN_008BEFB0)
 *
 * What it does:
 * Returns replicated "being built" state from UserEntity variable-data bytes.
 */
bool UserUnit::IsBeingBuilt() const
{
  return GetUiFlagView(this).isBeingBuilt != 0;
}

/**
 * Address: 0x008BFC50 (FUN_008BFC50)
 *
 * What it does:
 * Aggregates weapon min/max radii over runtime weapon entries filtered by
 * range category (`6` means match all categories).
 */
bool UserUnit::FindWeaponBy(
  const std::int32_t rangeCategoryFilter, float* const outMinRange, float* const outMaxRange
) const
{
  constexpr float kInitialMinRangeSentinel = std::numeric_limits<float>::max();
  constexpr float kInitialMaxRangeSentinel = std::numeric_limits<float>::lowest();

  *outMaxRange = kInitialMaxRangeSentinel;
  *outMinRange = kInitialMinRangeSentinel;

  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const auto& weaponBlueprints = blueprint->Weapons.WeaponBlueprints;
  const auto* const weaponRuntime = reinterpret_cast<const UserUnitWeaponRuntimeView*>(mWeaponTable);

  for (std::size_t i = 0; i < weaponBlueprints.size(); ++i) {
    const auto& weaponBlueprint = weaponBlueprints[i];
    if (rangeCategoryFilter != kRangeCategoryAll &&
        rangeCategoryFilter != static_cast<std::int32_t>(weaponBlueprint.RangeCategory)) {
      continue;
    }

    const auto& weaponStats = weaponRuntime[weaponBlueprint.WeaponIndex];
    if (weaponStats.maxRange > *outMaxRange) {
      *outMaxRange = weaponStats.maxRange;
    }
    if (weaponStats.minRange <= *outMinRange) {
      *outMinRange = weaponStats.minRange;
    }
  }

  if (*outMaxRange <= kInitialMaxRangeSentinel) {
    *outMaxRange = 0.0f;
  }
  if (kInitialMinRangeSentinel <= *outMinRange) {
    *outMinRange = 0.0f;
  }

  return *outMaxRange > 0.0f || *outMinRange > 0.0f;
}

/**
 * Address: 0x008BFD70 (FUN_008BFD70)
 *
 * What it does:
 * Returns active intel ranges (`omni`, `radar`, `sonar`) unless Intel toggle
 * state currently disables this intel block.
 */
bool UserUnit::GetIntelRanges(float* const outOmniRange, float* const outRadarRange, float* const outSonarRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if ((toggleCaps & kToggleCapIntel) != 0u && (mIntelToggleStateMask & kToggleCapIntel) != 0u) {
    return false;
  }

  *outOmniRange = GetIntelRangeAsFloat(this, EIntel::Sonar);
  *outRadarRange = GetIntelRangeAsFloat(this, EIntel::WaterVision);
  *outSonarRange = GetIntelRangeAsFloat(this, EIntel::Radar);

  return *outOmniRange > 0.0f || *outRadarRange > 0.0f || *outSonarRange > 0.0f;
}

/**
 * Address: 0x008BFE50 (FUN_008BFE50)
 *
 * What it does:
 * Computes the largest active counter-intel radius from replicated intel
 * ranges plus blueprint jam/spoof maxima.
 */
bool UserUnit::GetMaxCounterIntel(float* const outMaxCounterIntelRange) const
{
  const IUnit* const iunitBridge = GetIUnitBridge(this);
  const std::uint32_t toggleCaps = iunitBridge->GetAttributes().toggleCapsMask;
  if (((toggleCaps & kToggleCapJamming) != 0u && (mIntelToggleStateMask & kToggleCapJamming) != 0u) ||
      ((toggleCaps & kToggleCapStealth) != 0u && (mIntelToggleStateMask & kToggleCapStealth) != 0u)) {
    return false;
  }

  const RUnitBlueprint* const blueprint = iunitBridge->GetBlueprint();
  const std::uint32_t spoofRange = GetIntelRangeMagnitude(this, EIntel::Spoof);
  const std::uint32_t cloakRange = GetIntelRangeMagnitude(this, EIntel::Cloak);
  const std::uint32_t radarStealthRange = GetIntelRangeMagnitude(this, EIntel::RadarStealth);

  std::uint32_t maxCounterIntel = radarStealthRange;
  if (maxCounterIntel < cloakRange) {
    maxCounterIntel = cloakRange;
  }

  std::uint32_t maxJamOrSpoof = blueprint->Intel.SpoofRadius.max;
  if (maxJamOrSpoof < blueprint->Intel.JamRadius.max) {
    maxJamOrSpoof = blueprint->Intel.JamRadius.max;
  }
  if (maxCounterIntel < maxJamOrSpoof) {
    maxCounterIntel = maxJamOrSpoof;
  }
  if (maxCounterIntel < spoofRange) {
    maxCounterIntel = spoofRange;
  }

  *outMaxCounterIntelRange = static_cast<float>(maxCounterIntel);
  return *outMaxCounterIntelRange > 0.0f;
}

/**
 * Address: 0x008BEFD0 (FUN_008BEFD0)
 *
 * What it does:
 * Returns UI mirror of auto-mode state.
 */
bool UserUnit::GetAutoMode() const
{
  return mAutoMode;
}

/**
 * Address: 0x008BEFE0 (FUN_008BEFE0)
 *
 * What it does:
 * Returns UI mirror of auto-surface mode state.
 */
bool UserUnit::IsAutoSurfaceMode() const
{
  return mAutoSurfaceMode;
}

/**
 * Address: 0x008BEFF0 (FUN_008BEFF0)
 *
 * What it does:
 * Returns UI mirror of repeat-queue state.
 */
bool UserUnit::Func1() const
{
  return mRepeatQueueEnabled;
}

/**
 * Address: 0x008BF000 (FUN_008BF000)
 *
 * What it does:
 * Returns whether overcharge is currently paused in UI state.
 */
bool UserUnit::IsOverchargePaused() const
{
  return mOverchargePaused;
}

/**
 * Address: 0x008BF010 (FUN_008BF010)
 *
 * What it does:
 * Returns the in-object custom-name storage anchor at +0x1DC.
 */
char* UserUnit::GetCustomName()
{
  return mCustomNameStorage;
}

/**
 * Address: 0x008BF060 (FUN_008BF060)
 *
 * What it does:
 * Returns UI fuel ratio.
 */
float UserUnit::GetFuel() const
{
  return mFuelRatio;
}

/**
 * Address: 0x008BF070 (FUN_008BF070)
 *
 * What it does:
 * Returns UI shield ratio.
 */
float UserUnit::GetShield() const
{
  return mShieldRatio;
}

bool UserUnit::IsRepeatQueueEnabled() const
{
  return Func1();
}
