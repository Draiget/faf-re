#include "moho/misc/RangeExtractor.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "legacy/containers/String.h"
#include "moho/collision/CounterIntelExtractor.h"
#include "moho/collision/IntelExtractor.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/CombinedMilitaryExtractor.h"
#include "moho/misc/CountermeasureExtractor.h"
#include "moho/misc/MiscellaneousExtractor.h"
#include "moho/misc/OmniExtractor.h"
#include "moho/misc/RadarExtractor.h"
#include "moho/misc/SonarExtractor.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/core/WeaponExtractor.h"

namespace
{
  using BlueprintExtractorRegistry = std::map<std::string, std::unique_ptr<moho::RangeExtractor>>;

  [[nodiscard]] BlueprintExtractorRegistry& GetBlueprintExtractorRegistry()
  {
    static BlueprintExtractorRegistry registry;
    return registry;
  }

  bool gBlueprintExtractorsInitialized = false;

  void RegisterExtractor(
    BlueprintExtractorRegistry& registry,
    const char* const blueprintRangeName,
    std::unique_ptr<moho::RangeExtractor> extractor
  )
  {
    if (!blueprintRangeName || !extractor) {
      return;
    }

    registry[blueprintRangeName] = std::move(extractor);
  }

  [[nodiscard]] std::unique_ptr<moho::RangeExtractor>
  CreateWeaponExtractor(const moho::UnitWeaponRangeCategory rangeCategory)
  {
    auto extractor = std::make_unique<moho::WeaponExtractor>();
    extractor->mRangeCategory = static_cast<std::int32_t>(rangeCategory);
    return extractor;
  }

  void PopulateBlueprintExtractors(BlueprintExtractorRegistry& registry)
  {
    RegisterExtractor(registry, "AllMilitary", std::make_unique<moho::CombinedMilitaryExtractor>());
    RegisterExtractor(registry, "DirectFire", CreateWeaponExtractor(moho::UWRC_DirectFire));
    RegisterExtractor(registry, "IndirectFire", CreateWeaponExtractor(moho::UWRC_IndirectFire));
    RegisterExtractor(registry, "AntiAir", CreateWeaponExtractor(moho::UWRC_AntiAir));
    RegisterExtractor(registry, "AntiNavy", CreateWeaponExtractor(moho::UWRC_AntiNavy));
    RegisterExtractor(registry, "Defense", std::make_unique<moho::CountermeasureExtractor>());
    RegisterExtractor(registry, "Miscellaneous", std::make_unique<moho::MiscellaneousExtractor>());
    RegisterExtractor(registry, "AllIntel", std::make_unique<moho::IntelExtractor>());
    RegisterExtractor(registry, "Radar", std::make_unique<moho::RadarExtractor>());
    RegisterExtractor(registry, "Sonar", std::make_unique<moho::SonarExtractor>());
    RegisterExtractor(registry, "Omni", std::make_unique<moho::OmniExtractor>());
    RegisterExtractor(registry, "CounterIntel", std::make_unique<moho::CounterIntelExtractor>());
  }

  struct FactoryCommandQueueRangeView
  {
    std::uint8_t pad_0000_0460[0x460];
    float guardScanRadius;           // +0x460
    float guardReturnRadius;         // +0x464
    float stagingPlatformScanRadius; // +0x468
  };

  static_assert(
    offsetof(FactoryCommandQueueRangeView, guardScanRadius) == 0x460,
    "FactoryCommandQueueRangeView::guardScanRadius offset must be 0x460"
  );
  static_assert(
    offsetof(FactoryCommandQueueRangeView, stagingPlatformScanRadius) == 0x468,
    "FactoryCommandQueueRangeView::stagingPlatformScanRadius offset must be 0x468"
  );
}

namespace moho
{
  /**
   * Address: 0x00A82547 (_purecall slot in abstract base)
   */
  RangeExtractor::~RangeExtractor() = default;

  float RangeExtractor::ResolvePositiveRadius(const float preferredRadius, const float fallbackRadius) noexcept
  {
    return preferredRadius > 0.0f ? preferredRadius : fallbackRadius;
  }

  bool RangeExtractor::StoreRangeAtCenter(
    SRangeExtractionPayload* const outRange,
    const Wm3::Vec3f& center,
    const float outerRadius,
    const float innerRadius
  ) noexcept
  {
    if (!outRange || outerRadius <= 0.0f) {
      return false;
    }

    outRange->centerX = center.x;
    outRange->centerZ = center.z;
    outRange->innerRadius = innerRadius;
    outRange->outerRadius = outerRadius;
    return true;
  }

  bool RangeExtractor::StoreRangeAtEntity(
    SRangeExtractionPayload* const outRange,
    const UserEntity& userEntity,
    const float interpolationAlpha,
    const float outerRadius,
    const float innerRadius
  )
  {
    if (!outRange || outerRadius <= 0.0f) {
      return false;
    }

    const VTransform transform = userEntity.GetInterpolatedTransform(interpolationAlpha);
    outRange->centerX = transform.pos_.x;
    outRange->centerZ = transform.pos_.z;
    outRange->innerRadius = innerRadius;
    outRange->outerRadius = outerRadius;
    return true;
  }

  bool RangeExtractor::TryGetFactoryOverlayRadius(const UserUnit* const userUnit, float* const outRadius) noexcept
  {
    if (!userUnit || !outRadius) {
      return false;
    }

    const auto commandQueueWord = static_cast<std::uint32_t>(userUnit->GetFactoryCommandQueue2());
    if (commandQueueWord == 0u) {
      *outRadius = 0.0f;
      return false;
    }

    const auto* const commandQueue =
      reinterpret_cast<const FactoryCommandQueueRangeView*>(static_cast<std::uintptr_t>(commandQueueWord));
    const float radius = ResolvePositiveRadius(commandQueue->stagingPlatformScanRadius, commandQueue->guardScanRadius);
    *outRadius = radius;
    return radius > 0.0f;
  }

  bool RangeExtractor::TryGetIntelRanges(
    const UserEntity* const userEntity,
    float* const outOmniRange,
    float* const outRadarRange,
    float* const outSonarRange
  )
  {
    if (!userEntity || !outOmniRange || !outRadarRange || !outSonarRange) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    return userUnit && userUnit->GetIntelRanges(outOmniRange, outRadarRange, outSonarRange);
  }

  bool RangeExtractor::TryGetWeaponRangeByCategory(
    const UserEntity* const userEntity,
    const std::int32_t rangeCategoryFilter,
    float* const outInnerRadius,
    float* const outOuterRadius
  )
  {
    if (!userEntity || !outInnerRadius || !outOuterRadius) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    return userUnit && userUnit->FindWeaponBy(rangeCategoryFilter, outInnerRadius, outOuterRadius);
  }

  /**
   * Address: 0x007ED4B0 (FUN_007ED4B0, Moho::sBlueprintExtractors::sBlueprintExtractors)
   *
   * What it does:
   * Rebuilds the global blueprint range-extractor registry and installs
   * all known extractor instances by blueprint key.
   */
  void InitializeBlueprintExtractors()
  {
    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    registry.clear();
    PopulateBlueprintExtractors(registry);
    gBlueprintExtractorsInitialized = true;
  }

  /**
   * Address: 0x007ED9A0 (FUN_007ED9A0, Moho::sBlueprintExtractors::~sBlueprintExtractors)
   *
   * What it does:
   * Destroys the global blueprint range-extractor registry and releases
   * all registered extractor instances.
   */
  void ShutdownBlueprintExtractors()
  {
    if (!gBlueprintExtractorsInitialized) {
      return;
    }

    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    registry.clear();
    gBlueprintExtractorsInitialized = false;
  }

  /**
   * Address: 0x007EDA40 (FUN_007EDA40)
   *
   * msvc8::string const &
   *
   * What it does:
   * Looks up a registered extractor by blueprint range key and returns
   * the associated instance, or `nullptr` when no mapping exists.
   */
  RangeExtractor* GetRangeExtractor(const msvc8::string& extractorName)
  {
    if (!gBlueprintExtractorsInitialized) {
      InitializeBlueprintExtractors();
    }

    if (!extractorName.basic_sanity()) {
      return nullptr;
    }

    BlueprintExtractorRegistry& registry = GetBlueprintExtractorRegistry();
    const std::string rangeKey(extractorName.data(), extractorName.size());
    const auto it = registry.find(rangeKey);
    if (it == registry.end()) {
      return nullptr;
    }

    return it->second.get();
  }
} // namespace moho
