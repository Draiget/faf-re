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
  // The shipped registry is `Moho::sBlueprintExtractors`, an RB-tree whose node
  // is 0x30 bytes: the key string's `_Bx` lands at node+0x10 and its `_Myres`
  // at node+0x24 (0x007F2FA0 frees exactly those), the extractor pointer sits
  // at node+0x28 (0x007ED9A0 reads it and runs the scalar deleting destructor
  // through it), and the colour/nil pair follows at +0x2C/+0x2D. That is
  // `pair<const msvc8::string, RangeExtractor*>` -- a raw pointer, so the
  // `unique_ptr` this file used to hold was not a container substitution
  // forced by the value type, it was an invented ownership model.
  using BlueprintExtractorRegistry = msvc8::map<msvc8::string, moho::RangeExtractor*>;

  [[nodiscard]] BlueprintExtractorRegistry& GetBlueprintExtractorRegistry()
  {
    static BlueprintExtractorRegistry registry;
    return registry;
  }

  bool gBlueprintExtractorsInitialized = false;

  void RegisterExtractor(
    BlueprintExtractorRegistry& registry,
    const char* const blueprintRangeName,
    moho::RangeExtractor* const extractor
  )
  {
    if (blueprintRangeName == nullptr || extractor == nullptr) {
      return;
    }

    registry[msvc8::string(blueprintRangeName)] = extractor;
  }

  [[nodiscard]] moho::RangeExtractor* CreateWeaponExtractor(const moho::UnitWeaponRangeCategory rangeCategory)
  {
    auto* const extractor = new moho::WeaponExtractor();
    extractor->mRangeCategory = static_cast<std::int32_t>(rangeCategory);
    return extractor;
  }

  void PopulateBlueprintExtractors(BlueprintExtractorRegistry& registry)
  {
    RegisterExtractor(registry, "AllMilitary", new moho::CombinedMilitaryExtractor());
    RegisterExtractor(registry, "DirectFire", CreateWeaponExtractor(moho::UWRC_DirectFire));
    RegisterExtractor(registry, "IndirectFire", CreateWeaponExtractor(moho::UWRC_IndirectFire));
    RegisterExtractor(registry, "AntiAir", CreateWeaponExtractor(moho::UWRC_AntiAir));
    RegisterExtractor(registry, "AntiNavy", CreateWeaponExtractor(moho::UWRC_AntiNavy));
    RegisterExtractor(registry, "Defense", new moho::CountermeasureExtractor());
    RegisterExtractor(registry, "Miscellaneous", new moho::MiscellaneousExtractor());
    RegisterExtractor(registry, "AllIntel", new moho::IntelExtractor());
    RegisterExtractor(registry, "Radar", new moho::RadarExtractor());
    RegisterExtractor(registry, "Sonar", new moho::SonarExtractor());
    RegisterExtractor(registry, "Omni", new moho::OmniExtractor());
    RegisterExtractor(registry, "CounterIntel", new moho::CounterIntelExtractor());
  }

  [[nodiscard]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointer() noexcept
  {
    return &GetBlueprintExtractorRegistry();
  }

  /**
   * Address: 0x007EC590 (FUN_007EC590)
   *
   * What it does:
   * Rebinds one runtime lane to the base `RangeExtractor` vtable tag.
   */
  /**
   * The sibling emissions of this same vptr fixup, one per class whose
   * constructor or destructor writes a vtable into the lane. They were
   * recovered as seventeen separate free functions, every one of them
   * referenced by nothing (several were literally `return LaneA(view);`).
   *
   * No source line produces these: MSVC writes the vptr as part of ctor/dtor
   * codegen, so there is nothing to call and nothing to invent a caller for.
   * The addresses are kept here so they stay traceable.
   *
   * Address: 0x007EC380  base, void-adapter shape
   * Address: 0x007EC580  base, LaneD secondary
   * Address: 0x007EC860  base
   * Address: 0x007ECBF0  base
   * Address: 0x007EDBD0  base
   * Address: 0x007EDBE0  base
   * Address: 0x007EDBF0  base
   * Address: 0x007EDC00  base
   * Address: 0x007EDC10  base
   * Address: 0x007EDC20  base
   * Address: 0x007EC390  Moho::CombinedMilitaryExtractor
   * Address: 0x007EC870  Moho::CountermeasureExtractor
   * Address: 0x007EDAB0  Moho::MiscellaneousExtractor
   * Address: 0x007EDAC0  Moho::IntelExtractor
   * Address: 0x007EDAD0  Moho::RadarExtractor
   * Address: 0x007EDAE0  Moho::SonarExtractor
   * Address: 0x007EDAF0  Moho::OmniExtractor
   * Address: 0x007EDB00  Moho::CounterIntelExtractor
   * Address: 0x007EC590  base, the lane the two stand-in structs served
   * Address: 0x007EC5A0  Moho::WeaponExtractor, which also stores its
   *                      range category at +0x04
   *
   * The `ExtractorVtableOnlyRuntimeView` / `WeaponExtractorCtorRuntimeView`
   * stand-ins these were written over are gone with them (RULE ONE):
   * a vptr fixup has no source line to model an object for.
   */
  /**
   * Address: 0x007F1CB0 (FUN_007F1CB0)
   *
   * What it does:
   * Returns the process-global blueprint extractor registry pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneA(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F2CA0 (FUN_007F2CA0)
   *
   * What it does:
   * Secondary lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneB(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F3040 (FUN_007F3040)
   *
   * What it does:
   * Third lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneC(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

  /**
   * Address: 0x007F32C0 (FUN_007F32C0)
   *
   * What it does:
   * Fourth lane returning the process-global blueprint extractor registry
   * pointer.
   */
  [[maybe_unused]] BlueprintExtractorRegistry* GetBlueprintExtractorRegistryPointerLaneD(const int /*unused*/) noexcept
  {
    return GetBlueprintExtractorRegistryPointer();
  }

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

  bool RangeExtractor::TryGetAssistOverlayRadius(const UserEntity* const userEntity, float* const outRadius) noexcept
  {
    if (!userEntity || !outRadius) {
      return false;
    }

    const UserUnit* const userUnit = userEntity->IsUserUnit();
    if (userUnit == nullptr) {
      return false;
    }

    const RUnitBlueprint* const unitBlueprint = static_cast<const IUnit*>(userUnit)->GetBlueprint();
    if (unitBlueprint == nullptr) {
      return false;
    }

    // `CombinedMilitaryExtractor::Extract` (0x007EC3E1..0x007EC419) builds the
    // literal "OVERLAYMISC" and asks the entity, not the blueprint, whether it
    // is in that category; only then does it read the radius.
    if (!userEntity->IsInCategory(msvc8::string("OVERLAYMISC"))) {
      return false;
    }

    const float radius =
      ResolvePositiveRadius(unitBlueprint->AI.StagingPlatformScanRadius, unitBlueprint->AI.GuardScanRadius);
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
   *
   * Container substitution note: the real binary's tree-erase/clear core
   * for `sBlueprintExtractors` (FUN_007F1990, a `msvc8::map`-shaped
   * `erase(first,last)`/`clear()` walk) is deliberately NOT cited on
   * `registry.clear()` above. `BlueprintExtractorRegistry` holds
   * `std::unique_ptr<moho::RangeExtractor>` values -- a move-only owning
   * smart pointer this project's binary-layout-focused `msvc8::map` has no
   * way to model or store -- so the real `std::map` here is an intentional
   * substitution, not a fidelity gap to migrate away. `FUN_007F1990` marked
   * `skip` for this reason.
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
    // The shipped destructor walks the tree, runs each extractor's scalar
    // deleting destructor through the pointer at node+0x28, and only then
    // erases the whole range.
    for (const auto& entry : registry) {
      delete entry.second;
    }
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

    const auto foundEntry = registry.find(extractorName);
    if (foundEntry == registry.end()) {
      return nullptr;
    }

    return foundEntry->second;
  }
} // namespace moho
