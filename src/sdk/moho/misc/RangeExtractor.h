#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"

namespace msvc8
{
  struct string;
}

namespace moho
{
  class UserEntity;
  class UserUnit;
  struct RUnitBlueprint;

  /**
   * Range payload used by world overlay extraction:
   * `{centerX, centerZ, innerRadius, outerRadius}`.
   */
  struct SRangeExtractionPayload
  {
    float centerX;
    float centerZ;
    float innerRadius;
    float outerRadius;
  };

  static_assert(
    offsetof(SRangeExtractionPayload, centerX) == 0x00, "SRangeExtractionPayload::centerX offset must be 0x00"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, centerZ) == 0x04, "SRangeExtractionPayload::centerZ offset must be 0x04"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, innerRadius) == 0x08,
    "SRangeExtractionPayload::innerRadius offset must be 0x08"
  );
  static_assert(
    offsetof(SRangeExtractionPayload, outerRadius) == 0x0C,
    "SRangeExtractionPayload::outerRadius offset must be 0x0C"
  );
  static_assert(sizeof(SRangeExtractionPayload) == 0x10, "SRangeExtractionPayload size must be 0x10");

  /**
   * VFTABLE: 0x00E3F920
   * COL:  0x00E983F4
   */
  class RangeExtractor
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 0
     */
    virtual ~RangeExtractor() = 0;

    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 1
     */
    [[nodiscard]] virtual bool
    Range(SRangeExtractionPayload* outRange, const RUnitBlueprint* unitBlueprint, const Wm3::Vec3f& center) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in abstract base slot)
     * Slot: 2
     */
    [[nodiscard]] virtual bool
    Extract(SRangeExtractionPayload* outRange, const UserEntity* userEntity, float interpolationAlpha) const = 0;

  protected:
    [[nodiscard]] static float ResolvePositiveRadius(float preferredRadius, float fallbackRadius) noexcept;

    [[nodiscard]] static bool StoreRangeAtCenter(
      SRangeExtractionPayload* outRange,
      const Wm3::Vec3f& center,
      float outerRadius,
      float innerRadius = 0.0f
    ) noexcept;

    [[nodiscard]] static bool StoreRangeAtEntity(
      SRangeExtractionPayload* outRange,
      const UserEntity& userEntity,
      float interpolationAlpha,
      float outerRadius,
      float innerRadius = 0.0f
    );

    [[nodiscard]] static bool TryGetFactoryOverlayRadius(const UserUnit* userUnit, float* outRadius) noexcept;

    [[nodiscard]] static bool
    TryGetIntelRanges(const UserEntity* userEntity, float* outOmniRange, float* outRadarRange, float* outSonarRange);

    [[nodiscard]] static bool TryGetWeaponRangeByCategory(
      const UserEntity* userEntity,
      std::int32_t rangeCategoryFilter,
      float* outInnerRadius,
      float* outOuterRadius
    );
  };

  /**
   * Address: 0x007ED4B0 (FUN_007ED4B0, Moho::sBlueprintExtractors::sBlueprintExtractors)
   *
   * What it does:
   * Rebuilds the global blueprint range-extractor registry and installs
   * all known extractor instances by blueprint key.
   */
  void InitializeBlueprintExtractors();

  /**
   * Address: 0x007ED9A0 (FUN_007ED9A0, Moho::sBlueprintExtractors::~sBlueprintExtractors)
   *
   * What it does:
   * Destroys the global blueprint range-extractor registry and releases
   * all registered extractor instances.
   */
  void ShutdownBlueprintExtractors();

  /**
   * Address: 0x007EDA40 (FUN_007EDA40)
   *
   * std::string const &
   *
   * What it does:
   * Looks up a registered extractor by blueprint range key and returns
   * the associated instance, or `nullptr` when no mapping exists.
   */
  [[nodiscard]] RangeExtractor* GetRangeExtractor(const msvc8::string& extractorName);

#if defined(_M_IX86)
  static_assert(sizeof(RangeExtractor) == 0x04, "RangeExtractor size must be 0x04");
#endif
} // namespace moho
