#pragma once

#include <cstdint>

#include "moho/entity/EntityAttributes.h"

namespace moho
{
  /**
   * Engine rule fix (not an FA-Binary-Patches port): the layer a weapon's target-layer check sees for a
   * unit that wades.
   *
   * A walking unit keeps layer `Land` until the ground under it is deeper than its blueprint's
   * `Physics.LayerChangeOffsetHeight` below the water surface (`CUnitMotion::UpdateCurrentLayer`). Most units
   * have -0.1, so the band is thin; the big bots have -2.5 (Megalith) to -5 (Ythotha), so a Ythotha standing in
   * 4 uu of water, legs under, is still `Land`. A weapon whose `FireTargetLayerCapsTable` has no `Land` bit
   * (torpedo bombers: `Seabed|Sub|Water`) is then refused by `CanWeaponAttackEntityTarget` (0x006D5590) at
   * `(caps & layer) == 0`, before the above-/below-water target point checks that exist for exactly such
   * targets are reached. Seen as: torpedo bombers cannot attack a half-submerged experimental until it walks
   * deeper than its offset, then they can.
   *
   * With the fix on, a `Land` target whose ground contact point is below the water surface counts as `Seabed`
   * for a weapon that does not list `Land` but does list `Seabed`. The weapon's own `AboveWaterTargetsOnly` /
   * `BelowWaterTargetsOnly` flags then decide as they do for any `Seabed` target. Nothing changes for a weapon
   * that lists `Land` (it keeps attacking the wader as `Land`), for a target on dry land, or for a weapon
   * without a `Seabed` bit.
   *
   * Pure function so the rule is testable without a sim (tests/sim/WadingTargetLayerTests.cpp); the engine
   * and the UI both call it. `fixActive` is `FAF_IsSimFixActive(EFafSimFix::WadingTargetLayer)`.
   *
   * @param targetLayer    the target's single layer (`mVarDat.mLayerMask`)
   * @param weaponLayerCaps the weapon's `FireTargetLayerCapsTable` mask for the shooter's layer
   * @param targetGroundY  elevation of the target's ground contact point (its position y)
   * @param waterEnabled   there is water at the target's position
   * @param waterElevation water surface elevation at the target's position (`STIMap::GetWaterElevationAt`, which
   *                       follows water bodies)
   */
  [[nodiscard]] constexpr ELayer WadingTargetLayer(
    const bool fixActive,
    const ELayer targetLayer,
    const ELayer weaponLayerCaps,
    const float targetGroundY,
    const bool waterEnabled,
    const float waterElevation
  ) noexcept
  {
    if (!fixActive || !waterEnabled) {
      return targetLayer;
    }
    if (targetLayer != LAYER_Land) {
      return targetLayer;
    }
    if ((static_cast<std::int32_t>(weaponLayerCaps) & static_cast<std::int32_t>(LAYER_Land)) != 0) {
      return targetLayer;
    }
    if ((static_cast<std::int32_t>(weaponLayerCaps) & static_cast<std::int32_t>(LAYER_Seabed)) == 0) {
      return targetLayer;
    }
    // Strictly below the surface; an unordered (NaN) height is not "in the water".
    if (!(targetGroundY < waterElevation)) {
      return targetLayer;
    }
    return LAYER_Seabed;
  }
} // namespace moho
