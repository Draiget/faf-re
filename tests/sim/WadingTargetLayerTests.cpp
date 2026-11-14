// Engine rule fix: a wading `Land` unit counts as `Seabed` for weapons that cannot target `Land`
// (src/moho/unit/core/WadingTargetLayer.h). Pure-function test, no sim.
//
// The scenario is the reported bug: torpedo bombers (`FireTargetLayerCapsTable = Seabed|Sub|Water`) and a
// Seraphim Ythotha (`XSL0401`, `LayerChangeOffsetHeight = -5`) standing in water. The first block replays the
// old rule (`caps & layer`), which refuses it at every depth up to the offset; it is the reproduction of the
// bug and has to keep failing without the fix.

#include <cstdio>
#include <initializer_list>
#include <limits>

#include "moho/unit/core/WadingTargetLayer.h"

namespace
{
  using moho::ELayer;
  using moho::LAYER_Air;
  using moho::LAYER_Land;
  using moho::LAYER_Seabed;
  using moho::LAYER_Sub;
  using moho::LAYER_Water;

  int sFailures = 0;

  void Check(const bool ok, const char* const what)
  {
    if (!ok) {
      ++sFailures;
      std::printf("FAIL %s\n", what);
    }
  }

  // CUnitMotion::UpdateCurrentLayer for a land walker: Land until the ground is at or below
  // water + LayerChangeOffsetHeight.
  ELayer LayerAfterMotion(const float ground, const float water, const float offset)
  {
    return (ground > water + offset) ? LAYER_Land : LAYER_Seabed;
  }

  // The old check at the top of CanWeaponAttackEntityTarget.
  bool OldRuleAllows(const ELayer caps, const ELayer layer)
  {
    return (static_cast<int>(caps) & static_cast<int>(layer)) != 0;
  }

  bool NewRuleAllows(const bool fix, const ELayer caps, const ELayer layer, const float y, const bool water, const float surface)
  {
    return OldRuleAllows(caps, moho::WadingTargetLayer(fix, layer, caps, y, water, surface));
  }
} // namespace

int main()
{
  const ELayer torpedoCaps = static_cast<ELayer>(LAYER_Seabed | LAYER_Sub | LAYER_Water);
  const ELayer groundWeaponCaps = static_cast<ELayer>(LAYER_Land | LAYER_Water);
  const ELayer aaCaps = LAYER_Air;
  const float water = 10.0f;
  const float ythothaOffset = -5.0f;

  // The reported bug: refused while the unit is still Land (depth 0..5), accepted once it is Seabed.
  for (const float depth : {0.01f, 0.5f, 1.0f, 3.0f, 4.9f}) {
    const ELayer layer = LayerAfterMotion(water - depth, water, ythothaOffset);
    Check(layer == LAYER_Land, "Ythotha in 0..5 uu of water is still Land");
    Check(!OldRuleAllows(torpedoCaps, layer), "BUG: torpedo caps refuse the wading Ythotha (old rule)");
    Check(NewRuleAllows(true, torpedoCaps, layer, water - depth, true, water), "fix: torpedo caps accept the wading Ythotha");
    Check(!NewRuleAllows(false, torpedoCaps, layer, water - depth, true, water), "fix off: still refused (retail behaviour)");
  }
  for (const float depth : {5.1f, 8.0f}) {
    const ELayer layer = LayerAfterMotion(water - depth, water, ythothaOffset);
    Check(layer == LAYER_Seabed, "Ythotha deeper than the offset is Seabed");
    Check(OldRuleAllows(torpedoCaps, layer), "old rule accepts a Seabed Ythotha");
    Check(NewRuleAllows(true, torpedoCaps, layer, water - depth, true, water), "fix keeps accepting a Seabed Ythotha");
    Check(moho::WadingTargetLayer(true, layer, torpedoCaps, water - depth, true, water) == layer, "Seabed target is not remapped");
  }

  // Dry land stays Land: torpedo bombers must not attack land units on the shore.
  Check(!NewRuleAllows(true, torpedoCaps, LAYER_Land, water + 0.5f, true, water), "dry land target refused");
  Check(!NewRuleAllows(true, torpedoCaps, LAYER_Land, water, true, water), "ground exactly at the surface is dry");
  Check(!NewRuleAllows(true, torpedoCaps, LAYER_Land, water + 30.0f, true, water), "hill refused");

  // A weapon that lists Land keeps seeing the wader as Land, not remapped.
  Check(moho::WadingTargetLayer(true, LAYER_Land, groundWeaponCaps, water - 3.0f, true, water) == LAYER_Land,
        "ground weapon: layer unchanged");
  // A weapon without Seabed bit is not helped.
  Check(!NewRuleAllows(true, aaCaps, LAYER_Land, water - 3.0f, true, water), "AA weapon still refuses a wader");
  Check(!NewRuleAllows(true, static_cast<ELayer>(LAYER_Water | LAYER_Sub), LAYER_Land, water - 3.0f, true, water),
        "weapon without Seabed bit still refuses a wader");

  // Only Land is remapped.
  Check(moho::WadingTargetLayer(true, LAYER_Air, torpedoCaps, water - 3.0f, true, water) == LAYER_Air, "Air unchanged");
  Check(moho::WadingTargetLayer(true, LAYER_Water, torpedoCaps, water - 3.0f, true, water) == LAYER_Water, "Water unchanged");
  Check(moho::WadingTargetLayer(true, LAYER_Sub, torpedoCaps, water - 3.0f, true, water) == LAYER_Sub, "Sub unchanged");

  // No water, NaN height.
  Check(!NewRuleAllows(true, torpedoCaps, LAYER_Land, water - 3.0f, false, water), "map without water: unchanged");
  const float nan = std::numeric_limits<float>::quiet_NaN();
  Check(!NewRuleAllows(true, torpedoCaps, LAYER_Land, nan, true, water), "NaN height is not in the water");

  // Ordinary unit, default offset -0.1: the fix only moves the band 0..0.1 uu.
  Check(LayerAfterMotion(water - 0.05f, water, -0.1f) == LAYER_Land, "tank in 0.05 uu is Land");
  Check(NewRuleAllows(true, torpedoCaps, LAYER_Land, water - 0.05f, true, water), "fix: that tank counts as in the water");

  if (sFailures != 0) {
    std::printf("wading_target_layer: %d failure(s)\n", sFailures);
    return 1;
  }
  std::printf("wading_target_layer: all checks passed\n");
  return 0;
}
