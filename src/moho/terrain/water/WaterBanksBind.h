#pragma once

// Banks of the water bodies, render side: the console variables and the binding of the patched water effect (the pure
// parts, the source patch and the growth of a river's banks, are WaterBanks.h's; docs/WATER_SIMULATION.md, "Banks").
// Render only.
namespace moho::water
{
  /// Whether the water effect should get the banks patch (`ren_WaterBanks` not 0 when the effect is read).
  [[nodiscard]] bool BankPatchWanted();

  /// Whether the cut-out mask of a water body is laid per pixel (`ren_WaterBanks` 1 or more, live).
  [[nodiscard]] bool BankMaskWanted();

  /// Whether the mesh of a river grows to the ground (`ren_WaterBanks` 2, read when a map's bodies are first drawn),
  /// and how far in units past its half width.
  [[nodiscard]] bool BankGrowthWanted();
  [[nodiscard]] int BankReach();

  /// Around the draw of the cut-out mask of one water: `body` says that it is a body's (a lake's or a river's), whose
  /// mask is the depth test alone; the sea's is the shipped one. Call it before every water of the pass.
  void BindBankMask(bool body);
} // namespace moho::water
