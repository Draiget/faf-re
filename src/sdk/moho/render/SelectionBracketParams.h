#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00F57E1C (ren_SelectionSizeFudge)
   */
  extern float ren_SelectionSizeFudge;

  /**
   * Address: 0x00F57E20 (ren_SelectionHeightFudge)
   */
  extern float ren_SelectionHeightFudge;

  /**
   * Address: 0x00F57E24 (ren_UnitSelectionScale)
   */
  extern float ren_UnitSelectionScale;

  /**
   * Address: 0x00F57E30 (ren_SelectColor)
   */
  extern std::uint32_t ren_SelectColor;

  /**
   * Address: 0x00F57E28 (ren_SelectBracketMinPixelSize)
   */
  extern float ren_SelectBracketMinPixelSize;

  /**
   * Address: 0x00F57E2C (ren_SelectBracketSize)
   */
  extern float ren_SelectBracketSize;

  /**
   * Address: 0x007FC4B0 (FUN_007FC4B0, func_LoadLuaSelectionParams)
   *
   * What it does:
   * Imports `/lua/renderselectparams.lua`, applies selection render tuning
   * fields when present, and returns the caller-owned sentinel pointer
   * unchanged.
   */
  [[nodiscard]] void* LoadLuaSelectionParams(void* selectionParamsSentinel);
}
