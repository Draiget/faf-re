#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x006B7080 (FUN_006B7080)
   *
   * What it does:
   * Opaque reflected enum lane used by CUnitMotion state metadata/serializers.
   */
  enum EUnitMotionState : std::int32_t;

  /**
   * Address: 0x006B71B0 (FUN_006B71B0)
   *
   * What it does:
   * Opaque reflected enum lane for carrier-side CUnitMotion events.
   */
  enum EUnitMotionCarrierEvent : std::int32_t;

  /**
   * Address: 0x006B72E0 (FUN_006B72E0)
   *
   * What it does:
   * Opaque reflected enum lane for horizontal CUnitMotion events.
   */
  enum EUnitMotionHorzEvent : std::int32_t;

  /**
   * Address: 0x006B7540 (FUN_006B7540)
   *
   * What it does:
   * Turn-sharpness hint computed by `CUnitMotion::CalcMoveAir` from the dot
   * product between the current heading and the desired-velocity direction,
   * and reported to Lua as `OnMotionTurnEventChange`.
   *
   * The names are read straight out of the binary, not inferred: the script
   * notification indexes a three-entry name table at `0x00F58374`, whose
   * pointers resolve to "Straight" (0), "Turn" (1) and "SharpTurn" (2). That
   * table is bounded on both sides by its neighbours -- the five-entry vert
   * table at `0x00F58360` and the motion-state table at `0x00F58380` -- so it
   * is exactly three wide. The earlier Left/Right/Straight reading was a guess,
   * and it was both misordered and the wrong axis: this enum grades how sharp
   * the turn is, it does not pick a side.
   *
   * The mapping in `CalcMoveAir` agrees term for term (0x6BFEEB-0x6BFF1D):
   * dot < 0.5 is SharpTurn, dot > 0.95 is Straight, and anything between is
   * Turn -- i.e. better alignment means a straighter flight.
   */
  enum EUnitMotionTurnEvent : std::int32_t
  {
    UMTE_Straight = 0,
    UMTE_Turn = 1,
    UMTE_SharpTurn = 2,
  };
} // namespace moho

