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
   * Turn-direction hint computed by `CUnitMotion::CalcMoveAir` from the dot
   * product between the current heading and desired-velocity vectors.
   * `CUnitMotion::SetMotionTurnEvent` (0x006B8FB0) is a confirmed no-op in
   * this binary, so these three values (asm-confirmed literals 0/1/2 at the
   * three `CalcMoveAir` call sites, 0x6BFEFF/0x6BFF11/0x6BFF1D) have no
   * observable effect regardless of name; named by likely turn-direction
   * intent only.
   */
  enum EUnitMotionTurnEvent : std::int32_t
  {
    UMTE_Left = 0,
    UMTE_Right = 1,
    UMTE_Straight = 2,
  };
} // namespace moho

