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
   * Opaque reflected enum lane for turn-event CUnitMotion state.
   */
  enum EUnitMotionTurnEvent : std::int32_t;
} // namespace moho

