#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x006B76D0 (FUN_006B76D0)
   *
   * What it does:
   * Opaque enum type consumed by EAirCombatState reflection metadata.
   *
   * Notes:
   * Current FA evidence confirms enum width (`4`) and type name
   * (`EAirCombatState`), but does not expose lexical option labels in the
   * RTTI init path.
   */
  enum EAirCombatState : std::int32_t;
} // namespace moho
