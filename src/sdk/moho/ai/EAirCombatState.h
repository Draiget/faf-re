#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x006B76D0 (FUN_006B76D0)
   *
   * What it does:
   * Air-unit "dogfighting" combat state, advanced by
   * `CUnitMotion::ComputeAirCombatTactics` (0x006BCDB0).
   *
   * Notes:
   * `ACS_Combat`/`ACS_NormalTurn`/`ACS_CombatTurn` are IDA-confirmed literal
   * names (emitted directly by the decompiler at their compare/switch
   * sites). `ACS_None`, `ACS_CombatTurnB`, `ACS_Realign`, `ACS_BreakOff`,
   * `ACS_ReturnToMap` have confirmed numeric values (switch-jump-table and
   * compare evidence) but no decompiler-emitted name - these five names are
   * intent-first proposals, not proven binary symbol names.
   */
  enum EAirCombatState : std::int32_t
  {
    ACS_None = 0,
    ACS_Combat = 1,
    ACS_NormalTurn = 2,
    ACS_CombatTurn = 3,
    ACS_CombatTurnB = 4,
    ACS_Realign = 5,
    ACS_BreakOff = 6,
    ACS_ReturnToMap = 7,
  };
} // namespace moho
