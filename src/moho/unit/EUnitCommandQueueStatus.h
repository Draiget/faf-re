#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Recovered queue-status event domain consumed by command-dispatch listeners.
   *
   * Evidence:
   * - IAiCommandDispatchImpl::OnEvent signature:
   *   `void OnEvent(enum Moho::EUnitCommandQueueStatus)` (0x00599030).
   * - TypeInfo lexical name:
   *   `EUnitCommandQueueStatus` (FUN_006EDA50).
   *
   * Event values are recovered from queue mutator callsites:
   * - `0`: command inserted
   * - `1`: queue changed
   * - `2`: queue cleared
   * - `3`: queue needs refresh
   * - `4`: command queue reordered (head/item moved to tail)
   */
  enum EUnitCommandQueueStatus : std::int32_t
  {
    UCQS_CommandInserted = 0,
    UCQS_Changed = 1,
    UCQS_Cleared = 2,
    UCQS_NeedsRefresh = 3,
    UCQS_Reordered = 4,
  };

  static_assert(sizeof(EUnitCommandQueueStatus) == 0x04, "EUnitCommandQueueStatus size must be 0x04");
} // namespace moho
