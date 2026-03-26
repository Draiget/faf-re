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
   * Enumerator names/values are not promoted yet from current FA evidence.
   */
  enum EUnitCommandQueueStatus : std::int32_t;

  static_assert(sizeof(EUnitCommandQueueStatus) == 0x04, "EUnitCommandQueueStatus size must be 0x04");
} // namespace moho

