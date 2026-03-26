#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x005D5A60 (FUN_005D5A60)
   *
   * What it does:
   * AI attacker event flags registered into RTTI enum metadata.
   */
  enum EAiAttackerEvent : std::int32_t
  {
    AIATTACKEVENT_AcquiredDesiredTarget = 1,
    AIATTACKEVENT_OutOfRange = 2,
    AIATTACKEVENT_Success = 4,
  };

  static_assert(sizeof(EAiAttackerEvent) == 0x4, "EAiAttackerEvent size must be 4 bytes");
} // namespace moho
