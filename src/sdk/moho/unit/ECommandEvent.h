#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Recovered command-event domain routed through command broadcasters.
   *
   * Evidence:
   * - `Listener<enum Moho::ECommandEvent>` RTTI/vtable family in FA binaries.
   * - `CUnitScriptTask` secondary base at +0x64 uses this listener type
   *   (FUN_00622D80 / AddBase_Listener_ECommandEvent).
   *
   * Enumerator names/values are not promoted yet from current FA evidence.
   */
  enum ECommandEvent : std::int32_t;

  static_assert(sizeof(ECommandEvent) == 0x04, "ECommandEvent size must be 0x04");
} // namespace moho

