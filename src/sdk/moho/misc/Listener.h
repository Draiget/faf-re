#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/unit/Broadcaster.h"

namespace moho
{
  /**
   * Legacy intrusive listener base used by broadcaster-style event lists.
   *
   * Layout evidence:
   * - `Listener<enum Moho::EUnitCommandQueueStatus>` RTTI/vtable at 0x00E1B374.
   * - IAiCommandDispatchImpl secondary-base registration at +0x34 in FUN_00599970.
   */
  template <class TEvent>
  class Listener
  {
  public:
    virtual void OnEvent(TEvent event) = 0;

  public:
    Broadcaster mListenerLink; // +0x04
  };

  static_assert(offsetof(Listener<std::int32_t>, mListenerLink) == 0x04, "Listener<T>::mListenerLink offset must be 0x04");
  static_assert(sizeof(Listener<std::int32_t>) == 0x0C, "Listener<T> size must be 0x0C");
} // namespace moho

