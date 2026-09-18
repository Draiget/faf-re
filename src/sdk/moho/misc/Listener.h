#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/unit/Broadcaster.h"

namespace moho
{
  enum EFormationdStatus : std::int32_t;

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
    /**
     * Address: 0x005F2960 (FUN_005F2960, Listener<EAiAttackerEvent> ctor lane)
     * Address: 0x005F2970 (FUN_005F2970, Listener<ECommandEvent> ctor lane)
     * Address: 0x00618E40 (FUN_00618E40, Listener<EAiNavigatorEvent> ctor lane)
     * Address: 0x00618E50 (FUN_00618E50, Listener<EFormationdStatus> ctor lane)
     * Address: 0x00869A40 (FUN_00869A40, Listener<SPauseEvent> ctor lane)
     *
     * What it does:
     * Initializes one listener lane with a self-linked broadcaster node.
     */
    Listener()
      : mListenerLink()
    {}

    virtual void OnEvent(TEvent event) = 0;

  public:
    /**
     * The listener's own intrusive node, and the one every
     * `Listener<T>`-shaped owner links through. The compiler emits its
     * unlink/relink pair per instantiation:
     *
     * Address: 0x005F42F0, 0x005F4340 (unlink and self-link the node)
     * Address: 0x005F42C0, 0x005F4310 (unlink, then relink before an anchor)
     * Address: 0x005F4560 (the same relink reached through the owner pointer)
     *
     * All five were hand-written in moho/unit/Broadcaster.cpp over a
     * `BroadcasterOwnerNodeOffset4RuntimeView` stand-in - which is this class,
     * a vtable and a node at +0x04 - with no callers (RULE ONE), removed
     * 2026-09-18.
     */
    Broadcaster mListenerLink; // +0x04
  };

  static_assert(offsetof(Listener<std::int32_t>, mListenerLink) == 0x04, "Listener<T>::mListenerLink offset must be 0x04");
  static_assert(sizeof(Listener<std::int32_t>) == 0x0C, "Listener<T> size must be 0x0C");

  using Listener_EFormationdStatus = Listener<EFormationdStatus>;
} // namespace moho
