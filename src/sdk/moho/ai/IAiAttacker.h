#pragma once

#include <cstddef>

#include "moho/unit/Broadcaster.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * Broadcaster subobject used by `IAiAttacker` event-dispatch lists.
   *
   * Evidence:
   * - `FUN_005DE870` (`IAiAttackerTypeInfo::AddBase_Broadcaster_EAiAttackerEvent`)
   */
  class Broadcaster_EAiAttackerEvent : public Broadcaster
  {
  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(Broadcaster_EAiAttackerEvent) == 0x08, "Broadcaster_EAiAttackerEvent size must be 0x08");

  class IAiAttacker
  {
  public:
    /**
     * Address: 0x005D5780 (FUN_005D5780)
     *
     * What it does:
     * Unlinks this attacker from the attacker-event broadcaster list and
     * conditionally deletes storage in deleting-dtor mode.
     */
    virtual ~IAiAttacker();

    virtual void purecall1() = 0;
    virtual void purecall2() = 0;
    virtual void purecall3() = 0;
    virtual void purecall4() = 0;
    virtual void purecall5() = 0;
    virtual void purecall6() = 0;
    virtual void purecall7() = 0;
    virtual void purecall8() = 0;
    virtual void purecall9() = 0;
    virtual void purecall10() = 0;
    virtual void purecall11() = 0;
    virtual void purecall12() = 0;
    virtual void purecall13() = 0;
    virtual void purecall14() = 0;
    virtual void purecall15() = 0;
    virtual void purecall16() = 0;
    virtual void purecall17() = 0;
    virtual void purecall18() = 0;
    virtual void purecall19() = 0;
    virtual void purecall20() = 0;
    virtual void purecall21() = 0;
    virtual void purecall22() = 0;
    virtual void purecall23() = 0;
    virtual void purecall24() = 0;
    virtual void purecall25() = 0;
    virtual void purecall26() = 0;
    virtual void purecall27() = 0;
    virtual void purecall28() = 0;

  public:
    Broadcaster_EAiAttackerEvent mListeners; // +0x04

  public:
    static gpg::RType* sType;
  };

  static_assert(offsetof(IAiAttacker, mListeners) == 0x04, "IAiAttacker::mListeners offset must be 0x04");
  static_assert(sizeof(IAiAttacker) == 0x0C, "IAiAttacker size must be 0x0C");
} // namespace moho
