#pragma once
#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"

namespace moho
{
  class SelectionListener : public ISessionListener, boost::noncopyable_::noncopyable
  {
    // Primary vftable (2 entries)
  public:
    /**
     * Address: 0x00869540 (FUN_00869540)
     * Slot: 0
     *
     * What it does:
     * Re-links this listener node into the provided session-listener lane.
     */
    void AttachToSessionListenerLane(void* laneContext) override;

    /**
     * Address: 0x00869580 (FUN_00869580)
     * Slot: 1
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(void* laneContext) override;
  };
} // namespace moho
