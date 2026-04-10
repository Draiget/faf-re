#pragma once
#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"

namespace moho
{
  class PauseListener : public ISessionListener, boost::noncopyable_::noncopyable
  {
  public:
    /**
     * Address: 0x00869700 (FUN_00869700)
     * Slot: 0
     *
     * What it does:
     * Re-links this listener node into the pause lane embedded in `laneContext`.
     */
    void AttachToSessionListenerLane(void* laneContext) override;

    /**
     * Address: 0x00869750 (FUN_00869750)
     * Slot: 1
     *
     * What it does:
     * Unlinks this listener node from its current session-listener lane.
     */
    void DetachFromSessionListenerLane(void* laneContext) override;
  };
} // namespace moho
