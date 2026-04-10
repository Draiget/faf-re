#pragma once

namespace moho
{
  class ISessionListener
  {
    // Primary vftable (2 entries)
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * What it does:
     * Base lane-attach hook for concrete session listeners.
     */
    virtual void AttachToSessionListenerLane(void* laneContext) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * What it does:
     * Base lane-detach hook for concrete session listeners.
     */
    virtual void DetachFromSessionListenerLane(void* laneContext) = 0;
  };
} // namespace moho
