#pragma once

namespace moho
{
  class CWldSession;

  class ISessionListener
  {
    // Primary vftable (2 entries)
  public:
    /**
     * Address: 0x00A82547 (FUN_00A82547, _purecall)
     * Slot: 0
     *
     * What it does:
     * Subscribes the listener to the new session's broadcaster; the session
     * loader passes the active session.
     */
    virtual void AttachToSessionListenerLane(CWldSession* session) = 0;

    /**
     * Address: 0x00A82547 (FUN_00A82547, _purecall)
     * Slot: 1
     *
     * What it does:
     * Unsubscribes the listener when the session is torn down.
     */
    virtual void DetachFromSessionListenerLane(CWldSession* session) = 0;
  };
} // namespace moho
