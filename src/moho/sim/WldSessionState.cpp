// Engine addition (dedicated-server plan WPL.4, WPR.11): the world session's
// process-global state and its accessors, moved unchanged out of
// CWldSession.cpp (see WldSessionState.h). Simulation code calls these
// accessors (SessionIsReplay, SetFocusArmy, SetFireState, ...); without a user
// world the session is null, as it is in faf-replay.

#include "moho/sim/WldSessionState.h"

namespace moho
{
  CWldSession* gActiveWldSession = nullptr;
  EWldFrameAction gWldFrameAction = EWldFrameAction::Inactive;
  SessionSimDriverHook sSessionSimDriver = nullptr;

  EWldFrameAction WLD_GetFrameAction()
  {
    return gWldFrameAction;
  }

  void WLD_SetFrameAction(const EWldFrameAction action)
  {
    gWldFrameAction = action;
  }

  /**
   * Address: 0x008972F0 (FUN_008972F0, ?WLD_GetSession@Moho@@YAPAVCWldSession@1@XZ)
   *
   * What it does:
   * Returns the process-global active world-session pointer.
   */
  CWldSession* WLD_GetSession()
  {
    return gActiveWldSession;
  }

  /**
   * Address: 0x0088D330 (FUN_0088D330, ?WLD_GetDriver@Moho@@YAPAVISTIDriver@1@XZ)
   *
   * What it does:
   * Returns the world session's simulation driver (`sSimDriver.get()`, asked
   * through sSessionSimDriver).
   */
  ISTIDriver* WLD_GetDriver()
  {
    return sSessionSimDriver != nullptr ? sSessionSimDriver() : nullptr;
  }

  /**
   * Address context:
   * - global `Moho::sWldSession` consumed by save/load request paths.
   */
  CWldSession* WLD_GetActiveSession()
  {
    return gActiveWldSession;
  }
} // namespace moho
