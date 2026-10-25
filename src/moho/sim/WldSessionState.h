#pragma once

#include "moho/sim/CWldSession.h"

namespace moho
{
  /**
   * Engine addition (dedicated-server plan WPL.4): the world session's
   * process-global state that simulation code reads through WLD_GetActiveSession,
   * WLD_GetSession, WLD_GetFrameAction and WLD_GetDriver. The globals were
   * CWldSession.cpp's file-local `gActiveWldSession` and `gWldFrameAction`; they
   * are defined in WldSessionState.cpp (sim side) so the simulation's objects
   * link without the user world, which writes them from CWldSession.cpp.
   */
  extern CWldSession* gActiveWldSession;
  extern EWldFrameAction gWldFrameAction;

  /**
   * The session's simulation driver for WLD_GetDriver (CWldSession.cpp's
   * `sSimDriver.get()`). CWldSession.cpp sets it during static initialisation;
   * without a user world it is null and so is the driver.
   */
  using SessionSimDriverHook = ISTIDriver* (*)();
  extern SessionSimDriverHook sSessionSimDriver;
} // namespace moho
