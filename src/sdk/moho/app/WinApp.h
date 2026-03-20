#pragma once

#include "moho/task/CTaskThread.h"

namespace moho
{
  class CWaitHandleSet;
  class IWinApp;

  /**
   * Address: 0x004F2480
   */
  CTaskStage* WIN_GetBeforeEventsStage();

  /**
   * Address: 0x004F24F0
   */
  CTaskStage* WIN_GetBeforeWaitStage();

  /**
   * Address: 0x004F2420
   *
   * @return
   */
  CWaitHandleSet* WIN_GetWaitHandleSet();

  /**
   * Address: 0x004F20B0 (FUN_004F20B0)
   *
   * IWinApp *
   *
   * What it does:
   * Drives app bootstrap, frame pumping, and shutdown around the IWinApp interface.
   */
  void WIN_AppExecute(IWinApp* app);

  /**
   * Address: 0x004F1FC0 (called via Main-frame timing paths)
   *
   * What it does:
   * Requests that the main wait loop wake no later than `milliseconds` from now.
   */
  void WIN_SetWakeupTimer(float milliseconds);
} // namespace moho
