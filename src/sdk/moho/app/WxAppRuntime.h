#pragma once

#include "WxRuntimeTypes.h"

namespace moho
{
  /**
   * Shared recovered wxApp runtime owner used by app and sim-driver loops.
   *
   * This centralizes the recovered wxApp slot/field access used by:
   * - WIN_AppExecute (0x004F20B0)
   * - CSimDriver::PerformNextEvent (0x0073F430)
   */
  class WxAppRuntime
  {
  public:
    static bool IsAvailable();
    static void EnableLoopFlags();
    static bool Pending();
    static void Dispatch();
    static bool ProcessIdle();
    static bool KeepGoing();
    static void OnExit();

    /**
     * Shared window destroy helper used by CScApp teardown and related loops.
     */
    static bool DestroyWindow(wxWindowBase* window);
    static bool DestroyWindow(WSupComFrame* window);

    /**
     * Shared frame-active probe used by CScApp::HasFrame gate.
     *
     * Address: 0x008CE050 (FUN_008CE050)
     *
     * What it does:
     * Returns the WM_ACTIVATEAPP-derived active-bit lane from one SupCom frame.
     */
    static bool IsSupComFrameWindowActive(const WSupComFrame* frame);
  };
} // namespace moho
