#pragma once

#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  class CUIManager;

  /**
   * VFTABLE: 0x00E46274
   * COL: 0x00E9A4F0
   */
  class IUIManager
  {
  public:
    /**
     * Address: 0x0084CB30 (FUN_0084CB30)
     *
     * What it does:
     * Initializes UI manager runtime state for the current startup pass.
     */
    virtual bool Init() = 0;

    /**
     * Address: 0x0084CB70 (FUN_0084CB70)
     *
     * What it does:
     * Registers one input-window/host-window pair and installs key-handler state.
     */
    virtual int AddFrame(wxWindowBase* inputWindow, wxWindowBase* eventHostWindow) = 0;

    /**
     * Address: 0x0084CC50 (FUN_0084CC50)
     *
     * What it does:
     * Rebinds the UI manager to a new Lua state and recreates root frames.
     */
    virtual bool SetNewLuaState(LuaPlus::LuaState* state) = 0;

    /**
     * Address: 0x0084D150 (FUN_0084D150)
     */
    [[nodiscard]] virtual bool HasFrames() const = 0;

    /**
     * Address: 0x0084D010 (FUN_0084D010)
     */
    virtual void ClearFrames() = 0;

    /**
     * Address: 0x0084D160 (FUN_0084D160)
     */
    virtual void UpdateFrameRate(float deltaSeconds) = 0;

    /**
     * Address: 0x0084D310 (FUN_0084D310)
     */
    [[nodiscard]] virtual bool DoBeat() = 0;

    /**
     * Address: 0x0084D320 (FUN_0084D320)
     */
    virtual void SetMinimized(bool minimized) = 0;

    /**
     * Address: 0x0084D360 (FUN_0084D360)
     */
    virtual void ClearChildren(int frameIdx) = 0;

    /**
     * Address: 0x0084CFC0 (FUN_0084CFC0)
     */
    virtual void OnResize(int frameIdx, int width, int height) = 0;

    /**
     * Address: 0x0084D3C0 (FUN_0084D3C0)
     */
    virtual void SetUIControlsAlpha(float alpha) = 0;

    /**
     * Address: 0x0084D3D0 (FUN_0084D3D0)
     */
    [[nodiscard]] virtual float GetUIControlsAlpha() const = 0;

    /**
     * Address: 0x0084D000 (FUN_0084D000)
     */
    virtual void SetCursor(CMauiCursor* cursor) = 0;

    /**
     * Address: 0x0084C920 (FUN_0084C920)
     */
    [[nodiscard]] virtual CMauiCursor* GetCursor() const = 0;

    /**
     * Address: 0x0084D520 (FUN_0084D520)
     */
    virtual void ValidateFrame(int frameIdx) = 0;

    /**
     * Address: 0x0084D550 (FUN_0084D550)
     */
    virtual void RenderFrames(int head, CD3DPrimBatcher* primBatcher) = 0;

    /**
     * Address: 0x0084D5D0 (FUN_0084D5D0)
     */
    virtual void DrawUI(int head, CD3DPrimBatcher* primBatcher) = 0;

    /**
     * Address: 0x0084D650 (FUN_0084D650)
     */
    virtual void DrawHead(int head, CD3DPrimBatcher* primBatcher) = 0;

    /**
     * Address: 0x0084D6D0 (FUN_0084D6D0)
     */
    virtual void GetControlAtCursor(int* outViewport, float* outX, float* outY, CMauiControl** outControl) = 0;

    /**
     * Address: 0x0084D810 (FUN_0084D810)
     */
    virtual void DumpControlsUnderMouse() = 0;

    /**
     * Address: 0x0084D8E0 (FUN_0084D8E0)
     */
    virtual void DebugMouseOverControl(CD3DPrimBatcher* primBatcher) = 0;

    /**
     * Address: 0x0084C930 (FUN_0084C930)
     *
     * What it does:
     * Creates singleton UI manager instance on first request.
     */
    [[nodiscard]] static CUIManager* Create();
  };

  static_assert(sizeof(IUIManager) == 0x4, "moho::IUIManager size must be 0x4");

  extern CUIManager* g_UIManager;

  /**
   * Address: 0x0084C5E0 (FUN_0084C5E0)
   */
  void UI_Init();

  /**
   * Address: 0x0084C620 (FUN_0084C620)
   */
  void UI_Exit();

  /**
   * Address context: global accessor for DAT_010A6450 (`UI_Manager`).
   */
  [[nodiscard]] IUIManager* UI_GetManager();

  /**
   * Address: 0x0083D140 (FUN_0083D140, ?UI_StartFrontEnd@Moho@@YA_NXZ)
   *
   * What it does:
   * Rebinds the UI manager to the user Lua state and runs
   * `/lua/ui/uimain.lua:StartFrontEndUI()`.
   */
  [[nodiscard]] bool UI_StartFrontEnd();

  /**
   * Address: 0x0083CE20 (FUN_0083CE20, ?UI_StartSplashScreens@Moho@@YA_NXZ)
   *
   * What it does:
   * Rebinds UI to the user Lua state and runs
   * `/lua/ui/uimain.lua:StartSplashScreen()`.
   */
  [[nodiscard]] bool UI_StartSplashScreens();

  /**
   * Address: 0x0083CF20 (FUN_0083CF20, func_StartHostLobbyUI)
   *
   * What it does:
   * Rebinds UI to the user Lua state and runs
   * `/lua/ui/uimain.lua:StartHostLobbyUI(...)`.
   */
  [[nodiscard]]
  bool UI_StartHostLobbyUI(
    const char* protocol, int port, const char* playerName, const char* gameName, const char* mapName
  );

  /**
   * Address: 0x0083D030 (FUN_0083D030, func_StartJoinLobbyUI)
   *
   * What it does:
   * Rebinds UI to the user Lua state and runs
   * `/lua/ui/uimain.lua:StartJoinLobbyUI(...)`.
   */
  [[nodiscard]] bool UI_StartJoinLobbyUI(const char* protocol, const char* endpoint, const char* playerName);
} // namespace moho
