#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
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

  struct UICommandModeData
  {
    msvc8::string mMode;          // +0x00
    LuaPlus::LuaObject mPayload{}; // +0x1C

    /**
     * Address: 0x00833C20 (FUN_00833C20, Moho::UICommandModeData::UICommandModeData)
     * Mangled: ??0UICommandModeData@Moho@@QAE@XZ
     *
     * What it does:
     * Default-constructs command-mode name and payload Lua-object lanes.
     */
    UICommandModeData();

    /**
     * Address: 0x0083DF60 (FUN_0083DF60, ??0UICommandModeData@Moho@@QAE@ABU01@@Z)
     *
     * What it does:
     * Copy-constructs command-mode name and payload Lua-object lanes.
     */
    UICommandModeData(const UICommandModeData& other);

    /**
     * Address: 0x0081F700 (FUN_0081F700, ??1UICommandModeData@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases one payload Lua object and one command-mode text lane.
     */
    ~UICommandModeData();
  };

  static_assert(sizeof(UICommandModeData) == 0x30, "moho::UICommandModeData size must be 0x30");
  static_assert(
    offsetof(UICommandModeData, mPayload) == 0x1C, "moho::UICommandModeData::mPayload offset must be 0x1C"
  );

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
   * Address: 0x0084C680 (FUN_0084C680)
   *
   * What it does:
   * Returns the global UI-manager singleton lane.
   */
  [[nodiscard]] CUIManager* GetUiManagerGlobalLaneA() noexcept;

  /**
   * Address: 0x0084C960 (FUN_0084C960)
   *
   * What it does:
   * Secondary lane returning the global UI-manager singleton pointer.
   */
  [[nodiscard]] CUIManager* GetUiManagerGlobalLaneB() noexcept;

  /**
   * Address: 0x0083CE10 (FUN_0083CE10)
   *
   * What it does:
   * Forces UI state to lobby-mode.
   */
  void ForceUiStateLobbyMode();

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

  /**
   * Address: 0x0083D240 (FUN_0083D240, func_StartGameUI)
   *
   * What it does:
   * Rebinds UI to the supplied Lua state and runs
   * `/lua/ui/uimain.lua:StartGameUI()`.
   */
  [[nodiscard]] bool UI_StartGameUI(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083D340 (FUN_0083D340, Moho::ShowEscapeDialog)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:ShowEscapeDialog(showDialog)`.
   */
  [[nodiscard]] bool ShowEscapeDialog(bool showDialog);

  /**
   * Address: 0x0083D420 (FUN_0083D420, func_UpdateDisconnectDialogCallback)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:UpdateDisconnectDialog()` on the active UI
   * Lua state.
   */
  [[nodiscard]] bool UI_UpdateDisconnectDialogCallback();

  /**
   * Address: 0x0083DF90 (FUN_0083DF90, ?UI_StartCommandMode@Moho@@YAXABUUICommandModeData@1@@Z)
   *
   * What it does:
   * Invokes `/lua/ui/game/commandmode.lua:StartCommandMode(modeName, payload)`.
   */
  void UI_StartCommandMode(const UICommandModeData& commandModeData);

  /**
   * Address: 0x0083E080 (FUN_0083E080, ?UI_EndCommandMode@Moho@@YAXXZ)
   *
   * What it does:
   * Invokes `/lua/ui/game/commandmode.lua:EndCommandMode()` through the active
   * UI Lua state.
   */
  void UI_EndCommandMode();

  /**
   * Address: 0x0083ECF0 (FUN_0083ECF0, func_StartCursorText)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:StartCursorText(x, y, text, color, duration, anchorToCursor)`.
   */
  void UI_StartCursorText(
    const SMauiMousePos& screenPos,
    const char* text,
    std::uint32_t colorValue,
    float durationSeconds,
    bool anchorToCursor
  );

  /**
   * Address: 0x0083D500 (FUN_0083D500, ?UI_ShowDesyncDialog@Moho@@YAXHABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z)
   *
   * What it does:
   * Builds one Lua table from desync payload strings and invokes
   * `/lua/ui/uimain.lua:ShowDesyncDialog(sessionTick, payloadTable)`.
   */
  void UI_ShowDesyncDialog(int sessionTick, const msvc8::vector<msvc8::string>& payloadLines);
} // namespace moho
