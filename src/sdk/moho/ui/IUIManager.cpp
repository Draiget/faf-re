#include "moho/ui/IUIManager.h"

#include <cstdint>
#include <exception>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"

moho::CUIManager* moho::g_UIManager = nullptr;

namespace
{
  /**
   * Address: 0x0084C790 (FUN_0084C790, sub_84C790)
   *
   * What it does:
   * Converts one normalized UI point (`[0..1]` per lane) into head-pixel
   * coordinates using active D3D head dimensions.
   */
  [[maybe_unused]] float* ScaleNormalizedUiPointToHeadPixels(
    const float* const normalizedPoint,
    float* const outPixelPoint,
    const int headIndex
  )
  {
    moho::CD3DDevice* const widthDevice = moho::D3D_GetDevice();
    moho::CD3DDevice* const heightDevice = moho::D3D_GetDevice();
    const float headWidth = static_cast<float>(static_cast<unsigned int>(widthDevice->GetHeadWidth(headIndex)));
    const float headHeight = static_cast<float>(static_cast<unsigned int>(heightDevice->GetHeadHeight(headIndex)));

    outPixelPoint[0] = normalizedPoint[0] * headWidth;
    outPixelPoint[1] = normalizedPoint[1] * headHeight;
    return outPixelPoint;
  }

  /**
   * Address: 0x0084C800 (FUN_0084C800, sub_84C800)
   *
   * What it does:
   * Converts one head-pixel UI point into normalized (`[0..1]`) coordinates
   * using active D3D head dimensions.
   */
  [[maybe_unused]] float* ScaleHeadPixelsToNormalizedUiPoint(
    const float* const pixelPoint,
    float* const outNormalizedPoint,
    const int headIndex
  )
  {
    moho::CD3DDevice* const widthDevice = moho::D3D_GetDevice();
    moho::CD3DDevice* const heightDevice = moho::D3D_GetDevice();
    const float headWidth = static_cast<float>(static_cast<unsigned int>(widthDevice->GetHeadWidth(headIndex)));
    const float headHeight = static_cast<float>(static_cast<unsigned int>(heightDevice->GetHeadHeight(headIndex)));

    outNormalizedPoint[0] = pixelPoint[0] / headWidth;
    outNormalizedPoint[1] = pixelPoint[1] / headHeight;
    return outNormalizedPoint;
  }

  std::uint32_t gUiRuntimeScratchLaneA = 0u;
  std::uint32_t gUiRuntimeScratchLaneB = 0u;

  /**
   * Address: 0x0083C2A0 (FUN_0083C2A0)
   *
   * What it does:
   * Returns the primary UI runtime scratch-lane owner pointer.
   */
  [[maybe_unused]] void* GetUiRuntimeScratchLaneAEntryA(const int /*unused*/) noexcept
  {
    return &gUiRuntimeScratchLaneA;
  }

  /**
   * Address: 0x0083C380 (FUN_0083C380)
   *
   * What it does:
   * Returns the secondary UI runtime scratch-lane owner pointer.
   */
  [[maybe_unused]] void* GetUiRuntimeScratchLaneBEntryA(const int /*unused*/) noexcept
  {
    return &gUiRuntimeScratchLaneB;
  }

  /**
   * Address: 0x0083C3C0 (FUN_0083C3C0)
   *
   * What it does:
   * Secondary entry lane that returns the primary UI runtime scratch owner.
   */
  [[maybe_unused]] void* GetUiRuntimeScratchLaneAEntryB(const int /*unused*/) noexcept
  {
    return GetUiRuntimeScratchLaneAEntryA(0);
  }

  /**
   * Address: 0x0083C560 (FUN_0083C560)
   *
   * What it does:
   * Secondary entry lane that returns the secondary UI runtime scratch owner.
   */
  [[maybe_unused]] void* GetUiRuntimeScratchLaneBEntryB(const int /*unused*/) noexcept
  {
    return GetUiRuntimeScratchLaneBEntryA(0);
  }

  /**
   * Address: 0x0083C570 (FUN_0083C570)
   *
   * What it does:
   * Third entry lane that returns the primary UI runtime scratch owner.
   */
  [[maybe_unused]] void* GetUiRuntimeScratchLaneAEntryC(const int /*unused*/) noexcept
  {
    return GetUiRuntimeScratchLaneAEntryA(0);
  }

  template <typename TCall>
  bool StartUIMainEntryWithState(
    LuaPlus::LuaState* const state,
    const moho::EUIState stateValue,
    const char* const entryPointName,
    TCall&& callEntryPoint
  )
  {
    moho::IUIManager* const uiManager = moho::UI_GetManager();
    if (state == nullptr || uiManager == nullptr) {
      return false;
    }

    moho::sUIState = stateValue;
    if (!uiManager->SetNewLuaState(state)) {
      return false;
    }

    try {
      const LuaPlus::LuaObject uiMainModule = moho::SCR_ImportLuaModule(state, "/lua/ui/uimain.lua");
      if (uiMainModule.IsNil()) {
        return false;
      }

      const LuaPlus::LuaObject entryPoint = moho::SCR_GetLuaTableField(state, uiMainModule, entryPointName);
      if (entryPoint.IsNil()) {
        return false;
      }

      LuaPlus::LuaFunction<void> entryPointFn(entryPoint);
      callEntryPoint(entryPointFn);
      return true;
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/uimain.lua:%s':\n%s",
        entryPointName != nullptr ? entryPointName : "",
        exception.what() != nullptr ? exception.what() : ""
      );
      return false;
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/uimain.lua:%s'.", entryPointName != nullptr ? entryPointName : "");
      return false;
    }
  }

  template <typename TCall>
  bool StartUIMainEntry(const moho::EUIState stateValue, const char* const entryPointName, TCall&& callEntryPoint)
  {
    return StartUIMainEntryWithState(
      moho::USER_GetLuaState(),
      stateValue,
      entryPointName,
      static_cast<TCall&&>(callEntryPoint)
    );
  }
} // namespace

/**
 * Address: 0x0084C930 (FUN_0084C930)
 *
 * What it does:
 * Creates singleton UI manager instance on first request.
 */
moho::CUIManager* moho::IUIManager::Create()
{
  if (g_UIManager != nullptr) {
    return g_UIManager;
  }

  CUIManager* const created = new CUIManager();
  g_UIManager = created;
  return g_UIManager;
}

/**
 * Address: 0x0084C5E0 (FUN_0084C5E0)
 *
 * What it does:
 * Ensures singleton creation and runs `IUIManager::Init`.
 */
void moho::UI_Init()
{
  CUIManager* const manager = IUIManager::Create();
  if (manager == nullptr || !manager->Init()) {
    gpg::Die("UI_Init - Unable to create UI manager.");
  }
}

/**
 * Address: 0x0084C620 (FUN_0084C620)
 *
 * What it does:
 * Tears down and deletes the singleton UI manager instance.
 */
void moho::UI_Exit()
{
  CUIManager* const manager = g_UIManager;
  if (manager == nullptr) {
    return;
  }

  manager->DeleteDtor();
  delete manager;
  g_UIManager = nullptr;
}

moho::IUIManager* moho::UI_GetManager()
{
  return g_UIManager;
}

/**
 * Address: 0x0084C680 (FUN_0084C680)
 *
 * What it does:
 * Returns the global UI-manager singleton lane.
 */
[[maybe_unused]] moho::CUIManager* moho::GetUiManagerGlobalLaneA() noexcept
{
  return g_UIManager;
}

/**
 * Address: 0x0084C960 (FUN_0084C960)
 *
 * What it does:
 * Secondary lane returning the global UI-manager singleton pointer.
 */
[[maybe_unused]] moho::CUIManager* moho::GetUiManagerGlobalLaneB() noexcept
{
  return g_UIManager;
}

/**
 * Address: 0x00833C20 (FUN_00833C20, Moho::UICommandModeData::UICommandModeData)
 * Mangled: ??0UICommandModeData@Moho@@QAE@XZ
 *
 * What it does:
 * Default-constructs command-mode name and payload Lua-object lanes.
 */
moho::UICommandModeData::UICommandModeData() = default;

/**
 * Address: 0x0083DF60 (FUN_0083DF60, ??0UICommandModeData@Moho@@QAE@ABU01@@Z)
 *
 * What it does:
 * Copy-constructs command-mode name and payload Lua-object lanes.
 */
moho::UICommandModeData::UICommandModeData(const UICommandModeData& other)
  : mMode(other.mMode)
  , mPayload(other.mPayload)
{
}

/**
 * Address: 0x0081F700 (FUN_0081F700, ??1UICommandModeData@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases one payload Lua object and one command-mode text lane.
 */
moho::UICommandModeData::~UICommandModeData() = default;

/**
 * Address: 0x0083D140 (FUN_0083D140, ?UI_StartFrontEnd@Moho@@YA_NXZ)
 *
 * What it does:
 * Rebinds the UI manager to the user Lua state and runs
 * `/lua/ui/uimain.lua:StartFrontEndUI()`.
 */
bool moho::UI_StartFrontEnd()
{
  return StartUIMainEntry(UIS_frontend, "StartFrontEndUI", [](const LuaPlus::LuaFunction<void>& entryPointFn) {
    entryPointFn();
  });
}

/**
 * Address: 0x0083CE20 (FUN_0083CE20, ?UI_StartSplashScreens@Moho@@YA_NXZ)
 *
 * What it does:
 * Rebinds UI to the user Lua state and runs
 * `/lua/ui/uimain.lua:StartSplashScreen()`.
 */
bool moho::UI_StartSplashScreens()
{
  return StartUIMainEntry(UIS_splash, "StartSplashScreen", [](const LuaPlus::LuaFunction<void>& entryPointFn) {
    entryPointFn();
  });
}

/**
 * Address: 0x0083CE10 (FUN_0083CE10)
 *
 * What it does:
 * Forces UI state to lobby-mode.
 */
[[maybe_unused]] void moho::ForceUiStateLobbyMode()
{
  sUIState = UIS_lobby;
}

/**
 * Address: 0x0083E9A0 (FUN_0083E9A0, sub_83E9A0)
 *
 * What it does:
 * When UI state is `UIS_game`, builds one modifiers table and invokes
 * `/lua/ui/game/chat.lua:ActivateChat(modifiers)`.
 */
void moho::UI_ActivateChat(const bool shiftDown, const bool ctrlDown, const bool altDown)
{
  if (sUIState != UIS_game || g_UIManager == nullptr || g_UIManager->mLuaState == nullptr) {
    return;
  }

  LuaPlus::LuaState* const state = g_UIManager->mLuaState;
  LuaPlus::LuaObject modifierTable{};
  modifierTable.AssignNewTable(state, 3, 0);
  if (shiftDown) {
    modifierTable.SetBoolean("Shift", true);
  }
  if (ctrlDown) {
    modifierTable.SetBoolean("Ctrl", true);
  }
  if (altDown) {
    modifierTable.SetBoolean("Alt", true);
  }

  LuaPlus::LuaObject chatModule = SCR_Import(state, "/lua/ui/game/chat.lua");
  LuaPlus::LuaObject activateChat = chatModule["ActivateChat"];
  LuaPlus::LuaFunction callback(activateChat);
  try {
    callback.Call_Object(modifierTable);
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/chat.lua:ActivateChat': %s",
      exception.what() != nullptr ? exception.what() : "<unknown>"
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/chat.lua:ActivateChat': %s", "<unknown>");
  }
}

/**
 * Address: 0x0083EBC0 (FUN_0083EBC0, func_ReceiveChat)
 *
 * What it does:
 * Decodes one serialized Lua payload from network chat bytes and invokes
 * `/lua/ui/game/gamemain.lua:ReceiveChat(senderName, payloadObject)`.
 */
int moho::func_ReceiveChat(const char* const senderName, const gpg::MemBuffer<const char> data)
{
  if (g_UIManager == nullptr || g_UIManager->mLuaState == nullptr) {
    return 0;
  }

  LuaPlus::LuaState* const state = g_UIManager->mLuaState;
  gpg::MemBufferStream stream(data, 0xFFFFFFFFu);
  gpg::BinaryReader reader(&stream);
  LuaPlus::LuaObject payloadObject{};
  payloadObject.SCR_FromByteStream(payloadObject, state, &reader);

  LuaPlus::LuaObject gameMainModule = SCR_Import(state, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject receiveChat = gameMainModule["ReceiveChat"];
  LuaPlus::LuaFunction callback(receiveChat);
  try {
    callback.Call_StrObject(senderName != nullptr ? senderName : "", payloadObject);
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/gamemain.lua:ReceiveChat': %s",
      exception.what() != nullptr ? exception.what() : "<unknown>"
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/gamemain.lua:ReceiveChat': %s", "<unknown>");
  }

  return 0;
}

/**
 * Address: 0x0083CF20 (FUN_0083CF20, func_StartHostLobbyUI)
 *
 * What it does:
 * Rebinds UI to the user Lua state and runs
 * `/lua/ui/uimain.lua:StartHostLobbyUI(...)`.
 */
bool moho::UI_StartHostLobbyUI(
  const char* const protocol,
  const int port,
  const char* const playerName,
  const char* const gameName,
  const char* const mapName
)
{
  return StartUIMainEntry(
    UIS_lobby,
    "StartHostLobbyUI",
    [protocol, port, playerName, gameName, mapName](const LuaPlus::LuaFunction<void>& entryPointFn) {
      entryPointFn(
        protocol != nullptr ? protocol : "",
        port,
        playerName != nullptr ? playerName : "",
        gameName != nullptr ? gameName : "",
        mapName != nullptr ? mapName : ""
      );
    }
  );
}

/**
 * Address: 0x0083D030 (FUN_0083D030, func_StartJoinLobbyUI)
 *
 * What it does:
 * Rebinds UI to the user Lua state and runs
 * `/lua/ui/uimain.lua:StartJoinLobbyUI(...)`.
 */
bool moho::UI_StartJoinLobbyUI(
  const char* const protocol, const char* const endpoint, const char* const playerName
)
{
  return StartUIMainEntry(
    UIS_lobby,
    "StartJoinLobbyUI",
    [protocol, endpoint, playerName](const LuaPlus::LuaFunction<void>& entryPointFn) {
      entryPointFn(
        protocol != nullptr ? protocol : "",
        endpoint != nullptr ? endpoint : "",
        playerName != nullptr ? playerName : ""
      );
    }
  );
}

/**
 * Address: 0x0083D240 (FUN_0083D240, func_StartGameUI)
 *
 * What it does:
 * Rebinds UI to the provided Lua state and runs
 * `/lua/ui/uimain.lua:StartGameUI()`.
 */
bool moho::UI_StartGameUI(LuaPlus::LuaState* const state)
{
  return StartUIMainEntryWithState(state, UIS_game, "StartGameUI", [](const LuaPlus::LuaFunction<void>& entryPointFn) {
    entryPointFn();
  });
}

/**
 * Address: 0x0083D340 (FUN_0083D340, Moho::ShowEscapeDialog)
 *
 * What it does:
 * Imports `uimain.lua`, resolves `ShowEscapeDialog`, and dispatches one bool
 * argument to the Lua callback.
 */
bool moho::ShowEscapeDialog(const bool showDialog)
{
  CUIManager* const manager = g_UIManager;
  LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
  if (state == nullptr) {
    return true;
  }

  const LuaPlus::LuaObject uiMainModule = SCR_Import(state, "/lua/ui/uimain.lua");
  const LuaPlus::LuaObject showEscapeDialogObj = uiMainModule["ShowEscapeDialog"];
  LuaPlus::LuaFunction<bool> showEscapeDialogFn(showEscapeDialogObj);
  (void)showEscapeDialogFn(showDialog);
  return true;
}

/**
 * Address: 0x0083D420 (FUN_0083D420, func_UpdateDisconnectDialogCallback)
 *
 * What it does:
 * Imports `uimain.lua`, resolves `UpdateDisconnectDialog`, and invokes the
 * callback with no parameters.
 */
bool moho::UI_UpdateDisconnectDialogCallback()
{
  CUIManager* const manager = g_UIManager;
  LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
  if (state == nullptr) {
    return true;
  }

  const LuaPlus::LuaObject uiMainModule = SCR_Import(state, "/lua/ui/uimain.lua");
  const LuaPlus::LuaObject updateDisconnectDialogObj = uiMainModule["UpdateDisconnectDialog"];
  LuaPlus::LuaFunction<void> updateDisconnectDialogFn(updateDisconnectDialogObj);
  updateDisconnectDialogFn();
  return true;
}

/**
 * Address: 0x0083DF90 (FUN_0083DF90, ?UI_StartCommandMode@Moho@@YAXABUUICommandModeData@1@@Z)
 *
 * What it does:
 * Invokes `/lua/ui/game/commandmode.lua:StartCommandMode(modeName, payload)`.
 */
void moho::UI_StartCommandMode(const UICommandModeData& commandModeData)
{
  CUIManager* const manager = g_UIManager;
  LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  try {
    const LuaPlus::LuaObject commandModeModule = SCR_Import(state, "/lua/ui/game/commandmode.lua");
    const LuaPlus::LuaObject startCommandModeObj = commandModeModule["StartCommandMode"];
    LuaPlus::LuaFunction<void> startCommandModeFn(startCommandModeObj);
    startCommandModeFn(commandModeData.mMode.c_str(), commandModeData.mPayload);
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/commandmode.lua:StartCommandMode':\n%s",
      exception.what() != nullptr ? exception.what() : ""
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/game/commandmode.lua:StartCommandMode'.");
  }
}

/**
 * Address: 0x0083E080 (FUN_0083E080, ?UI_EndCommandMode@Moho@@YAXXZ)
 *
 * What it does:
 * Invokes `/lua/ui/game/commandmode.lua:EndCommandMode()` through the active
 * UI Lua state.
 */
void moho::UI_EndCommandMode()
{
  CUIManager* const manager = g_UIManager;
  LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  try {
    const LuaPlus::LuaObject commandModeModule = SCR_Import(state, "/lua/ui/game/commandmode.lua");
    const LuaPlus::LuaObject endCommandModeObj = commandModeModule["EndCommandMode"];
    LuaPlus::LuaFunction<bool> endCommandModeFn(endCommandModeObj);
    (void)endCommandModeFn();
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/game/commandmode.lua:EndCommandMode': %s",
      exception.what() != nullptr ? exception.what() : ""
    );
  }
}

/**
 * Address: 0x0083ECF0 (FUN_0083ECF0, func_StartCursorText)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:StartCursorText(x, y, text, color, duration, anchorToCursor)`.
 */
void moho::UI_StartCursorText(
  const SMauiMousePos& screenPos,
  const char* const text,
  const std::uint32_t colorValue,
  const float durationSeconds,
  const bool anchorToCursor
)
{
  CUIManager* const manager = g_UIManager;
  LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  try {
    const LuaPlus::LuaObject uiMainModule = SCR_Import(state, "/lua/ui/uimain.lua");
    const LuaPlus::LuaObject startCursorTextObj = uiMainModule["StartCursorText"];
    LuaPlus::LuaFunction<void> startCursorTextFn(startCursorTextObj);
    const LuaPlus::LuaObject encodedColor = SCR_EncodeColor(state, colorValue);
    startCursorTextFn(
      screenPos.x,
      screenPos.y,
      text != nullptr ? text : "",
      encodedColor,
      durationSeconds,
      anchorToCursor
    );
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/uimain.lua:StartCursorText':\n%s",
      exception.what() != nullptr ? exception.what() : ""
    );
  } catch (...) {
    gpg::Warnf("Error running '/lua/ui/uimain.lua:StartCursorText'.");
  }
}

/**
 * Address: 0x0083D500 (FUN_0083D500, ?UI_ShowDesyncDialog@Moho@@YAXHABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z)
 *
 * What it does:
 * Builds one Lua table from desync payload strings and invokes
 * `/lua/ui/uimain.lua:ShowDesyncDialog(sessionTick, payloadTable)`.
 */
void moho::UI_ShowDesyncDialog(const int sessionTick, const msvc8::vector<msvc8::string>& payloadLines)
{
  try {
    CUIManager* const manager = g_UIManager;
    LuaPlus::LuaState* const state = manager != nullptr ? manager->mLuaState : nullptr;
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject payloadTable;
    payloadTable.AssignNewTable(state, 0, 0);

    const msvc8::string* const begin = payloadLines.begin();
    const msvc8::string* const end = payloadLines.end();
    if (begin != nullptr && end != nullptr) {
      int payloadIndex = 1;
      for (const msvc8::string* it = begin; it != end; ++it, ++payloadIndex) {
        payloadTable.SetString(payloadIndex, it->c_str() != nullptr ? it->c_str() : "");
      }
    }

    const LuaPlus::LuaObject uiMainModule = SCR_Import(state, "/lua/ui/uimain.lua");
    const LuaPlus::LuaObject showDesyncDialogObj = uiMainModule["ShowDesyncDialog"];
    if (!showDesyncDialogObj.IsFunction()) {
      showDesyncDialogObj.TypeError("call");
    }

    LuaPlus::LuaFunction<void> showDesyncDialogFn(showDesyncDialogObj);
    showDesyncDialogFn(sessionTick, payloadTable);
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/uimain.lua:ShowDesyncDialog': %s",
      exception.what() != nullptr ? exception.what() : ""
    );
  }
}
