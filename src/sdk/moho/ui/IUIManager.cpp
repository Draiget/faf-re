#include "moho/ui/IUIManager.h"

#include <exception>

#include "gpg/core/utils/Logging.h"
#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/ui/CUIManager.h"

moho::CUIManager* moho::g_UIManager = nullptr;

namespace
{
  template <typename TCall>
  bool StartUIMainEntry(
    const moho::EUIState stateValue, const char* const entryPointName, TCall&& callEntryPoint
  )
  {
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
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
