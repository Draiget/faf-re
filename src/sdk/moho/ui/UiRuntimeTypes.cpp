#include "moho/ui/UiRuntimeTypes.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <map>
#include <new>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "legacy/containers/Vector.h"
#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/containers/TDatList.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "lua/LuaTableIterator.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/app/WinApp.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/resource/RResId.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/lua/SCR_Color.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/RCamManager.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/CUIWorldMesh.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/ui/EMauiScrollAxisTypeInfo.h"
#include "moho/unit/core/IUnit.h"
#include "moho/entity/UserEntity.h"
#include "moho/unit/core/UserUnit.h"

namespace moho
{
  bool WIN_CopyToClipboard(const wchar_t* text);
}

/**
 * Address: 0x0086A350 (FUN_0086A350, ??0IWldUIProvider@Moho@@QAE@XZ)
 * Address: 0x0086A5C0 (FUN_0086A5C0, IWldUIProvider ctor lane)
 *
 * What it does:
 * Initializes one world-UI-provider base interface object.
 */
moho::IWldUIProvider::IWldUIProvider() = default;

/**
 * Address: 0x0096B5B0 (FUN_0096B5B0, func_GetCursorPos)
 *
 * What it does:
 * Captures one Win32 cursor position into a local lane, copies X/Y into the
 * caller-provided `POINT`, and returns that destination pointer.
 */
POINT* WX_ReadCursorPositionPoint(POINT* const outPosition)
{
  POINT cursorPosition{};
  ::GetCursorPos(&cursorPosition);
  outPosition->x = cursorPosition.x;
  outPosition->y = cursorPosition.y;
  return outPosition;
}

moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* commandData,
  moho::MouseInfo* mouseInfo,
  int modifiers,
  moho::CWldSession* wldSession
);

namespace moho
{
  int cfunc_IN_ClearKeyMap(lua_State* luaContext);
  int func_FlushEvents(lua_State* luaContext);
}

/**
 * Address: 0x0096AFC0 (FUN_0096AFC0, wxCharCodeWXToMSW)
 *
 * What it does:
 * Translates one MAUI keycode into its Win32 virtual-key equivalent and
 * reports whether the key is handled as a special mapping lane.
 */
int wxCharCodeWXToMSW(
  int keyCode,
  bool* const isSpecial
)
{
  int mswKeyCode = keyCode;
  *isSpecial = true;

  if (keyCode > moho::MKEY_CANCEL) {
    switch (static_cast<moho::EMauiKeyCode>(keyCode)) {
    case moho::MKEY_CLEAR:
      mswKeyCode = 12;
      break;
    case moho::MKEY_SHIFT:
      mswKeyCode = 16;
      break;
    case moho::MKEY_CONTROL:
      mswKeyCode = 17;
      break;
    case moho::MKEY_MENU:
      mswKeyCode = 18;
      break;
    case moho::MKEY_PAUSE:
      mswKeyCode = 19;
      break;
    case moho::MKEY_CAPITAL:
      mswKeyCode = 20;
      break;
    case moho::MKEY_PRIOR:
      mswKeyCode = 33;
      break;
    case moho::MKEY_NEXT:
      mswKeyCode = 34;
      break;
    case moho::MKEY_END:
      mswKeyCode = 35;
      break;
    case moho::MKEY_HOME:
      mswKeyCode = 36;
      break;
    case moho::MKEY_LEFT:
      mswKeyCode = 37;
      break;
    case moho::MKEY_UP:
      mswKeyCode = 38;
      break;
    case moho::MKEY_RIGHT:
      mswKeyCode = 39;
      break;
    case moho::MKEY_DOWN:
      mswKeyCode = 40;
      break;
    case moho::MKEY_SELECT:
      mswKeyCode = 41;
      break;
    case moho::MKEY_PRINT:
      mswKeyCode = 42;
      break;
    case moho::MKEY_EXECUTE:
      mswKeyCode = 43;
      break;
    case moho::MKEY_INSERT:
      mswKeyCode = 45;
      break;
    case moho::MKEY_HELP:
      mswKeyCode = 47;
      break;
    case moho::MKEY_NUMPAD0:
      mswKeyCode = 96;
      break;
    case moho::MKEY_NUMPAD1:
      mswKeyCode = 97;
      break;
    case moho::MKEY_NUMPAD2:
      mswKeyCode = 98;
      break;
    case moho::MKEY_NUMPAD3:
      mswKeyCode = 99;
      break;
    case moho::MKEY_NUMPAD4:
      mswKeyCode = 100;
      break;
    case moho::MKEY_NUMPAD5:
      mswKeyCode = 101;
      break;
    case moho::MKEY_NUMPAD6:
      mswKeyCode = 102;
      break;
    case moho::MKEY_NUMPAD7:
      mswKeyCode = 103;
      break;
    case moho::MKEY_NUMPAD8:
      mswKeyCode = 104;
      break;
    case moho::MKEY_NUMPAD9:
      mswKeyCode = 105;
      break;
    case moho::MKEY_F1:
      mswKeyCode = 112;
      break;
    case moho::MKEY_F2:
      mswKeyCode = 113;
      break;
    case moho::MKEY_F3:
      mswKeyCode = 114;
      break;
    case moho::MKEY_F4:
      mswKeyCode = 115;
      break;
    case moho::MKEY_F5:
      mswKeyCode = 116;
      break;
    case moho::MKEY_F6:
      mswKeyCode = 117;
      break;
    case moho::MKEY_F7:
      mswKeyCode = 118;
      break;
    case moho::MKEY_F8:
      mswKeyCode = 119;
      break;
    case moho::MKEY_F9:
      mswKeyCode = 120;
      break;
    case moho::MKEY_F10:
      mswKeyCode = 121;
      break;
    case moho::MKEY_F11:
      mswKeyCode = 122;
      break;
    case moho::MKEY_F12:
      mswKeyCode = 123;
      break;
    case moho::MKEY_F13:
      mswKeyCode = 124;
      break;
    case moho::MKEY_F14:
      mswKeyCode = 125;
      break;
    case moho::MKEY_F15:
      mswKeyCode = 126;
      break;
    case moho::MKEY_F16:
      mswKeyCode = 127;
      break;
    case moho::MKEY_F17:
      mswKeyCode = 128;
      break;
    case moho::MKEY_F18:
      mswKeyCode = 129;
      break;
    case moho::MKEY_F19:
      mswKeyCode = 130;
      break;
    case moho::MKEY_F20:
      mswKeyCode = 131;
      break;
    case moho::MKEY_F21:
      mswKeyCode = 132;
      break;
    case moho::MKEY_F22:
      mswKeyCode = 133;
      break;
    case moho::MKEY_F23:
      mswKeyCode = 134;
      break;
    case moho::MKEY_F24:
      mswKeyCode = 135;
      break;
    case moho::MKEY_NUMLOCK:
      mswKeyCode = 144;
      break;
    case moho::MKEY_SCROLL:
      mswKeyCode = 145;
      break;
    case moho::MKEY_NUMPAD_MULTIPLY:
      mswKeyCode = 106;
      break;
    case moho::MKEY_NUMPAD_ADD:
      mswKeyCode = 107;
      break;
    case moho::MKEY_NUMPAD_SUBTRACT:
      mswKeyCode = 109;
      break;
    case moho::MKEY_NUMPAD_DECIMAL:
      mswKeyCode = 110;
      break;
    case moho::MKEY_NUMPAD_DIVIDE:
      mswKeyCode = 111;
      break;
    default:
      *isSpecial = false;
      break;
    }
  } else if (keyCode == moho::MKEY_CANCEL) {
    return 3;
  } else if (keyCode == moho::MKEY_DELETE) {
    return 46;
  } else {
    *isSpecial = false;
  }

  return mswKeyCode;
}

/**
 * Address: 0x0096ABB0 (FUN_0096ABB0, wxCharCodeMSWToWX)
 *
 * What it does:
 * Maps one Win32 virtual-key lane into the MAUI keycode enum/value space used
 * by UI event dispatch.
 */
int wxCharCodeMSWToWX(
  const int keyCode
)
{
  switch (keyCode) {
  case 3:
    return moho::MKEY_CANCEL;
  case 8:
    return moho::MKEY_BACK;
  case 9:
    return moho::MKEY_TAB;
  case 12:
    return moho::MKEY_CLEAR;
  case 13:
    return moho::MKEY_RETURN;
  case 16:
    return moho::MKEY_SHIFT;
  case 17:
    return moho::MKEY_CONTROL;
  case 18:
    return moho::MKEY_MENU;
  case 19:
    return moho::MKEY_PAUSE;
  case 20:
    return moho::MKEY_CAPITAL;
  case 27:
    return moho::MKEY_ESCAPE;
  case 32:
    return moho::MKEY_SPACE;
  case 33:
    return moho::MKEY_PRIOR;
  case 34:
    return moho::MKEY_NEXT;
  case 35:
    return moho::MKEY_END;
  case 36:
    return moho::MKEY_HOME;
  case 37:
    return moho::MKEY_LEFT;
  case 38:
    return moho::MKEY_UP;
  case 39:
    return moho::MKEY_RIGHT;
  case 40:
    return moho::MKEY_DOWN;
  case 41:
    return moho::MKEY_SELECT;
  case 42:
    return moho::MKEY_PRINT;
  case 43:
    return moho::MKEY_EXECUTE;
  case 45:
    return moho::MKEY_INSERT;
  case 46:
    return moho::MKEY_DELETE;
  case 47:
    return moho::MKEY_HELP;
  case 96:
    return moho::MKEY_NUMPAD0;
  case 97:
    return moho::MKEY_NUMPAD1;
  case 98:
    return moho::MKEY_NUMPAD2;
  case 99:
    return moho::MKEY_NUMPAD3;
  case 100:
    return moho::MKEY_NUMPAD4;
  case 101:
    return moho::MKEY_NUMPAD5;
  case 102:
    return moho::MKEY_NUMPAD6;
  case 103:
    return moho::MKEY_NUMPAD7;
  case 104:
    return moho::MKEY_NUMPAD8;
  case 105:
    return moho::MKEY_NUMPAD9;
  case 106:
    return moho::MKEY_NUMPAD_MULTIPLY;
  case 107:
    return moho::MKEY_NUMPAD_ADD;
  case 109:
    return moho::MKEY_NUMPAD_SUBTRACT;
  case 110:
    return moho::MKEY_NUMPAD_DECIMAL;
  case 111:
    return moho::MKEY_NUMPAD_DIVIDE;
  case 112:
    return moho::MKEY_F1;
  case 113:
    return moho::MKEY_F2;
  case 114:
    return moho::MKEY_F3;
  case 115:
    return moho::MKEY_F4;
  case 116:
    return moho::MKEY_F5;
  case 117:
    return moho::MKEY_F6;
  case 118:
    return moho::MKEY_F7;
  case 119:
    return moho::MKEY_F8;
  case 120:
    return moho::MKEY_F9;
  case 121:
    return moho::MKEY_F10;
  case 122:
    return moho::MKEY_F11;
  case 123:
    return moho::MKEY_F12;
  case 124:
    return moho::MKEY_F13;
  case 125:
    return moho::MKEY_F14;
  case 126:
    return moho::MKEY_F15;
  case 127:
    return moho::MKEY_F16;
  case 128:
    return moho::MKEY_F17;
  case 129:
    return moho::MKEY_F18;
  case 130:
    return moho::MKEY_F19;
  case 131:
    return moho::MKEY_F20;
  case 132:
    return moho::MKEY_F21;
  case 133:
    return moho::MKEY_F22;
  case 134:
    return moho::MKEY_F23;
  case 135:
    return moho::MKEY_F24;
  case 144:
    return moho::MKEY_NUMLOCK;
  case 145:
    return moho::MKEY_SCROLL;
  case 186:
    return ';';
  case 187:
    return '+';
  case 188:
    return ',';
  case 189:
    return '-';
  case 190:
    return '.';
  case 191:
    return '/';
  case 192:
    return '~';
  case 219:
    return '[';
  case 220:
    return '\\';
  case 221:
    return ']';
  case 222:
    return '\'';
  default:
    return 0;
  }
}

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<CLuaWldUIProvider> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CLuaWldUIProvider>) == 0x8,
    "CScrLuaMetatableFactory<CLuaWldUIProvider> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CUIWorldMesh> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIWorldMesh>) == 0x8,
    "CScrLuaMetatableFactory<CUIWorldMesh> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CUIWorldView> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIWorldView>) == 0x8,
    "CScrLuaMetatableFactory<CUIWorldView> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CUIMapPreview> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIMapPreview>) == 0x8,
    "CScrLuaMetatableFactory<CUIMapPreview> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiControl> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00783070 (FUN_00783070, Moho::CScrLuaMetatableFactory<Moho::CMauiControl>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiControl`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiControl>) == 0x8,
    "CScrLuaMetatableFactory<CMauiControl> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiBorder> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00786180 (FUN_00786180, Moho::CScrLuaMetatableFactory<Moho::CMauiBorder>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiBorder`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiBorder>) == 0x8,
    "CScrLuaMetatableFactory<CMauiBorder> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiBitmap> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00783040 (FUN_00783040, Moho::CScrLuaMetatableFactory<Moho::CMauiBitmap>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiBitmap`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiBitmap>) == 0x8,
    "CScrLuaMetatableFactory<CMauiBitmap> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiCursor> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x0078D940 (FUN_0078D940, Moho::CScrLuaMetatableFactory<Moho::CMauiCursor>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiCursor`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiCursor>) == 0x8,
    "CScrLuaMetatableFactory<CMauiCursor> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiLuaDragger> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x0078E660 (FUN_0078E660, Moho::CScrLuaMetatableFactory<Moho::CMauiLuaDragger>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiLuaDragger`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiLuaDragger>) == 0x8,
    "CScrLuaMetatableFactory<CMauiLuaDragger> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiEdit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00794E90 (FUN_00794E90, Moho::CScrLuaMetatableFactory<Moho::CMauiEdit>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiEdit`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiEdit>) == 0x8,
    "CScrLuaMetatableFactory<CMauiEdit> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiScrollbar> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x007A2470 (FUN_007A2470, Moho::CScrLuaMetatableFactory<Moho::CMauiScrollbar>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiScrollbar`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiScrollbar>) == 0x8,
    "CScrLuaMetatableFactory<CMauiScrollbar> size must be 0x8"
  );

  template <>
  class CScrLuaMetatableFactory<CMauiText> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x007A4250 (FUN_007A4250, Moho::CScrLuaMetatableFactory<Moho::CMauiText>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiText`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiText>) == 0x8,
    "CScrLuaMetatableFactory<CMauiText> size must be 0x8"
  );
} // namespace moho

namespace moho
{
  int cfunc_CMauiLuaDraggerDestroyL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewFontL(LuaPlus::LuaState* state);

  int cfunc_CLuaWldUIProviderDestroyL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshDestroyL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetMeshL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetStanceL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetHiddenL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshIsHiddenL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetAuxiliaryParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetFractionCompleteParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetFractionHealthParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetLifetimeParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetColorL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetScaleL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedPositionL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedSphereL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedScrollL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldViewGetScreenPosL(LuaPlus::LuaState* state);
  /**
   * Address: 0x00857BE0 (FUN_00857BE0, cfunc_AddCommandFeedbackBlipL)
   *
   * What it does:
   * Reads one blip descriptor table + duration and appends one temporary mesh
   * marker into the command-feedback runtime list.
   */
  int cfunc_AddCommandFeedbackBlipL(LuaPlus::LuaState* state);

  int cfunc_CMauiBitmapInternalSetSolidColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitMapGetNumFramesL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetNewTextureL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetUVL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapUseAlphaHitTestL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetTiledL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapLoopL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapPlayL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapStopL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapGetFrameL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetForwardPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetBackwardPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetPingPongPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetLoopPingPongPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetFramePatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapShareTexturesL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorSetNewTextureL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorResetToDefaultL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorHideL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorShowL(LuaPlus::LuaState* state);
  int register_CScrLuaMetatableFactory_CMauiHistogram_Index();
  int register_CScrLuaMetatableFactory_CMauiScrollbar_Index();
  int register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index();
  int register_CScrLuaMetatableFactory_CUIWorldMesh_Index();
  int register_CScrLuaMetatableFactory_CUIWorldView_Index();
  int cfunc_CMauiEditSetNewForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditShowBackgroundL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditIsBackgroundVisibleL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditIsEnabledL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditEnableInputL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditDisableInputL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewHighlightForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetHighlightForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewHighlightBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetHighlightBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetFontHeightL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetMaxCharsL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetMaxCharsL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditAcquireFocusL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditAbandonFocusL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetDropShadowL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetStringAdvanceL(LuaPlus::LuaState* state);
  int cfunc_CMauiHistogramSetDataL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateGroupL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateHistogramL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateBitmapL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateBorderL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateEditL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateScrollbarL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateItemListL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMeshL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMovieL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateTextL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMapPreviewL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListSetNewFontL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListModifyItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListDeleteItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListDeleteAllItemsL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetSelectionL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetItemCountL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListEmptyL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListScrollToTopL(LuaPlus::LuaState* state);
  int cfunc_CMauiListItemScrollToBottomL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetRowHeightL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowMouseoverItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowSelectionL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListNeedsScrollBarL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewFontL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextGetTextL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetDropShadowL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetCenteredHorizontallyL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetCenteredVerticallyL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewClipToWidthL(LuaPlus::LuaState* state);
  int cfunc_IsKeyDownL(LuaPlus::LuaState* state);
  int cfunc_KeycodeMauiToMSWL(LuaPlus::LuaState* state);
  int cfunc_KeycodeMSWToMauiL(LuaPlus::LuaState* state);
} // namespace moho

namespace
{
  using moho::CD3DFont;
  using moho::CMauiControlExtendedRuntimeView;
  using moho::CMauiCursorRuntimeView;
  using moho::CMauiCursorTextureRuntimeView;
  using moho::CMauiEditRuntimeView;
  using moho::CScriptLazyVar_float;

  moho::CMauiBitmapRuntimeView* SetBitmapAlphaHitTestEnabled(moho::CMauiBitmapRuntimeView* bitmapView, bool enabled) noexcept;
  moho::CMauiBitmapRuntimeView* SetBitmapTiledEnabled(moho::CMauiBitmapRuntimeView* bitmapView, bool enabled) noexcept;
  moho::CMauiBitmapRuntimeView* SetBitmapLoopEnabled(moho::CMauiBitmapRuntimeView* bitmapView, bool enabled) noexcept;
  std::int32_t ReadBitmapCurrentFrame(const moho::CMauiBitmapRuntimeView* bitmapView) noexcept;
  std::int32_t CountBitmapFramePatternEntries(const moho::CMauiBitmapRuntimeView* bitmapView) noexcept;
  std::uint32_t EnableBitmapAnimationIfMultipleTextures(moho::CMauiBitmapRuntimeView* bitmapView) noexcept;

  static_assert(
    sizeof(moho::CScriptLazyVar_float) >= sizeof(LuaPlus::LuaObject),
    "CScriptLazyVar_float must remain LuaObject-compatible"
  );

  [[nodiscard]] LuaPlus::LuaObject& AsLazyVarObject(moho::CScriptLazyVar_float& value) noexcept
  {
    return reinterpret_cast<LuaPlus::LuaObject&>(value);
  }

  [[nodiscard]] const LuaPlus::LuaObject& AsLazyVarObject(const moho::CScriptLazyVar_float& value) noexcept
  {
    return reinterpret_cast<const LuaPlus::LuaObject&>(value);
  }

  [[nodiscard]] std::int32_t GetItemListEntryCount(const moho::CMauiItemListRuntimeView& itemListView) noexcept
  {
    return itemListView.mItems.data() != nullptr ? static_cast<std::int32_t>(itemListView.mItems.size()) : 0;
  }

  constexpr moho::EMauiScrollAxis kVerticalScrollAxis = static_cast<moho::EMauiScrollAxis>(0);

  LuaPlus::LuaState* gUserLuaState = nullptr;
  std::uint8_t gUserLuaStateInitGuard = 0;
  std::aligned_storage_t<sizeof(LuaPlus::LuaState), alignof(LuaPlus::LuaState)> gUserLuaStateStorage{};
  std::aligned_storage_t<sizeof(moho::CTaskStage), alignof(moho::CTaskStage)> gUserStageStorage{};

  [[nodiscard]] LuaPlus::LuaState* GetUserLuaStateStorageObject() noexcept
  {
    return reinterpret_cast<LuaPlus::LuaState*>(&gUserLuaStateStorage);
  }

  [[nodiscard]] moho::CTaskStage* GetUserStageStorageObject() noexcept
  {
    return reinterpret_cast<moho::CTaskStage*>(&gUserStageStorage);
  }

  void CleanupUserLuaStateStorageAtExit()
  {
    std::destroy_at(GetUserLuaStateStorageObject());
    gUserLuaState = nullptr;
  }

  void CleanupUserStageStorageAtExit()
  {
    moho::sUserStage = nullptr;
  }

  void AttachTaskToStage(moho::CTask* const task, moho::CTaskStage* const stage, const bool owning)
  {
    if (task == nullptr || stage == nullptr || task->mOwnerThread != nullptr) {
      return;
    }

    moho::CTaskThread* const thread = new moho::CTaskThread(stage);
    if (thread == nullptr) {
      return;
    }

    task->mAutoDelete = owning;
    task->mOwnerThread = thread;
    task->mSubtask = thread->mTaskTop;
    thread->mTaskTop = task;
  }

  void RunLuaInitFormSetIfPresent(const char* const setName, LuaPlus::LuaState* const state)
  {
    moho::CScrLuaInitFormSet* const initSet = moho::SCR_FindLuaInitFormSet(setName);
    if (initSet == nullptr) {
      return;
    }

    initSet->mRegistered = 1;
    for (moho::CScrLuaInitForm* form = initSet->mForms; form != nullptr; form = form->mNextInSet) {
      form->Run(state);
    }
  }

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kCursorSetDefaultTextureHelpText = "Cursor:SetDefaultTexture(filename, hotspotX, hotspotY)";
  constexpr const char* kCursorSetNewTextureHelpText = "Cursor:SetTexture(filename, hotspotX, hotspotY)";
  constexpr const char* kCursorResetToDefaultHelpText = "Cursor:ResetToDefault()";
  constexpr const char* kCursorShowHelpText = "Cursor:Show()";
  constexpr const char* kCMauiControlDestroyHelpText = "Control:Destroy() -- destroy a control.\n";
  constexpr const char* kCMauiControlClearChildrenHelpText = "ClearChildren()";
  constexpr const char* kCMauiControlSetParentHelpText =
    "Control:SetParent(newParentControl) -- change the control's parent";
  constexpr const char* kCMauiControlDisableHitTestHelpText =
    "Control:DisableHitTest([recursive]) -- hit testing will be skipped for this control";
  constexpr const char* kCMauiControlEnableHitTestHelpText =
    "Control:EnableHitTest([recursive]) -- hit testing will be checked for this control";
  constexpr const char* kCMauiControlIsHitTestDisabledHelpText =
    "Control:IsHitTestDisabled() -- determine if hit testing is disabled";
  constexpr const char* kCMauiControlApplyFunctionHelpText =
    "ApplyFunction(func) - applys a function to this control and all children, function will recieve the control object "
    "as the only parameter";
  constexpr const char* kCMauiControlHitTestHelpText =
    "bool HitTest(x, y) - given x,y coordinates, tells you if the control is under the coordinates";
  constexpr const char* kCMauiControlGetParentHelpText =
    "Control:GetParent() -- return the parent of this control, or nil if it doesn't have one.";
  constexpr const char* kCMauiControlHideHelpText = "Control:Hide() -- stop rendering and hit testing the control";
  constexpr const char* kCMauiControlShowHelpText = "Control:Show() -- start rendering and hit testing the control";
  constexpr const char* kCMauiControlSetHiddenHelpText = "Control:SetHidden() -- set the hidden state of the control";
  constexpr const char* kCMauiControlIsHiddenHelpText = "Control:IsHidden() -- determine if the control is hidden";
  constexpr const char* kCMauiControlGetRootFrameHelpText = "Frame GetRootFrame()";
  constexpr const char* kCMauiControlSetAlphaHelpText =
    "SetAlpha(float, children) - Set the alpha of a given control, if children is true, also sets childrens alpha";
  constexpr const char* kCMauiControlGetAlphaHelpText = "float GetAlpha()";
  constexpr const char* kCMauiControlGetRenderPassHelpText = "int GetRenderPass()";
  constexpr const char* kCMauiControlSetRenderPassHelpText = "int SetRenderPass()";
  constexpr const char* kCMauiControlGetNameHelpText = "string GetName()";
  constexpr const char* kCMauiControlSetNameHelpText = "SetName(string)";
  constexpr const char* kCMauiControlDumpHelpText = "Dump";
  constexpr const char* kCMauiControlGetCurrentFocusControlHelpText = "GetCurrentFocusControl()";
  constexpr const char* kCMauiControlAcquireKeyboardFocusHelpText = "AcquireKeyboardFocus(bool blocksKeyDown)";
  constexpr const char* kCMauiControlAbandonKeyboardFocusHelpText = "AbandonKeyboardFocus()";
  constexpr const char* kCMauiControlNeedsFrameUpdateHelpText = "bool NeedsFrameUpdate()";
  constexpr const char* kCMauiControlSetNeedsFrameUpdateHelpText = "SetNeedsFrameUpdate(bool needsIt)";
  constexpr const char* kCMauiLuaDraggerDestroyHelpText = "Dragger:Destroy() -- destroy this dragger";
  constexpr const char* kPostDraggerHelpText =
    "PostDragger(originFrame, keycode, dragger)\n"
    "Make 'dragger' the active dragger from a particular frame. You can pass nil to cancel the current dragger.";
  constexpr const char* kPostDraggerInvalidKeyError = "Invalid key specified. Must be LBUTTON or RBUTTON or MBUTTON";
  constexpr const char* kCMauiEditSetNewFontHelpText = "Edit:SetNewFont(family, pointsize)";
  constexpr const char* kCMauiEditSetNewForegroundColorHelpText = "Edit:SetNewForegroundColor(color)";
  constexpr const char* kCMauiEditGetForegroundColorHelpText = "color Edit:GetForegroundColor()";
  constexpr const char* kCMauiEditSetNewBackgroundColorHelpText = "Edit:SetNewBackgroundColor(color)";
  constexpr const char* kCMauiEditGetBackgroundColorHelpText = "color Edit:GetBackgroundColor()";
  constexpr const char* kCMauiEditShowBackgroundHelpText = "Edit:ShowBackground(bool)";
  constexpr const char* kCMauiEditIsBackgroundVisibleHelpText = "bool Edit:IsBackgroundVisible()";
  constexpr const char* kCMauiEditClearTextHelpText = "Edit:ClearText()";
  constexpr const char* kCMauiEditSetTextHelpText = "Edit:SetText(string text)";
  constexpr const char* kCMauiEditGetTextHelpText = "string Edit:GetText()";
  constexpr const char* kCMauiEditSetCaretPositionHelpText = "SetCaretPosition(int)";
  constexpr const char* kCMauiEditGetCaretPositionHelpText = "int GetCaretPosition";
  constexpr const char* kCMauiEditShowCaretHelpText = "Edit:ShowCaret(bool)";
  constexpr const char* kCMauiEditIsCaretVisibleHelpText = "bool Edit:IsCaretVisible()";
  constexpr const char* kCMauiEditSetNewCaretColorHelpText = "Edit:SetNewCaretColor(color)";
  constexpr const char* kCMauiEditGetCaretColorHelpText = "color Edit:GetCaretColor()";
  constexpr const char* kCMauiEditSetCaretCycleHelpText =
    "edit:SetCaretCycle(float seconds, uint32 minAlpha, uint32 maxAlpha)";
  constexpr const char* kCMauiEditIsEnabledHelpText = "bool Edit:IsEnabled()";
  constexpr const char* kCMauiEditEnableInputHelpText = "Edit:EnableInput()";
  constexpr const char* kCMauiEditDisableInputHelpText = "Edit:Disable()";
  constexpr const char* kCMauiEditSetNewHighlightForegroundColorHelpText = "SetNewHightlightForegroundColor(color)";
  constexpr const char* kCMauiEditGetHighlightForegroundColorHelpText = "color GetHighlightForegroundColor()";
  constexpr const char* kCMauiEditSetNewHighlightBackgroundColorHelpText = "SetNewHighlightBackgroundColor(color)";
  constexpr const char* kCMauiEditGetHighlightBackgroundColorHelpText = "color GetHighlightBackgroundColor()";
  constexpr const char* kCMauiEditGetFontHeightHelpText = "int GetFontHeight()";
  constexpr const char* kCMauiEditSetMaxCharsHelpText = "Edit:SetMaxChars(int size)";
  constexpr const char* kCMauiEditGetMaxCharsHelpText = "int Edit:GetMaxChars()";
  constexpr const char* kCMauiEditAcquireFocusHelpText = "AcquireFocus()";
  constexpr const char* kCMauiEditAbandonFocusHelpText = "AbandonFocus()";
  constexpr const char* kCMauiEditSetDropShadowHelpText = "SetDropShadow(bool)";
  constexpr const char* kCMauiEditGetStringAdvanceHelpText =
    "number Edit:GetAdvance(string) - get the advance of a string using the same font as the control";
  constexpr const char* kCMauiFrameGetTopmostDepthHelpText = "float GetTopmostDepth()";
  constexpr const char* kCMauiFrameGetTargetHeadHelpText = "int GetTargetHead()";
  constexpr const char* kCMauiFrameSetTargetHeadHelpText = "CMauiFrame:SetTargetHead(targetHead)";
  constexpr const char* kCMauiHistogramSetXIncrementHelpText = "CMauiHistogram:SetXIncrement(increment)";
  constexpr const char* kCMauiHistogramSetYIncrementHelpText = "CMauiHistogram:SetYIncrement(increment)";
  constexpr const char* kCMauiHistogramSetDataHelpText = "SetData(dataTable)";
  constexpr const char* kInternalCreateHistogramHelpText =
    "InternalCreateHistogram(luaobj,parent) -- For internal use by CreateHistogram()";
  constexpr const char* kInternalCreateGroupHelpText =
    "InternalCreateGroup(luaobj,parent) -- For internal use by CreateGroup()";
  constexpr const char* kInternalCreateBitmapHelpText =
    "InternalCreateBitmap(luaobj,parent) -- for internal use by CreateBitmap()";
  constexpr const char* kInternalCreateBorderHelpText =
    "InternalCreateBorder(luaobj,parent) -- for internal use by CreateBorder()";
  constexpr const char* kInternalCreateEditHelpText = "InternalCreateEdit(luaobj,parent)";
  constexpr const char* kInternalCreateScrollbarHelpText =
    "InternalCreateScrollbar(luaobj,parent,axis) -- for internal use by CreateScrollBar()";
  constexpr const char* kInternalCreateItemListHelpText =
    "InternalCreateItemList(luaobj,parent) -- for internal use by CreateItemList()";
  constexpr const char* kInternalCreateMeshHelpText = "InternalCreateMesh(luaobj,parent) -- for internal use by CreateMesh()";
  constexpr const char* kInternalCreateMovieHelpText =
    "InternalCreateMovie(luaobj,parent) -- for internal use by CreateMovie()";
  constexpr const char* kInternalCreateTextHelpText = "InternalCreateText(luaobj,parent)";
  constexpr const char* kInternalCreateMapPreviewHelpText = "InternalCreateMapPreview(luaobj,parent)";
  constexpr const char* kInternalCreateWldUIProviderHelpText =
    "InternalCreateWldUIProvider(luaobj) - create the C++ script object";
  constexpr const char* kInternalCreateWorldMeshHelpText =
    "InternalCreateWorldMesh(luaobj) -- for internal use by WorldMesh()";
  constexpr const char* kCMauiItemListSetNewFontHelpText =
    "ItemList:SetNewFont(family, pointsize) -- set the font to use in this ItemList control";
  constexpr const char* kCMauiItemListAddItemHelpText =
    "itemlist = ItemList:AddItem('newitem')\n"
    "Add an new item to an itemlist. The new item must be a string.\n"
    "Returns the itemlist itself so you can chain calls.";
  constexpr const char* kCMauiItemListModifyItemHelpText = "itemlist = ItemList:ModifyItem(index, string)";
  constexpr const char* kCMauiItemListDeleteItemHelpText = "itemlist = ItemList:DeleteItem(index)";
  constexpr const char* kCMauiItemListDeleteAllItemsHelpText = "itemlist = ItemList:DeleteAllItems()";
  constexpr const char* kCMauiItemListGetSelectionHelpText = "index = ItemList:GetSelection()";
  constexpr const char* kCMauiItemListSetNewColorsHelpText =
    "CMauiItemList:SetNewColors(foreground, background, selectedForeground, selectedBackground, highlightForeground, "
    "highlightBackground)";
  constexpr const char* kCMauiItemListSetSelectionHelpText = "CMauiItemList:SetSelection(index)";
  constexpr const char* kCMauiItemListGetItemHelpText = "CMauiItemList:GetItem(index)";
  constexpr const char* kCMauiItemListGetItemCountHelpText = "int ItemList:GetItemCount()";
  constexpr const char* kCMauiItemListEmptyHelpText = "bool ItemList:Empty()";
  constexpr const char* kCMauiItemListScrollToTopHelpText = "ItemList:ScrollToTop()";
  constexpr const char* kCMauiListItemScrollToBottomHelpText = "ItemList:ScrollToBottom()";
  constexpr const char* kCMauiItemListShowItemHelpText = "ItemList:ShowItem(index)";
  constexpr const char* kCMauiItemListGetRowHeightHelpText = "float ItemList:GetRowHeight()";
  constexpr const char* kCMauiItemListShowMouseoverItemHelpText =
    "ShowMouseoverItem(bool) - enable or disable the showing of the mouseover item";
  constexpr const char* kCMauiItemListShowSelectionHelpText =
    "ShowSelection(bool) - enable or disable the highlighting of the selected item";
  constexpr const char* kCMauiItemListNeedsScrollBarHelpText =
    "bool NeedsScrollBar() - returns true if a scrollbar is needed, else false";
  constexpr const char* kCMauiMeshSetMeshHelpText = "SetMesh(meshBPName)";
  constexpr const char* kCMauiMeshSetOrientationHelpText = "SetOrientation(quaternion)";
  constexpr const char* kCMauiMovieInternalSetHelpText = "bool Movie:InternalSet(filename)";
  constexpr const char* kCMauiMovieLoopHelpText = "Loop(bool)";
  constexpr const char* kCMauiMoviePlayHelpText = "Play()";
  constexpr const char* kCMauiMovieStopHelpText = "Stop()";
  constexpr const char* kCMauiMovieIsLoadedHelpText = "IsLoaded()";
  constexpr const char* kCMauiMovieGetNumFramesHelpText =
    "int GetNumFrames() - returns the number of frames in the movie";
  constexpr const char* kCMauiMovieGetFrameRateHelpText =
    "number GetFrameRate() - returns the frame rate of the movie in FPS";
  constexpr const char* kCMauiScrollbarSetNewTexturesHelpText =
    "SetNewTextures(backgroundTexture, thumbMiddleTexture, thumbTopTexture, thumbBottomTexture)";
  constexpr const char* kCMauiScrollbarSetScrollableHelpText =
    "Scrollbar:SetScrollable(scrollable) -- set the scrollable object connected to this scrollbar";
  constexpr const char* kCMauiTextSetNewFontHelpText = "Text:SetNewFont(family, pointsize)";
  constexpr const char* kCMauiTextGetTextHelpText = "string Text:GetText()";
  constexpr const char* kCMauiTextSetNewColorHelpText = "Text:SetNewColor(color)";
  constexpr const char* kCMauiTextSetDropShadowHelpText = "Text:SetDropShadow(bool)";
  constexpr const char* kCMauiTextSetCenteredHorizontallyHelpText = "Text:SetCenteredHorizontally(bool)";
  constexpr const char* kCMauiTextSetCenteredVerticallyHelpText = "Text:SetCenteredVertically(bool)";
  constexpr const char* kCMauiTextSetNewClipToWidthHelpText =
    "SetNewClipToWidth(bool) - will cause the control to only render as many charachters as fit in its width";
  constexpr const char* kCMauiScrollbarDoScrollLinesHelpText = "DoScrollLines(float)";
  constexpr const char* kCMauiScrollbarDoScrollPagesHelpText = "DoScrollPages(float)";
  constexpr const char* kCMauiTextSetTextHelpText = "CMauiText:SetText(text)";
  constexpr const char* kCMauiItemListGetStringAdvanceHelpText =
    "number ItemList:GetAdvance(string) - get the advance of a string using the same font as the control";
  constexpr const char* kCMauiTextGetStringAdvanceHelpText =
    "number Text:GetAdvance(string) - get the advance of a string using the same font as the text control";
  constexpr const char* kCMauiBitmapSetNewTextureHelpText = "Bitmap:SetNewTexture(filename(s), border=1)";
  constexpr const char* kCMauiBitmapInternalSetSolidColorHelpText = "Bitmap:InternalSetSolidColor(color)";
  constexpr const char* kCMauiBitMapGetNumFramesHelpText = "GetNumFrames()";
  constexpr const char* kCMauiBitmapSetUVHelpText = "Bitmap:SetUV(float u0, float v0, float u1, float v1)";
  constexpr const char* kCMauiBitmapUseAlphaHitTestHelpText = "UseAlphaHitTest(bool)";
  constexpr const char* kCMauiBitmapSetTiledHelpText = "SetTiled(bool)";
  constexpr const char* kCMauiBitmapLoopHelpText = "Loop(bool)";
  constexpr const char* kCMauiBitmapPlayHelpText = "Play()";
  constexpr const char* kCMauiBitmapStopHelpText = "Stop()";
  constexpr const char* kCMauiBitmapSetFrameHelpText = "SetFrame(int)";
  constexpr const char* kCMauiBitmapGetFrameHelpText = "int GetFrame()";
  constexpr const char* kCMauiBitmapSetFrameRateHelpText = "CMauiBitmap:SetFrameRate(frameRate)";
  constexpr const char* kCMauiBitmapSetForwardPatternHelpText = "SetForwardPattern()";
  constexpr const char* kCMauiBitmapSetBackwardPatternHelpText = "SetBackwardPattern()";
  constexpr const char* kCMauiBitmapSetPingPongPatternHelpText = "SetPingPongPattern()";
  constexpr const char* kCMauiBitmapSetLoopPingPongPatternHelpText = "SetLoopPingPongPattern()";
  constexpr const char* kCMauiBitmapSetFramePatternHelpText = "SetFramePattern(pattern)";
  constexpr const char* kCMauiBitmapShareTexturesHelpText = "ShareTextures(bitmap) - allows two bitmaps to use the same textures";
  constexpr const char* kCMauiBorderSetNewTexturesHelpText =
    "SetNewTextures(vertical, horizontal, upperLeft, upperRight, lowerLeft, lowerRight)";
  constexpr const char* kCMauiBorderSetSolidColorHelpText = "SetSolidColor(color)";
  constexpr const char* kCUIMapPreviewSetTextureHelpText = "CUIMapPreview:SetTexture(texture_name)";
  constexpr const char* kCUIMapPreviewSetTextureFromMapHelpText = "CUIMapPreview:SetTextureFromMap(map_name)";
  constexpr const char* kCUIMapPreviewClearTextureHelpText = "CUIMapPreview::ClearTexture()";
  constexpr const char* kCLuaWldUIProviderDestroyHelpText = "WldUIProvider:Destroy() - destroy the wldUIProvider";
  constexpr const char* kCUIWorldMeshDestroyHelpText = "WorldMesh:Destroy() -- destroy this world mesh";
  constexpr const char* kCUIWorldMeshSetMeshHelpText = "WorldMesh:SetMesh(meshDesc)";
  constexpr const char* kCUIWorldMeshSetStanceHelpText = "WorldMesh:SetStance(vector position, [quaternion orientation])";
  constexpr const char* kCUIWorldMeshSetHiddenHelpText = "WorldMesh:SetHidden(bool hidden)";
  constexpr const char* kCUIWorldMeshIsHiddenHelpText = "bool WorldMesh:IsHidden()";
  constexpr const char* kCUIWorldMeshSetAuxiliaryParameterHelpText = "WorldMesh:SetAuxiliaryParameter(float param)";
  constexpr const char* kCUIWorldMeshSetFractionCompleteParameterHelpText =
    "WorldMesh:SetFractionCompleteParameter(float param)";
  constexpr const char* kCUIWorldMeshSetFractionHealthParameterHelpText =
    "WorldMesh:SetFractionHealthParameter(float param)";
  constexpr const char* kCUIWorldMeshSetLifetimeParameterHelpText = "WorldMesh:SetLifetimeParameter(float param)";
  constexpr const char* kCUIWorldMeshSetColorHelpText = "WorldMesh:SetColor(bool hidden)";
  constexpr const char* kCUIWorldMeshSetScaleHelpText = "WorldMesh:SetScale(vector scale)";
  constexpr const char* kCUIWorldMeshGetInterpolatedPositionHelpText = "Vector WorldMesh:GetInterpolatedPosition()";
  constexpr const char* kCUIWorldMeshGetInterpolatedSphereHelpText = "Vector WorldMesh:GetInterpolatedSphere()";
  constexpr const char* kCUIWorldMeshGetInterpolatedAlignedBoxHelpText =
    "Vector WorldMesh:GetInterpolatedAlignedBox()";
  constexpr const char* kCUIWorldMeshGetInterpolatedOrientedBoxHelpText =
    "Vector WorldMesh:GetInterpolatedOrientedBox()";
  constexpr const char* kCUIWorldMeshGetInterpolatedScrollHelpText = "Vector WorldMesh:GetInterpolatedScroll()";
  constexpr const char* kCUIWorldViewGetScreenPosHelpText = "(vector2f|nil) = GetScreenPos(unit)";
  constexpr const char* kIsKeyDownHelpText = "IsKeyDown(keyCode)";
  constexpr const char* kKeycodeMauiToMSWHelpText =
    "int KeycodeMauiToMSW(int) - given a char code from a key event, returns the MS Windows char code";
  constexpr const char* kKeycodeMSWToMauiHelpText =
    "int KeycodeMSWToMaui(int) - given a MS Windows char code, returns the Maui char code";
  constexpr const char* kAnyInputCaptureHelpText =
    "bool AnyInputCapture() - returns true if there is anything currently on the capture stack";
  constexpr const char* kGetInputCaptureHelpText =
    "control GetInputCapture() - returns the current capture control, or nil if none";
  constexpr const char* kAddInputCaptureHelpText = "AddInputCapture(control) - set a control as the current capture";
  constexpr const char* kRemoveInputCaptureHelpText =
    "RemoveInputCapture(control) - remove the control from the capture array (always first from back)";
  constexpr const char* kSetFrontEndDataHelpText = "SetFrontEndData(key, data)";
  constexpr const char* kGetFrontEndDataHelpText = "GetFrontEndData(key)";
  constexpr const char* kGetCursorHelpText = "GetCursor()";
  constexpr const char* kSetUIControlsAlphaHelpText =
    "SetUIControlsAlpha(float alpha) -- set the alpha multiplier for 2d UI controls";
  constexpr const char* kGetUIControlsAlphaHelpText = "float GetUIControlsAlpha() -- get the alpha multiplier for 2d UI controls";
  constexpr const char* kFlushEventsHelpText = "FlushEvents() -- flush mouse/keyboard events";
  constexpr const char* kClearCurrentFactoryForQueueDisplayHelpText = "ClearCurrentFactoryForQueueDisplay()";
  constexpr const char* kINAddKeyMapTableHelpText = "IN_AddKeyMapTable(keyMapTable) - add a set of key mappings";
  constexpr const char* kINRemoveKeyMapTableHelpText =
    "IN_RemoveKeyMapTable(keyMapTable) - removes the keys from the key map";
  constexpr const char* kINClearKeyMapHelpText = "IN_ClearKeyMap() - clears all key mappings";

  [[nodiscard]] std::map<int, std::string>& UiKeyActionMap() noexcept
  {
    static std::map<int, std::string> keyActionMap{};
    return keyActionMap;
  }

  [[nodiscard]] std::map<int, bool>& UiKeyRepeatMap() noexcept
  {
    static std::map<int, bool> keyRepeatMap{};
    return keyRepeatMap;
  }

  /**
   * Address: 0x0083A4F0 (FUN_0083A4F0, sub_83A4F0)
   *
   * What it does:
   * Returns mutable action-string storage lane for one parsed key mask,
   * creating the lane when it is not present.
   */
  [[nodiscard]] std::string* EnsureUiKeyActionEntry(const int keyMask) noexcept
  {
    return &UiKeyActionMap()[keyMask];
  }

  /**
   * Address: 0x0083A640 (FUN_0083A640, sub_83A640)
   *
   * What it does:
   * Erases one parsed key mask from action-string storage.
   */
  void RemoveUiKeyActionEntry(const int keyMask) noexcept
  {
    UiKeyActionMap().erase(keyMask);
  }

  /**
   * Address: 0x0083A9D0 (FUN_0083A9D0, sub_83A9D0)
   *
   * What it does:
   * Returns mutable key-repeat storage lane for one parsed key mask, creating
   * the lane when it is not present.
   */
  [[nodiscard]] bool* EnsureUiKeyRepeatEntry(const int keyMask) noexcept
  {
    return &UiKeyRepeatMap()[keyMask];
  }

  /**
   * Address: 0x0083AA70 (FUN_0083AA70, sub_83AA70)
   *
   * What it does:
   * Erases one parsed key mask from key-repeat storage.
   */
  void RemoveUiKeyRepeatEntry(const int keyMask) noexcept
  {
    UiKeyRepeatMap().erase(keyMask);
  }

  /**
   * Address: 0x00838FD0 (FUN_00838FD0, Moho::CUIKeyHandler::AddKeyMapTable)
   *
   * What it does:
   * Iterates one Lua key-map table, parses each key token to packed key-mask
   * form, stores the bound action string, and records optional key-repeat lanes.
   */
  void AddUiKeyMapEntries(const LuaPlus::LuaObject& keyMapTable)
  {
    if (!keyMapTable.IsTable()) {
      gpg::Warnf("CUIKeyHandler::AddKeyMapTable requires a table");
      return;
    }

    for (LuaPlus::LuaTableIterator iter(keyMapTable, 1); !iter.m_isDone; iter.Next()) {
      const char* const keyBindingSpecText = iter.m_keyObj.GetString();
      const std::string keyBindingSpec = keyBindingSpecText != nullptr ? keyBindingSpecText : "";
      const int keyMask = moho::IN_ParseKeyModifiers(keyBindingSpec);

      const LuaPlus::LuaObject actionObject = iter.m_valueObj["action"];
      const char* const actionText = actionObject.GetString();
      *EnsureUiKeyActionEntry(keyMask) = actionText != nullptr ? actionText : "";

      const LuaPlus::LuaObject keyRepeatObject = iter.m_valueObj["keyRepeat"];
      if (!keyRepeatObject.IsNil() && keyRepeatObject.GetBoolean()) {
        *EnsureUiKeyRepeatEntry(keyMask) = true;
      }
    }
  }

  /**
   * Address: 0x00839270 (FUN_00839270, Moho::CUIKeyHandler::RemoveKeyMapTable)
   *
   * What it does:
   * Iterates one Lua key-map table, parses each key token, and erases matching
   * action/repeat entries from runtime key-map stores.
   */
  void RemoveUiKeyMapEntries(const LuaPlus::LuaObject& keyMapTable)
  {
    if (!keyMapTable.IsTable()) {
      gpg::Warnf("CUIKeyHandler::RemoveKeyMapTable requires a table");
      return;
    }

    for (LuaPlus::LuaTableIterator iter(keyMapTable, 1); !iter.m_isDone; iter.Next()) {
      const char* const keyBindingSpecText = iter.m_keyObj.GetString();
      const std::string keyBindingSpec = keyBindingSpecText != nullptr ? keyBindingSpecText : "";
      const int keyMask = moho::IN_ParseKeyModifiers(keyBindingSpec);
      RemoveUiKeyActionEntry(keyMask);
      RemoveUiKeyRepeatEntry(keyMask);
    }
  }

  /**
   * Address: 0x00839440 (FUN_00839440, sub_839440)
   *
   * What it does:
   * Clears both runtime key-map stores and returns one success lane.
   */
  int ClearUiKeyMaps() noexcept
  {
    UiKeyActionMap().clear();
    UiKeyRepeatMap().clear();
    return 0;
  }
  constexpr const char* kAddBlinkyBoxHelpText = "AddBlinkyBox(entityId, onTime, offTime, totalTime)";
  constexpr const char* kAddCommandFeedbackBlipHelpText = "AddCommandFeedbackBlip(meshInfoTable, duration)";
  constexpr const char* kCUIWorldViewCameraResetHelpText = "moho.UIWorldView:Reset()";
  constexpr const char* kCUIWorldViewGetsGlobalCameraCommandsHelpText =
    "moho.UIWorldView:GetsGlobalCameraCommands(bool getsCommands)";
  constexpr const char* kCUIWorldViewGetRightMouseButtonOrderHelpText =
    "string moho.UIWorldView:GetRightMouseButtonOrder()";
  constexpr const char* kCUIWorldViewSetCartographicHelpText = "SetCartographic(bool)";
  constexpr const char* kCUIWorldViewIsCartographicHelpText = "bool IsCartographic()";
  constexpr const char* kCUIWorldViewEnableResourceRenderingHelpText = "EnableResourceRendering(bool)";
  constexpr const char* kCUIWorldViewIsResourceRenderingEnabledHelpText = "bool IsResourceRenderingEnabled()";
  constexpr const char* kCUIWorldViewUnlockInputHelpText = "UnlockInput(camera)";
  constexpr const char* kCUIWorldViewLockInputHelpText = "LockInput(camera)";
  constexpr const char* kCUIWorldViewIsInputLockedHelpText = "IsInputLocked(camera)";
  constexpr const char* kCUIWorldViewSetHighlightEnabledHelpText = "SetHighlightEnabled(bool)";
  constexpr const char* kCUIWorldViewZoomScaleHelpText =
    "ZoomScale(x, y, wheelRot, wheelDelta) - cause the world to zoom based on wheel rotation event";
  constexpr const char* kUnProjectHelpText = "VECTOR3 UnProject(self,VECTOR2)";
  constexpr const char* kCUIWorldViewProjectHelpText =
    "VECTOR2 Project(self,VECTOR3) - given a point in world space, projects the point to control space";
  constexpr const char* kCUIWorldViewHasHighlightCommandHelpText = "bool moho.UIWorldView:HasHighlightCommand()";
  constexpr const char* kCUIWorldShowConvertToPatrolCursorHelpText =
    "bool moho.UIWorldView:ShowConvertToPatrolCursor()";
  constexpr const char* kGetScrollValuesResultWarning =
    "GetScrollValues must return 4 values, minRange, maxRange, minVisible, maxVisible)";
  constexpr const char* kCMauiControlNegativeAlphaWarning =
    "Attempting to set a negative alpha value (%d) on control %s, setting to 0";
  constexpr const char* kCMauiControlAboveOneAlphaWarning =
    "Attempting to set an alpha value higher than 1.0 (%d) on control %s, are you sure you wan to do that?";

  [[nodiscard]] LuaPlus::LuaState* ResolveUiManagerLuaState() noexcept
  {
    return moho::g_UIManager->mLuaState;
  }

  template <typename TInvoke>
  bool InvokeUiLuaCallback(
    LuaPlus::LuaState* const state, const char* const modulePath, const char* const callbackName, TInvoke&& invoke
  )
  {
    try {
      const LuaPlus::LuaObject moduleObject = moho::SCR_Import(state, modulePath);
      const LuaPlus::LuaObject callbackObject = moduleObject[callbackName];
      LuaPlus::LuaFunction<void> callbackFunction(callbackObject);
      invoke(callbackFunction);
      return true;
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '%s:%s':\n%s",
        modulePath != nullptr ? modulePath : "",
        callbackName != nullptr ? callbackName : "",
        exception.what() != nullptr ? exception.what() : ""
      );
      return false;
    }
  }

  struct CMauiControlScriptObjectRuntimeView
  {
    std::uint8_t mUnknown00To1F[0x20]{};
    LuaPlus::LuaObject mLuaObj{}; // +0x20

    [[nodiscard]] static CMauiControlScriptObjectRuntimeView* FromControl(moho::CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlScriptObjectRuntimeView*>(control);
    }

    [[nodiscard]]
    static const CMauiControlScriptObjectRuntimeView* FromControl(const moho::CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlScriptObjectRuntimeView*>(control);
    }
  };

  static_assert(
    offsetof(CMauiControlScriptObjectRuntimeView, mLuaObj) == 0x20,
    "CMauiControlScriptObjectRuntimeView::mLuaObj offset must be 0x20"
  );

  using CMauiControlListNode = moho::TDatListItem<moho::CMauiControl, void>;
  constexpr std::uint32_t kCMauiControlListNodeNextOffset = static_cast<std::uint32_t>(offsetof(CMauiControlListNode, mNext));

  struct CMauiControlHierarchyRuntimeView
  {
    std::uint8_t mUnknown00To33[0x34]{};
    CMauiControlListNode mParentList{};                // +0x34
    moho::CMauiControl* mParent = nullptr;             // +0x3C
    moho::TDatList<moho::CMauiControl, void> mChildrenList{}; // +0x40
    moho::CScriptLazyVar_float mLeftLV{};              // +0x48
    moho::CScriptLazyVar_float mRightLV{};             // +0x5C
    moho::CScriptLazyVar_float mTopLV{};               // +0x70
    moho::CScriptLazyVar_float mBottomLV{};            // +0x84
    moho::CScriptLazyVar_float mWidthLV{};             // +0x98
    moho::CScriptLazyVar_float mHeightLV{};            // +0xAC
    moho::CScriptLazyVar_float mDepthLV{};             // +0xC0
    float mDepth = 0.0f;                               // +0xD4
    std::uint8_t mUnknown0D8To0E7[0x10]{};
    bool mInvalidated = false;   // +0xE8
    bool mDisableHitTest = false; // +0xE9
    bool mIsHidden = false;      // +0xEA
    bool mNeedsFrameUpdate = false; // +0xEB

    [[nodiscard]] static CMauiControlHierarchyRuntimeView* FromControl(moho::CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlHierarchyRuntimeView*>(control);
    }

    [[nodiscard]]
    static const CMauiControlHierarchyRuntimeView* FromControl(const moho::CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlHierarchyRuntimeView*>(control);
    }
  };

  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mParentList) == 0x34,
    "CMauiControlHierarchyRuntimeView::mParentList offset must be 0x34"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mParent) == 0x3C,
    "CMauiControlHierarchyRuntimeView::mParent offset must be 0x3C"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mChildrenList) == 0x40,
    "CMauiControlHierarchyRuntimeView::mChildrenList offset must be 0x40"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mLeftLV) == 0x48,
    "CMauiControlHierarchyRuntimeView::mLeftLV offset must be 0x48"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mDepthLV) == 0xC0,
    "CMauiControlHierarchyRuntimeView::mDepthLV offset must be 0xC0"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mDepth) == 0xD4,
    "CMauiControlHierarchyRuntimeView::mDepth offset must be 0xD4"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mInvalidated) == 0xE8,
    "CMauiControlHierarchyRuntimeView::mInvalidated offset must be 0xE8"
  );
  static_assert(
    offsetof(CMauiControlHierarchyRuntimeView, mDisableHitTest) == 0xE9,
    "CMauiControlHierarchyRuntimeView::mDisableHitTest offset must be 0xE9"
  );

  [[nodiscard]] moho::CMauiControl* ControlFromParentListNode(CMauiControlListNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    constexpr std::size_t kParentListOffset = offsetof(CMauiControlHierarchyRuntimeView, mParentList);
    return reinterpret_cast<moho::CMauiControl*>(reinterpret_cast<std::uint8_t*>(node) - kParentListOffset);
  }

  [[nodiscard]] const moho::CMauiControl* ControlFromParentListNode(const CMauiControlListNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    constexpr std::size_t kParentListOffset = offsetof(CMauiControlHierarchyRuntimeView, mParentList);
    return reinterpret_cast<const moho::CMauiControl*>(reinterpret_cast<const std::uint8_t*>(node) - kParentListOffset);
  }

  struct CScriptLazyVarFloatCachedValueView
  {
    std::uint8_t mUnknown00To13[0x14]{};
    float mCachedValue = 0.0f; // +0x14

    [[nodiscard]] static CScriptLazyVarFloatCachedValueView* FromLazyVar(moho::CScriptLazyVar_float* value) noexcept
    {
      return reinterpret_cast<CScriptLazyVarFloatCachedValueView*>(value);
    }

    [[nodiscard]]
    static const CScriptLazyVarFloatCachedValueView* FromLazyVar(const moho::CScriptLazyVar_float* value) noexcept
    {
      return reinterpret_cast<const CScriptLazyVarFloatCachedValueView*>(value);
    }
  };

  static_assert(
    offsetof(CScriptLazyVarFloatCachedValueView, mCachedValue) == 0x14,
    "CScriptLazyVarFloatCachedValueView::mCachedValue offset must be 0x14"
  );

  [[nodiscard]] std::uint32_t PackVertexAlphaFromScalar(const float alpha) noexcept
  {
    const std::int32_t truncatedLane = static_cast<std::int32_t>(alpha * -255.0f);
    return 0x00FFFFFFu - (static_cast<std::uint32_t>(truncatedLane) << 24u);
  }

  [[nodiscard]] moho::CMauiControl* FirstChildControl(moho::CMauiControl* const control) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(control);
    CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);
    CMauiControlListNode* const firstChildNode = controlView->mChildrenList.mNext;
    if (firstChildNode == sentinel) {
      return nullptr;
    }

    return ControlFromParentListNode(firstChildNode);
  }

  [[nodiscard]] moho::CMauiControl* NextSiblingControl(moho::CMauiControl* const control) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(control);
    moho::CMauiControl* const parentControl = controlView->mParent;
    if (parentControl == nullptr) {
      return nullptr;
    }

    CMauiControlHierarchyRuntimeView* const parentView = CMauiControlHierarchyRuntimeView::FromControl(parentControl);
    CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&parentView->mChildrenList);
    CMauiControlListNode* const siblingNode = controlView->mParentList.mNext;
    if (siblingNode == sentinel) {
      return nullptr;
    }

    return ControlFromParentListNode(siblingNode);
  }

    /**
   * Address: 0x007863B0 (FUN_007863B0)
   *
   * What it does:
   * Resolves one control's `Depth` lazy-var lane into the cached depth scalar
   * and reports whether the cached value changed.
   */
  [[nodiscard]] bool RefreshDepthLaneForControl(moho::CMauiControl* const control) noexcept
  {
    if (control == nullptr) {
      return false;
    }

    CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(control);
    const float resolvedDepth = moho::CScriptLazyVar_float::GetValue(&controlView->mDepthLV);
    if (controlView->mDepth == resolvedDepth) {
      return false;
    }

    controlView->mDepth = resolvedDepth;
    return true;
  }

  struct CMauiDepthTraversalCursor
  {
    moho::CMauiControl* mSubtreeRoot = nullptr;
    moho::CMauiControl* mCurrent = nullptr;
  };

  /**
   * Address: 0x007864C0 (FUN_007864C0)
   *
   * What it does:
   * Advances one `(subtreeRoot,current)` depth-first traversal cursor lane to
   * the next control and returns the updated cursor.
   */
  [[maybe_unused]] CMauiDepthTraversalCursor* AdvanceDepthTraversalCursor(
    CMauiDepthTraversalCursor* const cursor
  ) noexcept
  {
    if (cursor != nullptr && cursor->mCurrent != nullptr) {
      cursor->mCurrent = cursor->mCurrent->DepthFirstSuccessor(cursor->mSubtreeRoot);
    }
    return cursor;
  }

  [[nodiscard]] bool RefreshDepthLaneForSubtree(moho::CMauiControl* const subtreeRoot) noexcept
  {
    bool depthChanged = false;
    CMauiDepthTraversalCursor traversalCursor{ subtreeRoot, subtreeRoot };

    while (traversalCursor.mCurrent != nullptr) {
      moho::CMauiControl* const controlCursor = traversalCursor.mCurrent;
      if (controlCursor->IsHidden()) {
        (void)AdvanceDepthTraversalCursor(&traversalCursor);
        continue;
      }

      if (RefreshDepthLaneForControl(controlCursor)) {
        depthChanged = true;
      }

      (void)AdvanceDepthTraversalCursor(&traversalCursor);
    }

    return depthChanged;
  }
  void RebuildRenderedChildrenLane(moho::CMauiControl* const subtreeRoot)
  {
    CMauiControlExtendedRuntimeView* const rootView = CMauiControlExtendedRuntimeView::FromControl(subtreeRoot);
    rootView->mRenderedChildren.clear();

    for (moho::CMauiControl* controlCursor = subtreeRoot; controlCursor != nullptr;
         controlCursor = controlCursor->DepthFirstSuccessor(subtreeRoot)) {
      if (CMauiControlExtendedRuntimeView::FromControl(controlCursor)->mInvisible) {
        continue;
      }

      rootView->mRenderedChildren.push_back(controlCursor);
    }
  }

  /**
   * Address: 0x0078C7E0 (FUN_0078C7E0)
   *
   * What it does:
   * Stable-sorts the rendered-child lane by each control's resolved depth.
   */
  void SortRenderedChildrenByDepth(msvc8::vector<moho::CMauiControl*>& renderedChildren)
  {
    moho::CMauiControl** const begin = renderedChildren.begin();
    moho::CMauiControl** const end = renderedChildren.end();
    if (begin == nullptr || begin == end) {
      return;
    }

    std::stable_sort(
      begin,
      end,
      [](const moho::CMauiControl* const lhs, const moho::CMauiControl* const rhs) noexcept -> bool {
        if (lhs == nullptr || rhs == nullptr) {
          return lhs != nullptr && rhs == nullptr;
        }

        const auto* const lhsView = CMauiControlHierarchyRuntimeView::FromControl(lhs);
        const auto* const rhsView = CMauiControlHierarchyRuntimeView::FromControl(rhs);
        return lhsView->mDepth < rhsView->mDepth;
      }
    );
  }

  /**
   * Address: 0x0078C730 (FUN_0078C730)
   *
   * What it does:
   * Backward-copies one dword range `[sourceBegin, sourceEnd)` into destination
   * ending at `destinationEnd` and stores resulting begin pointer to output.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeBackwardToEnd(
    std::uint32_t** const outBeginSlot,
    const std::uint32_t* sourceEnd,
    const std::uint32_t* const sourceBegin,
    std::uint32_t* destinationEnd
  ) noexcept
  {
    if (sourceEnd != sourceBegin) {
      do {
        --sourceEnd;
        --destinationEnd;
        *destinationEnd = *sourceEnd;
      } while (sourceEnd != sourceBegin);
    }

    *outBeginSlot = destinationEnd;
    return outBeginSlot;
  }

  /**
   * Address: 0x0078C760 (FUN_0078C760)
   *
   * What it does:
   * Secondary entrypoint for backward dword-range copy into destination tail.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeBackwardToEndAlias(
    std::uint32_t** const outBeginSlot,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destinationEnd
  ) noexcept
  {
    return CopyDwordRangeBackwardToEnd(outBeginSlot, sourceEnd, sourceBegin, destinationEnd);
  }

  /**
   * Address: 0x0078C790 (FUN_0078C790)
   *
   * What it does:
   * Forward-copies one dword range `[sourceBegin, sourceEnd)` and stores
   * one-past-end destination pointer in output.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeForwardToEnd(
    std::uint32_t** const outEndSlot,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* destinationBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destinationBegin = *sourceBegin;
      ++sourceBegin;
      ++destinationBegin;
    }

    *outEndSlot = destinationBegin;
    return outEndSlot;
  }

  /**
   * Address: 0x0078C7C0 (FUN_0078C7C0)
   *
   * What it does:
   * Conditionally stores one source dword into destination when destination
   * storage is present.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresent(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != nullptr) {
      *destination = *source;
    }
    return destination;
  }

  /**
   * Address: 0x0078C8F0 (FUN_0078C8F0)
   *
   * What it does:
   * Advances one packed byte-address lane by `4 * dwordCount`.
   */
  [[maybe_unused]] std::uint32_t* AdvancePackedAddressByDwordCount(
    std::uint32_t* const packedAddressLane,
    const std::int32_t dwordCount
  ) noexcept
  {
    *packedAddressLane += static_cast<std::uint32_t>(4 * dwordCount);
    return packedAddressLane;
  }

  /**
   * Address: 0x0078C9E0 (FUN_0078C9E0)
   *
   * What it does:
   * Stores active cursor hotspot `(x,y)` lanes.
   */
  [[maybe_unused]] CMauiCursorTextureRuntimeView* SetCursorHotspotXY(
    CMauiCursorTextureRuntimeView* const cursorView,
    const std::int32_t hotspotX,
    const std::int32_t hotspotY
  ) noexcept
  {
    cursorView->mHotspotX = hotspotX;
    cursorView->mHotspotY = hotspotY;
    return cursorView;
  }

  /**
   * Address: 0x0078C9F0 (FUN_0078C9F0)
   *
   * What it does:
   * Stores default cursor hotspot `(x,y)` lanes.
   */
  [[maybe_unused]] CMauiCursorTextureRuntimeView* SetCursorDefaultHotspotXY(
    CMauiCursorTextureRuntimeView* const cursorView,
    const std::int32_t hotspotX,
    const std::int32_t hotspotY
  ) noexcept
  {
    cursorView->mDefaultHotspotX = hotspotX;
    cursorView->mDefaultHotspotY = hotspotY;
    return cursorView;
  }

  /**
   * Address: 0x0078CFA0 (FUN_0078CFA0)
   *
   * What it does:
   * Updates cursor-showing lane and marks cursor state dirty when value changes.
   */
  [[maybe_unused]] CMauiCursorTextureRuntimeView* SetCursorShowingAndMarkDirty(
    CMauiCursorTextureRuntimeView* const cursorView,
    const bool isShowing
  ) noexcept
  {
    if (cursorView->mIsShowing != isShowing) {
      cursorView->mIsShowing = isShowing;
      cursorView->mIsDefaultTexture = true;
    }
    return cursorView;
  }

  /**
   * Address: 0x00782F80 (FUN_00782F80)
   *
   * What it does:
   * Appends one texture batch entry to the bitmap's legacy vector lane.
   */
  void AppendBitmapTextureBatch(
    msvc8::vector<boost::shared_ptr<moho::CD3DBatchTexture>>& textureBatches,
    const boost::shared_ptr<moho::CD3DBatchTexture>& texture
  )
  {
    textureBatches.push_back(texture);
  }

  /**
   * Address: 0x0079C8A0 (FUN_0079C8A0)
   *
   * What it does:
   * Removes one item-list entry, compacts the tail left by one slot, and keeps
   * the selection lane consistent with the post-delete vector size.
   */
  void RemoveItemListEntryAtIndex(moho::CMauiItemListRuntimeView* const itemListView, const std::int32_t index)
  {
    if (itemListView == nullptr || index < 0) {
      return;
    }
    const std::size_t count = itemListView->mItems.size();
    if (static_cast<std::size_t>(index) >= count) {
      return;
    }

    for (std::size_t i = static_cast<std::size_t>(index) + 1u; i < count; ++i) {
      itemListView->mItems[i - 1u] = itemListView->mItems[i];
    }
    itemListView->mItems.pop_back();

    const std::int32_t currentSelection = itemListView->mCurSelection;
    if (index >= currentSelection) {
      if (currentSelection == GetItemListEntryCount(*itemListView)) {
        itemListView->mCurSelection = -1;
      }
    } else {
      itemListView->mCurSelection = currentSelection - 1;
    }
  }

  class CMoviePlaybackInterface
  {
  public:
    virtual ~CMoviePlaybackInterface() = default;
    virtual void UnknownVirtual1() = 0;
    virtual void UnknownVirtual2() = 0;
    virtual void PlayMovie() = 0;
    virtual void StopMovie() = 0;
    virtual void RestartMovie() = 0;
    [[nodiscard]] virtual bool IsLoaded() = 0;
    [[nodiscard]] virtual bool HasPlaybackFinished() = 0;
    virtual void StepPlayback() = 0;
    virtual void UnknownVirtual8() = 0;
    virtual void UnknownVirtual9() = 0;
    [[nodiscard]] virtual std::int32_t GetFrameCount() = 0;
    [[nodiscard]] virtual float GetFrameRate() = 0;
    [[nodiscard]] virtual const msvc8::string* GetSubtitleText() = 0;
    virtual void GetTexture(boost::shared_ptr<moho::CD3DBatchTexture>* texture) = 0;
  };

  struct CMauiMovieRuntimeView : moho::CMauiControlFrameUpdateRuntimeView
  {
    std::uint8_t mUnknown0ECTo0F3[0x8]{};
    float mTextureU = 0.0f; // +0xF4
    std::uint8_t mUnknown0F8To11B[0x24]{};
    CMoviePlaybackInterface* mMovie = nullptr; // +0x11C
    bool mIsPlaying = false; // +0x120
    bool mDoLoop = false;    // +0x121
    bool mIsStopped = false; // +0x122
    bool mIsMinimized = false; // +0x123
    msvc8::string mSubtitleCache{}; // +0x124
    moho::CScriptLazyVar_float mMovieWidthLV{}; // +0x140
    moho::CScriptLazyVar_float mMovieHeightLV{}; // +0x154

    [[nodiscard]] static CMauiMovieRuntimeView* FromMovie(moho::CMauiMovie* const movie) noexcept
    {
      return reinterpret_cast<CMauiMovieRuntimeView*>(movie);
    }

    [[nodiscard]] static const CMauiMovieRuntimeView* FromMovie(const moho::CMauiMovie* const movie) noexcept
    {
      return reinterpret_cast<const CMauiMovieRuntimeView*>(movie);
    }
  };

  static_assert(offsetof(CMauiMovieRuntimeView, mMovie) == 0x11C, "CMauiMovieRuntimeView::mMovie offset must be 0x11C");
  static_assert(offsetof(CMauiMovieRuntimeView, mTextureU) == 0xF4, "CMauiMovieRuntimeView::mTextureU offset must be 0xF4");
  static_assert(offsetof(CMauiMovieRuntimeView, mIsPlaying) == 0x120, "CMauiMovieRuntimeView::mIsPlaying offset must be 0x120");
  static_assert(offsetof(CMauiMovieRuntimeView, mDoLoop) == 0x121, "CMauiMovieRuntimeView::mDoLoop offset must be 0x121");
  static_assert(offsetof(CMauiMovieRuntimeView, mIsStopped) == 0x122, "CMauiMovieRuntimeView::mIsStopped offset must be 0x122");
  static_assert(offsetof(CMauiMovieRuntimeView, mIsMinimized) == 0x123, "CMauiMovieRuntimeView::mIsMinimized offset must be 0x123");
  static_assert(
    offsetof(CMauiMovieRuntimeView, mSubtitleCache) == 0x124,
    "CMauiMovieRuntimeView::mSubtitleCache offset must be 0x124"
  );
  static_assert(
    offsetof(CMauiMovieRuntimeView, mMovieWidthLV) == 0x140,
    "CMauiMovieRuntimeView::mMovieWidthLV offset must be 0x140"
  );
  static_assert(
    offsetof(CMauiMovieRuntimeView, mMovieHeightLV) == 0x154,
    "CMauiMovieRuntimeView::mMovieHeightLV offset must be 0x154"
  );

  struct CMauiScrollbarRuntimeView
  {
    std::uint8_t mUnknown00To11F[0x120]{};
    std::uint32_t mDraggerList = 0; // +0x120
    moho::CMauiCurrentFocusControlRuntimeView mScrollableLink{}; // +0x124
    boost::shared_ptr<moho::CD3DBatchTexture> mThumbTop{}; // +0x12C
    boost::shared_ptr<moho::CD3DBatchTexture> mThumbBottom{}; // +0x134
    boost::shared_ptr<moho::CD3DBatchTexture> mThumbMiddle{}; // +0x13C
    boost::shared_ptr<moho::CD3DBatchTexture> mBackground{}; // +0x144
    float mDragStart = 0.0f; // +0x14C
    float mTopAtDragStart = 0.0f; // +0x150
    moho::EMauiScrollAxis mAxis = static_cast<moho::EMauiScrollAxis>(0); // +0x154

    [[nodiscard]] static CMauiScrollbarRuntimeView* FromScrollbar(moho::CMauiScrollbar* const scrollbar) noexcept
    {
      return reinterpret_cast<CMauiScrollbarRuntimeView*>(scrollbar);
    }

    [[nodiscard]]
    static const CMauiScrollbarRuntimeView* FromScrollbar(const moho::CMauiScrollbar* const scrollbar) noexcept
    {
      return reinterpret_cast<const CMauiScrollbarRuntimeView*>(scrollbar);
    }

    [[nodiscard]] moho::CMauiControl* ResolveScrollableControl() const noexcept
    {
      return mScrollableLink.ResolveFocusedControl();
    }
  };

  static_assert(
    offsetof(CMauiScrollbarRuntimeView, mScrollableLink) == 0x124,
    "CMauiScrollbarRuntimeView::mScrollableLink offset must be 0x124"
  );
  static_assert(offsetof(CMauiScrollbarRuntimeView, mDraggerList) == 0x120, "CMauiScrollbarRuntimeView::mDraggerList offset must be 0x120");
  static_assert(offsetof(CMauiScrollbarRuntimeView, mThumbTop) == 0x12C, "CMauiScrollbarRuntimeView::mThumbTop offset must be 0x12C");
  static_assert(
    offsetof(CMauiScrollbarRuntimeView, mThumbBottom) == 0x134,
    "CMauiScrollbarRuntimeView::mThumbBottom offset must be 0x134"
  );
  static_assert(
    offsetof(CMauiScrollbarRuntimeView, mThumbMiddle) == 0x13C,
    "CMauiScrollbarRuntimeView::mThumbMiddle offset must be 0x13C"
  );
  static_assert(
    offsetof(CMauiScrollbarRuntimeView, mBackground) == 0x144,
    "CMauiScrollbarRuntimeView::mBackground offset must be 0x144"
  );
  static_assert(offsetof(CMauiScrollbarRuntimeView, mDragStart) == 0x14C, "CMauiScrollbarRuntimeView::mDragStart offset must be 0x14C");
  static_assert(
    offsetof(CMauiScrollbarRuntimeView, mTopAtDragStart) == 0x150,
    "CMauiScrollbarRuntimeView::mTopAtDragStart offset must be 0x150"
  );
  static_assert(offsetof(CMauiScrollbarRuntimeView, mAxis) == 0x154, "CMauiScrollbarRuntimeView::mAxis offset must be 0x154");

  struct CameraZoomRuntimeView
  {
    void* vftable = nullptr;

    [[nodiscard]] const moho::GeomCamera3& GetView() const
    {
      using GetViewFn = const moho::GeomCamera3&(__thiscall*)(const CameraZoomRuntimeView*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<GetViewFn>(table[2]);
      return fn(this);
    }

    [[nodiscard]] Wm3::Vector3f CameraScreenToSurface(const Wm3::Vector2f& screenPoint) const
    {
      using CameraScreenToSurfaceFn = void(__thiscall*)(const CameraZoomRuntimeView*, Wm3::Vector3f*, const Wm3::Vector2f*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<CameraScreenToSurfaceFn>(table[7]);
      Wm3::Vector3f worldPoint{};
      fn(this, &worldPoint, &screenPoint);
      return worldPoint;
    }

    void Reset()
    {
      using ResetFn = void(__thiscall*)(CameraZoomRuntimeView*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<ResetFn>(table[8]);
      fn(this);
    }

    void SetZoomAnchor(float* const zoomAnchor)
    {
      using SetZoomAnchorFn = void(__thiscall*)(CameraZoomRuntimeView*, float*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<SetZoomAnchorFn>(table[30]);
      fn(this, zoomAnchor);
    }

    void ApplyWheelZoomRatio(const float zoomRatio)
    {
      using ApplyWheelZoomRatioFn = void(__thiscall*)(CameraZoomRuntimeView*, float);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<ApplyWheelZoomRatioFn>(table[31]);
      fn(this, zoomRatio);
    }

    [[nodiscard]] float CameraGetTargetZoom() const
    {
      return reinterpret_cast<const moho::CameraImpl*>(this)->CameraGetTargetZoom();
    }

    [[nodiscard]] float CameraGetZoom() const
    {
      return reinterpret_cast<const moho::CameraImpl*>(this)->CameraGetZoom();
    }
  };

  struct CameraTargetRuntimeView
  {
    void* vftable = nullptr;

    [[nodiscard]] static CameraTargetRuntimeView* FromCamera(moho::CameraImpl* camera) noexcept
    {
      return reinterpret_cast<CameraTargetRuntimeView*>(camera);
    }

    void TargetLocation(const Wm3::Vector3f& worldPosition, const float transitionSeconds)
    {
      using TargetLocationFn = void(__thiscall*)(CameraTargetRuntimeView*, const Wm3::Vector3f*, float);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<TargetLocationFn>(table[10]);
      fn(this, &worldPosition, transitionSeconds);
    }
  };

  struct CRenderWorldViewRuntimeView
  {
    void* vftable = nullptr;
    moho::CameraImpl* mCamera = nullptr; // +0x04
    std::uint8_t mUnknown08To17[0x10]{};
    std::uint8_t mCanShake = 0; // +0x18
    std::uint8_t mIsMiniMap = 0; // +0x19
    std::uint8_t mUnknown1ATo1B[0x02]{};

    /**
     * Address: 0x0086EBF0 (FUN_0086EBF0, Moho::CRenderWorldView::GetCamera)
     *
     * What it does:
     * Returns the retained world-view camera pointer lane.
     */
    [[nodiscard]] CameraZoomRuntimeView* GetCamera()
    {
      return reinterpret_cast<CameraZoomRuntimeView*>(mCamera);
    }

    /**
     * Address: 0x0086DC90 (FUN_0086DC90, Moho::CRenderWorldView::IsMiniMap)
     *
     * What it does:
     * Returns minimap-view toggle lane.
     */
    [[nodiscard]] bool IsMiniMap() const
    {
      return mIsMiniMap != 0;
    }

    /**
     * Address: 0x0086EC10 (FUN_0086EC10, Moho::CRenderWorldView::CameraGetTargetZoom)
     *
     * What it does:
     * Returns target zoom from the retained camera lane.
     */
    [[nodiscard]] float CameraGetTargetZoom() const
    {
      return mCamera->CameraGetTargetZoom();
    }

    /**
     * Address: 0x0086EC30 (FUN_0086EC30, Moho::CRenderWorldView::CameraGetZoom)
     *
     * What it does:
     * Returns current zoom from the retained camera lane.
     */
    [[nodiscard]] float CameraGetZoom() const
    {
      return mCamera->CameraGetZoom();
    }

    /**
     * Address: 0x0086DC00 (FUN_0086DC00, Moho::CRenderWorldView::SetOrthographic)
     *
     * What it does:
     * Stores the orthographic toggle lane and mirrors it to the active camera:
     * enabling orthographic disables camera shake; disabling orthographic
     * re-enables camera shake.
     */
    void SetOrthographic(const bool orthographicEnabled)
    {
      mCanShake = static_cast<std::uint8_t>(orthographicEnabled ? 1 : 0);

      if (mCamera == nullptr) {
        return;
      }

      mCamera->CameraSetOrtho(orthographicEnabled);
      mCamera->CanShake(!orthographicEnabled);
    }

    /**
     * Address: 0x0086DC60 (FUN_0086DC60, Moho::CRenderWorldView::CanShake)
     *
     * What it does:
     * Returns the stored orthographic toggle lane.
     */
    [[nodiscard]] bool CanShake() const
    {
      return mCanShake != 0;
    }

    [[nodiscard]] bool IsOrthographic() const
    {
      return CanShake();
    }
  };

  static_assert(
    offsetof(CRenderWorldViewRuntimeView, mCamera) == 0x04,
    "CRenderWorldViewRuntimeView::mCamera offset must be 0x04"
  );
  static_assert(
    offsetof(CRenderWorldViewRuntimeView, mCanShake) == 0x18,
    "CRenderWorldViewRuntimeView::mCanShake offset must be 0x18"
  );
  static_assert(
    offsetof(CRenderWorldViewRuntimeView, mIsMiniMap) == 0x19,
    "CRenderWorldViewRuntimeView::mIsMiniMap offset must be 0x19"
  );

  struct CRenderWorldViewViewportRuntimeView
  {
    void* vftable = nullptr;

    void SetViewRect(const Wm3::Vector2f& minPoint, const Wm3::Vector2f& maxPoint)
    {
      using SetViewRectFn = void(__thiscall*)(
        CRenderWorldViewViewportRuntimeView*,
        const Wm3::Vector2f*,
        const Wm3::Vector2f*
      );
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<SetViewRectFn>(table[3]);
      fn(this, &minPoint, &maxPoint);
    }
  };

  struct CUIWorldViewOverlayRuntimeView
  {
    void* vftable = nullptr;

    void Draw(moho::CD3DPrimBatcher* const primBatcher)
    {
      using DrawFn = void(__thiscall*)(CUIWorldViewOverlayRuntimeView*, moho::CD3DPrimBatcher*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<DrawFn>(table[4]);
      fn(this, primBatcher);
    }
  };

  struct CRenderWorldViewRuntimeHandle
  {
    CRenderWorldViewRuntimeView* mPtr = nullptr; // +0x00

    [[nodiscard]] CameraZoomRuntimeView* GetCamera() const
    {
      return mPtr != nullptr ? mPtr->GetCamera() : nullptr;
    }

    void SetOrthographic(const bool orthographicEnabled) const
    {
      if (mPtr != nullptr) {
        mPtr->SetOrthographic(orthographicEnabled);
      }
    }

    [[nodiscard]] bool IsOrthographic() const
    {
      return mPtr != nullptr && mPtr->IsOrthographic();
    }
  };

  static_assert(sizeof(CRenderWorldViewRuntimeHandle) == 0x04);

  struct CUIWorldViewRuntimeView
  {
    std::uint8_t mUnknown00To47[0x48]{};
    moho::CScriptLazyVar_float mViewLeft{};   // +0x48
    std::uint8_t mUnknown5CTo6F[0x14]{};
    moho::CScriptLazyVar_float mViewTop{};    // +0x70
    std::uint8_t mUnknown84To97[0x14]{};
    moho::CScriptLazyVar_float mViewRight{};  // +0x98
    moho::CScriptLazyVar_float mViewBottom{}; // +0xAC
    std::uint8_t mUnknownC0To11B[0x5C]{};
    CRenderWorldViewRuntimeHandle mRenderWorldView{};
    CRenderWorldViewViewportRuntimeView* mViewportCallback = nullptr; // +0x120
    float mCachedViewLeft = 0.0f;   // +0x124
    float mCachedViewTop = 0.0f;    // +0x128
    float mCachedViewRight = 0.0f;  // +0x12C
    float mCachedViewBottom = 0.0f; // +0x130
    std::uint8_t mUnknown134To135[0x2]{};
    std::uint8_t mEnableResourceRendering = 0; // +0x136
    std::uint8_t mUnknown137 = 0;
    std::int32_t mInputLocks = 0; // +0x138
    std::uint8_t mUnknown13CTo273[0x138]{};
    std::uint8_t mShowConvertToPatrolCursor = 0; // +0x274
    std::uint8_t mUnknown275To29B[0x27]{};
    std::uint32_t mOverlayDrawToken = 0; // +0x29C
    std::uint8_t mUnknown2A0To2A3[0x4]{};
    std::uint8_t mHighlightEnabled = 0; // +0x2A4
    std::uint8_t mUnknown2A5 = 0;
    std::uint8_t mGetsGlobalCameraCommands = 0; // +0x2A6

    [[nodiscard]] static CUIWorldViewRuntimeView* FromWorldView(moho::CUIWorldView* worldView) noexcept
    {
      return reinterpret_cast<CUIWorldViewRuntimeView*>(worldView);
    }
  };

  static_assert(
    offsetof(CUIWorldViewRuntimeView, mRenderWorldView) == 0x11C,
    "CUIWorldViewRuntimeView::mRenderWorldView offset must be 0x11C"
  );
  static_assert(offsetof(CUIWorldViewRuntimeView, mViewLeft) == 0x48, "CUIWorldViewRuntimeView::mViewLeft offset must be 0x48");
  static_assert(offsetof(CUIWorldViewRuntimeView, mViewTop) == 0x70, "CUIWorldViewRuntimeView::mViewTop offset must be 0x70");
  static_assert(offsetof(CUIWorldViewRuntimeView, mViewRight) == 0x98, "CUIWorldViewRuntimeView::mViewRight offset must be 0x98");
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mViewBottom) == 0xAC,
    "CUIWorldViewRuntimeView::mViewBottom offset must be 0xAC"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mViewportCallback) == 0x120,
    "CUIWorldViewRuntimeView::mViewportCallback offset must be 0x120"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mCachedViewLeft) == 0x124,
    "CUIWorldViewRuntimeView::mCachedViewLeft offset must be 0x124"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mCachedViewTop) == 0x128,
    "CUIWorldViewRuntimeView::mCachedViewTop offset must be 0x128"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mCachedViewRight) == 0x12C,
    "CUIWorldViewRuntimeView::mCachedViewRight offset must be 0x12C"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mCachedViewBottom) == 0x130,
    "CUIWorldViewRuntimeView::mCachedViewBottom offset must be 0x130"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mOverlayDrawToken) == 0x29C,
    "CUIWorldViewRuntimeView::mOverlayDrawToken offset must be 0x29C"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mShowConvertToPatrolCursor) == 0x274,
    "CUIWorldViewRuntimeView::mShowConvertToPatrolCursor offset must be 0x274"
  );
  static_assert(offsetof(CUIWorldViewRuntimeView, mInputLocks) == 0x138, "CUIWorldViewRuntimeView::mInputLocks offset must be 0x138");
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mEnableResourceRendering) == 0x136,
    "CUIWorldViewRuntimeView::mEnableResourceRendering offset must be 0x136"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mHighlightEnabled) == 0x2A4,
    "CUIWorldViewRuntimeView::mHighlightEnabled offset must be 0x2A4"
  );
  static_assert(
    offsetof(CUIWorldViewRuntimeView, mGetsGlobalCameraCommands) == 0x2A6,
    "CUIWorldViewRuntimeView::mGetsGlobalCameraCommands offset must be 0x2A6"
  );

  struct CUIWorldViewLuaObjectRuntimeView
  {
    std::uint8_t mUnknown00To1F[0x20]{};
    LuaPlus::LuaObject mLuaObject{}; // +0x20

    [[nodiscard]] static CUIWorldViewLuaObjectRuntimeView* FromWorldView(moho::CUIWorldView* worldView) noexcept
    {
      return reinterpret_cast<CUIWorldViewLuaObjectRuntimeView*>(worldView);
    }
  };

  static_assert(
    offsetof(CUIWorldViewLuaObjectRuntimeView, mLuaObject) == 0x20,
    "CUIWorldViewLuaObjectRuntimeView::mLuaObject offset must be 0x20"
  );

  struct CWldSessionCursorRuntimeView
  {
    std::uint8_t mUnknown00To4AF[0x4B0]{};
    moho::MouseInfo mCursorInfo{}; // +0x4B0

    [[nodiscard]] static CWldSessionCursorRuntimeView* FromSession(moho::CWldSession* session) noexcept
    {
      return reinterpret_cast<CWldSessionCursorRuntimeView*>(session);
    }
  };

  static_assert(
    offsetof(CWldSessionCursorRuntimeView, mCursorInfo) == 0x4B0,
    "CWldSessionCursorRuntimeView::mCursorInfo offset must be 0x4B0"
  );

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  using IMauiDragger = moho::IMauiDragger;

  using DraggerLink = moho::TDatListItem<IMauiDragger, void>;

  struct IMauiDraggerRuntimeView
  {
    std::uint32_t mVftable = 0;
    DraggerLink* mList = nullptr;
  };

  static_assert(offsetof(IMauiDraggerRuntimeView, mList) == 0x4, "IMauiDraggerRuntimeView::mList offset must be 0x4");
  static_assert(sizeof(IMauiDraggerRuntimeView) == 0x8, "IMauiDraggerRuntimeView size must be 0x8");

class MauiDraggerVtableProbe final : public moho::IMauiDragger
{
public:
  void DragMove(const moho::SMauiEventData*) override
  {
  }

  void DragRelease(const moho::SMauiEventData*) override
  {
  }

  void OnCurrentDraggerReplaced() override
  {
  }
};

[[nodiscard]] static std::uint32_t ResolveMauiDraggerVtableLane() noexcept
{
  static MauiDraggerVtableProbe probe;
  return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(&probe)));
}

/**
 * Address: 0x0078DEE0 (FUN_0078DEE0)
 *
 * What it does:
 * Restores one dragger-base runtime lane with IMauiDragger vtable and clears
 * the primary list-link pointer lane.
 */
[[maybe_unused]] static IMauiDraggerRuntimeView* func_InitMauiDraggerBase(
  IMauiDraggerRuntimeView* const draggerView
) noexcept
{
  draggerView->mList = nullptr;
  draggerView->mVftable = ResolveMauiDraggerVtableLane();
  return draggerView;
}

  struct CMauiLuaDraggerEmbeddedRuntimeView
  {
    std::uint8_t mUnknown00To33[0x34]{};
    IMauiDraggerRuntimeView mDraggerBase{};
  };
  static_assert(
    offsetof(CMauiLuaDraggerEmbeddedRuntimeView, mDraggerBase) == 0x34,
    "CMauiLuaDraggerEmbeddedRuntimeView::mDraggerBase offset must be 0x34"
  );
  static_assert(
    sizeof(CMauiLuaDraggerEmbeddedRuntimeView) == 0x3C,
    "CMauiLuaDraggerEmbeddedRuntimeView size must be 0x3C"
  );

} // namespace

/**
 * Address: 0x0078DE50 (FUN_0078DE50, Moho::CMauiLuaDragger::CMauiLuaDragger)
 *
 * What it does:
 * Initializes one Lua dragger script-object base lane, resets the embedded
 * dragger-base runtime fields, and binds the incoming Lua object payload.
 */
moho::CMauiLuaDragger* moho::func_CMauiLuaDraggerConstruct(
  CMauiLuaDragger* const luaDragger,
  const LuaPlus::LuaObject* const luaObject
)
{
  auto* const draggerView = reinterpret_cast<CMauiLuaDraggerEmbeddedRuntimeView*>(luaDragger);
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(luaDragger);

  static_cast<WeakObject*>(scriptObject)->weakLinkHead_ = 0u;
  new (&scriptObject->cObject) LuaPlus::LuaObject();
  new (&scriptObject->mLuaObj) LuaPlus::LuaObject();

  IMauiDraggerRuntimeView* const draggerBaseView = &draggerView->mDraggerBase;
  (void)func_InitMauiDraggerBase(draggerBaseView);
  scriptObject->SetLuaObject(*luaObject);
  return luaDragger;
}

namespace
{
  using CameraDragDeltaFn = int(__thiscall*)(void*, Wm3::Vector2f*);

  struct CameraDraggerRuntimeView
  {
    void* mVftable = nullptr;            // +0x00
    DraggerLink* mListHead = nullptr;    // +0x04
    moho::CameraImpl* mCamera = nullptr; // +0x08
    Wm3::Vector2f mPos{};                // +0x0C
    std::uint32_t mUnknown14 = 0;        // +0x14
    CameraDragDeltaFn mDragMoveFn = nullptr; // +0x18
    std::int32_t mDragMoveOffset = 0;    // +0x1C
  };

  static_assert(offsetof(CameraDraggerRuntimeView, mCamera) == 0x8, "CameraDraggerRuntimeView::mCamera offset must be 0x8");
  static_assert(offsetof(CameraDraggerRuntimeView, mPos) == 0xC, "CameraDraggerRuntimeView::mPos offset must be 0xC");
  static_assert(
    offsetof(CameraDraggerRuntimeView, mDragMoveFn) == 0x18,
    "CameraDraggerRuntimeView::mDragMoveFn offset must be 0x18"
  );
  static_assert(
    offsetof(CameraDraggerRuntimeView, mDragMoveOffset) == 0x1C,
    "CameraDraggerRuntimeView::mDragMoveOffset offset must be 0x1C"
  );
  static_assert(sizeof(CameraDraggerRuntimeView) == 0x20, "CameraDraggerRuntimeView size must be 0x20");

  struct MiniMapDraggerRuntimeView
  {
    void* mVftable = nullptr;             // +0x00
    DraggerLink* mListHead = nullptr;     // +0x04
    std::uint32_t mUnknown08 = 0;         // +0x08
    msvc8::string mCameraName{};          // +0x0C
  };

  static_assert(offsetof(MiniMapDraggerRuntimeView, mListHead) == 0x4, "MiniMapDraggerRuntimeView::mListHead offset must be 0x4");
  static_assert(offsetof(MiniMapDraggerRuntimeView, mCameraName) == 0xC, "MiniMapDraggerRuntimeView::mCameraName offset must be 0xC");

  struct CurrentDraggerSentinel
  {
    DraggerLink* mPrev = nullptr;
    DraggerLink* mNext = nullptr;
  };

  static_assert(
    sizeof(CurrentDraggerSentinel) == sizeof(DraggerLink),
    "CurrentDraggerSentinel must remain intrusive-link-compatible"
  );

  struct WxWindowCaptureRuntimeView
  {
    std::uint8_t mUnknown00To107[0x108]{};
    HWND mWindowHandle = nullptr; // +0x108
  };

  static_assert(
    offsetof(WxWindowCaptureRuntimeView, mWindowHandle) == 0x108,
    "WxWindowCaptureRuntimeView::mWindowHandle offset must be 0x108"
  );

  class CMauiWxEventMapperRuntime final : public moho::wxEvtHandlerRuntime
  {
  public:
    std::uint8_t mUnknown04To27[0x24]{};
    WxWindowCaptureRuntimeView* mWindowRuntime = nullptr; // +0x28
    moho::CMauiFrame* mFrame = nullptr;                   // +0x2C

    /**
     * Address: 0x007A48D0 (FUN_007A48D0, ??1CMauiWxEventMapper@Moho@@QAE@@Z)
     * Mangled: ??1CMauiWxEventMapper@Moho@@QAE@@Z
     *
     * What it does:
     * Unlinks the global current-dragger sentinel from the dragger lane,
     * clears mouse-capture state, and then runs the wxEvtHandler base
     * destructor lane.
     */
    ~CMauiWxEventMapperRuntime() override;
  };

  using CMauiWxEventMapperRuntimeView = CMauiWxEventMapperRuntime;

  static_assert(
    offsetof(CMauiWxEventMapperRuntimeView, mWindowRuntime) == 0x28,
    "CMauiWxEventMapperRuntimeView::mWindowRuntime offset must be 0x28"
  );
  static_assert(
    offsetof(CMauiWxEventMapperRuntimeView, mFrame) == 0x2C,
    "CMauiWxEventMapperRuntimeView::mFrame offset must be 0x2C"
  );
  static_assert(sizeof(CMauiWxEventMapperRuntimeView) == 0x30, "CMauiWxEventMapperRuntimeView size must be 0x30");

  struct CMauiFrameDraggerRuntimeView
  {
    std::uint8_t mUnknown00To12B[0x12C]{};
    moho::wxEvtHandlerRuntime* mEventMapper = nullptr; // +0x12C
  };

  static_assert(
    offsetof(CMauiFrameDraggerRuntimeView, mEventMapper) == 0x12C,
    "CMauiFrameDraggerRuntimeView::mEventMapper offset must be 0x12C"
  );

  constexpr std::int32_t kMauiLButtonCode = 301;
  constexpr std::int32_t kMauiRButtonCode = 302;
  constexpr std::int32_t kMauiMButtonCode = 304;
  constexpr std::int32_t kPostDraggerLeftButton = 1;
  constexpr std::int32_t kPostDraggerMiddleButton = 2;
  constexpr std::int32_t kPostDraggerRightButton = 3;

  CurrentDraggerSentinel sCurrentDragger{};
  std::int32_t sCurrentDraggerKeycode = 0;
  std::uint8_t sMouseIsCaptured = 0;
  std::uint8_t sMouseIsScrubbing = 0;
  POINT sMouseMoveStart{};
  POINT sMouseScrubDelta{};
  POINT sMouseScrubAnchor{};

  [[nodiscard]] DraggerLink* CurrentDraggerSentinelLink() noexcept
  {
    return reinterpret_cast<DraggerLink*>(&sCurrentDragger);
  }

  [[nodiscard]] DraggerLink* DraggerLinkFromObject(IMauiDragger* const dragger) noexcept
  {
    if (dragger == nullptr) {
      return nullptr;
    }

    auto* const draggerView = reinterpret_cast<IMauiDraggerRuntimeView*>(dragger);
    return reinterpret_cast<DraggerLink*>(&draggerView->mList);
  }

  [[nodiscard]] IMauiDragger* DraggerFromLink(DraggerLink* const link) noexcept
  {
    if (link == nullptr) {
      return nullptr;
    }

    constexpr std::uintptr_t kListOffset = offsetof(IMauiDraggerRuntimeView, mList);
    const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(link);
    if (linkAddress < kListOffset) {
      return nullptr;
    }
    return reinterpret_cast<IMauiDragger*>(linkAddress - kListOffset);
  }

  DraggerLink* DetachDraggerList(DraggerLink*& head) noexcept
  {
    DraggerLink* node = head;
    while (node != nullptr) {
      head = node->mNext;
      node->mPrev = nullptr;
      node->mNext = nullptr;
      node = head;
    }
    return node;
  }

  /**
   * Address: 0x0078DEF0 (FUN_0078DEF0, Moho::CMauiLuaDragger::~CMauiLuaDragger)
   *
   * What it does:
   * Restores the embedded dragger-base vtable lane, unlinks all dragger-list
   * nodes rooted at that embedded lane, then runs `CScriptObject` base
   * destructor behavior.
   */
  [[maybe_unused]] static moho::CScriptObject* func_CMauiLuaDraggerDestruct(
    moho::CScriptObject* const scriptObject
  ) noexcept
  {
    auto* const draggerView = reinterpret_cast<CMauiLuaDraggerEmbeddedRuntimeView*>(scriptObject);
    IMauiDraggerRuntimeView* const draggerBaseView = &draggerView->mDraggerBase;
    draggerBaseView->mVftable = ResolveMauiDraggerVtableLane();
    (void)DetachDraggerList(draggerBaseView->mList);
    scriptObject->moho::CScriptObject::~CScriptObject();
    return scriptObject;
  }

  [[nodiscard]] IMauiDragger* ResolveEmbeddedLuaDragger(moho::CMauiLuaDragger* const luaDragger) noexcept
  {
    if (luaDragger == nullptr) {
      return nullptr;
    }

    auto* const draggerView = reinterpret_cast<CMauiLuaDraggerEmbeddedRuntimeView*>(luaDragger);
    return reinterpret_cast<IMauiDragger*>(&draggerView->mDraggerBase);
  }

  [[nodiscard]] std::int32_t NormalizePostDraggerKeycode(const std::int32_t keyCode) noexcept
  {
    if (keyCode == kMauiLButtonCode) {
      return kPostDraggerLeftButton;
    }
    if (keyCode == kMauiRButtonCode) {
      return kPostDraggerRightButton;
    }
    if (keyCode == kMauiMButtonCode) {
      return kPostDraggerMiddleButton;
    }
    return keyCode;
  }

  [[nodiscard]] bool IsValidPostDraggerKeycode(const std::int32_t keyCode) noexcept
  {
    return keyCode == kPostDraggerLeftButton || keyCode == kPostDraggerMiddleButton || keyCode == kPostDraggerRightButton;
  }

  [[nodiscard]] HWND ResolveCaptureWindowHandle(moho::wxEvtHandlerRuntime* const eventMapper) noexcept
  {
    auto* const mapperView = reinterpret_cast<CMauiWxEventMapperRuntimeView*>(eventMapper);
    auto* const windowView = mapperView->mWindowRuntime;
    return windowView->mWindowHandle;
  }

  msvc8::vector<moho::WeakPtr<moho::CMauiControl>> sInputCapture;

/**
 * Address: 0x007A59E0 (FUN_007A59E0)
 *
 * What it does:
 * Returns the process-global input-capture vector storage, ignoring one
 * stdcall argument lane.
 */
[[maybe_unused]] [[nodiscard]] msvc8::vector<moho::WeakPtr<moho::CMauiControl>>*
ResolveInputCaptureStorageWithArg(const std::int32_t /*ignoredArg*/) noexcept
{
  return &sInputCapture;
}

/**
 * Address: 0x007A5DA0 (FUN_007A5DA0)
 *
 * What it does:
 * Returns the process-global input-capture vector storage.
 */
[[maybe_unused]] [[nodiscard]] msvc8::vector<moho::WeakPtr<moho::CMauiControl>>* ResolveInputCaptureStorage() noexcept
{
  return ResolveInputCaptureStorageWithArg(0);
}

  /**
   * Address: 0x007A5680 (FUN_007A5680)
   *
   * What it does:
   * Stores the current global input-capture begin lane into `outBegin`.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>** StoreInputCaptureBeginLane(
    moho::WeakPtr<moho::CMauiControl>** const outBegin
  ) noexcept
  {
    const auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    *outBegin = view.begin;
    return outBegin;
  }

  /**
   * Address: 0x007A5690 (FUN_007A5690)
   *
   * What it does:
   * Stores the current global input-capture end lane into `outEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>** StoreInputCaptureEndLane(
    moho::WeakPtr<moho::CMauiControl>** const outEnd
  ) noexcept
  {
    const auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    *outEnd = view.end;
    return outEnd;
  }

  /**
   * Address: 0x007A56F0 (FUN_007A56F0)
   *
   * What it does:
   * Returns one indexed weak-control lane from the global input-capture
   * vector storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>* ResolveInputCaptureLaneAt(
    const std::size_t index
  ) noexcept
  {
    const auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    return view.begin + static_cast<std::ptrdiff_t>(index);
  }

  void UnlinkInputCaptureWeakPtrRange(
    moho::WeakPtr<moho::CMauiControl>* begin,
    moho::WeakPtr<moho::CMauiControl>* end
  ) noexcept
  {
    while (begin != end) {
      begin->UnlinkFromOwnerChain();
      ++begin;
    }
  }

  /**
   * Address: 0x007A5970 (FUN_007A5970)
   *
   * What it does:
   * Unlinks every weak-capture node from owner chains, frees the global
   * input-capture backing storage lane, and clears begin/end/capacity lanes.
   */
  [[maybe_unused]] void CleanupInputCaptureAtExit() noexcept
  {
    auto& captureView = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    if (captureView.begin != nullptr) {
      UnlinkInputCaptureWeakPtrRange(captureView.begin, captureView.end);
      ::operator delete(static_cast<void*>(captureView.begin));
    }
    captureView.begin = nullptr;
    captureView.end = nullptr;
    captureView.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00C032E0 (FUN_00C032E0)
   *
   * What it does:
   * Thunk lane that forwards global input-capture cleanup-at-exit teardown
   * into `FUN_007A5970`.
   */
  [[maybe_unused]] void CleanupInputCaptureAtExitAdapter() noexcept
  {
    CleanupInputCaptureAtExit();
  }
  /**
   * Address: 0x007A56A0 (FUN_007A56A0)
   *
   * What it does:
   * Returns the current number of weak-control entries in the global input
   * capture stack.
   */
  [[nodiscard]] std::size_t InputCaptureCount() noexcept
  {
    const auto& captureVector = *ResolveInputCaptureStorage();
    const auto& view = moho::AsWeakPtrVectorRuntimeView(captureVector);
    if (view.begin == nullptr || view.end == nullptr) {
      return 0;
    }
    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x007A5F60 (FUN_007A5F60)
   *
   * What it does:
   * Copy-assigns one contiguous weak-control range while preserving intrusive
   * weak-owner chain semantics for each destination lane.
   */
  [[nodiscard]] moho::WeakPtr<moho::CMauiControl>* CopyInputCaptureWeakRangeAssign(
    moho::WeakPtr<moho::CMauiControl>* destination,
    const moho::WeakPtr<moho::CMauiControl>* sourceBegin,
    const moho::WeakPtr<moho::CMauiControl>* sourceEnd
  ) noexcept
  {
    const moho::WeakPtr<moho::CMauiControl>* source = sourceBegin;
    while (source != sourceEnd) {
      if (source->ownerLinkSlot != destination->ownerLinkSlot) {
        if (destination->ownerLinkSlot != nullptr) {
          auto** ownerCursor = reinterpret_cast<moho::WeakPtr<moho::CMauiControl>**>(destination->ownerLinkSlot);
          while (*ownerCursor != destination) {
            ownerCursor = &(*ownerCursor)->nextInOwner;
          }
          *ownerCursor = destination->nextInOwner;
        }

        destination->ownerLinkSlot = source->ownerLinkSlot;
        if (source->ownerLinkSlot == nullptr) {
          destination->nextInOwner = nullptr;
        } else {
          auto** const sourceHead = reinterpret_cast<moho::WeakPtr<moho::CMauiControl>**>(source->ownerLinkSlot);
          destination->nextInOwner = *sourceHead;
          *sourceHead = destination;
        }
      }

      ++source;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x007A5E30 (FUN_007A5E30)
   *
   * What it does:
   * Register-order adapter that forwards one input-capture weak-range
   * copy-assign lane through CopyInputCaptureWeakRangeAssign.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>* CopyInputCaptureWeakRangeAssignRegisterAdapter(
    moho::WeakPtr<moho::CMauiControl>* const destination,
    const moho::WeakPtr<moho::CMauiControl>* const sourceBegin,
    const moho::WeakPtr<moho::CMauiControl>* const sourceEnd
  ) noexcept
  {
    return CopyInputCaptureWeakRangeAssign(destination, sourceBegin, sourceEnd);
  }
  void RemoveInputCaptureAt(const std::size_t index) noexcept
  {
    auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    const std::size_t count = InputCaptureCount();
    if (view.begin == nullptr || index >= count) {
      return;
    }

    view.begin[index].ResetFromObject(nullptr);
    moho::WeakPtr<moho::CMauiControl>* const oldEnd = view.end;
    (void)CopyInputCaptureWeakRangeAssign(&view.begin[index], &view.begin[index + 1u], oldEnd);

    moho::WeakPtr<moho::CMauiControl>* const newEnd = oldEnd - 1;
    newEnd->ResetFromObject(nullptr);
    view.end = newEnd;
  }

  /**
   * Address: 0x007A5870 (FUN_007A5870)
   *
   * What it does:
   * Inserts one weak-control capture lane at the requested position in the
   * global `sInputCapture` vector and returns the rebased inserted iterator.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>** InsertInputCaptureWithGrowth(
    moho::WeakPtr<moho::CMauiControl>** const outIterator,
    moho::WeakPtr<moho::CMauiControl>* const insertAt,
    const moho::WeakPtr<moho::CMauiControl>* const value
  )
  {
    using CaptureWeakPtr = moho::WeakPtr<moho::CMauiControl>;

    const CaptureWeakPtr* const begin = sInputCapture.data();
    const std::size_t count = sInputCapture.size();

    std::size_t insertIndex = 0u;
    if (begin != nullptr && count != 0u && insertAt != nullptr) {
      const std::uintptr_t beginAddress = reinterpret_cast<std::uintptr_t>(begin);
      const std::uintptr_t insertAddress = reinterpret_cast<std::uintptr_t>(insertAt);
      if (insertAddress >= beginAddress) {
        insertIndex = static_cast<std::size_t>((insertAddress - beginAddress) / sizeof(CaptureWeakPtr));
      }
    }
    insertIndex = std::min(insertIndex, count);

    CaptureWeakPtr captureValue{};
    if (value != nullptr) {
      captureValue = *value;
    }

    moho::EnsureWeakPtrVectorCapacity(sInputCapture, count + 1u);
    auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    for (std::size_t i = count; i > insertIndex; --i) {
      view.begin[i].ResetFromOwnerLinkSlot(view.begin[i - 1u].ownerLinkSlot);
      view.begin[i - 1u].ResetFromObject(nullptr);
    }

    if (value != nullptr) {
      view.begin[insertIndex].ResetFromOwnerLinkSlot(captureValue.ownerLinkSlot);
    } else {
      view.begin[insertIndex].ResetFromObject(nullptr);
    }
    view.end = view.begin + count + 1u;

    if (outIterator != nullptr) {
      CaptureWeakPtr* const rebasedBegin = view.begin;
      *outIterator = rebasedBegin != nullptr ? rebasedBegin + insertIndex : nullptr;
    }
    return outIterator;
  }

  /**
   * Address: 0x007A4720 (FUN_007A4720, sub_7A4720)
   *
   * What it does:
   * Compacts global input-capture weak-pointer lanes by erasing stale
   * entries whose owner link resolves to null/sentinel.
   */
  void CompactInputCaptureStack() noexcept
  {
    std::vector<std::size_t> staleIndices{};

    const auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    const std::size_t count = InputCaptureCount();
    if (view.begin != nullptr && count > 0u) {
      for (std::size_t index = 0; index < count; ++index) {
        if (view.begin[index].GetObjectPtr() == nullptr) {
          staleIndices.push_back(index);
        }
      }
    }

    for (std::size_t i = 0; i < staleIndices.size(); ++i) {
      RemoveInputCaptureAt(staleIndices[i]);
    }
  }

  /**
   * Address: 0x007A4680 (FUN_007A4680, sub_7A4680)
   *
   * What it does:
   * Returns the top control currently in the global input-capture stack
   * after compacting stale weak-pointer entries.
   */
  [[nodiscard]] moho::CMauiControl* ResolveTopInputCaptureControl() noexcept
  {
    CompactInputCaptureStack();

    const auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    const std::size_t count = InputCaptureCount();
    if (view.begin == nullptr || count == 0u) {
      return nullptr;
    }

    return view.begin[count - 1u].GetObjectPtr();
  }

  /**
   * Address: 0x007A5710 (FUN_007A5710, sub_7A5710)
   *
   * What it does:
   * Appends one weak-control entry to the global input-capture vector,
   * growing capacity when needed.
   */
  [[maybe_unused]] static moho::WeakPtr<moho::CMauiControl>* AppendInputCaptureWeakReference(
    const moho::WeakPtr<moho::CMauiControl>* const captureRef
  )
  {
    if (captureRef == nullptr) {
      return nullptr;
    }

    const std::size_t count = InputCaptureCount();
    moho::EnsureWeakPtrVectorCapacity(sInputCapture, count + 1u);

    auto& view = moho::AsWeakPtrVectorRuntimeView(sInputCapture);
    view.begin[count].ResetFromOwnerLinkSlot(captureRef->ownerLinkSlot);
    view.end = view.begin + count + 1u;
    return &view.begin[count];
  }

  /**
   * Address: 0x007A4540 (FUN_007A4540, sub_7A4540)
   *
   * What it does:
   * Wraps one control into one temporary weak-owner link and appends that
   * weak reference to the global input-capture stack.
   */
  void AddInputCaptureControl(moho::CMauiControl* const control)
  {
    if (control == nullptr) {
      return;
    }

    moho::WeakPtr<moho::CMauiControl> captureRef{};
    captureRef.ResetFromObject(control);
    (void)AppendInputCaptureWeakReference(&captureRef);
    captureRef.ResetFromObject(nullptr);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("user");
    return sSet;
  }

  struct WindowEventHandlerChain
  {
    wxWindowBase* window = nullptr;
    std::vector<moho::wxEvtHandlerRuntime*> handlers{};
  };

  std::vector<WindowEventHandlerChain> gWindowEventHandlerChains;

  [[nodiscard]]
  std::vector<WindowEventHandlerChain>::iterator FindWindowEventHandlerChain(const wxWindowBase* const window)
  {
    return std::find_if(
      gWindowEventHandlerChains.begin(),
      gWindowEventHandlerChains.end(),
      [window](const WindowEventHandlerChain& chain) { return chain.window == window; }
    );
  }

  gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CScriptObject*));
    }
    return cached;
  }

  gpg::RType* CachedCMauiFrameType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiFrame));
    }
    return cached;
  }

  gpg::RType* CachedCMauiControlType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiControl));
    }
    return cached;
  }

  gpg::RType* CachedCMauiCursorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiCursor));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCMauiLuaDraggerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiLuaDragger");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CMauiLuaDragger");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCLuaWldUIProviderType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CLuaWldUIProvider");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CLuaWldUIProvider");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUIWorldMeshType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CUIWorldMesh");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CUIWorldMesh");
      }
    }
    return cached;
  }

  [[nodiscard]] LuaPlus::LuaObject CopyLuaObjectToState(const LuaPlus::LuaObject& source, LuaPlus::LuaState* const targetState)
  {
    if (!targetState || !targetState->GetCState()) {
      return {};
    }

    LuaPlus::LuaObject copy{};
    lua_State* const lstate = targetState->GetCState();
    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(source).PushStack(lstate);
    copy = LuaPlus::LuaObject(LuaPlus::LuaStackObject(targetState, -1));
    lua_settop(lstate, savedTop);
    return copy;
  }

  gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const raw = lua_touserdata(lstate, -1);
    if (raw) {
      out = *static_cast<gpg::RRef*>(raw);
    }
    lua_settop(lstate, savedTop);
    return out;
  }

  moho::CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] moho::CMauiFrame* ResolveFrameFromLuaObjectOrError(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiFrameType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiFrame*>(upcast.mObj);
  }

  /**
   * Address: 0x00796E50 (FUN_00796E50, sub_796E50)
   *
   * What it does:
   * Assigns one retained frame owner into one weak self-owner lane.
   */
  [[maybe_unused]] boost::weak_ptr<moho::CMauiFrame>* AssignFrameWeakSelfFromSharedOwner(
    const boost::shared_ptr<moho::CMauiFrame>& owner,
    boost::weak_ptr<moho::CMauiFrame>* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    *destination = owner;
    return destination;
  }

  /**
   * Address: 0x0078ACE0 (FUN_0078ACE0, func_GetCMauiControlOpt)
   *
   * What it does:
   * Resolves one optional `CMauiControl` from Lua object payload; raises Lua
   * errors for non-game-object or incorrect-type payloads and returns null for
   * destroyed objects.
   */
  [[nodiscard]]
  moho::CMauiControl* ResolveControlFromLuaObjectOptionalOrError(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiControlType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiControl*>(upcast.mObj);
  }

  /**
   * Address: 0x0078E6F0 (FUN_0078E6F0, func_GetCMauiLuaDraggerOpt)
   *
   * What it does:
   * Resolves one optional `CMauiLuaDragger` from Lua object payload; raises
   * Lua errors for non-game-object or incorrect-type payloads and returns
   * null for destroyed objects.
   */
  [[nodiscard]] moho::CMauiLuaDragger* ResolveCMauiLuaDraggerOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    gpg::RType* const draggerType = CachedCMauiLuaDraggerType();
    if (draggerType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, draggerType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiLuaDragger*>(upcast.mObj);
  }

  /**
   * Address: 0x0086AC50 (FUN_0086AC50, func_GetCLuaWldUIProviderObjectOpt)
   *
   * What it does:
   * Resolves one optional `CLuaWldUIProvider` from Lua object payload; raises
   * Lua errors for non-game-object or incorrect-type payloads and returns
   * null for destroyed objects.
   */
  [[nodiscard]] moho::CLuaWldUIProvider* ResolveCLuaWldUIProviderOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    gpg::RType* const providerType = CachedCLuaWldUIProviderType();
    if (providerType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, providerType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CLuaWldUIProvider*>(upcast.mObj);
  }

  /**
   * Address: 0x0086D840 (FUN_0086D840, func_GetCUIWorldMeshObjectOpt)
   *
   * What it does:
   * Resolves one optional `CUIWorldMesh` from Lua object payload; raises Lua
   * errors for non-game-object or incorrect-type payloads and returns null
   * for destroyed objects.
   */
  [[nodiscard]] moho::CUIWorldMesh* ResolveCUIWorldMeshOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    gpg::RType* const worldMeshType = CachedCUIWorldMeshType();
    if (worldMeshType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, worldMeshType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUIWorldMesh*>(upcast.mObj);
  }

  [[nodiscard]] moho::CMauiCursor* ResolveCursorFromLuaObjectOrError(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiCursorType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiCursor*>(upcast.mObj);
  }

  /**
    * Alias of FUN_0040D820 (non-canonical helper lane).
   *
   * What it does:
   * Applies x87-style nearby-int rounding and adjusts down by one when the
   * original value sits below the rounded lane.
   */
  [[nodiscard]] int FloorFrndintAdjustDown(const float value) noexcept
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value < rounded) ? -1 : 0);
  }

  /**
   * Address: 0x0085AFE0 (FUN_0085AFE0, sub_85AFE0)
   *
   * What it does:
   * Converts one normalized device coordinate point into viewport pixel space
   * and floors X/Y lanes to match Lua-facing screen position semantics.
   */
  [[nodiscard]] Wm3::Vector3f ProjectNormalizedScreenPointToViewportFloor(
    const Wm3::Vector2f& normalizedPoint,
    const float viewportWidth,
    const float viewportHeight
  ) noexcept
  {
    Wm3::Vector3f screenPoint{};
    screenPoint.x = std::floor(((normalizedPoint.x - -1.0f) * viewportWidth) * 0.5f);
    screenPoint.y = std::floor(((-viewportHeight * (normalizedPoint.y - -1.0f)) * 0.5f) + viewportHeight);
    screenPoint.z = 0.0f;
    return screenPoint;
  }

  struct UserUnitScreenPosRuntimeView
  {
    std::uint8_t mUnknown00To2B[0x2C]{};
    moho::MeshInstance* mMeshInstance = nullptr; // +0x2C
    std::uint8_t mUnknown30To147[0x118]{};
    std::uint8_t mIUnitBridgeStorage[sizeof(moho::IUnit)]{}; // +0x148

    [[nodiscard]] static const UserUnitScreenPosRuntimeView* FromUserUnit(const moho::UserUnit* userUnit) noexcept
    {
      return reinterpret_cast<const UserUnitScreenPosRuntimeView*>(userUnit);
    }

    [[nodiscard]] const moho::IUnit* GetIUnitBridge() const noexcept
    {
      return reinterpret_cast<const moho::IUnit*>(mIUnitBridgeStorage);
    }
  };

  static_assert(
    offsetof(UserUnitScreenPosRuntimeView, mMeshInstance) == 0x2C,
    "UserUnitScreenPosRuntimeView::mMeshInstance offset must be 0x2C"
  );
  static_assert(
    offsetof(UserUnitScreenPosRuntimeView, mIUnitBridgeStorage) == 0x148,
    "UserUnitScreenPosRuntimeView::mIUnitBridgeStorage offset must be 0x148"
  );

  struct CUIWorldMeshRuntimeView
  {
    std::uint8_t mUnknown00To33[0x34]{};
    moho::MeshInstance* mMeshInstance = nullptr; // +0x34

    [[nodiscard]] static CUIWorldMeshRuntimeView* FromWorldMesh(moho::CUIWorldMesh* worldMesh) noexcept
    {
      return reinterpret_cast<CUIWorldMeshRuntimeView*>(worldMesh);
    }

    [[nodiscard]] static const CUIWorldMeshRuntimeView* FromWorldMesh(const moho::CUIWorldMesh* worldMesh) noexcept
    {
      return reinterpret_cast<const CUIWorldMeshRuntimeView*>(worldMesh);
    }
  };

  static_assert(
    offsetof(CUIWorldMeshRuntimeView, mMeshInstance) == 0x34,
    "CUIWorldMeshRuntimeView::mMeshInstance offset must be 0x34"
  );

  void ReleaseIntrusiveFont(CD3DFont*& font) noexcept
  {
    if (!font) {
      return;
    }

    --font->mRefCount;
    if (font->mRefCount == 0) {
      font->Release(1);
    }
    font = nullptr;
  }

  void AssignIntrusiveFont(CD3DFont*& destination, CD3DFont* const source) noexcept
  {
    if (destination == source) {
      return;
    }

    ReleaseIntrusiveFont(destination);
    destination = source;
    if (destination) {
      ++destination->mRefCount;
    }
  }

  /**
   * Address: 0x0078ECE0 (FUN_0078ECE0)
   *
   * What it does:
   * Returns one text-advance measurement from the edit font lane and falls
   * back to `0.0f` when no font is bound.
   */
  [[nodiscard]] float MeasureEditStringAdvanceOrZero(
    CMauiEditRuntimeView* const editView,
    const char* const text
  )
  {
    CD3DFont* const font = editView->mFont;
    if (font == nullptr) {
      return 0.0f;
    }
    return font->GetAdvance(text, 0);
  }
  /**
   * Address: 0x0078F310 (FUN_0078F310)
   *
   * What it does:
   * Shows the edit caret and assigns keyboard focus when the edit is enabled.
   */
  void AcquireEditKeyboardFocusIfEnabled(moho::CMauiEdit* const edit)
  {
    CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(edit);
    if (editView->mIsEnabled) {
      editView->mCaretVisible = true;
      moho::MAUI_SetKeyboardFocus(edit, true);
    }
  }
  /**
   * Address: 0x0078DC60 (FUN_0078DC60)
   *
   * What it does:
   * Returns CMauiEdit background-visible lane.
   */
  [[maybe_unused]] bool ReadEditBackgroundVisibleLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mBackgroundVisible;
  }

  /**
   * Address: 0x0078EBF0 (FUN_0078EBF0)
   *
   * What it does:
   * Returns one font descent metric lane.
   */
  [[maybe_unused]] float ReadFontDescentLane(const CD3DFont* const font) noexcept
  {
    return font->mDescent;
  }

  /**
   * Address: 0x0078ECC0 (FUN_0078ECC0)
   *
   * What it does:
   * Stores edit drop-shadow enable lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditDropShadowLane(
    CMauiEditRuntimeView* const editView,
    const bool enabled
  ) noexcept
  {
    editView->mDropShadow = enabled;
    return editView;
  }

  /**
   * Address: 0x0078ECD0 (FUN_0078ECD0)
   *
   * What it does:
   * Returns edit max-char limit lane.
   */
  [[maybe_unused]] std::int32_t ReadEditMaxCharsLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mMaxChars;
  }

  /**
   * Address: 0x0078ED10 (FUN_0078ED10)
   *
   * What it does:
   * Reads edit-bound font height lane (`0.0f` when font is missing).
   */
  [[maybe_unused]] float ReadEditFontHeightLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    const CD3DFont* const font = editView->mFont;
    return font != nullptr ? font->mHeight : 0.0f;
  }

  /**
   * Address: 0x0078ED30 (FUN_0078ED30)
   *
   * What it does:
   * Stores edit foreground color lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditForegroundColorLane(
    CMauiEditRuntimeView* const editView,
    const std::uint32_t color
  ) noexcept
  {
    editView->mForegroundColor = color;
    return editView;
  }

  /**
   * Address: 0x0078ED40 (FUN_0078ED40)
   *
   * What it does:
   * Returns edit foreground color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditForegroundColorLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mForegroundColor;
  }

  /**
   * Address: 0x0078ED50 (FUN_0078ED50)
   *
   * What it does:
   * Stores edit background-visible lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditBackgroundVisibleLane(
    CMauiEditRuntimeView* const editView,
    const bool visible
  ) noexcept
  {
    editView->mBackgroundVisible = visible;
    return editView;
  }

  /**
   * Address: 0x0078ED60 (FUN_0078ED60)
   *
   * What it does:
   * Returns edit background-visible lane.
   */
  [[maybe_unused]] bool ReadEditBackgroundVisibleLaneAlias(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mBackgroundVisible;
  }

  /**
   * Address: 0x0078ED70 (FUN_0078ED70)
   *
   * What it does:
   * Enables background rendering and stores edit background color lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* EnableEditBackgroundAndWriteColor(
    CMauiEditRuntimeView* const editView,
    const std::uint32_t color
  ) noexcept
  {
    editView->mBackgroundVisible = true;
    editView->mBackgroundColor = color;
    return editView;
  }

  /**
   * Address: 0x0078ED80 (FUN_0078ED80)
   *
   * What it does:
   * Returns edit background color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditBackgroundColorLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mBackgroundColor;
  }

  /**
   * Address: 0x0078ED90 (FUN_0078ED90)
   *
   * What it does:
   * Stores edit highlight-foreground color lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditHighlightForegroundColorLane(
    CMauiEditRuntimeView* const editView,
    const std::uint32_t color
  ) noexcept
  {
    editView->mHighlightForegroundColor = color;
    return editView;
  }

  /**
   * Address: 0x0078EDA0 (FUN_0078EDA0)
   *
   * What it does:
   * Returns edit highlight-foreground color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditHighlightForegroundColorLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mHighlightForegroundColor;
  }

  /**
   * Address: 0x0078EDB0 (FUN_0078EDB0)
   *
   * What it does:
   * Stores edit highlight-background color lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditHighlightBackgroundColorLane(
    CMauiEditRuntimeView* const editView,
    const std::uint32_t color
  ) noexcept
  {
    editView->mHighlightBackgroundColor = color;
    return editView;
  }

  /**
   * Address: 0x0078EDC0 (FUN_0078EDC0)
   *
   * What it does:
   * Returns edit highlight-background color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditHighlightBackgroundColorLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mHighlightBackgroundColor;
  }

  /**
   * Address: 0x0078EE00 (FUN_0078EE00)
   *
   * What it does:
   * Returns edit caret-position lane.
   */
  [[maybe_unused]] std::int32_t ReadEditCaretPositionLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mCaretPosition;
  }

  /**
   * Address: 0x0078EE10 (FUN_0078EE10)
   *
   * What it does:
   * Stores edit caret-visible lane.
   */
  [[maybe_unused]] CMauiEditRuntimeView* WriteEditCaretVisibleLane(
    CMauiEditRuntimeView* const editView,
    const bool visible
  ) noexcept
  {
    editView->mCaretVisible = visible;
    return editView;
  }

  /**
   * Address: 0x0078EE20 (FUN_0078EE20)
   *
   * What it does:
   * Returns edit caret-visible lane.
   */
  [[maybe_unused]] bool ReadEditCaretVisibleLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mCaretVisible;
  }

  /**
   * Address: 0x0078EE40 (FUN_0078EE40)
   *
   * What it does:
   * Returns edit caret color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditCaretColorLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mCaretColor;
  }

  /**
   * Address: 0x0078EE50 (FUN_0078EE50)
   *
   * What it does:
   * Returns edit input-enabled lane.
   */
  [[maybe_unused]] bool ReadEditInputEnabledLane(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mIsEnabled;
  }

  /**
   * Address: 0x0078EE70 (FUN_0078EE70)
   *
   * What it does:
   * Returns whether selection start/end lanes differ.
   */
  [[maybe_unused]] bool HasEditSelectionRange(const CMauiEditRuntimeView* const editView) noexcept
  {
    return editView->mSelectionStart != editView->mSelectionEnd;
  }

  /**
   * Address: 0x0078F360 (FUN_0078F360)
   *
   * What it does:
   * Writes edit input/caret-enabled lanes; when disabling, also abandons
   * keyboard focus through virtual dispatch path.
   */
  [[maybe_unused]] bool WriteEditInputEnabledAndCaretVisible(
    moho::CMauiEdit* const edit,
    const bool enabled
  )
  {
    CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(edit);
    editView->mIsEnabled = enabled;
    editView->mCaretVisible = enabled;
    if (!enabled) {
      edit->AbandonKeyboardFocus();
    }
    return enabled;
  }

  /**
   * Address: 0x00790580 (FUN_00790580)
   *
   * What it does:
   * Forwards one key code into `CScriptObject::RunScriptOnCharPressed`.
   */
  [[nodiscard]] bool RunScriptOnCharPressedThunk(
    moho::CScriptObject* const scriptObject,
    const int keyCode
  )
  {
    return scriptObject->RunScriptOnCharPressed(keyCode);
  }
  /**
   * Address: 0x00794DB0 (FUN_00794DB0)
   *
   * What it does:
   * Finds the first position at or after `startPos` where `text` contains any
   * character from `characterSet`.
   */
  [[maybe_unused, nodiscard]] std::size_t FindFirstOfCharacterSet(
    const msvc8::string& text,
    const msvc8::string& characterSet,
    const std::size_t startPos
  ) noexcept
  {
    return text.view().find_first_of(characterSet.view(), startPos);
  }

  /**
   * Address: 0x00790F90 (FUN_00790F90, Moho::CMauiEdit::SetClipOffsetLeft)
   *
   * What it does:
   * Updates clip offset and recomputes visible UTF-8 clip length from current
   * edit text, font, and width lazy-var lane.
   */
  void SetEditClipOffsetLeft(CMauiEditRuntimeView* const editView, int position)
  {
    if (!editView) {
      return;
    }

    editView->mClipOffset = position;
    CD3DFont* const font = editView->mFont;
    if (font == nullptr) {
      return;
    }

    const char* const text = editView->mText.c_str();
    const float advanceToOffset = font->GetAdvance(text, position);
    const float width = CScriptLazyVar_float::GetValue(&editView->mWidthLV);
    if (advanceToOffset <= width) {
      editView->mClipLength = gpg::STR_Utf8Len(text);
      return;
    }

    const int textLength = gpg::STR_Utf8Len(text);
    if (position > textLength) {
      position = textLength;
    }

    const int byteOffset = gpg::STR_Utf8ByteOffset(text, position);
    const char* const start = text + byteOffset;
    const char* cursor = start;
    float clippedAdvance = 0.0f;
    while (cursor != nullptr) {
      wchar_t decoded = 0;
      const char* const next = gpg::STR_DecodeUtf8Char(cursor, decoded);
      clippedAdvance += font->GetCharInfo(decoded).mAdvance;
      const float dynamicWidth = CScriptLazyVar_float::GetValue(&editView->mWidthLV);
      cursor = next;
      if (clippedAdvance > dynamicWidth || cursor == nullptr) {
        break;
      }
    }

    const std::size_t clippedBytes = (cursor != nullptr && cursor > start) ? static_cast<std::size_t>(cursor - start) : 0u;
    if (clippedBytes == 0u) {
      editView->mClipLength = 0;
      return;
    }

    const std::string clippedText(start, clippedBytes);
    editView->mClipLength = gpg::STR_Utf8Len(clippedText.c_str());
  }

  /**
   * Address: 0x00790D20 (FUN_00790D20, Moho::CMauiEdit::SetClipOffsetRight)
   *
   * What it does:
   * Recomputes clip window from the right side so the caret lane remains inside
   * the visible width while preserving right-side character count.
   */
  void SetEditClipOffsetRight(CMauiEditRuntimeView* const editView, int charsAfterCaret)
  {
    if (editView == nullptr || editView->mFont == nullptr) {
      return;
    }

    const char* const text = editView->mText.c_str();
    const float advanceToRight = editView->mFont->GetAdvance(text, charsAfterCaret);
    const float width = CScriptLazyVar_float::GetValue(&editView->mWidthLV);
    if (advanceToRight <= width) {
      editView->mClipLength = gpg::STR_Utf8Len(text);
      return;
    }

    int textLength = gpg::STR_Utf8Len(text);
    if (charsAfterCaret > textLength) {
      charsAfterCaret = textLength;
    }

    const int caretPosition = textLength - charsAfterCaret;
    const int textByteLength = gpg::STR_Utf8ByteOffset(text, textLength);
    const int caretByteOffset = textByteLength - gpg::STR_Utf8ByteOffset(text, charsAfterCaret);

    const char* const start = text;
    const char* threshold = start + caretByteOffset;
    float clippedAdvance = 0.0f;
    if (threshold != start) {
      while (true) {
        const char* const previous = gpg::STR_PreviousUtf8Char(threshold, start);

        wchar_t decoded = 0;
        const char* const next = gpg::STR_DecodeUtf8Char(previous, decoded);
        clippedAdvance += editView->mFont->GetCharInfo(decoded).mAdvance;
        const float dynamicWidth = CScriptLazyVar_float::GetValue(&editView->mWidthLV);
        if (clippedAdvance > dynamicWidth) {
          threshold = next;
          break;
        }

        threshold = previous;
        if (threshold == start) {
          break;
        }
      }
    }

    const std::ptrdiff_t copiedBytes = static_cast<std::ptrdiff_t>(caretByteOffset) - (threshold - start);
    const std::size_t visibleBytes = copiedBytes > 0 ? static_cast<std::size_t>(copiedBytes) : 0u;
    const std::string visibleText(threshold, visibleBytes);

    editView->mClipLength = gpg::STR_Utf8Len(visibleText.c_str());
    editView->mClipOffset = caretPosition - editView->mClipLength;
  }

  void CopyUtf8TextToClipboard(const msvc8::string& text)
  {
    const std::wstring wideText = gpg::STR_Utf8ToWide(text.c_str());
    (void)moho::WIN_CopyToClipboard(wideText.c_str());
  }

  void CopyEditSelectionToClipboard(moho::CMauiEdit* const edit)
  {
    if (edit == nullptr) {
      return;
    }

    CopyUtf8TextToClipboard(edit->GetSelection());
  }

  [[nodiscard]] IMauiDragger* ResolveEditClickDragger(CMauiEditRuntimeView* const editView) noexcept
  {
    return reinterpret_cast<IMauiDragger*>(editView->mClickDraggerStorage);
  }

  struct CMauiEditClickDraggerRuntimeView
  {
    std::uint32_t mVftable = 0;
    DraggerLink* mListHead = nullptr;
  };

  static_assert(
    sizeof(CMauiEditClickDraggerRuntimeView) == 0x08,
    "CMauiEditClickDraggerRuntimeView size must be 0x08"
  );

  [[nodiscard]] CMauiEditClickDraggerRuntimeView* ResolveEditClickDraggerRuntime(CMauiEditRuntimeView* const editView) noexcept
  {
    return reinterpret_cast<CMauiEditClickDraggerRuntimeView*>(editView->mClickDraggerStorage);
  }

  /**
   * Address: 0x0078F620 (FUN_0078F620, Moho::CMauiEdit::ApplyFontAndRefreshClip)
   *
   * What it does:
   * Applies requested edit font (or default Courier New 14 fallback), adjusts
   * intrusive font ownership, and recomputes text clipping at current offset.
   */
  void ApplyEditFontAndRefreshClip(
    CMauiEditRuntimeView* const editView,
    const boost::SharedPtrRaw<CD3DFont>& requestedFont
  )
  {
    if (!editView) {
      return;
    }

    if (requestedFont.px != nullptr) {
      AssignIntrusiveFont(editView->mFont, requestedFont.px);
    } else {
      boost::SharedPtrRaw<CD3DFont> defaultFont = CD3DFont::Create(14, "Courier New");
      AssignIntrusiveFont(editView->mFont, defaultFont.px);
      defaultFont.release();
    }

    SetEditClipOffsetLeft(editView, editView->mClipOffset);
  }

  [[nodiscard]] moho::CD3DPrimBatcher::Vertex MakeBorderVertex(
    const float x,
    const float y,
    const std::uint32_t color,
    const float u,
    const float v
  ) noexcept
  {
    moho::CD3DPrimBatcher::Vertex vertex{};
    vertex.mX = x;
    vertex.mY = y;
    vertex.mZ = 0.0f;
    vertex.mColor = color;
    vertex.mU = u;
    vertex.mV = v;
    return vertex;
  }

  void ApplyCursorDefaultTexture(moho::CMauiCursor* const cursor, const char* const texturePath)
  {
    if (!cursor) {
      return;
    }
    cursor->SetDefaultTexture(texturePath);
  }

  [[nodiscard]] std::uint32_t NarrowPointerToFocusField(const void* const pointer) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pointer));
  }

  [[nodiscard]] std::uint32_t FocusControlNextFieldAddress(moho::CMauiControl* const control) noexcept
  {
    if (control == nullptr) {
      return 0u;
    }

    const std::uintptr_t nextFieldAddress = reinterpret_cast<std::uintptr_t>(control) + kCMauiControlListNodeNextOffset;
    return static_cast<std::uint32_t>(nextFieldAddress);
  }

  [[nodiscard]] moho::CMauiControl* ResolveControlFromFocusField(const std::uint32_t focusField) noexcept
  {
    if (focusField == 0u || focusField == kCMauiControlListNodeNextOffset) {
      return nullptr;
    }

    const std::uintptr_t controlAddress = static_cast<std::uintptr_t>(focusField) - kCMauiControlListNodeNextOffset;
    return reinterpret_cast<moho::CMauiControl*>(controlAddress);
  }

  /**
   * Address: 0x0079DB80 (FUN_0079DB80)
   *
   * What it does:
   * Rebinds one focus-owner intrusive link head to a new control `mNext` lane.
   */
  void SetCurrentFocusControlLink(
    moho::CMauiCurrentFocusControlRuntimeView* const focusState,
    moho::CMauiControl* const control
  ) noexcept
  {
    const std::uint32_t newFocusField = FocusControlNextFieldAddress(control);
    const std::uint32_t currentFocusField = focusState->mFocusedControlPrevNextField;
    if (newFocusField == currentFocusField) {
      return;
    }

    if (currentFocusField != 0u) {
      std::uint32_t* focusCursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(currentFocusField));
      const std::uint32_t focusStateAddress = NarrowPointerToFocusField(focusState);
      while (*focusCursor != focusStateAddress) {
        focusCursor = reinterpret_cast<std::uint32_t*>(
          static_cast<std::uintptr_t>(*focusCursor) + kCMauiControlListNodeNextOffset
        );
      }
      *focusCursor = focusState->mNextPrevNextField;
    }

    focusState->mFocusedControlPrevNextField = newFocusField;
    if (newFocusField != 0u) {
      std::uint32_t* const focusFieldCursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(newFocusField));
      focusState->mNextPrevNextField = *focusFieldCursor;
      *focusFieldCursor = NarrowPointerToFocusField(focusState);
    } else {
      focusState->mNextPrevNextField = 0u;
    }
  }

  class ScriptCallbackWeakGuard final
  {
  public:
    explicit ScriptCallbackWeakGuard(moho::CScriptObject* const scriptObject) noexcept
      : m_guard(static_cast<moho::WeakObject*>(scriptObject))
    {
    }

    [[nodiscard]] moho::CScriptObject* ResolveObjectForWarning() const noexcept
    {
      const moho::WeakObject::WeakLinkSlot* const ownerLinkSlot = m_guard.OwnerLinkSlotAddress();
      if (!ownerLinkSlot) {
        return nullptr;
      }

      return moho::WeakPtr<moho::CScriptObject>::DecodeOwnerObject(
        reinterpret_cast<void*>(const_cast<moho::WeakObject::WeakLinkSlot*>(ownerLinkSlot))
      );
    }

  private:
    moho::WeakObject::ScopedWeakLinkGuard m_guard;
  };

  /**
   * Address: 0x0060C2C0 (FUN_0060C2C0)
   *
   * What it does:
   * Calls one script callback with `(self, objectArg)` and logs script warning
   * text on callback exceptions.
   */
  [[nodiscard]] bool InvokeControlScriptObjectBool(
    moho::CMauiControl* const control,
    const char* const callbackName,
    const LuaPlus::LuaObject& objectArg
  )
  {
    moho::CScriptObject* const scriptObject = reinterpret_cast<moho::CScriptObject*>(control);
    ScriptCallbackWeakGuard weakGuard(scriptObject);

    LuaPlus::LuaObject callbackObject{};
    scriptObject->FindScript(&callbackObject, callbackName);
    if (!callbackObject) {
      return false;
    }

    try {
      LuaPlus::LuaFunction<bool> callback(callbackObject);
      return callback(CMauiControlScriptObjectRuntimeView::FromControl(control)->mLuaObj, objectArg);
    } catch (const std::exception& exception) {
      scriptObject->LogScriptWarning(
        weakGuard.ResolveObjectForWarning(),
        callbackName != nullptr ? callbackName : "<unknown>",
        exception.what() != nullptr ? exception.what() : ""
      );
    } catch (...) {
      scriptObject->LogScriptWarning(
        weakGuard.ResolveObjectForWarning(),
        callbackName != nullptr ? callbackName : "<unknown>",
        "unknown exception"
      );
    }

    return false;
  }

  /**
   * Address: 0x0078A839 (FUN_0078A839)
   *
   * What it does:
   * Logs one `OnHide` Lua callback exception into script-warning output.
   */
  void LogOnHideCallbackException(
    moho::CScriptObject* const scriptObject,
    const std::exception& exception
  ) noexcept
  {
    if (scriptObject == nullptr) {
      return;
    }

    const char* const message = exception.what() != nullptr ? exception.what() : "";
    scriptObject->LogScriptWarning(scriptObject, "OnHide", message);
  }

  /**
   * Address: 0x0078AB39 (FUN_0078AB39)
   *
   * What it does:
   * Logs one `IsScrollable` Lua callback exception into script-warning output.
   */
  void LogIsScrollableCallbackException(
    moho::CScriptObject* const scriptObject,
    const std::exception& exception
  ) noexcept
  {
    if (scriptObject == nullptr) {
      return;
    }

    const char* const message = exception.what() != nullptr ? exception.what() : "";
    scriptObject->LogScriptWarning(scriptObject, "IsScrollable", message);
  }
} // namespace

moho::EUIState moho::sUIState = moho::UIS_none;
bool moho::cam_Free = false;
bool moho::ui_DisableCursorFixing = false;
bool moho::ui_WindowedAlwaysShowsCursor = false;
moho::IWldUIProvider* moho::sWldUIProvider = nullptr;
gpg::RType* moho::CMauiControl::sType = nullptr;
gpg::RType* moho::CMauiBorder::sType = nullptr;
moho::CMauiCurrentFocusControlRuntimeView moho::Maui_CurrentFocusControl{};
bool moho::Maui_ControlHasFocus = false;

moho::CMauiControl* moho::CMauiCurrentFocusControlRuntimeView::ResolveFocusedControl() const noexcept
{
  if (
    mFocusedControlPrevNextField == 0u
    || mFocusedControlPrevNextField == kCMauiControlListNodeNextOffset
  ) {
    return nullptr;
  }

  const std::uintptr_t controlAddress =
    static_cast<std::uintptr_t>(mFocusedControlPrevNextField) - kCMauiControlListNodeNextOffset;
  return reinterpret_cast<CMauiControl*>(controlAddress);
}

/**
 * Address: 0x0079CC10 (FUN_0079CC10, Moho::MAUI_SetKeyboardFocus)
 *
 * What it does:
 * Rebinds global focus owner and notifies previous focus owner through
 * `LosingKeyboardFocus()`.
 */
void moho::MAUI_SetKeyboardFocus(CMauiControl* const control, const bool blocksKeyDown)
{
  std::uint32_t previousFocusField = Maui_CurrentFocusControl.mFocusedControlPrevNextField;
  std::uint32_t previousFocusNextField = 0u;

  if (previousFocusField != 0u) {
    std::uint32_t* const previousFocusCursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(previousFocusField));
    previousFocusNextField = *previousFocusCursor;
    *previousFocusCursor = NarrowPointerToFocusField(&previousFocusField);
  }

  SetCurrentFocusControlLink(&Maui_CurrentFocusControl, control);
  Maui_ControlHasFocus = blocksKeyDown;

  if (previousFocusField != 0u) {
    if (CMauiControl* const previousFocusOwner = ResolveControlFromFocusField(previousFocusField); previousFocusOwner != nullptr) {
      previousFocusOwner->LosingKeyboardFocus();
    }

    std::uint32_t* restoreCursor = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(previousFocusField));
    const std::uint32_t markerField = NarrowPointerToFocusField(&previousFocusField);
    while (*restoreCursor != markerField) {
      restoreCursor = reinterpret_cast<std::uint32_t*>(
        static_cast<std::uintptr_t>(*restoreCursor) + kCMauiControlListNodeNextOffset
      );
    }
    *restoreCursor = previousFocusNextField;
  }
}

/**
 * Address: 0x0079CB70 (FUN_0079CB70, Moho::MAUI_KeyIsDown)
 *
 * What it does:
 * Polls one Maui key through MSW key state only when the GAL window is
 * foreground and focus capture does not block key-down processing.
 */
bool moho::MAUI_KeyIsDown(const EMauiKeyCode keyCode)
{
  if (!gpg::gal::WindowIsForeground()) {
    return false;
  }

  if (Maui_CurrentFocusControl.ResolveFocusedControl() != nullptr && Maui_ControlHasFocus) {
    return false;
  }

  bool isSpecial = false;
  const int virtualKey = wxCharCodeWXToMSW(static_cast<int>(keyCode), &isSpecial);
  (void)isSpecial;
  return ::GetKeyState(virtualKey) < 0;
}

moho::CScrLuaMetatableFactory<moho::CUIWorldView> moho::CScrLuaMetatableFactory<moho::CUIWorldView>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider> moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CUIWorldMesh> moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CUIMapPreview> moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiControl> moho::CScrLuaMetatableFactory<moho::CMauiControl>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiBorder> moho::CScrLuaMetatableFactory<moho::CMauiBorder>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiBitmap> moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiCursor> moho::CScrLuaMetatableFactory<moho::CMauiCursor>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger> moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiEdit> moho::CScrLuaMetatableFactory<moho::CMauiEdit>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiScrollbar> moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiText> moho::CScrLuaMetatableFactory<moho::CMauiText>::sInstance{};

moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>&
moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>& moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIWorldView>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CUIWorldView>& moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CUIMapPreview>& moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiControl>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiControl>&
moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00783EA0 (FUN_00783EA0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiControl>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiControl>*
startup_CScrLuaMetatableFactory_CMauiControl_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00783070 (FUN_00783070, Moho::CScrLuaMetatableFactory<Moho::CMauiControl>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiControl`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiControl>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiBorder>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiBorder>& moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007862E0 (FUN_007862E0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiBorder>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiBorder>*
startup_CScrLuaMetatableFactory_CMauiBorder_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00786180 (FUN_00786180, Moho::CScrLuaMetatableFactory<Moho::CMauiBorder>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiBorder`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiBitmap>& moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00783E70 (FUN_00783E70)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiBitmap>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiBitmap>*
startup_CScrLuaMetatableFactory_CMauiBitmap_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00783040 (FUN_00783040, Moho::CScrLuaMetatableFactory<Moho::CMauiBitmap>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiBitmap`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiCursor>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiCursor>& moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x0078DAA0 (FUN_0078DAA0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiCursor>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiCursor>*
startup_CScrLuaMetatableFactory_CMauiCursor_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x0078D940 (FUN_0078D940, Moho::CScrLuaMetatableFactory<Moho::CMauiCursor>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiCursor`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>&
moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x0078EAF0 (FUN_0078EAF0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiLuaDragger>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>*
startup_CScrLuaMetatableFactory_CMauiLuaDragger_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x0078E660 (FUN_0078E660, Moho::CScrLuaMetatableFactory<Moho::CMauiLuaDragger>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiLuaDragger`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiEdit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiEdit>& moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00795610 (FUN_00795610)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiEdit>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiEdit>*
startup_CScrLuaMetatableFactory_CMauiEdit_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00794E90 (FUN_00794E90, Moho::CScrLuaMetatableFactory<Moho::CMauiEdit>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiEdit`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>&
moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007A2470 (FUN_007A2470, Moho::CScrLuaMetatableFactory<Moho::CMauiScrollbar>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiScrollbar`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiText>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{
}

moho::CScrLuaMetatableFactory<moho::CMauiText>& moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007A4250 (FUN_007A4250, Moho::CScrLuaMetatableFactory<Moho::CMauiText>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiText`.
 */
LuaPlus::LuaObject
moho::CScrLuaMetatableFactory<moho::CMauiText>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00798BB0 (FUN_00798BB0, register_CScrLuaMetatableFactory_CMauiHistogram_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CMauiHistogram.
 */
int moho::register_CScrLuaMetatableFactory_CMauiHistogram_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x007A2890 (FUN_007A2890, register_CScrLuaMetatableFactory_CMauiScrollbar_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CMauiScrollbar.
 */
int moho::register_CScrLuaMetatableFactory_CMauiScrollbar_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x0086AD10 (FUN_0086AD10, register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CLuaWldUIProvider.
 */
int moho::register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x0086D9D0 (FUN_0086D9D0, register_CScrLuaMetatableFactory_CUIWorldMesh_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CUIWorldMesh.
 */
int moho::register_CScrLuaMetatableFactory_CUIWorldMesh_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x00873B50 (FUN_00873B50, register_CScrLuaMetatableFactory_CUIWorldView_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CUIWorldView.
 */
int moho::register_CScrLuaMetatableFactory_CUIWorldView_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

namespace
{
  struct UiRuntimeTypesFactoryIndexBootstrap
  {
    UiRuntimeTypesFactoryIndexBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CMauiHistogram_Index();
      (void)moho::register_CScrLuaMetatableFactory_CMauiScrollbar_Index();
      (void)moho::register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUIWorldMesh_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUIWorldView_Index();
    }
  };

  UiRuntimeTypesFactoryIndexBootstrap gUiRuntimeTypesFactoryIndexBootstrap;
} // namespace
/**
 * Address: 0x00783B00 (FUN_00783B00, sub_783B00)
 * Address: 0x007861B0 (FUN_007861B0, sub_7861B0)
 * Address: 0x00794EC0 (FUN_00794EC0, sub_794EC0)
 * Address: 0x00798950 (FUN_00798950, sub_798950)
 * Address: 0x0079C940 (FUN_0079C940, sub_79C940)
 * Address: 0x0079EAC0 (FUN_0079EAC0, sub_79EAC0)
 * Address: 0x007A0140 (FUN_007A0140, sub_7A0140)
 * Address: 0x007A2700 (FUN_007A2700, sub_7A2700)
 * Address: 0x008513D0 (FUN_008513D0, sub_8513D0)
 *
 * What it does:
 * Adds `CMauiControl` as one base descriptor on the target UI runtime type.
 */
[[maybe_unused]] static void AddCMauiControlBaseToUiRuntimeType(gpg::RType* const typeInfo)
{
  gpg::RType* baseType = moho::CMauiControl::sType;
  if (baseType == nullptr) {
    baseType = gpg::LookupRType(typeid(moho::CMauiControl));
    moho::CMauiControl::sType = baseType;
  }

  if (typeInfo == nullptr || baseType == nullptr) {
    return;
  }

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x0078A680 (FUN_0078A680, sub_78A680)
 * Address: 0x0078D970 (FUN_0078D970, sub_78D970)
 * Address: 0x0078E690 (FUN_0078E690, sub_78E690)
 *
 * What it does:
 * Adds `CScriptObject` as one base descriptor on the target UI runtime type.
 */
[[maybe_unused]] static void AddCScriptObjectBaseToUiRuntimeType(gpg::RType* const typeInfo)
{
  gpg::RType* baseType = moho::CScriptObject::sType;
  if (baseType == nullptr) {
    baseType = gpg::LookupRType(typeid(moho::CScriptObject));
    moho::CScriptObject::sType = baseType;
  }

  if (typeInfo == nullptr || baseType == nullptr) {
    return;
  }

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x007A4280 (FUN_007A4280, sub_7A4280)
 *
 * What it does:
 * Adds `CMauiControl` as one base descriptor on a `CMauiText` type-info owner.
 */
[[maybe_unused]] static void AddCMauiControlBaseToCMauiTextType(gpg::RType* const typeInfo)
{
  AddCMauiControlBaseToUiRuntimeType(typeInfo);
}

/**
 * Address: 0x007A43B0 (FUN_007A43B0, sub_7A43B0)
 *
 * What it does:
 * Rebinds one startup factory-index lane for the `CMauiText` metatable factory
 * singleton and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiText>* RegisterCMauiTextMetatableFactoryInstance()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00796F00 (FUN_00796F00)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiFrame>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiFrame>*
startup_CScrLuaMetatableFactory_CMauiFrame_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x007975A0 (FUN_007975A0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiGroup>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiGroup>*
startup_CScrLuaMetatableFactory_CMauiGroup_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiGroup>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

[[nodiscard]] static gpg::RType* CachedCMauiTextRuntimeType() noexcept
{
  static gpg::RType* cached = nullptr;
  if (cached == nullptr) {
    cached = gpg::LookupRType(typeid(moho::CMauiText));
  }
  return cached;
}

/**
 * Address: 0x007A43E0 (FUN_007A43E0, sub_7A43E0)
 *
 * What it does:
 * Upcasts one reflected object reference into the `CMauiText` lane and
 * returns the resolved object pointer.
 */
[[maybe_unused]] static void* UpcastRefToCMauiTextObject(const gpg::RRef& sourceRef)
{
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiTextRuntimeType());
  return upcast.mObj;
}

/**
 * Address: 0x007836E0 (FUN_007836E0, ??0CScriptLazyVar_float@Moho@@QAE@@Z)
 *
 * What it does:
 * Imports `/lua/lazyvar.lua` and initializes this lazy-var from
 * `lazyvar.Create(0.0)`.
 */
moho::CScriptLazyVar_float::CScriptLazyVar_float(LuaPlus::LuaState* const state)
{
  LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*this);
  new (&lazyVarObject) LuaPlus::LuaObject();

  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  LuaPlus::LuaObject lazyVarModule = SCR_Import(state, "/lua/lazyvar.lua");
  LuaPlus::LuaObject createFn = lazyVarModule.GetByName("Create");

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  createFn.PushStack(state);
  lua_pushnumber(rawState, 0.0f);

  if (lua_pcall(rawState, 1, 1, 0) != 0) {
    LuaPlus::LuaStackObject errorStack(state, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in lazyvar.Create(): %s", errorText);
  } else {
    LuaPlus::LuaObject created(state, -1);
    lazyVarObject = created;
  }

  lua_settop(rawState, savedTop);
}

/**
 * Address: 0x00783840 (FUN_00783840, Moho::CScriptLazyVar_float::GetValue)
 *
 * What it does:
 * Resolves lazy-var value lane `1`, evaluating the lazy callback when the
 * lane is nil and coercing error/non-number paths back to `0.0`.
 */
float moho::CScriptLazyVar_float::GetValue(const CScriptLazyVar_float* const value) noexcept
{
  if (value == nullptr) {
    return 0.0f;
  }

  const LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*value);
  if (lazyVarObject.m_state == nullptr) {
    return 0.0f;
  }

  LuaPlus::LuaObject resolvedValue = lazyVarObject.GetByIndex(1);
  if (resolvedValue.IsNil()) {
    LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
    if (activeState == nullptr || activeState->m_state == nullptr) {
      return 0.0f;
    }

    lua_State* const rawState = activeState->m_state;
    const int savedTop = lua_gettop(rawState);

    lazyVarObject.PushStack(activeState);
    if (lua_pcall(rawState, 0, 1, 0) != 0) {
      LuaPlus::LuaStackObject errorStack(activeState, -1);
      const char* errorText = errorStack.GetString();
      if (errorText == nullptr) {
        errorStack.TypeError("string");
        errorText = "<non-string>";
      }
      gpg::Warnf("Evaluating LazyVar failed: %s", errorText);
      const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
      lua_settop(rawState, savedTop);
      return 0.0f;
    }

    resolvedValue = LuaPlus::LuaObject(LuaPlus::LuaStackObject(activeState, -1));
    lua_settop(rawState, savedTop);
  }

  if (resolvedValue.IsNumber()) {
    return static_cast<float>(resolvedValue.GetNumber());
  }

  const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
  gpg::Warnf("LazyVar has non-number value.");
  return 0.0f;
}

/**
 * Address: 0x007839E0 (FUN_007839E0, Moho::CScriptLazyVar_float::SetValue)
 *
 * What it does:
 * Calls the Lua-side `SetValue` method on this lazy-var with `next`.
 */
void moho::CScriptLazyVar_float::SetValue(CScriptLazyVar_float* const value, const float next) noexcept
{
  if (value == nullptr) {
    return;
  }

  LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*value);
  LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
  if (activeState == nullptr || activeState->m_state == nullptr) {
    return;
  }

  lua_State* const rawState = activeState->m_state;
  const int savedTop = lua_gettop(rawState);

  lazyVarObject.PushStack(activeState);
  lua_pushstring(rawState, "SetValue");
  lua_gettable(rawState, -2);
  lazyVarObject.PushStack(activeState);
  lua_pushnumber(rawState, next);

  if (lua_pcall(rawState, 2, 0, 0) != 0) {
    LuaPlus::LuaStackObject errorStack(activeState, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Setting LazyVar value failed: %s", errorText);
  }

  lua_settop(rawState, savedTop);
}

/**
 * Address: 0x0077F670 (FUN_0077F670)
 *
 * What it does:
 * Writes `0.0` into Lua table lane `1` for one lazy-var object lane.
 */
[[maybe_unused]] void ResetLazyVarObjectLaneToZero(LuaPlus::LuaObject* const lazyVarObject)
{
  if (lazyVarObject != nullptr) {
    lazyVarObject->SetNumber(1, 0.0);
  }
}

/**
 * Address: 0x00782E60 (FUN_00782E60)
 *
 * What it does:
 * Adapter lane that resolves and returns one `CScriptLazyVar_float` value.
 */
[[maybe_unused]] float EvaluateLazyVarFloatValueAdapter(const moho::CScriptLazyVar_float* const value) noexcept
{
  return moho::CScriptLazyVar_float::GetValue(value);
}

/**
 * Address: 0x00782E70 (FUN_00782E70)
 *
 * What it does:
 * Adapter lane that sets one `CScriptLazyVar_float` value and returns the
 * same lazy-var lane pointer.
 */
[[maybe_unused]] moho::CScriptLazyVar_float* SetLazyVarFloatValueAdapter(
  moho::CScriptLazyVar_float* const value,
  const float next
) noexcept
{
  moho::CScriptLazyVar_float::SetValue(value, next);
  return value;
}

void moho::CMauiCursorLink::AssignCursor(CMauiCursor* const cursor) noexcept
{
  CMauiCursorLink** const nextOwnerHead =
    cursor != nullptr ? &CMauiCursorRuntimeView::FromCursor(cursor)->ownerChainHead : nullptr;
  if (nextOwnerHead == ownerHeadLink) {
    return;
  }

  if (ownerHeadLink != nullptr) {
    CMauiCursorLink** link = ownerHeadLink;
    while (*link != nullptr && *link != this) {
      link = &(*link)->nextInOwnerChain;
    }

    if (*link == this) {
      *link = nextInOwnerChain;
    }
  }

  ownerHeadLink = nextOwnerHead;
  if (ownerHeadLink != nullptr) {
    nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = this;
  } else {
    nextInOwnerChain = nullptr;
  }
}

void moho::CMauiCursorLink::Unlink() noexcept
{
  AssignCursor(nullptr);
}

moho::CMauiCursor* moho::CMauiCursorLink::GetCursor() const noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == reinterpret_cast<CMauiCursorLink**>(0x4)) {
    return nullptr;
  }

  const std::uintptr_t rawAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  const std::uintptr_t cursorAddress = rawAddress - offsetof(CMauiCursorRuntimeView, ownerChainHead);
  return reinterpret_cast<CMauiCursor*>(cursorAddress);
}

/**
 * Address: 0x0078CB50 (FUN_0078CB50, Moho::CMauiCursor::CMauiCursor)
 *
 * What it does:
 * Initializes cursor texture/hotspot runtime lanes and binds one Lua object
 * back-reference.
 */
moho::CMauiCursor::CMauiCursor(LuaPlus::LuaObject* const luaObject)
{
  struct SharedPtrRuntimeStorage final
  {
    void* object = nullptr;
    void* count = nullptr;
  };
  static_assert(sizeof(SharedPtrRuntimeStorage) == sizeof(boost::shared_ptr<RD3DTextureResource>));

  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  static_cast<WeakObject*>(scriptObject)->weakLinkHead_ = 0;
  new (&scriptObject->cObject) LuaPlus::LuaObject();
  new (&scriptObject->mLuaObj) LuaPlus::LuaObject();

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(this);
  *reinterpret_cast<SharedPtrRuntimeStorage*>(&cursorView->mTexture) = SharedPtrRuntimeStorage{};
  *reinterpret_cast<SharedPtrRuntimeStorage*>(&cursorView->mDefaultTexture) = SharedPtrRuntimeStorage{};
  cursorView->mHotspotX = 0;
  cursorView->mHotspotY = 0;
  cursorView->mDefaultHotspotX = 0;
  cursorView->mDefaultHotspotY = 0;
  cursorView->mIsDefaultTexture = true;
  cursorView->mIsShowing = true;

  if (luaObject != nullptr) {
    scriptObject->SetLuaObject(*luaObject);
  }
}

/**
 * Address: 0x0078CBF0 (FUN_0078CBF0, Moho::CMauiCursor::~CMauiCursor body)
 *
 * What it does:
 * Releases active/default cursor texture weak-owner lanes and destroys the
 * embedded script-object runtime base.
 */
moho::CMauiCursor::~CMauiCursor()
{
  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(this);
  cursorView->mTexture.reset();
  cursorView->mDefaultTexture.reset();
  reinterpret_cast<CScriptObject*>(this)->~CScriptObject();
}

/**
 * Address: 0x0078CCA0 (FUN_0078CCA0, Moho::CMauiCursor::SetTexture)
 *
 * What it does:
 * Loads one cursor texture resource and applies it to the active cursor
 * texture lane.
 */
void moho::CMauiCursor::SetTexture(const char* const texturePath)
{
  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  D3D_GetDevice()->GetResources()->GetTexture(loadedTexture, texturePath, 0, false);

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(this);
  if (loadedTexture.get() != cursorView->mTexture.get()) {
    cursorView->mTexture = loadedTexture;
    cursorView->mIsDefaultTexture = true;
  }
}

/**
 * Address: 0x0078CD80 (FUN_0078CD80, Moho::CMauiCursor::SetDefaultTexture)
 *
 * What it does:
 * Loads one default cursor texture and updates default/active texture lanes.
 * If active texture still equals the old default, it is replaced as well.
 */
void moho::CMauiCursor::SetDefaultTexture(const char* const texturePath)
{
  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  D3D_GetDevice()->GetResources()->GetTexture(loadedTexture, texturePath, 0, false);

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(this);
  if (loadedTexture.get() == cursorView->mDefaultTexture.get()) {
    return;
  }

  if (cursorView->mTexture.get() == cursorView->mDefaultTexture.get()) {
    cursorView->mTexture = loadedTexture;
    cursorView->mIsDefaultTexture = true;
  }

  cursorView->mDefaultTexture = loadedTexture;
}

/**
 * Address: 0x0078CEA0 (FUN_0078CEA0, Moho::CMauiCursor::ResetToDefault)
 *
 * What it does:
 * Restores active cursor texture/hotspot lanes from default cursor state.
 */
void moho::CMauiCursor::ResetToDefault()
{
  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(this);
  if (cursorView->mTexture.get() != cursorView->mDefaultTexture.get()) {
    cursorView->mTexture = cursorView->mDefaultTexture;
    cursorView->mHotspotX = cursorView->mDefaultHotspotX;
    cursorView->mHotspotY = cursorView->mDefaultHotspotY;
    cursorView->mIsDefaultTexture = true;
  }
}

/**
 * Address: 0x0078D390 (FUN_0078D390, cfunc_CMauiCursorSetDefaultTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorSetDefaultTextureL`.
 */
int moho::cfunc_CMauiCursorSetDefaultTexture(lua_State* const luaContext)
{
  return cfunc_CMauiCursorSetDefaultTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D3B0 (FUN_0078D3B0, func_CMauiCursorSetDefaultTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:SetDefaultTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorSetDefaultTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetDefaultTexture",
    &moho::cfunc_CMauiCursorSetDefaultTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorSetDefaultTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D410 (FUN_0078D410, cfunc_CMauiCursorSetDefaultTextureL)
 *
 * What it does:
 * Reads one cursor object plus texture/hotspot Lua args and updates cursor
 * default texture/hotspot lanes.
 */
int moho::cfunc_CMauiCursorSetDefaultTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorSetDefaultTextureHelpText, 4, argumentCount);
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }
  ApplyCursorDefaultTexture(cursor, texturePath);

  LuaPlus::LuaStackObject hotspotYArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotYArg, "integer");
  }
  const int hotspotY = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject hotspotXArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotXArg, "integer");
  }
  const int hotspotX = static_cast<int>(lua_tonumber(state->m_state, 3));

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorDefaultHotspotXY(cursorView, hotspotX, hotspotY);
  return 0;
}

/**
 * Address: 0x0078D130 (FUN_0078D130, cfunc_CMauiCursorSetNewTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorSetNewTextureL`.
 */
int moho::cfunc_CMauiCursorSetNewTexture(lua_State* const luaContext)
{
  return cfunc_CMauiCursorSetNewTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D150 (FUN_0078D150, func_CMauiCursorSetNewTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:SetNewTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorSetNewTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewTexture",
    &moho::cfunc_CMauiCursorSetNewTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorSetNewTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D1B0 (FUN_0078D1B0, cfunc_CMauiCursorSetNewTextureL)
 *
 * What it does:
 * Reads one cursor plus texture/hotspot Lua args and updates active cursor
 * texture/hotspot lanes.
 */
int moho::cfunc_CMauiCursorSetNewTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorSetNewTextureHelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  cursor->SetTexture(texturePath);

  LuaPlus::LuaStackObject hotspotYArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotYArg, "integer");
  }
  const int hotspotY = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject hotspotXArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotXArg, "integer");
  }
  const int hotspotX = static_cast<int>(lua_tonumber(state->m_state, 3));

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorHotspotXY(cursorView, hotspotX, hotspotY);
  return 0;
}

/**
 * Address: 0x0078D5A0 (FUN_0078D5A0, cfunc_CMauiCursorResetToDefault)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiCursorResetToDefaultL`.
 */
int moho::cfunc_CMauiCursorResetToDefault(lua_State* const luaContext)
{
  return cfunc_CMauiCursorResetToDefaultL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D5C0 (FUN_0078D5C0, func_CMauiCursorResetToDefault_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:ResetToDefault()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorResetToDefault_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ResetToDefault",
    &moho::cfunc_CMauiCursorResetToDefault,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorResetToDefaultHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D620 (FUN_0078D620, cfunc_CMauiCursorResetToDefaultL)
 *
 * What it does:
 * Resolves one cursor object and restores active texture/hotspot lanes from
 * default cursor state.
 */
int moho::cfunc_CMauiCursorResetToDefaultL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorResetToDefaultHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  cursor->ResetToDefault();
  return 0;
}

/**
 * Address: 0x0078D6C0 (FUN_0078D6C0, cfunc_CMauiCursorHide)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorHideL`.
 */
int moho::cfunc_CMauiCursorHide(lua_State* const luaContext)
{
  return cfunc_CMauiCursorHideL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D6E0 (FUN_0078D6E0, func_CMauiCursorHide_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:Hide()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorHide_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Hide",
    &moho::cfunc_CMauiCursorHide,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D740 (FUN_0078D740, cfunc_CMauiCursorHideL)
 *
 * What it does:
 * Resolves one cursor object and marks it hidden in runtime cursor state
 * lanes.
 */
int moho::cfunc_CMauiCursorHideL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorShowHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorShowingAndMarkDirty(cursorView, false);
  return 0;
}

/**
 * Address: 0x0078D7F0 (FUN_0078D7F0, cfunc_CMauiCursorShow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorShowL`.
 */
int moho::cfunc_CMauiCursorShow(lua_State* const luaContext)
{
  return cfunc_CMauiCursorShowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078D810 (FUN_0078D810, func_CMauiCursorShow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiCursor:Show()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiCursorShow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Show",
    &moho::cfunc_CMauiCursorShow,
    &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
    "CMauiCursor",
    kCursorShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078D870 (FUN_0078D870, cfunc_CMauiCursorShowL)
 *
 * What it does:
 * Resolves one cursor object and marks it visible in runtime cursor state
 * lanes.
 */
int moho::cfunc_CMauiCursorShowL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorShowHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);
  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorShowingAndMarkDirty(cursorView, true);
  return 0;
}

/**
 * Address: 0x00780ED0 (FUN_00780ED0, cfunc_CMauiBitmapSetNewTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetNewTextureL`.
 */
int moho::cfunc_CMauiBitmapSetNewTexture(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetNewTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00780EF0 (FUN_00780EF0, func_CMauiBitmapSetNewTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetNewTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetNewTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewTexture",
    &moho::cfunc_CMauiBitmapSetNewTexture,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetNewTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780F50 (FUN_00780F50, cfunc_CMauiBitmapSetNewTextureL)
 *
 * What it does:
 * Rebuilds one bitmap texture-batch sequence from one filename or filename
 * table and reapplies default forward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetNewTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kCMauiBitmapSetNewTextureHelpText, 2, 3, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(bitmap);
  bitmapView->mTextureBatches.clear();
  bitmap->SetFrame(0);

  int border = 1;
  if (argumentCount >= 3) {
    LuaPlus::LuaStackObject borderArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&borderArg, "integer");
    }
    border = static_cast<int>(lua_tonumber(state->m_state, 3));
  }
  const auto borderLane = static_cast<std::uint32_t>(border);

  if (lua_isstring(state->m_state, 2) != 0) {
    LuaPlus::LuaStackObject textureArg(state, 2);
    const char* texturePath = lua_tostring(state->m_state, 2);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(texturePath, borderLane);
    if (texture) {
      bitmap->SetTexture(texture);
    } else {
      bitmap->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFAAAA00u));
    }

    bitmap->SetDebugName(gpg::STR_Printf("Bitmap file = %s", texturePath));
  } else if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject frameTableObject(LuaPlus::LuaStackObject(state, 2));
    const int frameCount = frameTableObject.GetCount();
    for (int frameIndex = 1; frameIndex <= frameCount; ++frameIndex) {
      LuaPlus::LuaObject frameObject = frameTableObject[frameIndex];
      const char* texturePath = frameObject.GetString();
      const char* const pathText = texturePath != nullptr ? texturePath : "";

      boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(pathText, borderLane);
      if (texture) {
        bitmap->SetTexture(texture);
      } else {
        bitmap->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFAAAA00u));
      }

      const msvc8::string frameText = gpg::STR_Printf("Frame %d = %s\n", frameIndex, pathText);
      msvc8::string debugName = bitmap->GetDebugName();
      debugName += frameText;
      bitmap->SetDebugName(debugName);
    }
  }

  bitmap->SetForwardPattern();
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781440 (FUN_00781440, cfunc_CMauiBitmapInternalSetSolidColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapInternalSetSolidColorL`.
 */
int moho::cfunc_CMauiBitmapInternalSetSolidColor(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapInternalSetSolidColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781460 (FUN_00781460, func_CMauiBitmapInternalSetSolidColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:InternalSetSolidColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapInternalSetSolidColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalSetSolidColor",
    &moho::cfunc_CMauiBitmapInternalSetSolidColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapInternalSetSolidColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007814C0 (FUN_007814C0, cfunc_CMauiBitmapInternalSetSolidColorL)
 *
 * What it does:
 * Resolves one bitmap plus one color argument, rebuilds one solid-color
 * texture frame, and refreshes debug name text.
 */
int moho::cfunc_CMauiBitmapInternalSetSolidColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapInternalSetSolidColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(bitmap);
  bitmapView->mTextureBatches.clear();
  bitmap->SetFrame(0);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t rgba = SCR_DecodeColor(state, colorObject);
  const boost::shared_ptr<CD3DBatchTexture> solidTexture = CD3DBatchTexture::FromSolidColor(rgba);
  bitmap->SetTexture(solidTexture);
  bitmap->SetForwardPattern();

  LuaPlus::LuaStackObject colorTextArg(state, 2);
  const char* colorText = lua_tostring(state->m_state, 2);
  if (colorText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&colorTextArg, "string");
    colorText = "";
  }

  msvc8::string debugName("Bitmap is solid color ");
  debugName += colorText;
  bitmap->SetDebugName(debugName);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781690 (FUN_00781690, cfunc_CMauiBitmapSetUV)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetUVL`.
 */
int moho::cfunc_CMauiBitmapSetUV(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetUVL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007816B0 (FUN_007816B0, func_CMauiBitmapSetUV_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetUV(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetUV_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetUV",
    &moho::cfunc_CMauiBitmapSetUV,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetUVHelpText
  );
  return &binder;
}

/**
 * Address: 0x0077FE80 (FUN_0077FE80)
 *
 * What it does:
 * Clamps one bitmap UV quad `(u0,v0,u1,v1)` to `[0,1]` and writes the
 * runtime UV lanes.
 */
[[maybe_unused]] static moho::CMauiBitmapRuntimeView* func_SetBitmapUvClamped(
  moho::CMauiBitmapRuntimeView* const bitmapView,
  const float u0,
  const float v0,
  const float u1,
  const float v1
) noexcept
{
  const auto clamp01 = [](const float value) noexcept -> float {
    if (value >= 1.0f) {
      return 1.0f;
    }
    if (value < 0.0f) {
      return 0.0f;
    }
    return value;
  };

  bitmapView->mU0 = clamp01(u0);
  bitmapView->mV0 = clamp01(v0);
  bitmapView->mU1 = clamp01(u1);
  bitmapView->mV1 = clamp01(v1);
  return bitmapView;
}

/**
 * Address: 0x00781710 (FUN_00781710, cfunc_CMauiBitmapSetUVL)
 *
 * What it does:
 * Reads one bitmap plus `(u0,v0,u1,v1)` lanes, clamps each to `[0,1]`, and
 * updates UV runtime lanes.
 */
int moho::cfunc_CMauiBitmapSetUVL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetUVHelpText, 5, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject v1Arg(state, 5);
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&v1Arg, "number");
  }
  float v1 = static_cast<float>(lua_tonumber(state->m_state, 5));

  LuaPlus::LuaStackObject u1Arg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&u1Arg, "number");
  }
  float u1 = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject v0Arg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&v0Arg, "number");
  }
  float v0 = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject u0Arg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&u0Arg, "number");
  }
  float u0 = static_cast<float>(lua_tonumber(state->m_state, 2));

  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(bitmap);
  (void)func_SetBitmapUvClamped(bitmapView, u0, v0, u1, v1);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781950 (FUN_00781950, cfunc_CMauiBitmapUseAlphaHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapUseAlphaHitTestL`.
 */
int moho::cfunc_CMauiBitmapUseAlphaHitTest(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapUseAlphaHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781970 (FUN_00781970, func_CMauiBitmapUseAlphaHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:UseAlphaHitTest(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapUseAlphaHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UseAlphaHitTest",
    &moho::cfunc_CMauiBitmapUseAlphaHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapUseAlphaHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x007819D0 (FUN_007819D0, cfunc_CMauiBitmapUseAlphaHitTestL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates alpha-hit-test
 * state.
 */
int moho::cfunc_CMauiBitmapUseAlphaHitTestL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapUseAlphaHitTestHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject enabledArg(state, 2);
  (void)SetBitmapAlphaHitTestEnabled(CMauiBitmapRuntimeView::FromBitmap(bitmap), enabledArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781AA0 (FUN_00781AA0, cfunc_CMauiBitmapSetTiled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetTiledL`.
 */
int moho::cfunc_CMauiBitmapSetTiled(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetTiledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781AC0 (FUN_00781AC0, func_CMauiBitmapSetTiled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetTiled(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetTiled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetTiled",
    &moho::cfunc_CMauiBitmapSetTiled,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetTiledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781B20 (FUN_00781B20, cfunc_CMauiBitmapSetTiledL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates tiled-render
 * state.
 */
int moho::cfunc_CMauiBitmapSetTiledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetTiledHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject tiledArg(state, 2);
  (void)SetBitmapTiledEnabled(CMauiBitmapRuntimeView::FromBitmap(bitmap), tiledArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781BF0 (FUN_00781BF0, cfunc_CMauiBitmapLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapLoopL`.
 */
int moho::cfunc_CMauiBitmapLoop(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapLoopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781C10 (FUN_00781C10, func_CMauiBitmapLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Loop(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Loop",
    &moho::cfunc_CMauiBitmapLoop,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781C70 (FUN_00781C70, cfunc_CMauiBitmapLoopL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus one boolean lane and updates looping state.
 */
int moho::cfunc_CMauiBitmapLoopL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapLoopHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject loopArg(state, 2);
  (void)SetBitmapLoopEnabled(CMauiBitmapRuntimeView::FromBitmap(bitmap), loopArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781D40 (FUN_00781D40, cfunc_CMauiBitmapPlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapPlayL`.
 */
int moho::cfunc_CMauiBitmapPlay(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapPlayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781D60 (FUN_00781D60, func_CMauiBitmapPlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Play()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapPlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Play",
    &moho::cfunc_CMauiBitmapPlay,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapPlayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781DC0 (FUN_00781DC0, cfunc_CMauiBitmapPlayL)
 *
 * What it does:
 * Starts animated playback when this bitmap has more than one texture batch.
 */
int moho::cfunc_CMauiBitmapPlayL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapPlayHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  (void)EnableBitmapAnimationIfMultipleTextures(CMauiBitmapRuntimeView::FromBitmap(bitmap));

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00781EA0 (FUN_00781EA0, cfunc_CMauiBitmapStop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapStopL`.
 */
int moho::cfunc_CMauiBitmapStop(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapStopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00781EC0 (FUN_00781EC0, func_CMauiBitmapStop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:Stop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapStop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Stop",
    &moho::cfunc_CMauiBitmapStop,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapStopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00781F20 (FUN_00781F20, cfunc_CMauiBitmapStopL)
 *
 * What it does:
 * Stops animated playback and dispatches `OnAnimationStopped` when this
 * bitmap has active multi-frame texture state.
 */
int moho::cfunc_CMauiBitmapStopL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapStopHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  bitmap->StopAnimationPlayback();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782000 (FUN_00782000, cfunc_CMauiBitmapSetFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFrameL`.
 */
int moho::cfunc_CMauiBitmapSetFrame(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782020 (FUN_00782020, func_CMauiBitmapSetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFrame(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFrame",
    &moho::cfunc_CMauiBitmapSetFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782080 (FUN_00782080, cfunc_CMauiBitmapSetFrameL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus frame index and applies clamped frame
 * selection.
 */
int moho::cfunc_CMauiBitmapSetFrameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetFrameHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject frameArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&frameArg, "integer");
  }

  const int frameIndex = static_cast<int>(lua_tonumber(state->m_state, 2));
  bitmap->SetFrame(frameIndex);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782180 (FUN_00782180, cfunc_CMauiBitmapGetFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapGetFrameL`.
 */
int moho::cfunc_CMauiBitmapGetFrame(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapGetFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007821A0 (FUN_007821A0, func_CMauiBitmapGetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:GetFrame()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapGetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFrame",
    &moho::cfunc_CMauiBitmapGetFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapGetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782200 (FUN_00782200, cfunc_CMauiBitmapGetFrameL)
 *
 * What it does:
 * Reads one `CMauiBitmap` and pushes current frame index lane.
 */
int moho::cfunc_CMauiBitmapGetFrameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapGetFrameHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  const int frameIndex = ReadBitmapCurrentFrame(CMauiBitmapRuntimeView::FromBitmap(bitmap));

  lua_pushnumber(state->m_state, static_cast<float>(frameIndex));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007822C0 (FUN_007822C0, cfunc_CMauiBitMapGetNumFrames)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitMapGetNumFramesL`.
 */
int moho::cfunc_CMauiBitMapGetNumFrames(lua_State* const luaContext)
{
  return cfunc_CMauiBitMapGetNumFramesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007822E0 (FUN_007822E0, func_CMauiBitMapGetNumFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:GetNumFrames()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitMapGetNumFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetNumFrames",
    &moho::cfunc_CMauiBitMapGetNumFrames,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitMapGetNumFramesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782340 (FUN_00782340, cfunc_CMauiBitMapGetNumFramesL)
 *
 * What it does:
 * Resolves one bitmap object and pushes its frame-count lane.
 */
int moho::cfunc_CMauiBitMapGetNumFramesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitMapGetNumFramesHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  const int frameCount = CountBitmapFramePatternEntries(CMauiBitmapRuntimeView::FromBitmap(bitmap));
  lua_pushnumber(state->m_state, static_cast<float>(frameCount));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00782420 (FUN_00782420, cfunc_CMauiBitmapSetFrameRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFrameRateL`.
 */
int moho::cfunc_CMauiBitmapSetFrameRate(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetFrameRateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782440 (FUN_00782440, func_CMauiBitmapSetFrameRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFrameRate(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFrameRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFrameRate",
    &moho::cfunc_CMauiBitmapSetFrameRate,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFrameRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780250 (FUN_00780250)
 *
 * What it does:
 * Updates one bitmap frame-duration lane from `frameRate` as `1.0f / fps`.
 */
[[maybe_unused]] static moho::CMauiBitmapRuntimeView* func_SetBitmapFrameRate(
  moho::CMauiBitmapRuntimeView* const bitmapView,
  const float frameRate
) noexcept
{
  bitmapView->mFrameDurationSeconds = 1.0f / frameRate;
  return bitmapView;
}

/**
 * Address: 0x007824A0 (FUN_007824A0, cfunc_CMauiBitmapSetFrameRateL)
 *
 * What it does:
 * Reads one `CMauiBitmap` plus numeric frame-rate and updates its
 * frame-duration lane (`1.0 / fps`).
 */
int moho::cfunc_CMauiBitmapSetFrameRateL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetFrameRateHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  LuaPlus::LuaStackObject frameRateArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&frameRateArg, "number");
  }

  const float frameRate = static_cast<float>(lua_tonumber(state->m_state, 2));
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(bitmap);
  (void)func_SetBitmapFrameRate(bitmapView, frameRate);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007825A0 (FUN_007825A0, cfunc_CMauiBitmapSetForwardPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetForwardPatternL`.
 */
int moho::cfunc_CMauiBitmapSetForwardPattern(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetForwardPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007825C0 (FUN_007825C0, func_CMauiBitmapSetForwardPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetForwardPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetForwardPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetForwardPattern",
    &moho::cfunc_CMauiBitmapSetForwardPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetForwardPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782620 (FUN_00782620, cfunc_CMauiBitmapSetForwardPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its forward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetForwardPatternL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetForwardPatternHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetForwardPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007826E0 (FUN_007826E0, cfunc_CMauiBitmapSetBackwardPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetBackwardPatternL`.
 */
int moho::cfunc_CMauiBitmapSetBackwardPattern(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetBackwardPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782700 (FUN_00782700, func_CMauiBitmapSetBackwardPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetBackwardPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetBackwardPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetBackwardPattern",
    &moho::cfunc_CMauiBitmapSetBackwardPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetBackwardPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782760 (FUN_00782760, cfunc_CMauiBitmapSetBackwardPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its backward frame pattern.
 */
int moho::cfunc_CMauiBitmapSetBackwardPatternL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetBackwardPatternHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetBackwardPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782820 (FUN_00782820, cfunc_CMauiBitmapSetPingPongPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetPingPongPatternL`.
 */
int moho::cfunc_CMauiBitmapSetPingPongPattern(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetPingPongPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782840 (FUN_00782840, func_CMauiBitmapSetPingPongPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetPingPongPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetPingPongPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetPingPongPattern",
    &moho::cfunc_CMauiBitmapSetPingPongPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetPingPongPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x007828A0 (FUN_007828A0, cfunc_CMauiBitmapSetPingPongPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its ping-pong frame pattern.
 */
int moho::cfunc_CMauiBitmapSetPingPongPatternL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetPingPongPatternHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetPingPongPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782960 (FUN_00782960, cfunc_CMauiBitmapSetLoopPingPongPattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetLoopPingPongPatternL`.
 */
int moho::cfunc_CMauiBitmapSetLoopPingPongPattern(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetLoopPingPongPatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782980 (FUN_00782980, func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetLoopPingPongPattern()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetLoopPingPongPattern",
    &moho::cfunc_CMauiBitmapSetLoopPingPongPattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetLoopPingPongPatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x007829E0 (FUN_007829E0, cfunc_CMauiBitmapSetLoopPingPongPatternL)
 *
 * What it does:
 * Resolves one bitmap and rebuilds its loop ping-pong frame pattern.
 */
int moho::cfunc_CMauiBitmapSetLoopPingPongPatternL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetLoopPingPongPatternHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  bitmap->SetLoopPingPongPattern();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782AA0 (FUN_00782AA0, cfunc_CMauiBitmapSetFramePattern)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapSetFramePatternL`.
 */
int moho::cfunc_CMauiBitmapSetFramePattern(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapSetFramePatternL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782AC0 (FUN_00782AC0, func_CMauiBitmapSetFramePattern_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:SetFramePattern(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapSetFramePattern_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFramePattern",
    &moho::cfunc_CMauiBitmapSetFramePattern,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapSetFramePatternHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782B20 (FUN_00782B20, cfunc_CMauiBitmapSetFramePatternL)
 *
 * What it does:
 * Resolves one bitmap plus frame-index table and rebuilds frame-pattern lanes.
 */
int moho::cfunc_CMauiBitmapSetFramePatternL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapSetFramePatternHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);

  if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject frameTableObject(LuaPlus::LuaStackObject(state, 2));
    const int frameCount = frameTableObject.GetCount();

    msvc8::vector<std::int32_t> framePattern{};
    if (frameCount > 0) {
      framePattern.reserve(static_cast<std::size_t>(frameCount));
    }

    for (int frameIndex = 1; frameIndex <= frameCount; ++frameIndex) {
      LuaPlus::LuaObject frameObject = frameTableObject[frameIndex];
      framePattern.push_back(frameObject.GetInteger());
    }

    bitmap->SetFramePattern(framePattern);
  } else {
    gpg::Warnf("Bitmap:SetFramePattern requires an array of integers!");
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00782CE0 (FUN_00782CE0, cfunc_CMauiBitmapShareTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitmapShareTexturesL`.
 */
int moho::cfunc_CMauiBitmapShareTextures(lua_State* const luaContext)
{
  return cfunc_CMauiBitmapShareTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00782D00 (FUN_00782D00, func_CMauiBitmapShareTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:ShareTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitmapShareTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShareTextures",
    &moho::cfunc_CMauiBitmapShareTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitmapShareTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782D60 (FUN_00782D60, cfunc_CMauiBitmapShareTexturesL)
 *
 * What it does:
 * Reads two `CMauiBitmap` controls and shares texture-batch lanes from source
 * into destination bitmap runtime state.
 */
int moho::cfunc_CMauiBitmapShareTexturesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBitmapShareTexturesHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject destinationObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const destinationBitmap = SCR_FromLua_CMauiBitmap(destinationObject, state);

  LuaPlus::LuaObject sourceObject(LuaPlus::LuaStackObject(state, 2));
  CMauiBitmap* const sourceBitmap = SCR_FromLua_CMauiBitmap(sourceObject, state);

  destinationBitmap->ShareTextures(sourceBitmap);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00787A50 (FUN_00787A50, cfunc_CMauiControlDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlDestroyL`.
 */
int moho::cfunc_CMauiControlDestroy(lua_State* const luaContext)
{
  return cfunc_CMauiControlDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787A70 (FUN_00787A70, func_CMauiControlDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CMauiControlDestroy,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787AD0 (FUN_00787AD0, cfunc_CMauiControlDestroyL)
 *
 * What it does:
 * Resolves optional `CMauiControl`, blocks root-frame destruction, and
 * destroys non-root controls.
 */
int moho::cfunc_CMauiControlDestroyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlDestroyHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = ResolveControlFromLuaObjectOptionalOrError(controlObject, state);
  if (control != nullptr) {
    const CMauiControlExtendedRuntimeView* const controlView = CMauiControlExtendedRuntimeView::FromControl(control);
    if (control == controlView->mRootFrame) {
      LuaPlus::LuaState::Error(state, "Cannot destroy the root frame");
    }
    control->Destroy();
  }

  return 1;
}

/**
 * Address: 0x00787BA0 (FUN_00787BA0, cfunc_CMauiControlGetParent)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetParentL`.
 */
int moho::cfunc_CMauiControlGetParent(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetParentL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787BC0 (FUN_00787BC0, func_CMauiControlGetParent_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetParent()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetParent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetParent",
    &moho::cfunc_CMauiControlGetParent,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetParentHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787C20 (FUN_00787C20, cfunc_CMauiControlGetParentL)
 *
 * What it does:
 * Reads one `CMauiControl`, pushes parent control object when available, and
 * pushes `nil` otherwise.
 */
int moho::cfunc_CMauiControlGetParentL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetParentHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  CMauiControl* const parent = control->GetParent();
  if (parent != nullptr) {
    CMauiControlScriptObjectRuntimeView::FromControl(parent)->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x00787CF0 (FUN_00787CF0, cfunc_CMauiControlClearChildren)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlClearChildrenL`.
 */
int moho::cfunc_CMauiControlClearChildren(lua_State* const luaContext)
{
  return cfunc_CMauiControlClearChildrenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787D10 (FUN_00787D10, func_CMauiControlClearChildren_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:ClearChildren()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlClearChildren_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearChildren",
    &moho::cfunc_CMauiControlClearChildren,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlClearChildrenHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787D70 (FUN_00787D70, cfunc_CMauiControlClearChildrenL)
 *
 * What it does:
 * Reads one `CMauiControl` and clears all child controls.
 */
int moho::cfunc_CMauiControlClearChildrenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlClearChildrenHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->ClearChildren();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00787E30 (FUN_00787E30, cfunc_CMauiControlSetParent)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetParentL`.
 */
int moho::cfunc_CMauiControlSetParent(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetParentL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787E50 (FUN_00787E50, func_CMauiControlSetParent_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetParent(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetParent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetParent",
    &moho::cfunc_CMauiControlSetParent,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetParentHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787EB0 (FUN_00787EB0, cfunc_CMauiControlSetParentL)
 *
 * What it does:
 * Reads `CMauiControl` + parent control args, updates parent ownership, and
 * returns the control object lane.
 */
int moho::cfunc_CMauiControlSetParentL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlSetParentHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);
  control->SetParent(parentControl);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00787FB0 (FUN_00787FB0, cfunc_CMauiControlDisableHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlDisableHitTestL`.
 */
int moho::cfunc_CMauiControlDisableHitTest(lua_State* const luaContext)
{
  return cfunc_CMauiControlDisableHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787FD0 (FUN_00787FD0, func_CMauiControlDisableHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:DisableHitTest([recursive])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDisableHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DisableHitTest",
    &moho::cfunc_CMauiControlDisableHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDisableHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788030 (FUN_00788030, cfunc_CMauiControlDisableHitTestL)
 *
 * What it does:
 * Reads one `CMauiControl` plus optional recursion boolean and disables hit
 * testing.
 */
int moho::cfunc_CMauiControlDisableHitTestL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kCMauiControlDisableHitTestHelpText, 1, 2, argumentCount);
  }

  lua_settop(state->m_state, 2);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  bool applyChildren = false;
  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaStackObject recursiveArg(state, 2);
    applyChildren = LuaPlus::LuaStackObject::GetBoolean(&recursiveArg);
  }

  control->DisableHitTest(true, applyChildren);
  return 0;
}

/**
 * Address: 0x00788130 (FUN_00788130, cfunc_CMauiControlEnableHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlEnableHitTestL`.
 */
int moho::cfunc_CMauiControlEnableHitTest(lua_State* const luaContext)
{
  return cfunc_CMauiControlEnableHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788150 (FUN_00788150, func_CMauiControlEnableHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:EnableHitTest([recursive])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlEnableHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EnableHitTest",
    &moho::cfunc_CMauiControlEnableHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlEnableHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x007881B0 (FUN_007881B0, cfunc_CMauiControlEnableHitTestL)
 *
 * What it does:
 * Reads one `CMauiControl` plus optional recursion boolean and enables hit
 * testing.
 */
int moho::cfunc_CMauiControlEnableHitTestL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kCMauiControlEnableHitTestHelpText, 1, 2, argumentCount);
  }

  lua_settop(state->m_state, 2);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  bool applyChildren = false;
  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaStackObject recursiveArg(state, 2);
    applyChildren = LuaPlus::LuaStackObject::GetBoolean(&recursiveArg);
  }

  control->DisableHitTest(false, applyChildren);
  return 0;
}

/**
 * Address: 0x007882B0 (FUN_007882B0, cfunc_CMauiControlIsHitTestDisabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlIsHitTestDisabledL`.
 */
int moho::cfunc_CMauiControlIsHitTestDisabled(lua_State* const luaContext)
{
  return cfunc_CMauiControlIsHitTestDisabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007882D0 (FUN_007882D0, func_CMauiControlIsHitTestDisabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:IsHitTestDisabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlIsHitTestDisabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsHitTestDisabled",
    &moho::cfunc_CMauiControlIsHitTestDisabled,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlIsHitTestDisabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788330 (FUN_00788330, cfunc_CMauiControlIsHitTestDisabledL)
 *
 * What it does:
 * Reads one control and pushes `IsHitTestDisabled()` boolean result.
 */
int moho::cfunc_CMauiControlIsHitTestDisabledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlIsHitTestDisabledHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->IsHitTestDisabled());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007883F0 (FUN_007883F0, cfunc_CMauiControlHide)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlHideL`.
 */
int moho::cfunc_CMauiControlHide(lua_State* const luaContext)
{
  return cfunc_CMauiControlHideL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788410 (FUN_00788410, func_CMauiControlHide_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Hide()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlHide_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Hide",
    &moho::cfunc_CMauiControlHide,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlHideHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788470 (FUN_00788470, cfunc_CMauiControlHideL)
 *
 * What it does:
 * Reads one `CMauiControl` and sets hidden-state to `true`.
 */
int moho::cfunc_CMauiControlHideL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlHideHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->SetHidden(true);
  return 0;
}

/**
 * Address: 0x00788520 (FUN_00788520, cfunc_CMauiControlShow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlShowL`.
 */
int moho::cfunc_CMauiControlShow(lua_State* const luaContext)
{
  return cfunc_CMauiControlShowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788540 (FUN_00788540, func_CMauiControlShow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Show()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlShow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Show",
    &moho::cfunc_CMauiControlShow,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x007885A0 (FUN_007885A0, cfunc_CMauiControlShowL)
 *
 * What it does:
 * Reads one `CMauiControl` and sets hidden-state to `false`.
 */
int moho::cfunc_CMauiControlShowL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlShowHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->SetHidden(false);
  return 0;
}

/**
 * Address: 0x00788650 (FUN_00788650, cfunc_CMauiControlSetHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetHiddenL`.
 */
int moho::cfunc_CMauiControlSetHidden(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788670 (FUN_00788670, func_CMauiControlSetHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetHidden(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetHidden",
    &moho::cfunc_CMauiControlSetHidden,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x007886D0 (FUN_007886D0, cfunc_CMauiControlSetHiddenL)
 *
 * What it does:
 * Reads one `CMauiControl` plus boolean hidden lane and applies it.
 */
int moho::cfunc_CMauiControlSetHiddenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlSetHiddenHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject hiddenArg(state, 2);
  const bool hidden = LuaPlus::LuaStackObject::GetBoolean(&hiddenArg);
  control->SetHidden(hidden);
  return 0;
}

/**
 * Address: 0x00788790 (FUN_00788790, cfunc_CMauiControlIsHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlIsHiddenL`.
 */
int moho::cfunc_CMauiControlIsHidden(lua_State* const luaContext)
{
  return cfunc_CMauiControlIsHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007887B0 (FUN_007887B0, func_CMauiControlIsHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:IsHidden()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlIsHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsHidden",
    &moho::cfunc_CMauiControlIsHidden,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlIsHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788810 (FUN_00788810, cfunc_CMauiControlIsHiddenL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its hidden-state to Lua.
 */
int moho::cfunc_CMauiControlIsHiddenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlIsHiddenHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->IsHidden());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007888D0 (FUN_007888D0, cfunc_CMauiControlGetRenderPass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetRenderPassL`.
 */
int moho::cfunc_CMauiControlGetRenderPass(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetRenderPassL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007888F0 (FUN_007888F0, func_CMauiControlGetRenderPass_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetRenderPass()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetRenderPass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetRenderPass",
    &moho::cfunc_CMauiControlGetRenderPass,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetRenderPassHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788950 (FUN_00788950, cfunc_CMauiControlGetRenderPassL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its render-pass lane to Lua.
 */
int moho::cfunc_CMauiControlGetRenderPassL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetRenderPassHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(control->GetRenderPass()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00788A10 (FUN_00788A10, cfunc_CMauiControlSetRenderPass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetRenderPassL`.
 */
int moho::cfunc_CMauiControlSetRenderPass(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetRenderPassL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788A30 (FUN_00788A30, func_CMauiControlSetRenderPass_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetRenderPass(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetRenderPass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetRenderPass",
    &moho::cfunc_CMauiControlSetRenderPass,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetRenderPassHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788A90 (FUN_00788A90, cfunc_CMauiControlSetRenderPassL)
 *
 * What it does:
 * Reads one `CMauiControl` plus integer render-pass lane from Lua and stores
 * it into the control runtime view.
 */
int moho::cfunc_CMauiControlSetRenderPassL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlSetRenderPassHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject renderPassArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&renderPassArg, "integer");
  }

  control->SetRenderPass(static_cast<std::int32_t>(lua_tonumber(state->m_state, 2)));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788B90 (FUN_00788B90, cfunc_CMauiControlGetName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetNameL`.
 */
int moho::cfunc_CMauiControlGetName(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetNameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788BB0 (FUN_00788BB0, func_CMauiControlGetName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetName()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetName",
    &moho::cfunc_CMauiControlGetName,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788C10 (FUN_00788C10, cfunc_CMauiControlGetNameL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its debug-name lane to Lua.
 */
int moho::cfunc_CMauiControlGetNameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetNameHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  const msvc8::string debugName = control->GetDebugName();
  lua_pushstring(state->m_state, debugName.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00788D00 (FUN_00788D00, cfunc_CMauiControlSetName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetNameL`.
 */
int moho::cfunc_CMauiControlSetName(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetNameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788D20 (FUN_00788D20, func_CMauiControlSetName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetName(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetName",
    &moho::cfunc_CMauiControlSetName,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788D80 (FUN_00788D80, cfunc_CMauiControlSetNameL)
 *
 * What it does:
 * Reads one `CMauiControl` plus debug-name string from Lua and stores it in
 * the control debug-name lane.
 */
int moho::cfunc_CMauiControlSetNameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlSetNameHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject nameArg(state, 2);
  const char* debugName = lua_tostring(state->m_state, 2);
  if (debugName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&nameArg, "string");
    debugName = "";
  }

  control->SetDebugName(msvc8::string(debugName));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788E90 (FUN_00788E90, cfunc_CMauiControlDump)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlDumpL`.
 */
int moho::cfunc_CMauiControlDump(lua_State* const luaContext)
{
  return cfunc_CMauiControlDumpL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788EB0 (FUN_00788EB0, func_CMauiControlDump_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Dump()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDump_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Dump",
    &moho::cfunc_CMauiControlDump,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDumpHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788F00 (FUN_00788F00, cfunc_CMauiControlDumpL)
 *
 * What it does:
 * Reads one `CMauiControl`, invokes `Dump()`, and returns the original control
 * object.
 */
int moho::cfunc_CMauiControlDumpL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlDumpHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->Dump();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788FC0 (FUN_00788FC0, cfunc_CMauiControlGetCurrentFocusControl)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetCurrentFocusControlL`.
 */
int moho::cfunc_CMauiControlGetCurrentFocusControl(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetCurrentFocusControlL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788FE0 (FUN_00788FE0, func_CMauiControlGetCurrentFocusControl_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetCurrentFocusControl()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetCurrentFocusControl_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCurrentFocusControl",
    &moho::cfunc_CMauiControlGetCurrentFocusControl,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetCurrentFocusControlHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789040 (FUN_00789040, cfunc_CMauiControlGetCurrentFocusControlL)
 *
 * What it does:
 * Pushes the currently focused control Lua object, or `nil` when no control
 * currently owns keyboard focus.
 */
int moho::cfunc_CMauiControlGetCurrentFocusControlL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetCurrentFocusControlHelpText, 1, argumentCount);
  }

  CMauiControl* const focusedControl = Maui_CurrentFocusControl.ResolveFocusedControl();
  if (focusedControl != nullptr) {
    CMauiControlScriptObjectRuntimeView::FromControl(focusedControl)->mLuaObj.PushStack(state);
    return 1;
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007890B0 (FUN_007890B0, cfunc_CMauiControlAcquireKeyboardFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlAcquireKeyboardFocusL`.
 */
int moho::cfunc_CMauiControlAcquireKeyboardFocus(lua_State* const luaContext)
{
  return cfunc_CMauiControlAcquireKeyboardFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007890D0 (FUN_007890D0, func_CMauiControlAcquireKeyboardFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:AcquireKeyboardFocus(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlAcquireKeyboardFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AcquireKeyboardFocus",
    &moho::cfunc_CMauiControlAcquireKeyboardFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlAcquireKeyboardFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789130 (FUN_00789130, cfunc_CMauiControlAcquireKeyboardFocusL)
 *
 * What it does:
 * Reads one `CMauiControl` plus boolean `blocksKeyDown` lane and forwards to
 * `CMauiControl::AcquireKeyboardFocus`.
 */
int moho::cfunc_CMauiControlAcquireKeyboardFocusL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlAcquireKeyboardFocusHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject blocksKeyDownArg(state, 2);
  const bool blocksKeyDown = LuaPlus::LuaStackObject::GetBoolean(&blocksKeyDownArg);
  control->AcquireKeyboardFocus(blocksKeyDown);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789210 (FUN_00789210, cfunc_CMauiControlAbandonKeyboardFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlAbandonKeyboardFocusL`.
 */
int moho::cfunc_CMauiControlAbandonKeyboardFocus(lua_State* const luaContext)
{
  return cfunc_CMauiControlAbandonKeyboardFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789230 (FUN_00789230, func_CMauiControlAbandonKeyboardFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:AbandonKeyboardFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlAbandonKeyboardFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AbandonKeyboardFocus",
    &moho::cfunc_CMauiControlAbandonKeyboardFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlAbandonKeyboardFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789290 (FUN_00789290, cfunc_CMauiControlAbandonKeyboardFocusL)
 *
 * What it does:
 * Reads one `CMauiControl` and forwards to
 * `CMauiControl::AbandonKeyboardFocus`.
 */
int moho::cfunc_CMauiControlAbandonKeyboardFocusL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlAbandonKeyboardFocusHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->AbandonKeyboardFocus();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789350 (FUN_00789350, cfunc_CMauiControlNeedsFrameUpdate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlNeedsFrameUpdateL`.
 */
int moho::cfunc_CMauiControlNeedsFrameUpdate(lua_State* const luaContext)
{
  return cfunc_CMauiControlNeedsFrameUpdateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789370 (FUN_00789370, func_CMauiControlNeedsFrameUpdate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:NeedsFrameUpdate()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlNeedsFrameUpdate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "NeedsFrameUpdate",
    &moho::cfunc_CMauiControlNeedsFrameUpdate,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlNeedsFrameUpdateHelpText
  );
  return &binder;
}

/**
 * Address: 0x007893D0 (FUN_007893D0, cfunc_CMauiControlNeedsFrameUpdateL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its frame-update flag lane to Lua.
 */
int moho::cfunc_CMauiControlNeedsFrameUpdateL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlNeedsFrameUpdateHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->NeedsFrameUpdate());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00789490 (FUN_00789490, cfunc_CMauiControlSetNeedsFrameUpdate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetNeedsFrameUpdateL`.
 */
int moho::cfunc_CMauiControlSetNeedsFrameUpdate(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetNeedsFrameUpdateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007894B0 (FUN_007894B0, func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetNeedsFrameUpdate(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNeedsFrameUpdate",
    &moho::cfunc_CMauiControlSetNeedsFrameUpdate,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetNeedsFrameUpdateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789510 (FUN_00789510, cfunc_CMauiControlSetNeedsFrameUpdateL)
 *
 * What it does:
 * Resolves optional `CMauiControl` plus one boolean lane and updates the
 * control frame-update flag.
 */
int moho::cfunc_CMauiControlSetNeedsFrameUpdateL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlSetNeedsFrameUpdateHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = ResolveControlFromLuaObjectOptionalOrError(controlObject, state);
  if (control != nullptr) {
    LuaPlus::LuaStackObject needsUpdateArg(state, 2);
    const bool needsUpdate = LuaPlus::LuaStackObject::GetBoolean(&needsUpdateArg);
    control->SetNeedsFrameUpdate(needsUpdate);
  }

  return 0;
}

/**
 * Address: 0x007895D0 (FUN_007895D0, cfunc_CMauiControlGetRootFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetRootFrameL`.
 */
int moho::cfunc_CMauiControlGetRootFrame(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetRootFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007895F0 (FUN_007895F0, func_CMauiControlGetRootFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetRootFrame()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetRootFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetRootFrame",
    &moho::cfunc_CMauiControlGetRootFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetRootFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789650 (FUN_00789650, cfunc_CMauiControlGetRootFrameL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes root-frame Lua object lane.
 */
int moho::cfunc_CMauiControlGetRootFrameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetRootFrameHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  CMauiFrame* const rootFrame = control->GetRootFrame();
  CMauiControlScriptObjectRuntimeView::FromControl(static_cast<CMauiControl*>(rootFrame))->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00789710 (FUN_00789710, cfunc_CMauiControlSetAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetAlphaL`.
 */
int moho::cfunc_CMauiControlSetAlpha(lua_State* const luaContext)
{
  return cfunc_CMauiControlSetAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789730 (FUN_00789730, func_CMauiControlSetAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetAlpha(alpha[, children])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAlpha",
    &moho::cfunc_CMauiControlSetAlpha,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789790 (FUN_00789790, cfunc_CMauiControlSetAlphaL)
 *
 * What it does:
 * Reads alpha (and optional recursive flag) and updates one control or its
 * full descendant closure alpha lanes.
 */
int moho::cfunc_CMauiControlSetAlphaL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kCMauiControlSetAlphaHelpText, 2, 3, argumentCount);
  }

  lua_settop(state->m_state, 3);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject alphaArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }

  float alpha = static_cast<float>(lua_tonumber(state->m_state, 2));
  if (alpha < 0.0f) {
    const msvc8::string debugName = control->GetDebugName();
    gpg::Warnf(kCMauiControlNegativeAlphaWarning, static_cast<int>(alpha), debugName.c_str());
    alpha = 0.0f;
  } else if (alpha > 1.0f) {
    const msvc8::string debugName = control->GetDebugName();
    gpg::Warnf(kCMauiControlAboveOneAlphaWarning, static_cast<int>(alpha), debugName.c_str());
  }

  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    CMauiControl* traversalCursor = control;
    if (traversalCursor != nullptr) {
      const std::uint32_t vertexAlpha = PackVertexAlphaFromScalar(alpha);
      do {
        CMauiControlExtendedRuntimeView* const controlView = CMauiControlExtendedRuntimeView::FromControl(traversalCursor);
        controlView->mAlpha = alpha;
        controlView->mVertexAlpha = vertexAlpha;
        traversalCursor = traversalCursor->DepthFirstSuccessor(control);
      } while (traversalCursor != nullptr);
    }
  } else {
    control->SetAlpha(alpha);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789A30 (FUN_00789A30, cfunc_CMauiControlGetAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetAlphaL`.
 */
int moho::cfunc_CMauiControlGetAlpha(lua_State* const luaContext)
{
  return cfunc_CMauiControlGetAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789A50 (FUN_00789A50, func_CMauiControlGetAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetAlpha()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAlpha",
    &moho::cfunc_CMauiControlGetAlpha,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789AB0 (FUN_00789AB0, cfunc_CMauiControlGetAlphaL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes current alpha lane to Lua.
 */
int moho::cfunc_CMauiControlGetAlphaL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlGetAlphaHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushnumber(state->m_state, control->GetAlpha());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00789B70 (FUN_00789B70, cfunc_CMauiControlApplyFunction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlApplyFunctionL`.
 */
int moho::cfunc_CMauiControlApplyFunction(lua_State* const luaContext)
{
  return cfunc_CMauiControlApplyFunctionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789B90 (FUN_00789B90, func_CMauiControlApplyFunction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:ApplyFunction(func)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlApplyFunction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ApplyFunction",
    &moho::cfunc_CMauiControlApplyFunction,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlApplyFunctionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789BF0 (FUN_00789BF0, cfunc_CMauiControlApplyFunctionL)
 *
 * What it does:
 * Reads one control plus Lua function object and applies it to control +
 * direct children.
 */
int moho::cfunc_CMauiControlApplyFunctionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlApplyFunctionHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaObject functionObject(LuaPlus::LuaStackObject(state, 2));
  control->ApplyFunction(functionObject);
  return 0;
}

/**
 * Address: 0x00789CD0 (FUN_00789CD0, cfunc_CMauiControlHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlHitTestL`.
 */
int moho::cfunc_CMauiControlHitTest(lua_State* const luaContext)
{
  return cfunc_CMauiControlHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789CF0 (FUN_00789CF0, func_CMauiControlHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:HitTest(x, y)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HitTest",
    &moho::cfunc_CMauiControlHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789D50 (FUN_00789D50, cfunc_CMauiControlHitTestL)
 *
 * What it does:
 * Reads one control plus `(x,y)` numeric lanes and pushes hit-test result.
 */
int moho::cfunc_CMauiControlHitTestL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiControlHitTestHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }
  const float y = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(state->m_state, 2));

  lua_pushboolean(state->m_state, control->HitTest(x, y) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00785960 (FUN_00785960, cfunc_CMauiBorderSetNewTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBorderSetNewTexturesL`.
 */
int moho::cfunc_CMauiBorderSetNewTextures(lua_State* const luaContext)
{
  return cfunc_CMauiBorderSetNewTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00785980 (FUN_00785980, func_CMauiBorderSetNewTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBorder:SetNewTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBorderSetNewTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewTextures",
    &moho::cfunc_CMauiBorderSetNewTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
    "CMauiBorder",
    kCMauiBorderSetNewTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007859E0 (FUN_007859E0, cfunc_CMauiBorderSetNewTexturesL)
 *
 * What it does:
 * Reads one `CMauiBorder` plus six optional texture-path lanes and forwards
 * resolved texture handles to `CMauiBorder::SetTextures`.
 */
int moho::cfunc_CMauiBorderSetNewTexturesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 7) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBorderSetNewTexturesHelpText, 7, argumentCount);
  }

  LuaPlus::LuaObject borderObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBorder* const border = SCR_FromLua_CMauiBorder(borderObject, state);

  const auto readOptionalTexturePath = [state](const int index) -> const char* {
    if (lua_type(state->m_state, index) == LUA_TNIL) {
      return nullptr;
    }

    LuaPlus::LuaStackObject textureArg(state, index);
    const char* texturePath = lua_tostring(state->m_state, index);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }
    return texturePath;
  };

  const char* const vertPath = readOptionalTexturePath(2);
  const char* const horzPath = readOptionalTexturePath(3);
  const char* const ulPath = readOptionalTexturePath(4);
  const char* const urPath = readOptionalTexturePath(5);
  const char* const llPath = readOptionalTexturePath(6);
  const char* const lrPath = readOptionalTexturePath(7);

  const boost::shared_ptr<CD3DBatchTexture> vertTexture =
    vertPath != nullptr ? CD3DBatchTexture::FromFile(vertPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> horzTexture =
    horzPath != nullptr ? CD3DBatchTexture::FromFile(horzPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> ulTexture =
    ulPath != nullptr ? CD3DBatchTexture::FromFile(ulPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> urTexture =
    urPath != nullptr ? CD3DBatchTexture::FromFile(urPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> llTexture =
    llPath != nullptr ? CD3DBatchTexture::FromFile(llPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};
  const boost::shared_ptr<CD3DBatchTexture> lrTexture =
    lrPath != nullptr ? CD3DBatchTexture::FromFile(lrPath, 1u) : boost::shared_ptr<CD3DBatchTexture>{};

  border->SetTextures(vertTexture, horzTexture, ulTexture, urTexture, llTexture, lrTexture);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00785FA0 (FUN_00785FA0, cfunc_CMauiBorderSetSolidColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBorderSetSolidColorL`.
 */
int moho::cfunc_CMauiBorderSetSolidColor(lua_State* const luaContext)
{
  return cfunc_CMauiBorderSetSolidColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00785FC0 (FUN_00785FC0, func_CMauiBorderSetSolidColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBorder:SetSolidColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBorderSetSolidColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetSolidColor",
    &moho::cfunc_CMauiBorderSetSolidColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
    "CMauiBorder",
    kCMauiBorderSetSolidColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00786020 (FUN_00786020, cfunc_CMauiBorderSetSolidColorL)
 *
 * What it does:
 * Reads one `CMauiBorder` plus one color lane and assigns one shared
 * solid-color texture to all six border texture slots.
 */
int moho::cfunc_CMauiBorderSetSolidColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiBorderSetSolidColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject borderObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBorder* const border = SCR_FromLua_CMauiBorder(borderObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t rgba = SCR_DecodeColor(state, colorObject);
  const boost::shared_ptr<CD3DBatchTexture> solidTexture = CD3DBatchTexture::FromSolidColor(rgba);
  border->SetTextures(solidTexture, solidTexture, solidTexture, solidTexture, solidTexture, solidTexture);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00796900 (FUN_00796900, cfunc_CMauiFrameGetTopmostDepth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameGetTopmostDepthL`.
 */
int moho::cfunc_CMauiFrameGetTopmostDepth(lua_State* const luaContext)
{
  return cfunc_CMauiFrameGetTopmostDepthL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796920 (FUN_00796920, func_CMauiFrameGetTopmostDepth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:GetTopmostDepth()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameGetTopmostDepth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetTopmostDepth",
    &moho::cfunc_CMauiFrameGetTopmostDepth,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameGetTopmostDepthHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796980 (FUN_00796980, cfunc_CMauiFrameGetTopmostDepthL)
 *
 * What it does:
 * Reads one `CMauiFrame` and pushes the topmost depth lane.
 */
int moho::cfunc_CMauiFrameGetTopmostDepthL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiFrameGetTopmostDepthHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);
  lua_pushnumber(state->m_state, frame->GetTopmostDepth());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00796A50 (FUN_00796A50, cfunc_CMauiFrameGetTargetHead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameGetTargetHeadL`.
 */
int moho::cfunc_CMauiFrameGetTargetHead(lua_State* const luaContext)
{
  return cfunc_CMauiFrameGetTargetHeadL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796A70 (FUN_00796A70, func_CMauiFrameGetTargetHead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:GetTargetHead()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameGetTargetHead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetTargetHead",
    &moho::cfunc_CMauiFrameGetTargetHead,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameGetTargetHeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796AD0 (FUN_00796AD0, cfunc_CMauiFrameGetTargetHeadL)
 *
 * What it does:
 * Reads one `CMauiFrame` and pushes integer target-head lane.
 */
int moho::cfunc_CMauiFrameGetTargetHeadL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiFrameGetTargetHeadHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);
  const CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(frame);
  lua_pushnumber(state->m_state, static_cast<float>(frameView->mTargetHead));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00796B90 (FUN_00796B90, cfunc_CMauiFrameSetTargetHead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameSetTargetHeadL`.
 */
int moho::cfunc_CMauiFrameSetTargetHead(lua_State* const luaContext)
{
  return cfunc_CMauiFrameSetTargetHeadL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796BB0 (FUN_00796BB0, func_CMauiFrameSetTargetHead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:SetTargetHead(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameSetTargetHead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetTargetHead",
    &moho::cfunc_CMauiFrameSetTargetHead,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameSetTargetHeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796C10 (FUN_00796C10, cfunc_CMauiFrameSetTargetHeadL)
 *
 * What it does:
 * Reads one `CMauiFrame` plus numeric target-head lane and stores it into the
 * frame runtime view.
 */
int moho::cfunc_CMauiFrameSetTargetHeadL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiFrameSetTargetHeadHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);

  LuaPlus::LuaStackObject targetHeadArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&targetHeadArg, "number");
  }

  CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(frame);
  frameView->mTargetHead = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00822FA0 (FUN_00822FA0, ??0UIBuildDragger@Moho@@QAE@@Z)
 *
 * What it does:
 * Captures the current world cursor position as both start/end drag points and
 * mirrors those lanes into the world-view build-drag state.
 */
moho::UIBuildDragger::UIBuildDragger(
  moho::CWldSession* const session,
  moho::CUIWorldViewBuildDragRuntimeView* const worldView,
  moho::CameraImpl* const camera
)
  : mList(nullptr)
  , mWldSession(session)
  , mWldView(worldView)
  , mCam(camera)
  , mStart(0.0f, 0.0f, 0.0f)
  , mEnd(0.0f, 0.0f, 0.0f)
{
  if (mWldSession != nullptr) {
    mStart = mWldSession->CursorWorldPos;
  }

  mEnd = mStart;

  if (mWldView != nullptr) {
    mWldView->mStart = mStart;
    mWldView->mEnd = mEnd;
  }
}

struct BuildDragStepStateRuntimeView
{
  float mX;                // +0x00
  float mZ;                // +0x04
  float mXStep;            // +0x08
  float mZStep;            // +0x0C
  std::int32_t mStepCount; // +0x10
};

static_assert(sizeof(BuildDragStepStateRuntimeView) == 0x14, "BuildDragStepStateRuntimeView size must be 0x14");
static_assert(
  offsetof(BuildDragStepStateRuntimeView, mStepCount) == 0x10,
  "BuildDragStepStateRuntimeView::mStepCount offset must be 0x10"
);

/**
 * Address: 0x0040DAD0 (FUN_0040DAD0)
 *
 * What it does:
 * Initializes one build-drag stepping lane from start/end world XZ
 * coordinates, deriving normalized per-step deltas and integer step count.
 */
[[maybe_unused]] static void InitBuildDragStepState(
  BuildDragStepStateRuntimeView* const state,
  const float stepLength,
  const float startX,
  const float startZ,
  const float endX,
  const float endZ
) noexcept
{
  const float deltaX = endX - startX;
  const float deltaZ = endZ - startZ;

  state->mX = startX;
  state->mZ = startZ;

  const float absDeltaZ = std::fabs(deltaZ);
  const float absDeltaX = std::fabs(deltaX);
  const float maxAxisDelta = (absDeltaZ <= absDeltaX) ? absDeltaX : absDeltaZ;

  if (maxAxisDelta == 0.0f) {
    state->mXStep = 0.0f;
    state->mZStep = 0.0f;
    state->mStepCount = 1;
    return;
  }

  const float inverseMaxAxisDelta = 1.0f / maxAxisDelta;
  state->mXStep = (inverseMaxAxisDelta * deltaX) * stepLength;
  state->mZStep = (inverseMaxAxisDelta * deltaZ) * stepLength;

  const float rawStepCount = maxAxisDelta / stepLength;
  const float roundedStepCount = std::nearbyintf(rawStepCount);
  std::int32_t carryAdjust = 0;
  if (rawStepCount < roundedStepCount) {
    carryAdjust = -1;
  }

  state->mStepCount = static_cast<std::int32_t>(roundedStepCount) + carryAdjust + 1;
}

/**
 * Address: 0x00822F60 (FUN_00822F60)
 *
 * What it does:
 * Thin forwarding lane that adapts drag-step initializer arguments and
 * returns the same state pointer.
 */
[[maybe_unused]] static BuildDragStepStateRuntimeView* InitBuildDragStepStateAndReturnState(
  BuildDragStepStateRuntimeView* const state,
  const float stepLength,
  const float startX,
  const float startZ,
  const float endX,
  const float endZ
) noexcept
{
  InitBuildDragStepState(state, stepLength, startX, startZ, endX, endZ);
  return state;
}
/**
 * Address: 0x0078DDC0 (FUN_0078DDC0, sub_78DDC0)
 *
 * What it does:
 * Returns the currently active dragger lane from global dragger sentinel
 * links, or null when no dragger is active.
 */
static IMauiDragger* func_GetCurrentDraggerFromMouseMoveLane()
{
  return DraggerFromLink(sCurrentDragger.mPrev);
}

/**
 * Address: 0x0078DDD0 (FUN_0078DDD0, sub_78DDD0)
 *
 * What it does:
 * Returns the keycode lane associated with the current dragger.
 */
static std::int32_t func_GetCurrentDraggerKeycode()
{
  return sCurrentDraggerKeycode;
}

/**
 * Address: 0x0078E600 (FUN_0078E600, func_GetCurrentDragger)
 *
 * What it does:
 * Returns the current dragger lane from global dragger sentinel links.
 */
static IMauiDragger* func_GetCurrentDragger()
{
  return func_GetCurrentDraggerFromMouseMoveLane();
}

/**
 * Address: 0x0078E610 (FUN_0078E610, func_GetCurrentDragger2)
 *
 * What it does:
 * Alias entry that returns the same current dragger lane as
 * `func_GetCurrentDragger`.
 */
static IMauiDragger* func_GetCurrentDragger2()
{
  return func_GetCurrentDragger();
}

/**
 * Address: 0x0086DDF0 (FUN_0086DDF0, sub_86DDF0)
 *
 * What it does:
 * Clears the global mouse-scrub active flag and returns its storage address.
 */
[[maybe_unused]] static std::uint8_t* func_ResetMouseScrubStateFlag()
{
  sMouseIsScrubbing = 0;
  return &sMouseIsScrubbing;
}

/**
 * Address: 0x0086DE00 (FUN_0086DE00, sub_86DE00)
 *
 * What it does:
 * Converts integer mouse-scrub delta lanes to float XY output.
 */
[[maybe_unused]] static float* func_GetMouseScrubDelta(float* const outDelta)
{
  outDelta[0] = static_cast<float>(sMouseScrubDelta.x);
  outDelta[1] = static_cast<float>(sMouseScrubDelta.y);
  return outDelta;
}

/**
 * Address: 0x0086DE20 (FUN_0086DE20, sub_86DE20)
 *
 * What it does:
 * Returns whether mouse-scrub mode is currently active.
 */
[[maybe_unused]] static std::uint8_t func_IsMouseScrubbingActive()
{
  return sMouseIsScrubbing;
}

/**
 * Address: 0x0086DFE0 (FUN_0086DFE0, sub_86DFE0)
 *
 * What it does:
 * Clears accumulated integer mouse-scrub deltas and returns zero.
 */
[[maybe_unused]] static int func_ResetMouseScrubDelta()
{
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;
  return 0;
}

/**
 * Address: 0x0086DFF0 (FUN_0086DFF0, func_ProcessMouseScrubbing)
 *
 * What it does:
 * While scrub mode is active, accumulates mouse delta into scrub lanes,
 * recenters the cursor to scrub anchor, and hides cursor texture state.
 */
[[maybe_unused]] static void func_ProcessMouseScrubbing()
{
  if (sMouseIsScrubbing == 0) {
    return;
  }

  POINT cursorPoint{};
  ::GetCursorPos(&cursorPoint);
  sMouseScrubDelta.x += cursorPoint.x - sMouseScrubAnchor.x;
  sMouseScrubDelta.y += cursorPoint.y - sMouseScrubAnchor.y;
  ::SetCursorPos(sMouseScrubAnchor.x, sMouseScrubAnchor.y);

  auto* const cursor = moho::g_UIManager->GetCursor();
  auto* const cursorView = moho::CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorShowingAndMarkDirty(cursorView, false);
}

/**
 * Address: 0x0086DE30 (FUN_0086DE30, func_StartMouseScrubbing)
 *
 * What it does:
 * Toggles mouse-scrub mode, updates cursor visibility/default state, and when
 * enabling scrub mode recenters the cursor to the control midpoint inside the
 * active UI head rectangle.
 */
[[maybe_unused]] static void func_StartMouseScrubbing(const bool doStart, moho::CMauiControl* const control)
{
  if (moho::ui_DisableCursorFixing || sMouseIsScrubbing == static_cast<std::uint8_t>(doStart)) {
    return;
  }

  sMouseIsScrubbing = static_cast<std::uint8_t>(doStart);

  auto* const cursor = moho::g_UIManager->GetCursor();
  auto* const cursorView = moho::CMauiCursorTextureRuntimeView::FromCursor(cursor);
  (void)SetCursorShowingAndMarkDirty(cursorView, !doStart);

  if (!doStart) {
    ::SetCursorPos(sMouseMoveStart.x, sMouseMoveStart.y);
    return;
  }

  POINT cursorPoint{};
  ::GetCursorPos(&cursorPoint);
  sMouseMoveStart = cursorPoint;
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device->GetDeviceContext();

  HWND secondHeadWindow = nullptr;
  if (static_cast<unsigned int>(context->GetHeadCount()) > 1u) {
    secondHeadWindow = reinterpret_cast<HWND>(context->GetHead(1u).mWindow);
  }

  RECT viewportRect{};
  const HWND mainWindowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
  ::GetWindowRect(mainWindowHandle, &viewportRect);

  if (
    cursorPoint.x < viewportRect.left || cursorPoint.x > viewportRect.right || cursorPoint.y < viewportRect.top
    || cursorPoint.y > viewportRect.bottom
  ) {
    if (secondHeadWindow != nullptr) {
      ::GetWindowRect(secondHeadWindow, &viewportRect);
    }
  }

  auto* const controlView = moho::CMauiControlRuntimeView::FromControl(control);
  const float top = moho::CScriptLazyVar_float::GetValue(&controlView->mTopLV);
  const float height = moho::CScriptLazyVar_float::GetValue(&controlView->mHeightLV);
  const LONG scrubY = static_cast<LONG>(top + static_cast<float>(viewportRect.top) + (height * 0.5f));

  const float left = moho::CScriptLazyVar_float::GetValue(&controlView->mLeftLV);
  const float width = moho::CScriptLazyVar_float::GetValue(&controlView->mWidthLV);
  sMouseScrubAnchor.x = static_cast<LONG>(left + static_cast<float>(viewportRect.left) + (width * 0.5f));
  sMouseScrubAnchor.y = scrubY;
  ::SetCursorPos(sMouseScrubAnchor.x, sMouseScrubAnchor.y);
}

/**
 * Address: 0x0086E140 (FUN_0086E140, Moho::CameraDragger::DragMove)
 *
 * What it does:
 * Applies camera drag delta from either raw mouse motion (cursor-fixing
 * disabled) or accumulated scrub delta, then resets scrub delta lanes.
 */
[[maybe_unused]] static int func_CameraDraggerDragMove(
  CameraDraggerRuntimeView* const dragger, const moho::SMauiEventData* const eventData
)
{
  auto* const cameraBytes = reinterpret_cast<std::uint8_t*>(dragger->mCamera);
  void* const dragTarget = cameraBytes + dragger->mDragMoveOffset;
  CameraDragDeltaFn const dragMoveFn = dragger->mDragMoveFn;

  if (moho::ui_DisableCursorFixing) {
    const Wm3::Vector2f currentMousePos(eventData->mMousePos.x, eventData->mMousePos.y);
    Wm3::Vector2f dragDelta(currentMousePos.x - dragger->mPos.x, currentMousePos.y - dragger->mPos.y);
    const int result = dragMoveFn(dragTarget, &dragDelta);
    dragger->mPos = currentMousePos;
    return result;
  }

  Wm3::Vector2f dragDelta(static_cast<float>(sMouseScrubDelta.x), static_cast<float>(sMouseScrubDelta.y));
  (void)dragMoveFn(dragTarget, &dragDelta);
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;
  return 0;
}

/**
 * Address: 0x0086E060 (FUN_0086E060, Moho::CameraDragger::CameraDragger)
 *
 * What it does:
 * Initializes one camera dragger with drag target camera/lane and enables
 * mouse-scrub mode for the owning control.
 */
[[maybe_unused]] static CameraDraggerRuntimeView* func_CameraDraggerConstruct(
  CameraDraggerRuntimeView* const dragger,
  moho::CameraImpl* const camera,
  const Wm3::Vector2f* const mousePos,
  moho::CMauiControl* const ownerControl,
  CameraDragDeltaFn const dragMoveFn,
  const std::int32_t dragMoveOffset
)
{
  dragger->mListHead = nullptr;
  dragger->mCamera = camera;
  dragger->mPos = *mousePos;
  dragger->mDragMoveFn = dragMoveFn;
  dragger->mDragMoveOffset = dragMoveOffset;
  func_StartMouseScrubbing(true, ownerControl);
  return dragger;
}

/**
 * Address: 0x0086E0D0 (FUN_0086E0D0, Moho::CameraDragger::~CameraDragger)
 *
 * What it does:
 * Disables mouse-scrub mode and unlinks all attached dragger-list nodes.
 */
[[maybe_unused]] static void func_CameraDraggerDestruct(CameraDraggerRuntimeView* const dragger)
{
  func_StartMouseScrubbing(false, nullptr);
  (void)DetachDraggerList(dragger->mListHead);
}

/**
 * Address: 0x0086E250 (FUN_0086E250, Moho::CameraDragger::dtr)
 *
 * What it does:
 * Runs `CameraDragger` destructor behavior and frees storage when requested.
 */
[[maybe_unused]] static CameraDraggerRuntimeView* func_CameraDraggerDeletingDtor(
  CameraDraggerRuntimeView* const dragger, const char deleteFlags
)
{
  func_CameraDraggerDestruct(dragger);
  if ((deleteFlags & 1) != 0) {
    ::operator delete(dragger);
  }
  return dragger;
}

/**
 * Address: 0x0086E1F0 (FUN_0086E1F0, Moho::CameraDragger::DragCancel)
 *
 * What it does:
 * Reverts held camera rotation when free-look is off, then destroys this
 * dragger instance.
 */
[[maybe_unused]] static void func_CameraDraggerDragCancel(CameraDraggerRuntimeView* const dragger)
{
  if (!moho::cam_Free) {
    dragger->mCamera->CameraRevertRotation();
  }
  if (dragger != nullptr) {
    (void)func_CameraDraggerDeletingDtor(dragger, 1);
  }
}

/**
 * Address: 0x0086E220 (FUN_0086E220, Moho::CameraDragger::DragRelease)
 *
 * What it does:
 * Mirrors `DragCancel`: conditionally reverts camera rotation and destroys
 * the dragger.
 */
[[maybe_unused]] static void func_CameraDraggerDragRelease(
  CameraDraggerRuntimeView* const dragger, const moho::SMauiEventData* const /*eventData*/
)
{
  if (!moho::cam_Free) {
    dragger->mCamera->CameraRevertRotation();
  }
  if (dragger != nullptr) {
    (void)func_CameraDraggerDeletingDtor(dragger, 1);
  }
}

/**
 * Address: 0x0086E270 (FUN_0086E270, Moho::CMiniMapDragger::CMiniMapDragger)
 *
 * What it does:
 * Initializes one minimap dragger and copies its camera-name lane from the
 * incoming string payload.
 */
[[maybe_unused]] static MiniMapDraggerRuntimeView* func_MiniMapDraggerConstruct(
  MiniMapDraggerRuntimeView* const dragger, msvc8::string cameraName
)
{
  dragger->mListHead = nullptr;
  ::new (&dragger->mCameraName) msvc8::string();
  dragger->mCameraName.assign(cameraName, 0, msvc8::string::npos);
  return dragger;
}

/**
 * Address: 0x0086E2F0 (FUN_0086E2F0, Moho::CMiniMapDragger::DragMove)
 *
 * What it does:
 * Updates world-session cursor screen lanes from incoming Maui event coords
 * and retargets the named minimap camera to the current cursor world point.
 */
[[maybe_unused]] static void func_MiniMapDraggerDragMove(
  MiniMapDraggerRuntimeView* const dragger, const moho::SMauiEventData* const eventData
)
{
  moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return;
  }

  auto* const sessionView = CWldSessionCursorRuntimeView::FromSession(activeSession);
  if (sessionView->mCursorInfo.mHitValid == 0u) {
    return;
  }

  moho::RCamManager* const cameraManager = moho::CAM_GetManager();
  moho::CameraImpl* const camera = cameraManager != nullptr ? cameraManager->GetCamera(dragger->mCameraName.c_str()) : nullptr;
  if (camera == nullptr) {
    return;
  }

  moho::MouseInfo cursorInfo = sessionView->mCursorInfo;
  cursorInfo.mMouseScreenPos.x = eventData->mMousePos.x;
  cursorInfo.mMouseScreenPos.y = eventData->mMousePos.y;
  sessionView->mCursorInfo = cursorInfo;

  CameraTargetRuntimeView::FromCamera(camera)->TargetLocation(cursorInfo.mMouseWorldPos, 0.0f);
}

/**
 * Address: 0x0086E430 (FUN_0086E430, Moho::CMiniMapDragger::~CMiniMapDragger)
 *
 * What it does:
 * Releases minimap dragger camera-name storage, restores empty-string state,
 * and unlinks all attached dragger-list nodes.
 */
[[maybe_unused]] static DraggerLink* func_MiniMapDraggerDestruct(MiniMapDraggerRuntimeView* const dragger)
{
  dragger->mCameraName.~string();
  ::new (&dragger->mCameraName) msvc8::string();
  return DetachDraggerList(dragger->mListHead);
}

/**
 * Address: 0x0086E410 (FUN_0086E410, Moho::CMiniMapDragger::dtr)
 *
 * What it does:
 * Runs `CMiniMapDragger` destructor behavior and frees storage when requested.
 */
[[maybe_unused]] static MiniMapDraggerRuntimeView* func_MiniMapDraggerDeletingDtor(
  MiniMapDraggerRuntimeView* const dragger, const char deleteFlags
)
{
  (void)func_MiniMapDraggerDestruct(dragger);
  if ((deleteFlags & 1) != 0) {
    ::operator delete(dragger);
  }
  return dragger;
}

/**
 * Address: 0x0086E3E0 (FUN_0086E3E0, Moho::CMiniMapDragger::DragCancel)
 *
 * What it does:
 * Destroys this minimap dragger instance.
 */
[[maybe_unused]] static void func_MiniMapDraggerDragCancel(MiniMapDraggerRuntimeView* const dragger)
{
  if (dragger != nullptr) {
    (void)func_MiniMapDraggerDeletingDtor(dragger, 1);
  }
}

/**
 * Address: 0x0086E3F0 (FUN_0086E3F0, Moho::CMiniMapDragger::DragRelease)
 *
 * What it does:
 * Destroys this minimap dragger instance.
 */
[[maybe_unused]] static void func_MiniMapDraggerDragRelease(
  MiniMapDraggerRuntimeView* const dragger, const moho::SMauiEventData* const /*eventData*/
)
{
  if (dragger != nullptr) {
    (void)func_MiniMapDraggerDeletingDtor(dragger, 1);
  }
}

/**
 * Address: 0x0078E540 (FUN_0078E540, sub_78E540)
 *
 * What it does:
 * Clears the global current-dragger sentinel link lanes.
 */
static DraggerLink* func_ResetCurrentDraggerLink()
{
  sCurrentDragger.mPrev = nullptr;
  sCurrentDragger.mNext = nullptr;
  return CurrentDraggerSentinelLink();
}

/**
 * Address: 0x0078E560 (FUN_0078E560, sub_78E560)
 *
 * What it does:
 * Unlinks the global current-dragger sentinel from its intrusive owner lane.
 */
static DraggerLink* func_UnlinkCurrentDraggerLink()
{
  DraggerLink* const sentinelLink = CurrentDraggerSentinelLink();
  DraggerLink* result = sCurrentDragger.mPrev;
  if (sCurrentDragger.mPrev != nullptr) {
    if (sCurrentDragger.mPrev->mPrev != sentinelLink) {
      do {
        result = result->mPrev->mNext;
      } while (result->mPrev != sentinelLink);
    }
    result->mPrev = sCurrentDragger.mNext;
  }
  return result;
}

/**
 * Address: 0x007A48D0 (FUN_007A48D0, ??1CMauiWxEventMapper@Moho@@QAE@@Z)
 * Mangled: ??1CMauiWxEventMapper@Moho@@QAE@@Z
 *
 * What it does:
 * Restores dragger/capture globals while the event mapper is being destroyed.
 */
CMauiWxEventMapperRuntime::~CMauiWxEventMapperRuntime()
{
  (void)func_UnlinkCurrentDraggerLink();
  (void)func_ResetCurrentDraggerLink();
  sMouseIsCaptured = 0;
}

/**
 * Address: 0x007A48B0 (FUN_007A48B0)
 *
 * What it does:
 * Scalar-deleting destructor wrapper for `CMauiWxEventMapper`.
 */
[[maybe_unused]] static moho::wxEvtHandlerRuntime* func_DestroyMauiWxEventMapper(
  moho::wxEvtHandlerRuntime* const eventMapper,
  const char deleteFlags
)
{
  auto* const typedMapper = static_cast<CMauiWxEventMapperRuntime*>(eventMapper);
  typedMapper->~CMauiWxEventMapperRuntime();
  if ((deleteFlags & 1) != 0) {
    ::operator delete(typedMapper);
  }
  return eventMapper;
}

/**
 * Address: 0x0078E590 (FUN_0078E590, func_SetCurDragger)
 *
 * What it does:
 * Relinks the global current-dragger sentinel to track one dragger lane.
 */
static DraggerLink* func_SetCurDragger(IMauiDragger* const dragger)
{
  DraggerLink* const sentinelLink = CurrentDraggerSentinelLink();
  DraggerLink* const draggerLink = DraggerLinkFromObject(dragger);
  DraggerLink* previous = sCurrentDragger.mPrev;

  if (draggerLink != sCurrentDragger.mPrev) {
    if (sCurrentDragger.mPrev != nullptr) {
      if (sCurrentDragger.mPrev->mPrev != sentinelLink) {
        do {
          previous = previous->mPrev->mNext;
        } while (previous->mPrev != sentinelLink);
      }
      previous->mPrev = sCurrentDragger.mNext;
    }

    sCurrentDragger.mPrev = draggerLink;
    if (draggerLink != nullptr) {
      sCurrentDragger.mNext = draggerLink->mPrev;
      draggerLink->mPrev = sentinelLink;
      return sentinelLink;
    }

    sCurrentDragger.mNext = nullptr;
  }

  return sentinelLink;
}

/**
 * Address: 0x00823E40 (FUN_00823E40, func_OnCommandDragBegin)
 *
 * What it does:
 * Imports `/lua/ui/game/commandgraph.lua` and invokes
 * `OnCommandDragBegin()` on the active UI Lua state.
 */
[[maybe_unused]] static void func_OnCommandDragBegin(LuaPlus::LuaState* const state)
{
  (void)InvokeUiLuaCallback(
    state,
    "/lua/ui/game/commandgraph.lua",
    "OnCommandDragBegin",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

/**
 * Address: 0x00823F00 (FUN_00823F00, func_OnCommandDragEnd)
 *
 * What it does:
 * Builds one Maui-event Lua payload and invokes
 * `/lua/ui/game/commandgraph.lua:OnCommandDragEnd(event, isDragger)`.
 */
[[maybe_unused]] static void func_OnCommandDragEnd(
  moho::SMauiEventData* const eventData, const std::int32_t isDragger, LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject eventObject{};
  (void)moho::CreateLuaEventObject(eventData, &eventObject, state);

  (void)InvokeUiLuaCallback(
    state,
    "/lua/ui/game/commandgraph.lua",
    "OnCommandDragEnd",
    [&eventObject, isDragger](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(eventObject, isDragger); }
  );
}

/**
 * Address: 0x007A4920 (FUN_007A4920, func_SetMouseCapture)
 *
 * What it does:
 * Applies Win32 mouse capture transitions for the active Maui event mapper.
 */
static std::uint8_t func_SetMouseCapture(const bool shouldCapture, moho::wxEvtHandlerRuntime* const eventMapper)
{
  std::uint8_t result = sMouseIsCaptured;
  if (static_cast<std::uint8_t>(shouldCapture) != sMouseIsCaptured) {
    if (sMouseIsCaptured != 0) {
      result = static_cast<std::uint8_t>(::ReleaseCapture());
      sMouseIsCaptured = 0;
    }
    if (shouldCapture) {
      const HWND windowHandle = ResolveCaptureWindowHandle(eventMapper);
      const HWND capturedWindow = ::SetCapture(windowHandle);
      result = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(capturedWindow));
      sMouseIsCaptured = 1;
    }
  }
  return result;
}

/**
 * Address: 0x0078DDE0 (FUN_0078DDE0, func_PostDragger)
 *
 * What it does:
 * Switches active dragger ownership, updates Win32 mouse-capture state, and
 * records the keycode lane used by the current dragger.
 */
static void func_PostDragger(moho::CMauiFrame* const originFrame, IMauiDragger* const dragger, moho::SMauiEventData* const eventData)
{
  IMauiDragger* const currentDragger = func_GetCurrentDragger();
  if (dragger == currentDragger) {
    return;
  }

  if (currentDragger != nullptr) {
    currentDragger->OnCurrentDraggerReplaced();
  }

  (void)func_SetCurDragger(dragger);

  if (originFrame != nullptr) {
    auto* const frameView = reinterpret_cast<CMauiFrameDraggerRuntimeView*>(originFrame);
    (void)func_SetMouseCapture(dragger != nullptr, frameView->mEventMapper);
  }

  if (func_GetCurrentDragger2() == nullptr) {
    sCurrentDraggerKeycode = 0;
  } else {
    sCurrentDraggerKeycode = eventData->mKeyCode;
  }
}

class UIBuildDraggerRuntimeConcrete final : public moho::UIBuildDragger
{
public:
  UIBuildDraggerRuntimeConcrete(
    moho::CWldSession* const session,
    moho::CUIWorldViewBuildDragRuntimeView* const worldView,
    moho::CameraImpl* const camera
  )
    : moho::UIBuildDragger(session, worldView, camera)
  {
  }

  void DragMove(const moho::SMauiEventData* const /*eventData*/) override
  {
    if (mWldSession != nullptr) {
      mEnd = mWldSession->CursorWorldPos;
    }

    if (mWldView != nullptr) {
      mWldView->mEnd = mEnd;
    }
  }

  void DragRelease(const moho::SMauiEventData* const /*eventData*/) override
  {
  }

  void OnCurrentDraggerReplaced() override
  {
  }
};

static_assert(
  sizeof(UIBuildDraggerRuntimeConcrete) == sizeof(moho::UIBuildDragger),
  "UIBuildDraggerRuntimeConcrete size must match moho::UIBuildDragger"
);

/**
 * Address: 0x00823CB0 (FUN_00823CB0, func_NewUIBuildDragger)
 *
 * What it does:
 * Allocates one UIBuildDragger, runs its constructor with session/world-view/
 * camera lanes, then posts the dragger; on allocation failure it posts a null
 * dragger lane.
 */
[[maybe_unused]] static void func_NewUIBuildDragger(
  moho::CMauiFrame* const originFrame,
  moho::CWldSession* const session,
  moho::SMauiEventData* const eventData,
  moho::CameraImpl* const camera,
  moho::CUIWorldViewBuildDragRuntimeView* const worldView
)
{
  auto* const storage = static_cast<UIBuildDraggerRuntimeConcrete*>(
    ::operator new(sizeof(UIBuildDraggerRuntimeConcrete), std::nothrow)
  );
  if (storage != nullptr) {
    auto* const dragger = new (storage) UIBuildDraggerRuntimeConcrete(session, worldView, camera);
    func_PostDragger(originFrame, dragger, eventData);
    return;
  }

  func_PostDragger(originFrame, nullptr, eventData);
}

/**
 * Address: 0x0078E210 (FUN_0078E210, cfunc_PostDragger)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_PostDraggerL`.
 */
int moho::cfunc_PostDragger(lua_State* const luaContext)
{
  return cfunc_PostDraggerL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078E230 (FUN_0078E230, func_PostDragger_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `PostDragger(originFrame, keycode, dragger)` Lua
 * binder.
 */
moho::CScrLuaInitForm* moho::func_PostDragger_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "PostDragger",
    &moho::cfunc_PostDragger,
    nullptr,
    "<global>",
    kPostDraggerHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078DC30 (FUN_0078DC30)
 *
 * What it does:
 * Initializes one `SMauiEventData` lane to the default unknown-event state
 * used by dragger posting paths.
 */
[[maybe_unused]] static moho::SMauiEventData* func_InitUnknownMauiEventData(
  moho::SMauiEventData* const eventData
) noexcept
{
  eventData->mEventType = moho::MET_Unknown;
  eventData->mMousePos.x = -1.0f;
  eventData->mMousePos.y = -1.0f;
  eventData->mWheelRotation = 0;
  eventData->mWheelData = 0;
  eventData->mKeyCode = 0;
  eventData->mRawKeyCode = 0;
  eventData->mModifiers = moho::MEM_None;
  eventData->mSource = nullptr;
  return eventData;
}

/**
 * Address: 0x0078E290 (FUN_0078E290, cfunc_PostDraggerL)
 *
 * What it does:
 * Reads `(originFrame, keycode, dragger)` from Lua, normalizes mouse-button
 * key lanes, and posts one dragger activation payload.
 */
int moho::cfunc_PostDraggerL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPostDraggerHelpText, 3, argumentCount);
  }

  CMauiFrame* originFrame = nullptr;
  if (lua_type(state->m_state, 1) != LUA_TNIL) {
    LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
    originFrame = SCR_FromLua_CMauiFrame(frameObject, state);
  }

  std::int32_t keyCode = 0;
  if (lua_type(state->m_state, 2) == LUA_TNUMBER) {
    LuaPlus::LuaStackObject keyCodeArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
    }
    keyCode = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  } else if (lua_isstring(state->m_state, 2) != 0) {
    LuaPlus::LuaStackObject keyCodeArg(state, 2);
    const char* keyCodeName = lua_tostring(state->m_state, 2);
    if (keyCodeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "string");
      keyCodeName = "";
    }

    gpg::RRef keyCodeEnumRef{};
    gpg::RRef_EMauiKeyCode(&keyCodeEnumRef, reinterpret_cast<EMauiKeyCode*>(&keyCode));
    SCR_GetEnum(state, keyCodeName, keyCodeEnumRef);
  }

  keyCode = NormalizePostDraggerKeycode(keyCode);
  if (!IsValidPostDraggerKeycode(keyCode)) {
    LuaPlus::LuaState::Error(state, kPostDraggerInvalidKeyError);
  }

  IMauiDragger* dragger = nullptr;
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    LuaPlus::LuaObject draggerObject(LuaPlus::LuaStackObject(state, 3));
    CMauiLuaDragger* const luaDragger = SCR_FromLua_CMauiLuaDragger(draggerObject, state);
    dragger = ResolveEmbeddedLuaDragger(luaDragger);
  }

  SMauiEventData eventData{};
  (void)func_InitUnknownMauiEventData(&eventData);
  eventData.mKeyCode = keyCode;

  func_PostDragger(originFrame, dragger, &eventData);
  return 0;
}

/**
 * Address: 0x0078DF80 (FUN_0078DF80, cfunc_CMauiLuaDraggerDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiLuaDraggerDestroyL`.
 */
int moho::cfunc_CMauiLuaDraggerDestroy(lua_State* const luaContext)
{
  return cfunc_CMauiLuaDraggerDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078DFA0 (FUN_0078DFA0, func_CMauiLuaDraggerDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiLuaDragger:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiLuaDraggerDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CMauiLuaDraggerDestroy,
    &moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance(),
    "CMauiLuaDragger",
    kCMauiLuaDraggerDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078E000 (FUN_0078E000, cfunc_CMauiLuaDraggerDestroyL)
 *
 * What it does:
 * Resolves one optional `CMauiLuaDragger` and executes scalar deleting
 * destructor semantics when present.
 */
int moho::cfunc_CMauiLuaDraggerDestroyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiLuaDraggerDestroyHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject draggerObject(LuaPlus::LuaStackObject(state, 1));
  CMauiLuaDragger* const dragger = ResolveCMauiLuaDraggerOptionalOrError(draggerObject, state);
  if (dragger != nullptr) {
    CScriptObject* const draggerObjectBase = reinterpret_cast<CScriptObject*>(dragger);
    delete draggerObjectBase;
  }

  return 1;
}

/**
 * Address: 0x007921A0 (FUN_007921A0, cfunc_CMauiEditSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetNewFontL`.
 */
int moho::cfunc_CMauiEditSetNewFont(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007921C0 (FUN_007921C0, func_CMauiEditSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiEditSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792220 (FUN_00792220, cfunc_CMauiEditSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus `(family, pointsize)`, creates one D3D font, and
 * applies it to edit runtime state.
 */
int moho::cfunc_CMauiEditSetNewFontL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewFontHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    ApplyEditFontAndRefreshClip(CMauiEditRuntimeView::FromEdit(edit), createdFont);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x007923C0 (FUN_007923C0, cfunc_CMauiEditSetNewForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewForegroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewForegroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007923E0 (FUN_007923E0, func_CMauiEditSetNewForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewForegroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewForegroundColor",
    &moho::cfunc_CMauiEditSetNewForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792440 (FUN_00792440, cfunc_CMauiEditSetNewForegroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one color lane and stores foreground color.
 */
int moho::cfunc_CMauiEditSetNewForegroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewForegroundColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditForegroundColorLane(CMauiEditRuntimeView::FromEdit(edit), SCR_DecodeColor(state, colorObject));

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792530 (FUN_00792530, cfunc_CMauiEditGetForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetForegroundColorL`.
 */
int moho::cfunc_CMauiEditGetForegroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792550 (FUN_00792550, func_CMauiEditGetForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetForegroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetForegroundColor",
    &moho::cfunc_CMauiEditGetForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007925B0 (FUN_007925B0, cfunc_CMauiEditGetForegroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded foreground color.
 */
int moho::cfunc_CMauiEditGetForegroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetForegroundColorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditForegroundColorLane(CMauiEditRuntimeView::FromEdit(edit)));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00792690 (FUN_00792690, cfunc_CMauiEditSetNewBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewBackgroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewBackgroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007926B0 (FUN_007926B0, func_CMauiEditSetNewBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewBackgroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewBackgroundColor",
    &moho::cfunc_CMauiEditSetNewBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792710 (FUN_00792710, cfunc_CMauiEditSetNewBackgroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one color lane, enables background rendering, and
 * stores background color.
 */
int moho::cfunc_CMauiEditSetNewBackgroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewBackgroundColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t backgroundColor = SCR_DecodeColor(state, colorObject);

  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(edit);
  (void)EnableEditBackgroundAndWriteColor(editView, backgroundColor);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792810 (FUN_00792810, cfunc_CMauiEditGetBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetBackgroundColorL`.
 */
int moho::cfunc_CMauiEditGetBackgroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792830 (FUN_00792830, func_CMauiEditGetBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetBackgroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetBackgroundColor",
    &moho::cfunc_CMauiEditGetBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792890 (FUN_00792890, cfunc_CMauiEditGetBackgroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded background color.
 */
int moho::cfunc_CMauiEditGetBackgroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetBackgroundColorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditBackgroundColorLane(CMauiEditRuntimeView::FromEdit(edit)));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00792970 (FUN_00792970, cfunc_CMauiEditShowBackground)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditShowBackgroundL`.
 */
int moho::cfunc_CMauiEditShowBackground(lua_State* const luaContext)
{
  return cfunc_CMauiEditShowBackgroundL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792990 (FUN_00792990, func_CMauiEditShowBackground_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ShowBackground(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditShowBackground_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowBackground",
    &moho::cfunc_CMauiEditShowBackground,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditShowBackgroundHelpText
  );
  return &binder;
}

/**
 * Address: 0x007929F0 (FUN_007929F0, cfunc_CMauiEditShowBackgroundL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one boolean lane and updates background-visibility
 * state.
 */
int moho::cfunc_CMauiEditShowBackgroundL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditShowBackgroundHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject visibleArg(state, 2);
  (void)WriteEditBackgroundVisibleLane(CMauiEditRuntimeView::FromEdit(edit), visibleArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792AC0 (FUN_00792AC0, cfunc_CMauiEditIsBackgroundVisible)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditIsBackgroundVisibleL`.
 */
int moho::cfunc_CMauiEditIsBackgroundVisible(lua_State* const luaContext)
{
  return cfunc_CMauiEditIsBackgroundVisibleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792AE0 (FUN_00792AE0, func_CMauiEditIsBackgroundVisible_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsBackgroundVisible()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsBackgroundVisible_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsBackgroundVisible",
    &moho::cfunc_CMauiEditIsBackgroundVisible,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsBackgroundVisibleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792B40 (FUN_00792B40, cfunc_CMauiEditIsBackgroundVisibleL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes background visibility as one Lua boolean.
 */
int moho::cfunc_CMauiEditIsBackgroundVisibleL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditIsBackgroundVisibleHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushboolean(state->m_state, ReadEditBackgroundVisibleLaneAlias(CMauiEditRuntimeView::FromEdit(edit)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00792C00 (FUN_00792C00, cfunc_CMauiEditClearText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditClearTextL`.
 */
int moho::cfunc_CMauiEditClearText(lua_State* const luaContext)
{
  return cfunc_CMauiEditClearTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792C20 (FUN_00792C20, func_CMauiEditClearText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ClearText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditClearText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearText",
    &moho::cfunc_CMauiEditClearText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditClearTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792C80 (FUN_00792C80, cfunc_CMauiEditClearTextL)
 *
 * What it does:
 * Reads one `CMauiEdit`, clears text/caret/selection lanes, and returns self.
 */
int moho::cfunc_CMauiEditClearTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditClearTextHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  edit->ClearText();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792D30 (FUN_00792D30, cfunc_CMauiEditSetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetTextL`.
 */
int moho::cfunc_CMauiEditSetText(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792D50 (FUN_00792D50, func_CMauiEditSetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetText",
    &moho::cfunc_CMauiEditSetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792DB0 (FUN_00792DB0, cfunc_CMauiEditSetTextL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus text lane, applies text update, and returns self.
 */
int moho::cfunc_CMauiEditSetTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetTextHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    text = "";
  }

  edit->SetText(msvc8::string(text));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792F00 (FUN_00792F00, cfunc_CMauiEditGetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetTextL`.
 */
int moho::cfunc_CMauiEditGetText(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792F20 (FUN_00792F20, func_CMauiEditGetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetText",
    &moho::cfunc_CMauiEditGetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792F80 (FUN_00792F80, cfunc_CMauiEditGetTextL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current text lane.
 */
int moho::cfunc_CMauiEditGetTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetTextHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  const msvc8::string text = edit->GetText();
  lua_pushstring(state->m_state, text.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793340 (FUN_00793340, cfunc_CMauiEditSetCaretPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetCaretPositionL`.
 */
int moho::cfunc_CMauiEditSetCaretPosition(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetCaretPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793360 (FUN_00793360, func_CMauiEditSetCaretPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetCaretPosition(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetCaretPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetCaretPosition",
    &moho::cfunc_CMauiEditSetCaretPosition,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetCaretPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x007933C0 (FUN_007933C0, cfunc_CMauiEditSetCaretPositionL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus integer caret lane and updates caret/clip state.
 */
int moho::cfunc_CMauiEditSetCaretPositionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetCaretPositionHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject caretArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&caretArg, "integer");
  }

  const int caretPosition = static_cast<int>(lua_tonumber(state->m_state, 2));
  edit->SetCaretPosition(caretPosition);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007934C0 (FUN_007934C0, cfunc_CMauiEditGetCaretPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetCaretPositionL`.
 */
int moho::cfunc_CMauiEditGetCaretPosition(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetCaretPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007934E0 (FUN_007934E0, func_CMauiEditGetCaretPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetCaretPosition()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetCaretPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCaretPosition",
    &moho::cfunc_CMauiEditGetCaretPosition,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetCaretPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793540 (FUN_00793540, cfunc_CMauiEditGetCaretPositionL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current caret-position lane.
 */
int moho::cfunc_CMauiEditGetCaretPositionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetCaretPositionHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(ReadEditCaretPositionLane(CMauiEditRuntimeView::FromEdit(edit))));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793600 (FUN_00793600, cfunc_CMauiEditShowCaret)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditShowCaretL`.
 */
int moho::cfunc_CMauiEditShowCaret(lua_State* const luaContext)
{
  return cfunc_CMauiEditShowCaretL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793620 (FUN_00793620, func_CMauiEditShowCaret_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ShowCaret(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditShowCaret_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowCaret",
    &moho::cfunc_CMauiEditShowCaret,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditShowCaretHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793680 (FUN_00793680, cfunc_CMauiEditShowCaretL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus bool lane and updates caret-visibility lane.
 */
int moho::cfunc_CMauiEditShowCaretL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditShowCaretHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject visibleArg(state, 2);
  (void)WriteEditCaretVisibleLane(CMauiEditRuntimeView::FromEdit(edit), visibleArg.GetBoolean());
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793750 (FUN_00793750, cfunc_CMauiEditIsCaretVisible)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditIsCaretVisibleL`.
 */
int moho::cfunc_CMauiEditIsCaretVisible(lua_State* const luaContext)
{
  return cfunc_CMauiEditIsCaretVisibleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793770 (FUN_00793770, func_CMauiEditIsCaretVisible_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsCaretVisible()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsCaretVisible_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsCaretVisible",
    &moho::cfunc_CMauiEditIsCaretVisible,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsCaretVisibleHelpText
  );
  return &binder;
}

/**
 * Address: 0x007937D0 (FUN_007937D0, cfunc_CMauiEditIsCaretVisibleL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes caret-visible state.
 */
int moho::cfunc_CMauiEditIsCaretVisibleL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditIsCaretVisibleHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  lua_pushboolean(state->m_state, ReadEditCaretVisibleLane(CMauiEditRuntimeView::FromEdit(edit)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793890 (FUN_00793890, cfunc_CMauiEditSetNewCaretColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetNewCaretColorL`.
 */
int moho::cfunc_CMauiEditSetNewCaretColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewCaretColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007938B0 (FUN_007938B0, func_CMauiEditSetNewCaretColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewCaretColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewCaretColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewCaretColor",
    &moho::cfunc_CMauiEditSetNewCaretColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewCaretColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078EE30 (FUN_0078EE30)
 *
 * What it does:
 * Masks one caret color lane to RGB24 and stores it in edit runtime state.
 */
[[maybe_unused]] static std::uint32_t func_SetEditCaretColorRgb24(
  moho::CMauiEditRuntimeView* const editView,
  const std::uint32_t color
) noexcept
{
  const std::uint32_t color24 = color & 0x00FFFFFFu;
  editView->mCaretColor = color24;
  return color24;
}

/**
 * Address: 0x00793910 (FUN_00793910, cfunc_CMauiEditSetNewCaretColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus color lane and updates caret RGB lane.
 */
int moho::cfunc_CMauiEditSetNewCaretColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewCaretColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t caretColor = SCR_DecodeColor(state, colorObject);
  (void)func_SetEditCaretColorRgb24(CMauiEditRuntimeView::FromEdit(edit), caretColor);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793A00 (FUN_00793A00, cfunc_CMauiEditGetCaretColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetCaretColorL`.
 */
int moho::cfunc_CMauiEditGetCaretColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetCaretColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793A20 (FUN_00793A20, func_CMauiEditGetCaretColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetCaretColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetCaretColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCaretColor",
    &moho::cfunc_CMauiEditGetCaretColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetCaretColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793A80 (FUN_00793A80, cfunc_CMauiEditGetCaretColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded caret color.
 */
int moho::cfunc_CMauiEditGetCaretColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetCaretColorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditCaretColorLane(CMauiEditRuntimeView::FromEdit(edit)));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00793B60 (FUN_00793B60, cfunc_CMauiEditSetCaretCycle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetCaretCycleL`.
 */
int moho::cfunc_CMauiEditSetCaretCycle(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetCaretCycleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793B80 (FUN_00793B80, func_CMauiEditSetCaretCycle_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetCaretCycle(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetCaretCycle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetCaretCycle",
    &moho::cfunc_CMauiEditSetCaretCycle,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetCaretCycleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793BE0 (FUN_00793BE0, cfunc_CMauiEditSetCaretCycleL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus cycle+alpha lanes and stores caret-cycle state.
 */
int moho::cfunc_CMauiEditSetCaretCycleL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetCaretCycleHelpText, 4, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject cycleSecondsArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&cycleSecondsArg, "number");
  }

  const float cycleSeconds = lua_tonumber(state->m_state, 2);
  LuaPlus::LuaObject offAlphaObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject onAlphaObject(LuaPlus::LuaStackObject(state, 4));

  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(edit);
  editView->mCaretCycleSeconds = cycleSeconds;
  editView->mCaretCycleOnAlpha = static_cast<std::uint8_t>(SCR_DecodeColor(state, onAlphaObject));
  editView->mCaretCycleOffAlpha = static_cast<std::uint8_t>(SCR_DecodeColor(state, offAlphaObject));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793070 (FUN_00793070, cfunc_CMauiEditSetMaxChars)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetMaxCharsL`.
 */
int moho::cfunc_CMauiEditSetMaxChars(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetMaxCharsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793090 (FUN_00793090, func_CMauiEditSetMaxChars_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetMaxChars(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetMaxChars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetMaxChars",
    &moho::cfunc_CMauiEditSetMaxChars,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetMaxCharsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007930F0 (FUN_007930F0, cfunc_CMauiEditSetMaxCharsL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus integer arg, clamps minimum to 1, applies max-char
 * limit, and returns self.
 */
int moho::cfunc_CMauiEditSetMaxCharsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetMaxCharsHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject maxCharsArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxCharsArg, "integer");
  }

  int maxChars = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (maxChars < 1) {
    maxChars = 1;
  }

  edit->SetMaxChars(maxChars);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793200 (FUN_00793200, cfunc_CMauiEditGetMaxChars)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetMaxCharsL`.
 */
int moho::cfunc_CMauiEditGetMaxChars(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetMaxCharsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793220 (FUN_00793220, func_CMauiEditGetMaxChars_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetMaxChars()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetMaxChars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMaxChars",
    &moho::cfunc_CMauiEditGetMaxChars,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetMaxCharsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793280 (FUN_00793280, cfunc_CMauiEditGetMaxCharsL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current max-char limit.
 */
int moho::cfunc_CMauiEditGetMaxCharsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetMaxCharsHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(ReadEditMaxCharsLane(CMauiEditRuntimeView::FromEdit(edit))));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793D70 (FUN_00793D70, cfunc_CMauiEditIsEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditIsEnabledL`.
 */
int moho::cfunc_CMauiEditIsEnabled(lua_State* const luaContext)
{
  return cfunc_CMauiEditIsEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793D90 (FUN_00793D90, func_CMauiEditIsEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsEnabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsEnabled",
    &moho::cfunc_CMauiEditIsEnabled,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793DF0 (FUN_00793DF0, cfunc_CMauiEditIsEnabledL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes enabled-input state.
 */
int moho::cfunc_CMauiEditIsEnabledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditIsEnabledHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  lua_pushboolean(state->m_state, ReadEditInputEnabledLane(CMauiEditRuntimeView::FromEdit(edit)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793EB0 (FUN_00793EB0, cfunc_CMauiEditEnableInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditEnableInputL`.
 */
int moho::cfunc_CMauiEditEnableInput(lua_State* const luaContext)
{
  return cfunc_CMauiEditEnableInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793ED0 (FUN_00793ED0, func_CMauiEditEnableInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:EnableInput()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditEnableInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EnableInput",
    &moho::cfunc_CMauiEditEnableInput,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditEnableInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793F30 (FUN_00793F30, cfunc_CMauiEditEnableInputL)
 *
 * What it does:
 * Enables edit input/caret lanes and returns self.
 */
int moho::cfunc_CMauiEditEnableInputL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditEnableInputHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  (void)WriteEditInputEnabledAndCaretVisible(edit, true);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793FF0 (FUN_00793FF0, cfunc_CMauiEditDisableInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditDisableInputL`.
 */
int moho::cfunc_CMauiEditDisableInput(lua_State* const luaContext)
{
  return cfunc_CMauiEditDisableInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794010 (FUN_00794010, func_CMauiEditDisableInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:DisableInput()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditDisableInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DisableInput",
    &moho::cfunc_CMauiEditDisableInput,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditDisableInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794070 (FUN_00794070, cfunc_CMauiEditDisableInputL)
 *
 * What it does:
 * Disables edit input/caret lanes, abandons keyboard focus, and returns self.
 */
int moho::cfunc_CMauiEditDisableInputL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditDisableInputHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  (void)WriteEditInputEnabledAndCaretVisible(edit, false);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794140 (FUN_00794140, cfunc_CMauiEditSetNewHighlightForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewHighlightForegroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewHighlightForegroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewHighlightForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794160 (FUN_00794160, func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewHighlightForegroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewHighlightForegroundColor",
    &moho::cfunc_CMauiEditSetNewHighlightForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewHighlightForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007941C0 (FUN_007941C0, cfunc_CMauiEditSetNewHighlightForegroundColorL)
 *
 * What it does:
 * Decodes one highlight-foreground color from Lua and stores it in edit
 * runtime lanes.
 */
int moho::cfunc_CMauiEditSetNewHighlightForegroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewHighlightForegroundColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditHighlightForegroundColorLane(CMauiEditRuntimeView::FromEdit(edit), SCR_DecodeColor(state, colorObject));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007942B0 (FUN_007942B0, cfunc_CMauiEditGetHighlightForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetHighlightForegroundColorL`.
 */
int moho::cfunc_CMauiEditGetHighlightForegroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetHighlightForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007942D0 (FUN_007942D0, func_CMauiEditGetHighlightForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetHighlightForegroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetHighlightForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetHighlightForegroundColor",
    &moho::cfunc_CMauiEditGetHighlightForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetHighlightForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794330 (FUN_00794330, cfunc_CMauiEditGetHighlightForegroundColorL)
 *
 * What it does:
 * Reads one edit highlight-foreground color and pushes encoded Lua color.
 */
int moho::cfunc_CMauiEditGetHighlightForegroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetHighlightForegroundColorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditHighlightForegroundColorLane(CMauiEditRuntimeView::FromEdit(edit)));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00794410 (FUN_00794410, cfunc_CMauiEditSetNewHighlightBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewHighlightBackgroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewHighlightBackgroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetNewHighlightBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794430 (FUN_00794430, func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewHighlightBackgroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewHighlightBackgroundColor",
    &moho::cfunc_CMauiEditSetNewHighlightBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewHighlightBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794490 (FUN_00794490, cfunc_CMauiEditSetNewHighlightBackgroundColorL)
 *
 * What it does:
 * Decodes one highlight-background color from Lua and stores it in edit
 * runtime lanes.
 */
int moho::cfunc_CMauiEditSetNewHighlightBackgroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetNewHighlightBackgroundColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditHighlightBackgroundColorLane(CMauiEditRuntimeView::FromEdit(edit), SCR_DecodeColor(state, colorObject));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794580 (FUN_00794580, cfunc_CMauiEditGetHighlightBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetHighlightBackgroundColorL`.
 */
int moho::cfunc_CMauiEditGetHighlightBackgroundColor(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetHighlightBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007945A0 (FUN_007945A0, func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetHighlightBackgroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetHighlightBackgroundColor",
    &moho::cfunc_CMauiEditGetHighlightBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetHighlightBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794600 (FUN_00794600, cfunc_CMauiEditGetHighlightBackgroundColorL)
 *
 * What it does:
 * Reads one edit highlight-background color and pushes encoded Lua color.
 */
int moho::cfunc_CMauiEditGetHighlightBackgroundColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetHighlightBackgroundColorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditHighlightBackgroundColorLane(CMauiEditRuntimeView::FromEdit(edit)));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x007946E0 (FUN_007946E0, cfunc_CMauiEditGetFontHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetFontHeightL`.
 */
int moho::cfunc_CMauiEditGetFontHeight(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetFontHeightL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794700 (FUN_00794700, func_CMauiEditGetFontHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetFontHeight()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetFontHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFontHeight",
    &moho::cfunc_CMauiEditGetFontHeight,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetFontHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794760 (FUN_00794760, cfunc_CMauiEditGetFontHeightL)
 *
 * What it does:
 * Reads edit font lane and pushes integerized font height (`0` when missing).
 */
int moho::cfunc_CMauiEditGetFontHeightL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetFontHeightHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  const float fontHeight = ReadEditFontHeightLane(CMauiEditRuntimeView::FromEdit(edit));
  lua_pushnumber(state->m_state, static_cast<float>(static_cast<int>(fontHeight)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00794840 (FUN_00794840, cfunc_CMauiEditAcquireFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditAcquireFocusL`.
 */
int moho::cfunc_CMauiEditAcquireFocus(lua_State* const luaContext)
{
  return cfunc_CMauiEditAcquireFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794860 (FUN_00794860, func_CMauiEditAcquireFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:AcquireFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditAcquireFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AcquireFocus",
    &moho::cfunc_CMauiEditAcquireFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditAcquireFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x007948C0 (FUN_007948C0, cfunc_CMauiEditAcquireFocusL)
 *
 * What it does:
 * Reads one `CMauiEdit`, enables caret+keyboard focus when edit is enabled,
 * and returns self.
 */
int moho::cfunc_CMauiEditAcquireFocusL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditAcquireFocusHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  AcquireEditKeyboardFocusIfEnabled(edit);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794990 (FUN_00794990, cfunc_CMauiEditAbandonFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditAbandonFocusL`.
 */
int moho::cfunc_CMauiEditAbandonFocus(lua_State* const luaContext)
{
  return cfunc_CMauiEditAbandonFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007949B0 (FUN_007949B0, func_CMauiEditAbandonFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:AbandonFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditAbandonFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AbandonFocus",
    &moho::cfunc_CMauiEditAbandonFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditAbandonFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794A10 (FUN_00794A10, cfunc_CMauiEditAbandonFocusL)
 *
 * What it does:
 * Reads one `CMauiEdit`, abandons keyboard focus, and returns self.
 */
int moho::cfunc_CMauiEditAbandonFocusL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditAbandonFocusHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  edit->AbandonKeyboardFocus();
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794AD0 (FUN_00794AD0, cfunc_CMauiEditSetDropShadow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetDropShadowL`.
 */
int moho::cfunc_CMauiEditSetDropShadow(lua_State* const luaContext)
{
  return cfunc_CMauiEditSetDropShadowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794AF0 (FUN_00794AF0, func_CMauiEditSetDropShadow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetDropShadow(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetDropShadow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetDropShadow",
    &moho::cfunc_CMauiEditSetDropShadow,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetDropShadowHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794B50 (FUN_00794B50, cfunc_CMauiEditSetDropShadowL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus bool arg, stores drop-shadow flag, and returns
 * self.
 */
int moho::cfunc_CMauiEditSetDropShadowL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditSetDropShadowHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject dropShadowArg(state, 2);
  (void)WriteEditDropShadowLane(CMauiEditRuntimeView::FromEdit(edit), dropShadowArg.GetBoolean());
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794C20 (FUN_00794C20, cfunc_CMauiEditGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetStringAdvanceL`.
 */
int moho::cfunc_CMauiEditGetStringAdvance(lua_State* const luaContext)
{
  return cfunc_CMauiEditGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794C40 (FUN_00794C40, func_CMauiEditGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiEditGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794CA0 (FUN_00794CA0, cfunc_CMauiEditGetStringAdvanceL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus string arg and returns measured text advance
 * from edit font lane.
 */
int moho::cfunc_CMauiEditGetStringAdvanceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiEditGetStringAdvanceHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  const float advance = MeasureEditStringAdvanceOrZero(CMauiEditRuntimeView::FromEdit(edit), text);
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00797AD0 (FUN_00797AD0, cfunc_CMauiHistogramSetXIncrement)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetXIncrementL`.
 */
int moho::cfunc_CMauiHistogramSetXIncrement(lua_State* const luaContext)
{
  return cfunc_CMauiHistogramSetXIncrementL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797AF0 (FUN_00797AF0, func_CMauiHistogramSetXIncrement_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetXIncrement(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetXIncrement_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetXIncrement",
    &moho::cfunc_CMauiHistogramSetXIncrement,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetXIncrementHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797B50 (FUN_00797B50, cfunc_CMauiHistogramSetXIncrementL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus integer X-increment lane and updates the
 * histogram runtime view.
 */
int moho::cfunc_CMauiHistogramSetXIncrementL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiHistogramSetXIncrementHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  CMauiHistogram* const histogram = SCR_FromLua_CMauiHistogram(histogramObject, state);

  LuaPlus::LuaStackObject incrementArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&incrementArg, "integer");
  }

  CMauiHistogramRuntimeView* const histogramView = CMauiHistogramRuntimeView::FromHistogram(histogram);
  histogramView->mXIncrement = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00797C50 (FUN_00797C50, cfunc_CMauiHistogramSetYIncrement)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetYIncrementL`.
 */
int moho::cfunc_CMauiHistogramSetYIncrement(lua_State* const luaContext)
{
  return cfunc_CMauiHistogramSetYIncrementL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797C70 (FUN_00797C70, func_CMauiHistogramSetYIncrement_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetYIncrement(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetYIncrement_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetYIncrement",
    &moho::cfunc_CMauiHistogramSetYIncrement,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetYIncrementHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797CD0 (FUN_00797CD0, cfunc_CMauiHistogramSetYIncrementL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus integer Y-increment lane and updates the
 * histogram runtime view.
 */
int moho::cfunc_CMauiHistogramSetYIncrementL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiHistogramSetYIncrementHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  CMauiHistogram* const histogram = SCR_FromLua_CMauiHistogram(histogramObject, state);

  LuaPlus::LuaStackObject incrementArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&incrementArg, "integer");
  }

  CMauiHistogramRuntimeView* const histogramView = CMauiHistogramRuntimeView::FromHistogram(histogram);
  histogramView->mYIncrement = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00797DD0 (FUN_00797DD0, cfunc_CMauiHistogramSetData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiHistogramSetDataL`.
 */
int moho::cfunc_CMauiHistogramSetData(lua_State* const luaContext)
{
  return cfunc_CMauiHistogramSetDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797DF0 (FUN_00797DF0, func_CMauiHistogramSetData_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiHistogram:SetData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiHistogramSetData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetData",
    &moho::cfunc_CMauiHistogramSetData,
    &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
    "CMauiHistogram",
    kCMauiHistogramSetDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797E50 (FUN_00797E50, cfunc_CMauiHistogramSetDataL)
 *
 * What it does:
 * Reads one `CMauiHistogram` plus data table and validates per-entry
 * color/data lanes.
 */
int moho::cfunc_CMauiHistogramSetDataL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiHistogramSetDataHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject histogramObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CMauiHistogram(histogramObject, state);

  if (lua_type(state->m_state, 2) == LUA_TTABLE) {
    LuaPlus::LuaObject dataRowsObject(LuaPlus::LuaStackObject(state, 2));
    const int dataRowCount = dataRowsObject.GetCount();
    for (int rowIndex = 1; rowIndex <= dataRowCount; ++rowIndex) {
      LuaPlus::LuaObject rowObject = dataRowsObject[rowIndex];
      LuaPlus::LuaObject colorObject = rowObject.GetByName("color");
      const std::uint32_t sampleColor = SCR_DecodeColor(state, colorObject);
      (void)sampleColor;

      LuaPlus::LuaObject valueTableObject = rowObject.GetByName("data");
      const int valueCount = valueTableObject.GetCount();
      std::vector<float> sampleValues{};
      if (valueCount > 0) {
        sampleValues.reserve(static_cast<std::size_t>(valueCount));
      }
      for (int valueIndex = 1; valueIndex <= valueCount; ++valueIndex) {
        LuaPlus::LuaObject valueObject = valueTableObject[valueIndex];
        sampleValues.push_back(static_cast<float>(valueObject.GetNumber()));
      }
    }
  } else {
    gpg::Warnf("Histogram:SetData a table of data!");
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00780D20 (FUN_00780D20, cfunc_InternalCreateBitmap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateBitmapL`.
 */
int moho::cfunc_InternalCreateBitmap(lua_State* const luaContext)
{
  return cfunc_InternalCreateBitmapL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00780D40 (FUN_00780D40, func_InternalCreateBitmap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateBitmap(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateBitmap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateBitmap",
    &moho::cfunc_InternalCreateBitmap,
    nullptr,
    "<global>",
    kInternalCreateBitmapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00780DA0 (FUN_00780DA0, cfunc_InternalCreateBitmapL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiBitmap`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateBitmapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateBitmapHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = new CMauiBitmap(&luaObject, parentControl);
  bitmap->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(bitmap)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007857B0 (FUN_007857B0, cfunc_InternalCreateBorder)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateBorderL`.
 */
int moho::cfunc_InternalCreateBorder(lua_State* const luaContext)
{
  return cfunc_InternalCreateBorderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007857D0 (FUN_007857D0, func_InternalCreateBorder_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateBorder(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateBorder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateBorder",
    &moho::cfunc_InternalCreateBorder,
    nullptr,
    "<global>",
    kInternalCreateBorderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00785830 (FUN_00785830, cfunc_InternalCreateBorderL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiBorder`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateBorderL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateBorderHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBorder* const border = new CMauiBorder(&luaObject, parentControl);
  border->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(border)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00784A10 (FUN_00784A10, Moho::CMauiBorder::CMauiBorder)
 *
 * What it does:
 * Constructs one border control from Lua object + parent lanes and initializes
 * border texture/lazy-var runtime fields.
 */
moho::CMauiBorder::CMauiBorder(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "border")
{
  CMauiBorderRuntimeView* const borderView = CMauiBorderRuntimeView::FromBorder(this);
  borderView->mTex1 = {};
  borderView->mTexHorz = {};
  borderView->mTexUL = {};
  borderView->mTexUR = {};
  borderView->mTexLL = {};
  borderView->mTexLR = {};

  LuaPlus::LuaState* const activeState = luaObject != nullptr ? luaObject->m_state : nullptr;
  new (&borderView->mBorderWidthLV) CScriptLazyVar_float(activeState);
  new (&borderView->mBorderHeightLV) CScriptLazyVar_float(activeState);

  LuaPlus::LuaObject& controlLuaObject = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj;
  controlLuaObject.SetObject("BorderWidth", &AsLazyVarObject(borderView->mBorderWidthLV));
  controlLuaObject.SetObject("BorderHeight", &AsLazyVarObject(borderView->mBorderHeightLV));
}

/**
 * Address: 0x00784B40 (FUN_00784B40, Moho::CMauiBorder::~CMauiBorder)
 *
 * What it does:
 * Releases border lazy-var/object texture lanes before base `CMauiControl`
 * teardown.
 */
moho::CMauiBorder::~CMauiBorder()
{
  CMauiBorderRuntimeView* const borderView = CMauiBorderRuntimeView::FromBorder(this);
  AsLazyVarObject(borderView->mBorderHeightLV).~LuaObject();
  AsLazyVarObject(borderView->mBorderWidthLV).~LuaObject();

  borderView->mTexLR.~shared_ptr();
  borderView->mTexLL.~shared_ptr();
  borderView->mTexUR.~shared_ptr();
  borderView->mTexUL.~shared_ptr();
  borderView->mTexHorz.~shared_ptr();
  borderView->mTex1.~shared_ptr();
}

/**
 * Address: 0x00791FF0 (FUN_00791FF0, cfunc_InternalCreateEdit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateEditL`.
 */
int moho::cfunc_InternalCreateEdit(lua_State* const luaContext)
{
  return cfunc_InternalCreateEditL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792010 (FUN_00792010, func_InternalCreateEdit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateEdit(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateEdit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateEdit",
    &moho::cfunc_InternalCreateEdit,
    nullptr,
    "<global>",
    kInternalCreateEditHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792070 (FUN_00792070, cfunc_InternalCreateEditL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiEdit`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateEditL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateEditHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = new CMauiEdit(&luaObject, parentControl);
  edit->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(edit)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00797310 (FUN_00797310, cfunc_InternalCreateGroup)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InternalCreateGroupL`.
 */
int moho::cfunc_InternalCreateGroup(lua_State* const luaContext)
{
  return cfunc_InternalCreateGroupL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797330 (FUN_00797330, func_InternalCreateGroup_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateGroup(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateGroup_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateGroup",
    &moho::cfunc_InternalCreateGroup,
    nullptr,
    "<global>",
    kInternalCreateGroupHelpText
  );
  return &binder;
}

/**
 * Address: 0x00797390 (FUN_00797390, cfunc_InternalCreateGroupL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one group control, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateGroupL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateGroupHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiGroup* const group = new CMauiGroup(&luaObject, parentControl);
  group->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(group)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00797280 (FUN_00797280, ??0CMauiGroup@Moho@@QAE@@Z)
 *
 * What it does:
 * Constructs one group control from Lua object + parent lanes.
 */
moho::CMauiGroup::CMauiGroup(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "group")
{
}

/**
 * Address: 0x00797300 (FUN_00797300, Moho::CMauiGroup::Draw)
 *
 * What it does:
 * No-op draw lane used by the group control vtable.
 */
void moho::CMauiGroup::Draw(CD3DPrimBatcher* const /*primBatcher*/, const std::int32_t /*drawMask*/)
{
}

/**
 * Address: 0x00797920 (FUN_00797920, cfunc_InternalCreateHistogram)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateHistogramL`.
 */
int moho::cfunc_InternalCreateHistogram(lua_State* const luaContext)
{
  return cfunc_InternalCreateHistogramL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00797940 (FUN_00797940, func_InternalCreateHistogram_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateHistogram(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateHistogram_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateHistogram",
    &moho::cfunc_InternalCreateHistogram,
    nullptr,
    "<global>",
    kInternalCreateHistogramHelpText
  );
  return &binder;
}

/**
 * Address: 0x007979A0 (FUN_007979A0, cfunc_InternalCreateHistogramL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiHistogram`, dispatches
 * `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateHistogramL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateHistogramHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiHistogram* const histogram = new CMauiHistogram(&luaObject, parentControl);
  histogram->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(histogram)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007977A0 (FUN_007977A0, Moho::CMauiHistogram::CMauiHistogram)
 *
 * What it does:
 * Constructs one histogram control from Lua object + parent lanes and
 * initializes histogram runtime counters/state lanes.
 */
moho::CMauiHistogram::CMauiHistogram(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "group")
{
  CMauiHistogramRuntimeView* const histogramView = CMauiHistogramRuntimeView::FromHistogram(this);
  histogramView->mUnknown128 = 0;
  histogramView->mUnknown12C = 0;
  histogramView->mUnknown130 = 0;
}

/**
 * Address: 0x00797900 (FUN_00797900, Moho::CMauiHistogram::Dump)
 *
 * What it does:
 * Logs base control debug state plus one histogram class banner line.
 */
void moho::CMauiHistogram::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiHistogram");
}

/**
 * Address: 0x007978F0 (FUN_007978F0, Moho::CMauiHistogram::Draw)
 *
 * What it does:
 * No-op draw lane used by the histogram vtable.
 */
void moho::CMauiHistogram::Draw(CD3DPrimBatcher* const /*primBatcher*/, const std::int32_t /*drawMask*/)
{
}

/**
 * Address: 0x0079E590 (FUN_0079E590, cfunc_InternalCreateMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMeshL`.
 */
int moho::cfunc_InternalCreateMesh(lua_State* const luaContext)
{
  return cfunc_InternalCreateMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E5B0 (FUN_0079E5B0, func_InternalCreateMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateMesh",
    &moho::cfunc_InternalCreateMesh,
    nullptr,
    "<global>",
    kInternalCreateMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079E610 (FUN_0079E610, cfunc_InternalCreateMeshL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiMesh`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMeshL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateMeshHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMesh* const mesh = new CMauiMesh(&luaObject, parentControl);
  mesh->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(mesh)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079DDB0 (FUN_0079DDB0, Moho::CMauiMesh::CMauiMesh)
 *
 * What it does:
 * Constructs one mesh control from Lua object + parent lanes and initializes
 * mesh texture/orientation/runtime defaults.
 */
moho::CMauiMesh::CMauiMesh(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "Mesh")
{
  CMauiMeshRuntimeView* const meshView = CMauiMeshRuntimeView::FromMesh(this);
  meshView->mTexture = {};
  meshView->mIsRotated = false;
  meshView->mMeshBlueprint = nullptr;
  meshView->mOrientation = Wm3::Quaternionf::Identity();
  meshView->mUnknown13C = -1;
  CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = true;
}

/**
 * Address: 0x0079DE70 (FUN_0079DE70, Moho::CMauiMesh::dtr)
 *
 * What it does:
 * Releases the mesh preview texture shared-pointer lane and continues base
 * control teardown.
 */
moho::CMauiMesh::~CMauiMesh()
{
  CMauiMeshRuntimeView* const meshView = CMauiMeshRuntimeView::FromMesh(this);
  meshView->mTexture.reset();
}

/**
 * Address: 0x0079E580 (FUN_0079E580, Moho::CMauiMesh::Dump)
 *
 * What it does:
 * No-op dump lane used by the mesh control vtable.
 */
void moho::CMauiMesh::Dump()
{
}

/**
 * Address: 0x0079F540 (FUN_0079F540, cfunc_InternalCreateMovie)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMovieL`.
 */
int moho::cfunc_InternalCreateMovie(lua_State* const luaContext)
{
  return cfunc_InternalCreateMovieL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F560 (FUN_0079F560, func_InternalCreateMovie_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMovie(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMovie_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateMovie",
    &moho::cfunc_InternalCreateMovie,
    nullptr,
    "<global>",
    kInternalCreateMovieHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079F5C0 (FUN_0079F5C0, cfunc_InternalCreateMovieL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiMovie`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMovieL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateMovieHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = new CMauiMovie(&luaObject, parentControl);
  movie->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(movie)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007A1590 (FUN_007A1590, cfunc_InternalCreateScrollbar)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateScrollbarL`.
 */
int moho::cfunc_InternalCreateScrollbar(lua_State* const luaContext)
{
  return cfunc_InternalCreateScrollbarL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A15B0 (FUN_007A15B0, func_InternalCreateScrollbar_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateScrollbar(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateScrollbar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateScrollbar",
    &moho::cfunc_InternalCreateScrollbar,
    nullptr,
    "<global>",
    kInternalCreateScrollbarHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A1610 (FUN_007A1610, cfunc_InternalCreateScrollbarL)
 *
 * What it does:
 * Reads `(luaobj,parent,axisText)`, constructs one scrollbar control,
 * dispatches `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateScrollbarL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateScrollbarHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaStackObject axisArg(state, 3);
  const char* const axisLexical = lua_tostring(state->m_state, 3);
  if (axisLexical == nullptr) {
    axisArg.TypeError("string");
  }

  EMauiScrollAxis axis = static_cast<EMauiScrollAxis>(0);
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axis);
  (void)axisRef.SetLexical(axisLexical);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = new CMauiScrollbar(&luaObject, parentControl, axis);
  scrollbar->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(scrollbar)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007A3340 (FUN_007A3340, cfunc_InternalCreateText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InternalCreateTextL`.
 */
int moho::cfunc_InternalCreateText(lua_State* const luaContext)
{
  return cfunc_InternalCreateTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3360 (FUN_007A3360, func_InternalCreateText_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateText",
    &moho::cfunc_InternalCreateText,
    nullptr,
    "<global>",
    kInternalCreateTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A33C0 (FUN_007A33C0, cfunc_InternalCreateTextL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiText`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateTextHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const text = new CMauiText(&luaObject, parentControl);
  text->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(text)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007A2BE0 (FUN_007A2BE0, Moho::CMauiText::CMauiText)
 *
 * What it does:
 * Constructs one text control from Lua object + parent lanes and initializes
 * text/font/lazy-var runtime fields.
 */
moho::CMauiText::CMauiText(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "text")
{
  CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(this);
  textView->mFont = nullptr;
  new (&textView->mText) msvc8::string();
  textView->mDropShadow = false;
  textView->mClipToWidth = false;
  textView->mCenteredHorizontally = false;
  textView->mCenteredVertically = false;
  textView->mColor = static_cast<std::uint32_t>(-1);

  LuaPlus::LuaState* const activeState = luaObject != nullptr ? luaObject->m_state : nullptr;
  new (&textView->mTextAdvanceLV) CScriptLazyVar_float(activeState);
  new (&textView->mFontAscentLV) CScriptLazyVar_float(activeState);
  new (&textView->mFontDescentLV) CScriptLazyVar_float(activeState);
  new (&textView->mFontExternalLeadingLV) CScriptLazyVar_float(activeState);

  LuaPlus::LuaObject& controlLuaObject = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj;
  controlLuaObject.SetObject("TextAdvance", &AsLazyVarObject(textView->mTextAdvanceLV));
  controlLuaObject.SetObject("FontAscent", &AsLazyVarObject(textView->mFontAscentLV));
  controlLuaObject.SetObject("FontDescent", &AsLazyVarObject(textView->mFontDescentLV));
  controlLuaObject.SetObject("FontExternalLeading", &AsLazyVarObject(textView->mFontExternalLeadingLV));
}

/**
 * Address: 0x00799340 (FUN_00799340, Moho::CMauiItemList::CMauiItemList)
 *
 * What it does:
 * Constructs one item-list control from Lua object + parent lanes and
 * initializes palette, selection, and default font runtime state.
 */
moho::CMauiItemList::CMauiItemList(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "itemlist")
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  itemListView->mFont = nullptr;
  itemListView->mForegroundColor = 0xFF808080u;
  itemListView->mBackgroundColor = 0xFF000000u;
  itemListView->mSelectedForegroundColor = 0xFF000000u;
  itemListView->mSelectedBackgroundColor = 0xFF808080u;
  itemListView->mHighlightForegroundColor = 0xFFA0A0A0u;
  itemListView->mHighlightBackgroundColor = 0xFF202020u;
  itemListView->mItems.reset_range_lanes_preserve_proxy();
  itemListView->mCurSelection = -1;
  itemListView->mHoverItem = -1;
  itemListView->mShowSelection = true;
  itemListView->mShowMouseoverItem = false;
  itemListView->mScrollPosition = 0;

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(16, "New Times Roman");
  AssignIntrusiveFont(itemListView->mFont, createdFont.px);
  createdFont.release();
}

/**
 * Address: 0x0079A960 (FUN_0079A960, cfunc_InternalCreateItemList)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateItemListL`.
 */
int moho::cfunc_InternalCreateItemList(lua_State* const luaContext)
{
  return cfunc_InternalCreateItemListL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079A980 (FUN_0079A980, func_InternalCreateItemList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateItemList(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateItemList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateItemList",
    &moho::cfunc_InternalCreateItemList,
    nullptr,
    "<global>",
    kInternalCreateItemListHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079A9E0 (FUN_0079A9E0, cfunc_InternalCreateItemListL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiItemList`, dispatches
 * `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateItemListL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateItemListHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = new CMauiItemList(&luaObject, parentControl);
  itemList->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(itemList)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079AB10 (FUN_0079AB10, cfunc_CMauiItemListSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetNewFontL`.
 */
int moho::cfunc_CMauiItemListSetNewFont(lua_State* const luaContext)
{
  return cfunc_CMauiItemListSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079AB30 (FUN_0079AB30, func_CMauiItemListSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiItemListSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079AB90 (FUN_0079AB90, cfunc_CMauiItemListSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus `(family, pointsize)`, creates one font, and
 * applies it to item-list runtime state.
 */
int moho::cfunc_CMauiItemListSetNewFontL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListSetNewFontHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    itemList->SetFont(createdFont.px);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x0079AD30 (FUN_0079AD30, cfunc_CMauiItemListSetNewColors)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetNewColorsL`.
 */
int moho::cfunc_CMauiItemListSetNewColors(lua_State* const luaContext)
{
  return cfunc_CMauiItemListSetNewColorsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079AD50 (FUN_0079AD50, func_CMauiItemListSetNewColors_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetNewColors(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetNewColors_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewColors",
    &moho::cfunc_CMauiItemListSetNewColors,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetNewColorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079ADB0 (FUN_0079ADB0, cfunc_CMauiItemListSetNewColorsL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus optional color lanes and updates the
 * item-list color palette runtime fields.
 */
int moho::cfunc_CMauiItemListSetNewColorsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 7) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListSetNewColorsHelpText, 7, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);

  const auto decodeColorIfPresent = [state](const int index, std::uint32_t& destination) {
    if (lua_type(state->m_state, index) != LUA_TNIL) {
      LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, index));
      destination = SCR_DecodeColor(state, colorObject);
    }
  };

  decodeColorIfPresent(2, itemListView->mForegroundColor);
  decodeColorIfPresent(3, itemListView->mBackgroundColor);
  decodeColorIfPresent(4, itemListView->mSelectedForegroundColor);
  decodeColorIfPresent(5, itemListView->mSelectedBackgroundColor);
  decodeColorIfPresent(6, itemListView->mHighlightForegroundColor);
  decodeColorIfPresent(7, itemListView->mHighlightBackgroundColor);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B980 (FUN_0079B980, cfunc_CMauiItemListSetSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListSetSelectionL`.
 */
int moho::cfunc_CMauiItemListSetSelection(lua_State* const luaContext)
{
  return cfunc_CMauiItemListSetSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B9A0 (FUN_0079B9A0, func_CMauiItemListSetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:SetSelection(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListSetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetSelection",
    &moho::cfunc_CMauiItemListSetSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListSetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BA00 (FUN_0079BA00, cfunc_CMauiItemListSetSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and updates the current
 * selection lane when the index is in range.
 */
int moho::cfunc_CMauiItemListSetSelectionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListSetSelectionHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  if (index >= 0) {
    CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
    const std::size_t itemCount = itemListView->mItems.data() ? itemListView->mItems.size() : 0u;
    const std::size_t selectionIndex = static_cast<std::size_t>(index);
    itemListView->mCurSelection = selectionIndex < itemCount ? index : -1;
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B040 (FUN_0079B040, cfunc_CMauiItemListGetItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetItemL`.
 */
int moho::cfunc_CMauiItemListGetItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListGetItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B060 (FUN_0079B060, func_CMauiItemListGetItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetItem",
    &moho::cfunc_CMauiItemListGetItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B0C0 (FUN_0079B0C0, cfunc_CMauiItemListGetItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and returns the selected item
 * string lane to Lua.
 */
int moho::cfunc_CMauiItemListGetItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListGetItemHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  msvc8::string* const itemBase = itemListView->mItems.data();
  const msvc8::string& itemName = itemBase[index];
  lua_pushstring(state->m_state, itemName.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BB40 (FUN_0079BB40, cfunc_CMauiItemListGetItemCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetItemCountL`.
 */
int moho::cfunc_CMauiItemListGetItemCount(lua_State* const luaContext)
{
  return cfunc_CMauiItemListGetItemCountL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BB60 (FUN_0079BB60, func_CMauiItemListGetItemCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetItemCount()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetItemCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetItemCount",
    &moho::cfunc_CMauiItemListGetItemCount,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetItemCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BBC0 (FUN_0079BBC0, cfunc_CMauiItemListGetItemCountL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns its current item count.
 */
int moho::cfunc_CMauiItemListGetItemCountL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListGetItemCountHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  const int itemCount = GetItemListEntryCount(*itemListView);

  lua_pushnumber(state->m_state, static_cast<float>(static_cast<std::uint32_t>(itemCount)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BCB0 (FUN_0079BCB0, cfunc_CMauiItemListEmpty)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiItemListEmptyL`.
 */
int moho::cfunc_CMauiItemListEmpty(lua_State* const luaContext)
{
  return cfunc_CMauiItemListEmptyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BCD0 (FUN_0079BCD0, func_CMauiItemListEmpty_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:Empty()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListEmpty_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Empty",
    &moho::cfunc_CMauiItemListEmpty,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BD30 (FUN_0079BD30, cfunc_CMauiItemListEmptyL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns whether the item storage is empty.
 */
int moho::cfunc_CMauiItemListEmptyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListEmptyHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  const int itemCount = GetItemListEntryCount(*itemListView);

  lua_pushboolean(state->m_state, itemCount == 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079BE10 (FUN_0079BE10, cfunc_CMauiItemListScrollToTop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListScrollToTopL`.
 */
int moho::cfunc_CMauiItemListScrollToTop(lua_State* const luaContext)
{
  return cfunc_CMauiItemListScrollToTopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BE30 (FUN_0079BE30, func_CMauiItemListScrollToTop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ScrollToTop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListScrollToTop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ScrollToTop",
    &moho::cfunc_CMauiItemListScrollToTop,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListScrollToTopHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BE90 (FUN_0079BE90, cfunc_CMauiItemListScrollToTopL)
 *
 * What it does:
 * Reads one `CMauiItemList` and scrolls to top.
 */
int moho::cfunc_CMauiItemListScrollToTopL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListScrollToTopHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  itemList->ScrollSetTop(kVerticalScrollAxis, 0.0f);
  return 0;
}

/**
 * Address: 0x0079BF40 (FUN_0079BF40, cfunc_CMauiListItemScrollToBottom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiListItemScrollToBottomL`.
 */
int moho::cfunc_CMauiListItemScrollToBottom(lua_State* const luaContext)
{
  return cfunc_CMauiListItemScrollToBottomL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BF60 (FUN_0079BF60, func_CMauiListItemScrollToBottom_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ScrollToBottom()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiListItemScrollToBottom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ScrollToBottom",
    &moho::cfunc_CMauiListItemScrollToBottom,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiListItemScrollToBottomHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BFC0 (FUN_0079BFC0, cfunc_CMauiListItemScrollToBottomL)
 *
 * What it does:
 * Reads one `CMauiItemList` and scrolls to bottom.
 */
int moho::cfunc_CMauiListItemScrollToBottomL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiListItemScrollToBottomHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  itemList->ScrollToBottom();
  return 0;
}

/**
 * Address: 0x0079C070 (FUN_0079C070, cfunc_CMauiItemListShowItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowItemL`.
 */
int moho::cfunc_CMauiItemListShowItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListShowItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C090 (FUN_0079C090, func_CMauiItemListShowItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowItem(index)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowItem",
    &moho::cfunc_CMauiItemListShowItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C0F0 (FUN_0079C0F0, cfunc_CMauiItemListShowItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus integer index and scrolls when that row is
 * outside the current visible range.
 */
int moho::cfunc_CMauiItemListShowItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListShowItemHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    itemList->ShowItem(index);
  }

  return 0;
}

/**
 * Address: 0x0079C200 (FUN_0079C200, cfunc_CMauiItemListGetRowHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetRowHeightL`.
 */
int moho::cfunc_CMauiItemListGetRowHeight(lua_State* const luaContext)
{
  return cfunc_CMauiItemListGetRowHeightL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C220 (FUN_0079C220, func_CMauiItemListGetRowHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetRowHeight()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetRowHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetRowHeight",
    &moho::cfunc_CMauiItemListGetRowHeight,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetRowHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C280 (FUN_0079C280, cfunc_CMauiItemListGetRowHeightL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns line height from font metrics.
 */
int moho::cfunc_CMauiItemListGetRowHeightL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListGetRowHeightHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  const CD3DFont* const font = itemListView->mFont;

  lua_pushnumber(state->m_state, font->mExternalLeading + font->mHeight);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079C4E0 (FUN_0079C4E0, cfunc_CMauiItemListShowMouseoverItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowMouseoverItemL`.
 */
int moho::cfunc_CMauiItemListShowMouseoverItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListShowMouseoverItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C500 (FUN_0079C500, func_CMauiItemListShowMouseoverItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowMouseoverItem(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowMouseoverItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowMouseoverItem",
    &moho::cfunc_CMauiItemListShowMouseoverItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowMouseoverItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C560 (FUN_0079C560, cfunc_CMauiItemListShowMouseoverItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus boolean and toggles hover-item highlight.
 */
int moho::cfunc_CMauiItemListShowMouseoverItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListShowMouseoverItemHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject flagArg(state, 2);
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  itemListView->mShowMouseoverItem = LuaPlus::LuaStackObject::GetBoolean(&flagArg);
  return 0;
}

/**
 * Address: 0x0079C620 (FUN_0079C620, cfunc_CMauiItemListShowSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListShowSelectionL`.
 */
int moho::cfunc_CMauiItemListShowSelection(lua_State* const luaContext)
{
  return cfunc_CMauiItemListShowSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C640 (FUN_0079C640, func_CMauiItemListShowSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ShowSelection(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListShowSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowSelection",
    &moho::cfunc_CMauiItemListShowSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListShowSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C6A0 (FUN_0079C6A0, cfunc_CMauiItemListShowSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus boolean and toggles selection highlight.
 */
int moho::cfunc_CMauiItemListShowSelectionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListShowSelectionHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject flagArg(state, 2);
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  itemListView->mShowSelection = LuaPlus::LuaStackObject::GetBoolean(&flagArg);
  return 0;
}

/**
 * Address: 0x0079C760 (FUN_0079C760, cfunc_CMauiItemListNeedsScrollBar)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListNeedsScrollBarL`.
 */
int moho::cfunc_CMauiItemListNeedsScrollBar(lua_State* const luaContext)
{
  return cfunc_CMauiItemListNeedsScrollBarL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C780 (FUN_0079C780, func_CMauiItemListNeedsScrollBar_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:NeedsScrollBar()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListNeedsScrollBar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "NeedsScrollBar",
    &moho::cfunc_CMauiItemListNeedsScrollBar,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListNeedsScrollBarHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C7E0 (FUN_0079C7E0, cfunc_CMauiItemListNeedsScrollBarL)
 *
 * What it does:
 * Reads one `CMauiItemList` and returns whether visible rows are fewer than
 * total item count.
 */
int moho::cfunc_CMauiItemListNeedsScrollBarL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListNeedsScrollBarHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  lua_pushboolean(state->m_state, itemList->NeedsScrollBar());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007994C0 (FUN_007994C0, sub_7994C0)
 *
 * What it does:
 * Releases list-item string storage and one intrusive font reference, then
 * continues base `CMauiControl` teardown.
 */
moho::CMauiItemList::~CMauiItemList()
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  itemListView->mItems = msvc8::vector<msvc8::string>{};
  ReleaseIntrusiveFont(itemListView->mFont);
}

/**
 * Address: 0x00799610 (FUN_00799610, Moho::CMauiItemList::SetFont)
 *
 * What it does:
 * Rebinds item-list font lane, falling back to default face/size when nil is
 * requested.
 */
void moho::CMauiItemList::SetFont(CD3DFont* const font)
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  if (font != nullptr) {
    AssignIntrusiveFont(itemListView->mFont, font);
    return;
  }

  boost::SharedPtrRaw<CD3DFont> defaultFont = CD3DFont::Create(16, "New Times Roman");
  AssignIntrusiveFont(itemListView->mFont, defaultFont.px);
  defaultFont.release();
}

/**
 * Address: 0x00799780 (FUN_00799780, Moho::CMauiItemList::ModifyItem)
 *
 * What it does:
 * Replaces one existing item string lane by index and throws when index is
 * out of range.
 */
void moho::CMauiItemList::ModifyItem(const std::uint32_t index, msvc8::string text)
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  msvc8::string* const itemBase = itemListView->mItems.data();
  const std::uint32_t itemCount = itemBase != nullptr ? static_cast<std::uint32_t>(itemListView->mItems.size()) : 0u;

  if (itemBase == nullptr || index >= itemCount) {
    throw std::runtime_error(
      gpg::STR_Printf("ModifyItem: index %u out of range; must be < %u", index, itemCount).c_str()
    );
  }

  itemBase[index] = text;
}

/**
 * Address: 0x00799940 (FUN_00799940, Moho::CMauiItemList::DeleteItem)
 *
 * What it does:
 * Removes one item lane by index and adjusts current selection to preserve
 * post-delete selection semantics.
 */
void moho::CMauiItemList::DeleteItem(const std::int32_t index)
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  if (index < 0) {
    return;
  }

  msvc8::string* const itemBase = itemListView->mItems.data();
  if (itemBase == nullptr || static_cast<std::size_t>(index) >= itemListView->mItems.size()) {
    return;
  }

  RemoveItemListEntryAtIndex(itemListView, index);
}

/**
 * Address: 0x00799870 (FUN_00799870, Moho::CMauiItemList::AddItem)
 *
 * What it does:
 * Appends one item string lane to the item-list storage vector.
 */
void moho::CMauiItemList::AddItem(msvc8::string text)
{
  CMauiItemListRuntimeView::FromItemList(this)->mItems.push_back(text);
}

/**
 * Address: 0x0079A0B0 (FUN_0079A0B0, Moho::CMauiItemList::GetItem)
 *
 * What it does:
 * Converts one Y-coordinate lane to an item index lane using top/scroll/font
 * metrics and returns `-1` when no item row is hit.
 */
std::int32_t moho::CMauiItemList::GetItem(const float yCoordinate)
{
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  const CD3DFont* const font = itemListView->mFont;

  const float localY = yCoordinate - CScriptLazyVar_float::GetValue(&itemListView->mTopLV);
  const float rowHeight = font->mExternalLeading + font->mHeight;

  const auto* const itemBase = itemListView->mItems.data();
  const std::int32_t rowIndex = itemListView->mScrollPosition + static_cast<std::int32_t>(localY / rowHeight);
  if (
    itemBase != nullptr
    && rowIndex >= 0
    && static_cast<std::size_t>(rowIndex) < itemListView->mItems.size()
    && font->mHeight > std::fmod(localY, rowHeight)
  ) {
    return rowIndex;
  }

  return -1;
}

/**
 * Address: 0x00799560 (FUN_00799560, Moho::CMauiItemList::Dump)
 *
 * What it does:
 * Logs item-list palette lanes and current-selection text state.
 */
void moho::CMauiItemList::Dump()
{
  CMauiControl::Dump();
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);

  gpg::Logf("CMauiItemList");
  gpg::Logf(
    "FG Color = %#08X BG Color = %#08X HLFG Color = %#08X HLBG Color = %#08X MOFG Color = %#08X MOBG Color = %#08X",
    itemListView->mForegroundColor,
    itemListView->mBackgroundColor,
    itemListView->mSelectedForegroundColor,
    itemListView->mSelectedBackgroundColor,
    itemListView->mHighlightForegroundColor,
    itemListView->mHighlightBackgroundColor
  );

  const std::int32_t curSelection = itemListView->mCurSelection;
  if (curSelection == -1) {
    gpg::Logf("Current Selection = %d Text = %s", curSelection, "");
    return;
  }

  const msvc8::string* const itemStorage = itemListView->mItems.data();
  const msvc8::string& selectedItem = itemStorage[curSelection];
  gpg::Logf("Current Selection = %d Text = %s", curSelection, selectedItem.c_str());
}

/**
 * Address: 0x0079A560 (FUN_0079A560, Moho::CMauiItemList::GetScrollValues)
 *
 * What it does:
 * Computes current item-list scroll extents and visible-range window.
 */
moho::SMauiScrollValues moho::CMauiItemList::GetScrollValues(const EMauiScrollAxis /*axis*/)
{
  const int visibleLineCount = LinesVisible();
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);

  SMauiScrollValues scrollValues{};
  scrollValues.mMinRange = 0.0f;
  scrollValues.mMaxRange = static_cast<float>(GetItemListEntryCount(*itemListView));
  scrollValues.mMinVisible = static_cast<float>(itemListView->mScrollPosition);
  scrollValues.mMaxVisible = static_cast<float>(itemListView->mScrollPosition + visibleLineCount);
  return scrollValues;
}

/**
 * Address: 0x0079A5F0 (FUN_0079A5F0, Moho::CMauiItemList::ScrollLines)
 *
 * What it does:
 * Applies line-scroll delta and clamps top-scroll lane to valid item-list
 * bounds.
 */
void moho::CMauiItemList::ScrollLines(const EMauiScrollAxis /*axis*/, const float amount)
{
  const int visibleLineCount = LinesVisible();
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  int clampedTop = GetItemListEntryCount(*itemListView) - visibleLineCount;

  const int lineDelta = static_cast<int>(std::nearbyintf(amount));
  const int candidateTop = itemListView->mScrollPosition + lineDelta;
  if (candidateTop < clampedTop) {
    clampedTop = candidateTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  itemListView->mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A6D0 (FUN_0079A6D0, Moho::CMauiItemList::ScrollSetTop)
 *
 * What it does:
 * Sets top-scroll lane from one absolute row index and clamps it to valid
 * item-list bounds.
 */
void moho::CMauiItemList::ScrollSetTop(const EMauiScrollAxis /*axis*/, const float amount)
{
  const int visibleLineCount = LinesVisible();
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  int clampedTop = GetItemListEntryCount(*itemListView) - visibleLineCount;

  const int requestedTop = static_cast<int>(std::nearbyintf(amount));
  if (requestedTop < clampedTop) {
    clampedTop = requestedTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  itemListView->mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A650 (FUN_0079A650, Moho::CMauiItemList::ScrollLines2)
 *
 * What it does:
 * Applies page-scroll delta (`amount * visible-row-count`) and clamps
 * top-scroll lane to `[0, itemCount - visibleLineCount]`.
 */
void moho::CMauiItemList::ScrollPages(const EMauiScrollAxis /*axis*/, const float amount)
{
  const int visibleLineCount = LinesVisible();
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  int clampedTop = GetItemListEntryCount(*itemListView) - visibleLineCount;

  const auto visibleLineCountUnsigned = static_cast<std::uint32_t>(visibleLineCount);
  const float scaledDelta = static_cast<float>(visibleLineCountUnsigned) * amount;
  const int pageDelta = static_cast<int>(std::nearbyintf(scaledDelta));
  const int candidateTop = itemListView->mScrollPosition + pageDelta;
  if (candidateTop < clampedTop) {
    clampedTop = candidateTop;
  }

  if (clampedTop < 0) {
    clampedTop = 0;
  }

  itemListView->mScrollPosition = clampedTop;
}

/**
 * Address: 0x0079A730 (FUN_0079A730, Moho::CMauiItemList::LinesVisible)
 *
 * What it does:
 * Computes one visible-row count from current control/font metrics and
 * clamps scroll-position lane against available item count.
 */
std::int32_t moho::CMauiItemList::LinesVisible()
{
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  const CD3DFont* const font = itemListView->mFont;
  const float controlHeight = CScriptLazyVar_float::GetValue(&itemListView->mHeightLV);
  const float lineHeight = font->mHeight + font->mExternalLeading;
  const float visibleLineRatio = (font->mExternalLeading + controlHeight) / lineHeight;
  const int visibleLineCount = static_cast<std::int32_t>(std::floor(visibleLineRatio));

  const int itemCount = GetItemListEntryCount(*itemListView);
  if (visibleLineCount > itemCount) {
    itemListView->mScrollPosition = 0;
    return itemCount;
  }

  if (visibleLineCount + itemListView->mScrollPosition > itemCount) {
    if (itemCount == 0) {
      itemListView->mScrollPosition = -visibleLineCount;
      return visibleLineCount;
    }
    itemListView->mScrollPosition = itemCount - visibleLineCount;
  }

  return visibleLineCount;
}

/**
 * Address: 0x0079A870 (FUN_0079A870, Moho::CMauiItemList::ScrollToBottom)
 *
 * What it does:
 * Scrolls to the bottommost list row by setting top-scroll to current
 * item count.
 */
void moho::CMauiItemList::ScrollToBottom()
{
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  const int itemCount = GetItemListEntryCount(*itemListView);
  ScrollSetTop(kVerticalScrollAxis, static_cast<float>(itemCount));
}

/**
 * Address: 0x0079A8C0 (FUN_0079A8C0, Moho::CMauiItemList::ShowItem)
 *
 * What it does:
 * Scrolls the item list so index is visible inside the current viewport.
 */
void moho::CMauiItemList::ShowItem(const std::int32_t index)
{
  const std::int32_t visibleLineCount = LinesVisible();
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  const std::int32_t scrollPosition = itemListView->mScrollPosition;
  if (index < scrollPosition || index >= (scrollPosition + visibleLineCount)) {
    ScrollSetTop(kVerticalScrollAxis, static_cast<float>(index));
  }
}

/**
 * Address: 0x0079A8F0 (FUN_0079A8F0, Moho::CMauiItemList::NeedsScrollBar)
 *
 * What it does:
 * Returns whether visible-row capacity is smaller than item count.
 */
bool moho::CMauiItemList::NeedsScrollBar()
{
  const int visibleLineCount = LinesVisible();
  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(this);
  return visibleLineCount < GetItemListEntryCount(*itemListView);
}

/**
 * Address: 0x0079B1E0 (FUN_0079B1E0, cfunc_CMauiItemListAddItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListAddItemL`.
 */
int moho::cfunc_CMauiItemListAddItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListAddItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B200 (FUN_0079B200, func_CMauiItemListAddItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:AddItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListAddItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddItem",
    &moho::cfunc_CMauiItemListAddItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListAddItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B260 (FUN_0079B260, cfunc_CMauiItemListAddItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus string arg and appends one item.
 */
int moho::cfunc_CMauiItemListAddItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListAddItemHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* itemText = lua_tostring(state->m_state, 2);
  if (itemText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    itemText = "";
  }

  itemList->AddItem(msvc8::string(itemText));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B370 (FUN_0079B370, cfunc_CMauiItemListModifyItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListModifyItemL`.
 */
int moho::cfunc_CMauiItemListModifyItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListModifyItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B390 (FUN_0079B390, func_CMauiItemListModifyItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ModifyItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListModifyItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ModifyItem",
    &moho::cfunc_CMauiItemListModifyItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListModifyItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B560 (FUN_0079B560, cfunc_CMauiItemListDeleteItem)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListDeleteItemL`.
 */
int moho::cfunc_CMauiItemListDeleteItem(lua_State* const luaContext)
{
  return cfunc_CMauiItemListDeleteItemL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B580 (FUN_0079B580, func_CMauiItemListDeleteItem_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:DeleteItem(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListDeleteItem_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DeleteItem",
    &moho::cfunc_CMauiItemListDeleteItem,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListDeleteItemHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B6E0 (FUN_0079B6E0, cfunc_CMauiItemListDeleteAllItems)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListDeleteAllItemsL`.
 */
int moho::cfunc_CMauiItemListDeleteAllItems(lua_State* const luaContext)
{
  return cfunc_CMauiItemListDeleteAllItemsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B700 (FUN_0079B700, func_CMauiItemListDeleteAllItems_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:DeleteAllItems()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListDeleteAllItems_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DeleteAllItems",
    &moho::cfunc_CMauiItemListDeleteAllItems,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListDeleteAllItemsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B840 (FUN_0079B840, cfunc_CMauiItemListGetSelection)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetSelectionL`.
 */
int moho::cfunc_CMauiItemListGetSelection(lua_State* const luaContext)
{
  return cfunc_CMauiItemListGetSelectionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079B860 (FUN_0079B860, func_CMauiItemListGetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetSelection()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSelection",
    &moho::cfunc_CMauiItemListGetSelection,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079B3F0 (FUN_0079B3F0, cfunc_CMauiItemListModifyItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus `(index,text)` and updates one list item
 * when the provided index is non-negative.
 */
int moho::cfunc_CMauiItemListModifyItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListModifyItemHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    LuaPlus::LuaStackObject textArg(state, 3);
    const char* itemText = lua_tostring(state->m_state, 3);
    if (itemText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textArg, "string");
      itemText = "";
    }

    itemList->ModifyItem(static_cast<std::uint32_t>(index), msvc8::string(itemText));
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B5E0 (FUN_0079B5E0, cfunc_CMauiItemListDeleteItemL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus one index and deletes that item when index
 * is non-negative.
 */
int moho::cfunc_CMauiItemListDeleteItemL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListDeleteItemHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject indexArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }
  const int index = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (index >= 0) {
    itemList->DeleteItem(index);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B760 (FUN_0079B760, cfunc_CMauiItemListDeleteAllItemsL)
 *
 * What it does:
 * Clears all item lanes and resets current selection to no-selection.
 */
int moho::cfunc_CMauiItemListDeleteAllItemsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListDeleteAllItemsHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);

  itemListView->mItems.clear();
  itemListView->mCurSelection = -1;

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079B8C0 (FUN_0079B8C0, cfunc_CMauiItemListGetSelectionL)
 *
 * What it does:
 * Reads one `CMauiItemList` and pushes current selected-index lane.
 */
int moho::cfunc_CMauiItemListGetSelectionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListGetSelectionHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(CMauiItemListRuntimeView::FromItemList(itemList)->mCurSelection));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079C350 (FUN_0079C350, cfunc_CMauiItemListGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiItemListGetStringAdvanceL`.
 */
int moho::cfunc_CMauiItemListGetStringAdvance(lua_State* const luaContext)
{
  return cfunc_CMauiItemListGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079C370 (FUN_0079C370, func_CMauiItemListGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiItemListGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiItemListGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiItemListGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079C3D0 (FUN_0079C3D0, cfunc_CMauiItemListGetStringAdvanceL)
 *
 * What it does:
 * Reads one `CMauiItemList` plus string arg and returns measured text
 * advance from the item-list font lane.
 */
int moho::cfunc_CMauiItemListGetStringAdvanceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiItemListGetStringAdvanceHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  const CMauiItemListRuntimeView* const itemListView = CMauiItemListRuntimeView::FromItemList(itemList);
  CD3DFont* const font = itemListView->mFont;
  const float advance = font != nullptr ? font->GetAdvance(text, 0) : 0.0f;
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079DF40 (FUN_0079DF40, Moho::CMauiMesh::SetMesh)
 *
 * What it does:
 * Resolves one mesh blueprint from active world rules and updates the mesh
 * control runtime lanes.
 */
void moho::CMauiMesh::SetMesh(const char* const meshBlueprintName)
{
  CWldSession* const worldSession = WLD_GetActiveSession();
  if (worldSession == nullptr) {
    return;
  }

  RResId meshId{};
  gpg::STR_InitFilename(&meshId.name, meshBlueprintName != nullptr ? meshBlueprintName : "");

  CMauiMeshRuntimeView* const meshView = CMauiMeshRuntimeView::FromMesh(this);
  meshView->mMeshBlueprint = worldSession->mRules->GetMeshBlueprint(meshId);
  meshView->mIsRotated = true;
}

/**
 * Address: 0x0079E430 (FUN_0079E430, Moho::CMauiMesh::Draw)
 *
 * What it does:
 * Binds current mesh texture lane and draws one fullscreen quad over this
 * control rectangle with fixed UV mapping.
 */
void moho::CMauiMesh::Draw(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  (void)drawMask;
  const CMauiMeshRuntimeView* const meshView = CMauiMeshRuntimeView::FromMesh(this);

  const float left = CScriptLazyVar_float::GetValue(&meshView->mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&meshView->mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&meshView->mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&meshView->mBottomLV);

  primBatcher->SetTexture(meshView->mTexture);

  CD3DPrimBatcher::Vertex topLeft{};
  topLeft.mX = left;
  topLeft.mY = top;
  topLeft.mZ = 0.0f;
  topLeft.mColor = 0xFFFFFFFFu;
  topLeft.mU = 0.0f;
  topLeft.mV = 0.0f;

  CD3DPrimBatcher::Vertex topRight{};
  topRight.mX = right;
  topRight.mY = top;
  topRight.mZ = 0.0f;
  topRight.mColor = 0xFFFFFFFFu;
  topRight.mU = 1.0f;
  topRight.mV = 0.0f;

  CD3DPrimBatcher::Vertex bottomRight{};
  bottomRight.mX = right;
  bottomRight.mY = bottom;
  bottomRight.mZ = 0.0f;
  bottomRight.mColor = 0xFFFFFFFFu;
  bottomRight.mU = 1.0f;
  bottomRight.mV = 1.0f;

  CD3DPrimBatcher::Vertex bottomLeft{};
  bottomLeft.mX = left;
  bottomLeft.mY = bottom;
  bottomLeft.mZ = 0.0f;
  bottomLeft.mColor = 0xFFFFFFFFu;
  bottomLeft.mU = 0.0f;
  bottomLeft.mV = 1.0f;

  primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
}

/**
 * Address: 0x0079E930 (FUN_0079E930, cfunc_CMauiMeshSetOrientationL)
 *
 * What it does:
 * Stores one new orientation quaternion and enables mesh-rotation runtime
 * lane updates.
 */
void moho::CMauiMesh::SetOrientation(const Wm3::Quaternionf& orientation)
{
  CMauiMeshRuntimeView* const meshView = CMauiMeshRuntimeView::FromMesh(this);
  meshView->mOrientation = orientation;
  meshView->mIsRotated = true;
}

/**
 * Address: 0x0079E740 (FUN_0079E740, cfunc_CMauiMeshSetMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMeshSetMeshL`.
 */
int moho::cfunc_CMauiMeshSetMesh(lua_State* const luaContext)
{
  return cfunc_CMauiMeshSetMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E760 (FUN_0079E760, func_CMauiMeshSetMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMesh:SetMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMeshSetMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetMesh",
    &moho::cfunc_CMauiMeshSetMesh,
    &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
    "CMauiMesh",
    kCMauiMeshSetMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079E7C0 (FUN_0079E7C0, cfunc_CMauiMeshSetMeshL)
 *
 * What it does:
 * Reads one `CMauiMesh` plus mesh-path string and calls `SetMesh`.
 */
int moho::cfunc_CMauiMeshSetMeshL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMeshSetMeshHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject meshObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMesh* const mesh = SCR_FromLua_CMauiMesh(meshObject, state);

  LuaPlus::LuaStackObject meshArg(state, 2);
  const char* meshBlueprintName = lua_tostring(state->m_state, 2);
  if (meshBlueprintName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&meshArg, "string");
    meshBlueprintName = "";
  }

  mesh->SetMesh(meshBlueprintName);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079E8B0 (FUN_0079E8B0, cfunc_CMauiMeshSetOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMeshSetOrientationL`.
 */
int moho::cfunc_CMauiMeshSetOrientation(lua_State* const luaContext)
{
  return cfunc_CMauiMeshSetOrientationL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E8D0 (FUN_0079E8D0, func_CMauiMeshSetOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMesh:SetOrientation(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMeshSetOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetOrientation",
    &moho::cfunc_CMauiMeshSetOrientation,
    &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
    "CMauiMesh",
    kCMauiMeshSetOrientationHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079E930 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMesh` plus quaternion arg and stores mesh orientation.
 */
int moho::cfunc_CMauiMeshSetOrientationL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMeshSetOrientationHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject meshObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMesh* const mesh = SCR_FromLua_CMauiMesh(meshObject, state);

  const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Quaternionf orientation = SCR_FromLuaCopy<Wm3::Quaternionf>(orientationObject);
  mesh->SetOrientation(orientation);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079EE20 (FUN_0079EE20, Moho::CMauiMovie::CMauiMovie)
 *
 * What it does:
 * Constructs one movie control and initializes movie playback/subtitle/lazy-var
 * runtime lanes.
 */
moho::CMauiMovie::CMauiMovie(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "Movie")
{
  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  movieView->mMovie = nullptr;
  movieView->mIsPlaying = false;
  movieView->mDoLoop = false;
  movieView->mIsStopped = false;
  movieView->mIsMinimized = false;

  new (&movieView->mSubtitleCache) msvc8::string();
  new (&movieView->mMovieWidthLV) CScriptLazyVar_float(luaObject->m_state);
  new (&movieView->mMovieHeightLV) CScriptLazyVar_float(luaObject->m_state);

  LuaPlus::LuaObject& controlLuaObject = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj;
  controlLuaObject.SetObject("MovieWidth", AsLazyVarObject(movieView->mMovieWidthLV));
  controlLuaObject.SetObject("MovieHeight", AsLazyVarObject(movieView->mMovieHeightLV));
}

/**
 * Address: 0x0079F1C0 (FUN_0079F1C0, Moho::CMauiMovie::OnFrame)
 *
 * What it does:
 * Advances movie playback state and dispatches movie script callbacks.
 */
void moho::CMauiMovie::Frame(const float deltaSeconds)
{
  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  if (movieView->mIsMinimized) {
    return;
  }

  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  if (!movieView->mIsPlaying) {
    CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = false;
    (void)scriptObject->RunScript("OnFinished");
    return;
  }

  scriptObject->RunScriptNum("OnFrame", deltaSeconds);

  if (movieView->mIsStopped) {
    CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = false;
    (void)scriptObject->RunScript("OnStopped");
    return;
  }

  CMoviePlaybackInterface* const moviePlayback = movieView->mMovie;
  if (moviePlayback == nullptr) {
    return;
  }

  if (moviePlayback->HasPlaybackFinished()) {
    if (movieView->mDoLoop) {
      moviePlayback->RestartMovie();
    } else {
      movieView->mIsPlaying = false;
      CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = false;
      (void)scriptObject->RunScript("OnFinished");
    }
    return;
  }

  moviePlayback->StepPlayback();

  const msvc8::string* const subtitle = moviePlayback->GetSubtitleText();
  if (subtitle != nullptr && movieView->mSubtitleCache.view() != subtitle->view()) {
    movieView->mSubtitleCache.assign_owned(subtitle->view());
    const char* subtitleText = subtitle->c_str();
    scriptObject->CallbackStr("OnSubtitle", &subtitleText);
  }
}

/**
 * Address: 0x0079F310 (FUN_0079F310, Moho::CMauiMovie::Draw)
 *
 * What it does:
 * Draws one movie texture quad when playback is active.
 */
void moho::CMauiMovie::DoRender(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  (void)drawMask;

  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  CMoviePlaybackInterface* const moviePlayback = movieView->mMovie;
  if (moviePlayback == nullptr || !movieView->mIsPlaying) {
    return;
  }

  const CMauiControlRuntimeView* const controlView = CMauiControlRuntimeView::FromControl(this);
  const float left = CScriptLazyVar_float::GetValue(&controlView->mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&controlView->mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&controlView->mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&controlView->mBottomLV);

  boost::shared_ptr<CD3DBatchTexture> movieTexture{};
  moviePlayback->GetTexture(&movieTexture);
  primBatcher->SetTexture(movieTexture);

  const float textureU = movieView->mTextureU;

  CD3DPrimBatcher::Vertex topLeft{};
  topLeft.mX = left;
  topLeft.mY = top;
  topLeft.mZ = 0.0f;
  topLeft.mColor = 0;
  topLeft.mU = textureU;
  topLeft.mV = 0.0f;

  CD3DPrimBatcher::Vertex topRight{};
  topRight.mX = right;
  topRight.mY = top;
  topRight.mZ = 0.0f;
  topRight.mColor = 0;
  topRight.mU = textureU;
  topRight.mV = 1.0f;

  CD3DPrimBatcher::Vertex bottomRight{};
  bottomRight.mX = right;
  bottomRight.mY = bottom;
  bottomRight.mZ = 0.0f;
  bottomRight.mColor = 0;
  bottomRight.mU = textureU;
  bottomRight.mV = 1.0f;

  CD3DPrimBatcher::Vertex bottomLeft{};
  bottomLeft.mX = left;
  bottomLeft.mY = bottom;
  bottomLeft.mZ = 0.0f;
  bottomLeft.mColor = 0;
  bottomLeft.mU = textureU;
  bottomLeft.mV = 0.0f;

  primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
}

/**
 * Address: 0x0079F490 (FUN_0079F490, Moho::CMauiMovie::OnMinimized)
 *
 * What it does:
 * Stops active movie playback while minimized and resumes playback when the
 * control is restored from minimized state.
 */
void moho::CMauiMovie::OnMinimized(const bool minimized)
{
  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);

  if (minimized) {
    if (movieView->mIsPlaying && !movieView->mIsStopped) {
      CMoviePlaybackInterface* const moviePlayback = movieView->mMovie;
      if (moviePlayback != nullptr) {
        moviePlayback->StopMovie();
        movieView->mIsMinimized = true;
        CMauiControl::OnMinimized(minimized);
        return;
      }
    }
  } else if (movieView->mIsMinimized) {
    movieView->mMovie->PlayMovie();
    movieView->mIsMinimized = false;
  }

  CMauiControl::OnMinimized(minimized);
}

/**
 * Address: 0x0079F8F0 (FUN_0079F8F0, cfunc_CMauiMovieLoopL)
 *
 * What it does:
 * Updates the movie loop flag lane used by playback runtime.
 */
void moho::CMauiMovie::Loop(const bool shouldLoop)
{
  CMauiMovieRuntimeView::FromMovie(this)->mDoLoop = shouldLoop;
}

/**
 * Address: 0x0079FA40 (FUN_0079FA40, cfunc_CMauiMoviePlayL)
 *
 * What it does:
 * Starts attached movie playback and updates control frame-update lanes.
 */
void moho::CMauiMovie::Play()
{
  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  CMoviePlaybackInterface* const moviePlayback = movieView->mMovie;

  movieView->mIsPlaying = false;
  CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = true;
  if (moviePlayback != nullptr) {
    moviePlayback->PlayMovie();
    movieView->mIsPlaying = true;
    movieView->mIsStopped = false;
  }
}

/**
 * Address: 0x0079FBA0 (FUN_0079FBA0, cfunc_CMauiMovieStopL)
 *
 * What it does:
 * Stops attached movie playback and records stopped state.
 */
void moho::CMauiMovie::Stop()
{
  CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  CMoviePlaybackInterface* const moviePlayback = movieView->mMovie;
  if (moviePlayback != nullptr) {
    movieView->mIsStopped = true;
    moviePlayback->StopMovie();
  }
}

/**
 * Address: 0x0079FCF0 (FUN_0079FCF0, cfunc_CMauiMovieIsLoadedL)
 *
 * What it does:
 * Returns whether the attached movie resource exists and is loaded.
 */
bool moho::CMauiMovie::IsLoaded() const
{
  const CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  return movieView->mMovie != nullptr && movieView->mMovie->IsLoaded();
}

/**
 * Address: 0x0079FE50 (FUN_0079FE50, cfunc_CMauiMovieGetNumFramesL)
 *
 * What it does:
 * Returns frame count from attached movie playback resource.
 */
std::int32_t moho::CMauiMovie::GetNumFrames() const
{
  return CMauiMovieRuntimeView::FromMovie(this)->mMovie->GetFrameCount();
}

/**
 * Address: 0x0079FFA0 (FUN_0079FFA0, cfunc_CMauiMovieGetFrameRateL)
 *
 * What it does:
 * Returns playback framerate from attached movie resource.
 */
float moho::CMauiMovie::GetFrameRate() const
{
  return CMauiMovieRuntimeView::FromMovie(this)->mMovie->GetFrameRate();
}

/**
 * Address: 0x0079F500 (FUN_0079F500, Moho::CMauiMovie::Dump)
 *
 * What it does:
 * Logs this movie control label and current `mIsPlaying` state.
 */
void moho::CMauiMovie::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiMovie");

  const CMauiMovieRuntimeView* const movieView = CMauiMovieRuntimeView::FromMovie(this);
  const char* const isPlaying = movieView->mIsPlaying ? "true" : "false";
  gpg::Logf("Is Playing = %s", isPlaying);
}

/**
 * Address: 0x0079F6F0 (FUN_0079F6F0, cfunc_CMauiMovieInternalSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieInternalSetL`.
 */
int moho::cfunc_CMauiMovieInternalSet(lua_State* const luaContext)
{
  return cfunc_CMauiMovieInternalSetL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F710 (FUN_0079F710, func_CMauiMovieInternalSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:InternalSet(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieInternalSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalSet",
    &moho::cfunc_CMauiMovieInternalSet,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieInternalSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079F770 (FUN_0079F770, cfunc_CMauiMovieInternalSetL)
 *
 * What it does:
 * Reads one `CMauiMovie` plus filename string, calls `LoadFile`, and returns
 * one boolean success lane.
 */
int moho::cfunc_CMauiMovieInternalSetL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieInternalSetHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);

  LuaPlus::LuaStackObject filenameArg(state, 2);
  const char* filename = lua_tostring(state->m_state, 2);
  if (filename == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&filenameArg, "string");
    filename = "";
  }

  const bool loaded = movie->LoadFile(filename);
  lua_pushboolean(state->m_state, loaded);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079F870 (FUN_0079F870, cfunc_CMauiMovieLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieLoopL`.
 */
int moho::cfunc_CMauiMovieLoop(lua_State* const luaContext)
{
  return cfunc_CMauiMovieLoopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F890 (FUN_0079F890, func_CMauiMovieLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Loop(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Loop",
    &moho::cfunc_CMauiMovieLoop,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieLoopHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079F8F0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` plus bool and updates loop state.
 */
int moho::cfunc_CMauiMovieLoopL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieLoopHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);

  LuaPlus::LuaStackObject loopArg(state, 2);
  movie->Loop(loopArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079F9C0 (FUN_0079F9C0, cfunc_CMauiMoviePlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMoviePlayL`.
 */
int moho::cfunc_CMauiMoviePlay(lua_State* const luaContext)
{
  return cfunc_CMauiMoviePlayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F9E0 (FUN_0079F9E0, func_CMauiMoviePlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Play()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMoviePlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Play",
    &moho::cfunc_CMauiMoviePlay,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMoviePlayHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079FA40 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and starts playback.
 */
int moho::cfunc_CMauiMoviePlayL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMoviePlayHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  movie->Play();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079FB20 (FUN_0079FB20, cfunc_CMauiMovieStop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieStopL`.
 */
int moho::cfunc_CMauiMovieStop(lua_State* const luaContext)
{
  return cfunc_CMauiMovieStopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FB40 (FUN_0079FB40, func_CMauiMovieStop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Stop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieStop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Stop",
    &moho::cfunc_CMauiMovieStop,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieStopHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079FBA0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and stops playback.
 */
int moho::cfunc_CMauiMovieStopL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieStopHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  movie->Stop();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079FC70 (FUN_0079FC70, cfunc_CMauiMovieIsLoaded)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieIsLoadedL`.
 */
int moho::cfunc_CMauiMovieIsLoaded(lua_State* const luaContext)
{
  return cfunc_CMauiMovieIsLoadedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FC90 (FUN_0079FC90, func_CMauiMovieIsLoaded_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:IsLoaded()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieIsLoaded_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsLoaded",
    &moho::cfunc_CMauiMovieIsLoaded,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieIsLoadedHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079FCF0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns whether it has loaded movie content.
 */
int moho::cfunc_CMauiMovieIsLoadedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieIsLoadedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushboolean(state->m_state, movie->IsLoaded());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079FDD0 (FUN_0079FDD0, cfunc_CMauiMovieGetNumFrames)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieGetNumFramesL`.
 */
int moho::cfunc_CMauiMovieGetNumFrames(lua_State* const luaContext)
{
  return cfunc_CMauiMovieGetNumFramesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FDF0 (FUN_0079FDF0, func_CMauiMovieGetNumFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:GetNumFrames()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieGetNumFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetNumFrames",
    &moho::cfunc_CMauiMovieGetNumFrames,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieGetNumFramesHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079FE50 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns frame-count numeric result.
 */
int moho::cfunc_CMauiMovieGetNumFramesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieGetNumFramesHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushnumber(state->m_state, static_cast<float>(movie->GetNumFrames()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079FF20 (FUN_0079FF20, cfunc_CMauiMovieGetFrameRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieGetFrameRateL`.
 */
int moho::cfunc_CMauiMovieGetFrameRate(lua_State* const luaContext)
{
  return cfunc_CMauiMovieGetFrameRateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FF40 (FUN_0079FF40, func_CMauiMovieGetFrameRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:GetFrameRate()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieGetFrameRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFrameRate",
    &moho::cfunc_CMauiMovieGetFrameRate,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieGetFrameRateHelpText
  );
  return &binder;
}

/**
  * Alias of FUN_0079FFA0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns frame-rate numeric result.
 */
int moho::cfunc_CMauiMovieGetFrameRateL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiMovieGetFrameRateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushnumber(state->m_state, movie->GetFrameRate());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A04B0 (FUN_007A04B0, Moho::CMauiScrollbar::CMauiScrollbar)
 *
 * What it does:
 * Constructs one scrollbar control from Lua object + parent lanes and
 * initializes draggable/texture/axis runtime state lanes.
 */
moho::CMauiScrollbar::CMauiScrollbar(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent,
  const EMauiScrollAxis axis
)
  : CMauiControl(luaObject, parent, "scrollbar")
{
  CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(this);
  scrollbarView->mDraggerList = 0;
  scrollbarView->mScrollableLink = {};
  scrollbarView->mThumbTop = {};
  scrollbarView->mThumbBottom = {};
  scrollbarView->mThumbMiddle = {};
  scrollbarView->mBackground = {};
  scrollbarView->mDragStart = 0.0f;
  scrollbarView->mTopAtDragStart = 0.0f;
  scrollbarView->mAxis = axis;
}

/**
 * Address: 0x007A0740 (FUN_007A0740, Moho::CMauiScrollbar::SetTextures)
 *
 * What it does:
 * Replaces any non-null scrollbar texture lanes (background, thumb-middle,
 * thumb-top, thumb-bottom).
 */
void moho::CMauiScrollbar::SetTextures(
  const boost::shared_ptr<CD3DBatchTexture>& background,
  const boost::shared_ptr<CD3DBatchTexture>& thumbMiddle,
  const boost::shared_ptr<CD3DBatchTexture>& thumbTop,
  const boost::shared_ptr<CD3DBatchTexture>& thumbBottom
)
{
  CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(this);

  if (background.get() != nullptr) {
    scrollbarView->mBackground = background;
  }
  if (thumbMiddle.get() != nullptr) {
    scrollbarView->mThumbMiddle = thumbMiddle;
  }
  if (thumbTop.get() != nullptr) {
    scrollbarView->mThumbTop = thumbTop;
  }
  if (thumbBottom.get() != nullptr) {
    scrollbarView->mThumbBottom = thumbBottom;
  }
}

/**
 * Address: 0x007A11C0 (FUN_007A11C0, Moho::CMauiScrollbar::HandleEvent)
 *
 * What it does:
 * Handles click/wheel scrollbar interaction lanes by translating mouse
 * position to page-step or drag-capture behavior on the bound scroll target.
 */
bool moho::CMauiScrollbar::HandleEvent(const SMauiEventData& eventData)
{
  const EMauiEventType eventType = eventData.mEventType;
  CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(this);
  CMauiControl* const scrollableControl = scrollbarView->ResolveScrollableControl();

  if ((eventType == MET_ButtonPress || eventType == MET_ButtonDClick) && eventData.mKeyCode == kPostDraggerLeftButton) {
    if (scrollableControl != nullptr) {
      const EMauiScrollAxis axis = scrollbarView->mAxis;
      const CMauiControlRuntimeView* const controlView = CMauiControlRuntimeView::FromControl(this);

      const CScriptLazyVar_float* topLane = &controlView->mTopLV;
      const CScriptLazyVar_float* bottomLane = &controlView->mBottomLV;
      if (axis != MSA_Vert) {
        topLane = &controlView->mRightLV;
        bottomLane = &controlView->mLeftLV;
      }

      const float topEdge = CScriptLazyVar_float::GetValue(topLane);
      const float bottomEdge = CScriptLazyVar_float::GetValue(bottomLane);
      const float mousePosition = axis == MSA_Vert ? eventData.mMousePos.y : eventData.mMousePos.x;

      const SMauiScrollValues scrollValues = scrollableControl->GetScrollValues(axis);
      const float minRange = scrollValues.mMinRange;
      const float maxRange = scrollValues.mMaxRange;
      const float minVisible = scrollValues.mMinVisible;

      float thumbStart = topEdge;
      float thumbEnd = bottomEdge;
      if (maxRange > minRange) {
        const float trackSpan = bottomEdge - topEdge;
        const float rangeSpan = maxRange - minRange;
        thumbStart = (((scrollValues.mMinVisible - minRange) / rangeSpan) * trackSpan) + topEdge;
        thumbEnd = (((scrollValues.mMaxVisible - minRange) / rangeSpan) * trackSpan) + topEdge;
      }

      if (topEdge <= mousePosition) {
        if (thumbStart > mousePosition) {
          scrollableControl->ScrollPages(axis, -1.0f);
          return true;
        }

        if (thumbEnd > mousePosition) {
          scrollbarView->mDragStart = mousePosition;
          scrollbarView->mTopAtDragStart = minVisible;
          SMauiEventData mutableEventData = eventData;
          func_PostDragger(GetRootFrame(), static_cast<moho::IMauiDragger*>(this), &mutableEventData);
          return true;
        }

        if (bottomEdge > mousePosition) {
          scrollableControl->ScrollPages(axis, 1.0f);
        }
      }
    }

    return true;
  }

  if (eventType != MET_WheelRotation) {
    return false;
  }

  if (scrollableControl != nullptr && scrollbarView->mAxis == MSA_Vert) {
    const float lineDelta = eventData.mWheelRotation <= 0 ? 1.0f : -1.0f;
    scrollableControl->ScrollLines(MSA_Vert, lineDelta);
  }

  return true;
}

/**
 * Address: 0x007A1410 (FUN_007A1410, Moho::CMauiScrollbar::DragMove)
 *
 * What it does:
 * Converts mouse drag delta into scroll-range displacement and updates
 * `ScrollSetTop` on the attached scrollable control.
 */
void moho::CMauiScrollbar::DragMove(const SMauiEventData* const eventData)
{
  CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(this);
  CMauiControl* const scrollableControl = scrollbarView->ResolveScrollableControl();
  if (scrollableControl == nullptr) {
    return;
  }

  const EMauiScrollAxis axis = scrollbarView->mAxis;
  const float mousePosition = axis == MSA_Vert ? eventData->mMousePos.y : eventData->mMousePos.x;
  const float delta = mousePosition - scrollbarView->mDragStart;

  const SMauiScrollValues scrollValues = scrollableControl->GetScrollValues(axis);
  const float minRange = scrollValues.mMinRange;
  const float maxRange = scrollValues.mMaxRange;

  const CMauiControlRuntimeView* const controlView = CMauiControlRuntimeView::FromControl(this);
  const float bottom = CScriptLazyVar_float::GetValue(&controlView->mBottomLV);
  const float top = CScriptLazyVar_float::GetValue(&controlView->mTopLV);
  const float rangePerPixel = (maxRange - minRange) / (bottom - top);

  scrollableControl->ScrollSetTop(axis, (rangePerPixel * delta) + scrollbarView->mTopAtDragStart);
}

/**
 * Address: 0x007A1500 (FUN_007A1500, Moho::CMauiScrollbar::DragRelease)
 *
 * What it does:
 * No-op drag release hook for the scrollbar dragger lane.
 */
void moho::CMauiScrollbar::DragRelease(const SMauiEventData* const)
{
}

/**
 * Address: 0x007A1510 (FUN_007A1510, Moho::CMauiScrollbar::DragCancel)
 *
 * What it does:
 * No-op replacement/cancel hook for the scrollbar dragger lane.
 */
void moho::CMauiScrollbar::OnCurrentDraggerReplaced()
{
}

/**
 * Address: 0x007A17A0 (FUN_007A17A0, cfunc_CMauiScrollbarSetScrollable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarSetScrollableL`.
 */
int moho::cfunc_CMauiScrollbarSetScrollable(lua_State* const luaContext)
{
  return cfunc_CMauiScrollbarSetScrollableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A17C0 (FUN_007A17C0, func_CMauiScrollbarSetScrollable_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:SetScrollable(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarSetScrollable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetScrollable",
    &moho::cfunc_CMauiScrollbarSetScrollable,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarSetScrollableHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A1820 (FUN_007A1820, cfunc_CMauiScrollbarSetScrollableL)
 *
 * What it does:
 * Reads one scrollbar and one control and binds scroll target link lanes.
 */
int moho::cfunc_CMauiScrollbarSetScrollableL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiScrollbarSetScrollableHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  const LuaPlus::LuaObject scrollableObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const scrollableControl = SCR_FromLua_CMauiControl(scrollableObject, state);

  CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(scrollbar);
  SetCurrentFocusControlLink(&scrollbarView->mScrollableLink, scrollableControl);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A1920 (FUN_007A1920, cfunc_CMauiScrollbarSetNewTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarSetNewTexturesL`.
 */
int moho::cfunc_CMauiScrollbarSetNewTextures(lua_State* const luaContext)
{
  return cfunc_CMauiScrollbarSetNewTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A1940 (FUN_007A1940, func_CMauiScrollbarSetNewTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:SetNewTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarSetNewTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewTextures",
    &moho::cfunc_CMauiScrollbarSetNewTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarSetNewTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A19A0 (FUN_007A19A0, cfunc_CMauiScrollbarSetNewTexturesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus four optional texture-path lanes and
 * forwards resolved textures (with warning-color fallbacks) to
 * `CMauiScrollbar::SetTextures`.
 */
int moho::cfunc_CMauiScrollbarSetNewTexturesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiScrollbarSetNewTexturesHelpText, 5, argumentCount);
  }

  LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  const auto loadOptionalTexture = [state](const int index, const char* const laneName) -> boost::shared_ptr<CD3DBatchTexture> {
    if (lua_type(state->m_state, index) == LUA_TNIL) {
      return {};
    }

    LuaPlus::LuaStackObject textureArg(state, index);
    const char* texturePath = lua_tostring(state->m_state, index);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(texturePath, 1u);
    if (texture.get() == nullptr) {
      gpg::Warnf("Scrollbar:SetTextures couldn't load %s: %s", laneName, texturePath);
      texture = CD3DBatchTexture::FromSolidColor(0xFFAAAA00u);
    }

    return texture;
  };

  const boost::shared_ptr<CD3DBatchTexture> backgroundTexture = loadOptionalTexture(2, "background");
  const boost::shared_ptr<CD3DBatchTexture> thumbMiddleTexture = loadOptionalTexture(3, "thumbMiddle");
  const boost::shared_ptr<CD3DBatchTexture> thumbTopTexture = loadOptionalTexture(4, "thumbTop");
  const boost::shared_ptr<CD3DBatchTexture> thumbBottomTexture = loadOptionalTexture(5, "thumbBottom");

  scrollbar->SetTextures(backgroundTexture, thumbMiddleTexture, thumbTopTexture, thumbBottomTexture);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A2080 (FUN_007A2080, cfunc_CMauiScrollbarDoScrollLines)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarDoScrollLinesL`.
 */
int moho::cfunc_CMauiScrollbarDoScrollLines(lua_State* const luaContext)
{
  return cfunc_CMauiScrollbarDoScrollLinesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A20A0 (FUN_007A20A0, func_CMauiScrollbarDoScrollLines_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:DoScrollLines(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarDoScrollLines_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DoScrollLines",
    &moho::cfunc_CMauiScrollbarDoScrollLines,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarDoScrollLinesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A2100 (FUN_007A2100, cfunc_CMauiScrollbarDoScrollLinesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus numeric amount and forwards line-scroll to
 * its current scrollable control lane.
 */
int moho::cfunc_CMauiScrollbarDoScrollLinesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiScrollbarDoScrollLinesHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  const CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(scrollbar);
  if (CMauiControl* const scrollableControl = scrollbarView->ResolveScrollableControl()) {
    LuaPlus::LuaStackObject amountArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&amountArg, "number");
    }

    const float amount = static_cast<float>(lua_tonumber(state->m_state, 2));
    scrollableControl->ScrollLines(scrollbarView->mAxis, amount);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A2220 (FUN_007A2220, cfunc_CMauiScrollbarDoScrollPages)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarDoScrollPagesL`.
 */
int moho::cfunc_CMauiScrollbarDoScrollPages(lua_State* const luaContext)
{
  return cfunc_CMauiScrollbarDoScrollPagesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A2240 (FUN_007A2240, func_CMauiScrollbarDoScrollPages_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:DoScrollPages(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarDoScrollPages_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DoScrollPages",
    &moho::cfunc_CMauiScrollbarDoScrollPages,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarDoScrollPagesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A22A0 (FUN_007A22A0, cfunc_CMauiScrollbarDoScrollPagesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus numeric amount and forwards page-scroll to
 * its current scrollable control lane.
 */
int moho::cfunc_CMauiScrollbarDoScrollPagesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiScrollbarDoScrollPagesHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  const CMauiScrollbarRuntimeView* const scrollbarView = CMauiScrollbarRuntimeView::FromScrollbar(scrollbar);
  if (CMauiControl* const scrollableControl = scrollbarView->ResolveScrollableControl()) {
    LuaPlus::LuaStackObject amountArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&amountArg, "number");
    }

    const float amount = static_cast<float>(lua_tonumber(state->m_state, 2));
    scrollableControl->ScrollPages(scrollbarView->mAxis, amount);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A2EA0 (FUN_007A2EA0, Moho::CMauiText::SetNewFont)
 *
 * What it does:
 * Rebinds text font lane and refreshes cached text/font metric lazy-vars.
 */
void moho::CMauiText::SetNewFont(CD3DFont* const font)
{
  CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(this);
  AssignIntrusiveFont(textView->mFont, font);

  if (textView->mFont != nullptr) {
    const float advance = textView->mFont->GetAdvance(textView->mText.c_str(), 0);
    CScriptLazyVar_float::SetValue(&textView->mTextAdvanceLV, advance);
    CScriptLazyVar_float::SetValue(&textView->mFontAscentLV, textView->mFont->mAscent);
    CScriptLazyVar_float::SetValue(&textView->mFontDescentLV, ReadFontDescentLane(textView->mFont));
    CScriptLazyVar_float::SetValue(
      &textView->mFontExternalLeadingLV,
      textView->mFont->mExternalLeading
    );
  } else {
    CScriptLazyVar_float::SetValue(&textView->mTextAdvanceLV, 0.0f);
    CScriptLazyVar_float::SetValue(&textView->mFontAscentLV, 0.0f);
    CScriptLazyVar_float::SetValue(&textView->mFontDescentLV, 0.0f);
    CScriptLazyVar_float::SetValue(&textView->mFontExternalLeadingLV, 0.0f);
  }
}

/**
 * Address: 0x007A2FA0 (FUN_007A2FA0, Moho::CMauiText::SetText)
 *
 * What it does:
 * Stores one new text lane and refreshes cached text-advance width when a
 * font is bound.
 */
void moho::CMauiText::SetText(const char* const text)
{
  CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(this);
  const char* const safeText = text != nullptr ? text : "";
  textView->mText.assign_owned(safeText);

  if (textView->mFont != nullptr) {
    const float advance = textView->mFont->GetAdvance(textView->mText.c_str(), 0);
    CScriptLazyVar_float::SetValue(&textView->mTextAdvanceLV, advance);
  }
}

/**
 * Address: 0x007A2E40 (FUN_007A2E40, Moho::CMauiText::Dump)
 *
 * What it does:
 * Logs this text control label, color lane, and current text payload.
 */
void moho::CMauiText::Dump()
{
  CMauiControl::Dump();
  const CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(this);

  gpg::Logf("CMauiText");
  gpg::Logf("Color = %#08X", textView->mColor);
  gpg::Logf("Text = %s", textView->mText.c_str());
}

/**
 * Address: 0x007A34F0 (FUN_007A34F0, cfunc_CMauiTextSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetNewFontL`.
 */
int moho::cfunc_CMauiTextSetNewFont(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3510 (FUN_007A3510, func_CMauiTextSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiTextSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3570 (FUN_007A3570, cfunc_CMauiTextSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiText` plus `(family, pointsize)`, creates one font, and
 * applies it to text runtime lanes.
 */
int moho::cfunc_CMauiTextSetNewFontL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetNewFontHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    textControl->SetNewFont(createdFont.px);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x007A3710 (FUN_007A3710, cfunc_CMauiTextSetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetTextL`.
 */
int moho::cfunc_CMauiTextSetText(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3730 (FUN_007A3730, func_CMauiTextSetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetText",
    &moho::cfunc_CMauiTextSetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3790 (FUN_007A3790, cfunc_CMauiTextSetTextL)
 *
 * What it does:
 * Reads one `CMauiText` plus text string and updates control text and cached
 * text advance.
 */
int moho::cfunc_CMauiTextSetTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetTextHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textControlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textControlObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    text = "";
  }

  textControl->SetText(text);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3880 (FUN_007A3880, cfunc_CMauiTextGetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextGetTextL`.
 */
int moho::cfunc_CMauiTextGetText(lua_State* const luaContext)
{
  return cfunc_CMauiTextGetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A38A0 (FUN_007A38A0, func_CMauiTextGetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:GetText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextGetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetText",
    &moho::cfunc_CMauiTextGetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextGetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3900 (FUN_007A3900, cfunc_CMauiTextGetTextL)
 *
 * What it does:
 * Reads one `CMauiText` and returns its current text lane.
 */
int moho::cfunc_CMauiTextGetTextL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextGetTextHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);
  const CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(textControl);
  lua_pushstring(state->m_state, textView->mText.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A39F0 (FUN_007A39F0, cfunc_CMauiTextSetNewColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetNewColorL`.
 */
int moho::cfunc_CMauiTextSetNewColor(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetNewColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3A10 (FUN_007A3A10, func_CMauiTextSetNewColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewColor",
    &moho::cfunc_CMauiTextSetNewColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3A70 (FUN_007A3A70, cfunc_CMauiTextSetNewColorL)
 *
 * What it does:
 * Reads one `CMauiText` plus color arg and updates text color lane.
 */
int moho::cfunc_CMauiTextSetNewColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetNewColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  CMauiTextRuntimeView::FromText(textControl)->mColor = SCR_DecodeColor(state, colorObject);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3B60 (FUN_007A3B60, cfunc_CMauiTextSetDropShadow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetDropShadowL`.
 */
int moho::cfunc_CMauiTextSetDropShadow(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetDropShadowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3B80 (FUN_007A3B80, func_CMauiTextSetDropShadow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetDropShadow(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetDropShadow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetDropShadow",
    &moho::cfunc_CMauiTextSetDropShadow,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetDropShadowHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3BE0 (FUN_007A3BE0, cfunc_CMauiTextSetDropShadowL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates drop-shadow lane.
 */
int moho::cfunc_CMauiTextSetDropShadowL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetDropShadowHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject dropShadowArg(state, 2);
  CMauiTextRuntimeView::FromText(textControl)->mDropShadow = LuaPlus::LuaStackObject::GetBoolean(&dropShadowArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3CB0 (FUN_007A3CB0, cfunc_CMauiTextSetCenteredHorizontally)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetCenteredHorizontallyL`.
 */
int moho::cfunc_CMauiTextSetCenteredHorizontally(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetCenteredHorizontallyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3CD0 (FUN_007A3CD0, func_CMauiTextSetCenteredHorizontally_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetCenteredHorizontally(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetCenteredHorizontally_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetCenteredHorizontally",
    &moho::cfunc_CMauiTextSetCenteredHorizontally,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetCenteredHorizontallyHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3D30 (FUN_007A3D30, cfunc_CMauiTextSetCenteredHorizontallyL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates horizontal-centering lane.
 */
int moho::cfunc_CMauiTextSetCenteredHorizontallyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetCenteredHorizontallyHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject centeredArg(state, 2);
  CMauiTextRuntimeView::FromText(textControl)->mCenteredHorizontally = LuaPlus::LuaStackObject::GetBoolean(&centeredArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3E00 (FUN_007A3E00, cfunc_CMauiTextSetCenteredVertically)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetCenteredVerticallyL`.
 */
int moho::cfunc_CMauiTextSetCenteredVertically(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetCenteredVerticallyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3E20 (FUN_007A3E20, func_CMauiTextSetCenteredVertically_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetCenteredVertically(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetCenteredVertically_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetCenteredVertically",
    &moho::cfunc_CMauiTextSetCenteredVertically,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetCenteredVerticallyHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3E80 (FUN_007A3E80, cfunc_CMauiTextSetCenteredVerticallyL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates vertical-centering lane.
 */
int moho::cfunc_CMauiTextSetCenteredVerticallyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetCenteredVerticallyHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject centeredArg(state, 2);
  CMauiTextRuntimeView::FromText(textControl)->mCenteredVertically = LuaPlus::LuaStackObject::GetBoolean(&centeredArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A3F50 (FUN_007A3F50, cfunc_CMauiTextGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextGetStringAdvanceL`.
 */
int moho::cfunc_CMauiTextGetStringAdvance(lua_State* const luaContext)
{
  return cfunc_CMauiTextGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A3F70 (FUN_007A3F70, func_CMauiTextGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiTextGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A3FD0 (FUN_007A3FD0, cfunc_CMauiTextCMauiTextL)
 *
 * What it does:
 * Reads one `CMauiText` plus string arg and returns measured text advance
 * from the text-control font lane.
 */
int moho::cfunc_CMauiTextGetStringAdvanceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextGetStringAdvanceHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textControlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textControlObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  const CMauiTextRuntimeView* const textView = CMauiTextRuntimeView::FromText(textControl);
  CD3DFont* const font = textView->mFont;
  const float advance = font != nullptr ? font->GetAdvance(text, 0) : 0.0f;
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A40E0 (FUN_007A40E0, cfunc_CMauiTextSetNewClipToWidth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiTextSetNewClipToWidthL`.
 */
int moho::cfunc_CMauiTextSetNewClipToWidth(lua_State* const luaContext)
{
  return cfunc_CMauiTextSetNewClipToWidthL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A4100 (FUN_007A4100, func_CMauiTextSetNewClipToWidth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiText:SetNewClipToWidth(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiTextSetNewClipToWidth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetNewClipToWidth",
    &moho::cfunc_CMauiTextSetNewClipToWidth,
    &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
    "CMauiText",
    kCMauiTextSetNewClipToWidthHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A4160 (FUN_007A4160, cfunc_CMauiTextSetNewClipToWidthL)
 *
 * What it does:
 * Reads one `CMauiText` plus bool and updates clip-to-width lane.
 */
int moho::cfunc_CMauiTextSetNewClipToWidthL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCMauiTextSetNewClipToWidthHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject textObject(LuaPlus::LuaStackObject(state, 1));
  CMauiText* const textControl = SCR_FromLua_CMauiText(textObject, state);

  LuaPlus::LuaStackObject clipArg(state, 2);
  CMauiTextRuntimeView::FromText(textControl)->mClipToWidth = LuaPlus::LuaStackObject::GetBoolean(&clipArg);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00846760 (FUN_00846760, cfunc_SetFrontEndData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetFrontEndDataL`.
 */
int moho::cfunc_SetFrontEndData(lua_State* const luaContext)
{
  return cfunc_SetFrontEndDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846780 (FUN_00846780, func_SetFrontEndData_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetFrontEndData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetFrontEndData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFrontEndData",
    &moho::cfunc_SetFrontEndData,
    nullptr,
    "<global>",
    kSetFrontEndDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008467E0 (FUN_008467E0, cfunc_SetFrontEndDataL)
 *
 * What it does:
 * Copies caller key/data lanes into user-state global `FrontEndData`.
 */
int moho::cfunc_SetFrontEndDataL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetFrontEndDataHelpText, 2, argumentCount);
  }

  LuaPlus::LuaState* const userState = USER_GetLuaState();
  LuaPlus::LuaObject frontEndData = userState->GetGlobals()["FrontEndData"];

  const LuaPlus::LuaObject callerValue(LuaPlus::LuaStackObject(state, 2));
  const LuaPlus::LuaObject callerKey(LuaPlus::LuaStackObject(state, 1));
  const LuaPlus::LuaObject valueOnUserState = CopyLuaObjectToState(callerValue, userState);
  const LuaPlus::LuaObject keyOnUserState = CopyLuaObjectToState(callerKey, userState);
  frontEndData.SetObject(keyOnUserState, valueOnUserState);
  return 0;
}

/**
 * Address: 0x00846960 (FUN_00846960, cfunc_GetFrontEndData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFrontEndDataL`.
 */
int moho::cfunc_GetFrontEndData(lua_State* const luaContext)
{
  return cfunc_GetFrontEndDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846980 (FUN_00846980, func_GetFrontEndData_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetFrontEndData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetFrontEndData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFrontEndData",
    &moho::cfunc_GetFrontEndData,
    nullptr,
    "<global>",
    kGetFrontEndDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008469E0 (FUN_008469E0, cfunc_GetFrontEndDataL)
 *
 * What it does:
 * Resolves one key from caller Lua state against user-state `FrontEndData`
 * and pushes the copied lookup result back to caller state.
 */
int moho::cfunc_GetFrontEndDataL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFrontEndDataHelpText, 1, argumentCount);
  }

  LuaPlus::LuaState* const userState = USER_GetLuaState();
  LuaPlus::LuaObject frontEndData = userState->GetGlobals()["FrontEndData"];

  const LuaPlus::LuaObject keyObject(LuaPlus::LuaStackObject(state, 1));
  const LuaPlus::LuaObject keyOnUserState = CopyLuaObjectToState(keyObject, userState);
  const LuaPlus::LuaObject valueOnUserState = frontEndData.GetByObject(keyOnUserState);
  LuaPlus::LuaObject valueOnCallerState = CopyLuaObjectToState(valueOnUserState, state);
  valueOnCallerState.PushStack(state);
  return 1;
}

/**
 * Address: 0x0084DDE0 (FUN_0084DDE0, cfunc_GetCursor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetCursorL`.
 */
int moho::cfunc_GetCursor(lua_State* const luaContext)
{
  return cfunc_GetCursorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084DE00 (FUN_0084DE00, func_GetCursor_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetCursor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetCursor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCursor",
    &moho::cfunc_GetCursor,
    nullptr,
    "<global>",
    kGetCursorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084DE60 (FUN_0084DE60, cfunc_GetCursorL)
 *
 * What it does:
 * Returns active UI cursor script object when present; otherwise pushes `nil`.
 */
int moho::cfunc_GetCursorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCursorHelpText, 0, argumentCount);
  }

  CMauiCursor* const cursor = g_UIManager != nullptr ? g_UIManager->GetCursor() : nullptr;
  if (cursor == nullptr) {
    lua_pushnil(state->m_state);
    return 1;
  }

  reinterpret_cast<CScriptObject*>(cursor)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0084DEF0 (FUN_0084DEF0, cfunc_SetUIControlsAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetUIControlsAlphaL`.
 */
int moho::cfunc_SetUIControlsAlpha(lua_State* const luaContext)
{
  return cfunc_SetUIControlsAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084DF10 (FUN_0084DF10, func_SetUIControlsAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetUIControlsAlpha(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetUIControlsAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetUIControlsAlpha",
    &moho::cfunc_SetUIControlsAlpha,
    nullptr,
    "<global>",
    kSetUIControlsAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084DF70 (FUN_0084DF70, cfunc_SetUIControlsAlphaL)
 *
 * What it does:
 * Reads one float arg and updates active UI manager controls-alpha lane.
 */
int moho::cfunc_SetUIControlsAlphaL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetUIControlsAlphaHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject alphaArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }

  const float alphaValue = static_cast<float>(lua_tonumber(state->m_state, 1));
  if (g_UIManager != nullptr) {
    g_UIManager->SetUIControlsAlpha(alphaValue);
  }
  return 0;
}

/**
 * Address: 0x0084E000 (FUN_0084E000, cfunc_GetUIControlsAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUIControlsAlphaL`.
 */
int moho::cfunc_GetUIControlsAlpha(lua_State* const luaContext)
{
  return cfunc_GetUIControlsAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084E020 (FUN_0084E020, func_GetUIControlsAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetUIControlsAlpha()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUIControlsAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetUIControlsAlpha",
    &moho::cfunc_GetUIControlsAlpha,
    nullptr,
    "<global>",
    kGetUIControlsAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084E080 (FUN_0084E080, cfunc_GetUIControlsAlphaL)
 *
 * What it does:
 * Reads active UI controls-alpha lane and pushes it, or `nil` if unavailable.
 */
int moho::cfunc_GetUIControlsAlphaL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUIControlsAlphaHelpText, 0, argumentCount);
  }

  if (g_UIManager == nullptr) {
    lua_pushnil(state->m_state);
    return 1;
  }

  lua_pushnumber(state->m_state, g_UIManager->GetUIControlsAlpha());
  return 1;
}

/**
 * Address: 0x0084E140 (FUN_0084E140, func_FlushEvents_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `FlushEvents()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_FlushEvents_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "FlushEvents",
    &moho::func_FlushEvents,
    nullptr,
    "<global>",
    kFlushEventsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE4EC0 (FUN_00BE4EC0, register_FlushEvents_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_FlushEvents_LuaFuncDef()
{
  return func_FlushEvents_LuaFuncDef();
}

/**
 * Address: 0x00850D20 (FUN_00850D20, cfunc_InternalCreateMapPreview)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMapPreviewL`.
 */
int moho::cfunc_InternalCreateMapPreview(lua_State* const luaContext)
{
  return cfunc_InternalCreateMapPreviewL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00850D40 (FUN_00850D40, func_InternalCreateMapPreview_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMapPreview(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMapPreview_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateMapPreview",
    &moho::cfunc_InternalCreateMapPreview,
    nullptr,
    "<global>",
    kInternalCreateMapPreviewHelpText
  );
  return &binder;
}

/**
 * Address: 0x00850DA0 (FUN_00850DA0, cfunc_InternalCreateMapPreviewL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CUIMapPreview`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMapPreviewL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateMapPreviewHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = new CUIMapPreview(&luaObject, parentControl);
  mapPreview->DoInit();
  CMauiControlScriptObjectRuntimeView::FromControl(mapPreview)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00850770 (FUN_00850770, Moho::CUIMapPreview::CUIMapPreview)
 *
 * What it does:
 * Constructs one map-preview control from Lua object + parent lanes and
 * initializes preview texture ownership lanes.
 */
moho::CUIMapPreview::CUIMapPreview(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "mappreview")
{
  CUIMapPreviewRuntimeView* const mapPreviewView = CUIMapPreviewRuntimeView::FromMapPreview(this);
  mapPreviewView->mTexture = {};
}

/**
 * Address: 0x008507F0 (FUN_008507F0, Moho::CUIMapPreview::~CUIMapPreview)
 *
 * What it does:
 * Releases the preview texture lane before the inherited control teardown
 * continues through `CMauiControl`.
 */
moho::CUIMapPreview::~CUIMapPreview()
{
  CUIMapPreviewRuntimeView::FromMapPreview(this)->mTexture = {};
}

/**
 * Address: 0x008507D0 (FUN_008507D0, Moho::CUIMapPreview::Delete)
 *
 * What it does:
 * Mirrors the deleting-destructor thunk lane for map-preview controls and
 * optionally frees the storage block.
 */
moho::CUIMapPreview* moho::CUIMapPreview::DeleteWithFlag(
  CUIMapPreview* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  object->~CUIMapPreview();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }

  return object;
}

/**
 * Address: 0x00850870 (FUN_00850870, Moho::CUIMapPreview::SetTexture)
 *
 * What it does:
 * Clears existing preview texture ownership and loads one map-preview texture
 * from D3D device resources by file path.
 */
bool moho::CUIMapPreview::SetTexture(const char* const texturePath)
{
  CUIMapPreviewRuntimeView* const mapPreviewView = CUIMapPreviewRuntimeView::FromMapPreview(this);
  mapPreviewView->mTexture = {};

  if (texturePath == nullptr || texturePath[0] == '\0') {
    return false;
  }

  ID3DDeviceResources::TextureResourceHandle loadedTexture{};
  if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
    if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
      resources->GetTexture(loadedTexture, texturePath, 0, true);
    }
  }

  mapPreviewView->mTexture = boost::static_pointer_cast<ID3DTextureSheet>(loadedTexture);
  return mapPreviewView->mTexture.get() != nullptr;
}

/**
 * Address: 0x008509A0 (FUN_008509A0, Moho::CUIMapPreview::SetTextureFromMap)
 *
 * What it does:
 * Clears existing preview texture ownership, loads one map in preview-only
 * mode, and binds the resulting preview texture sheet when present.
 */
bool moho::CUIMapPreview::SetTextureFromMap(const char* const mapPath)
{
  CUIMapPreviewRuntimeView* const mapPreviewView = CUIMapPreviewRuntimeView::FromMapPreview(this);
  mapPreviewView->mTexture = {};

  if (mapPath == nullptr || mapPath[0] == '\0') {
    return false;
  }

  CWldMap loadedMap{};
  CBackgroundTaskControl loadControl{};
  if (loadedMap.MapLoad(mapPath, nullptr, true, loadControl) && loadedMap.mMapPreviewChunk != nullptr) {
    mapPreviewView->mTexture = loadedMap.mMapPreviewChunk->mPreviewTexture;
  }

  return mapPreviewView->mTexture.get() != nullptr;
}

/**
 * Address: 0x00850AC0 (FUN_00850AC0, Moho::CUIMapPreview::ClearTexture)
 *
 * What it does:
 * Releases any currently bound map-preview texture ownership.
 */
void moho::CUIMapPreview::ClearTexture()
{
  CUIMapPreviewRuntimeView::FromMapPreview(this)->mTexture = {};
}

/**
 * Address: 0x00850ED0 (FUN_00850ED0, cfunc_CUIMapPreviewSetTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewSetTextureL`.
 */
int moho::cfunc_CUIMapPreviewSetTexture(lua_State* const luaContext)
{
  return cfunc_CUIMapPreviewSetTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00850EF0 (FUN_00850EF0, func_CUIMapPreviewSetTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:SetTexture(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewSetTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetTexture",
    &moho::cfunc_CUIMapPreviewSetTexture,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewSetTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00850F50 (FUN_00850F50, cfunc_CUIMapPreviewSetTextureL)
 *
 * What it does:
 * Reads one `CUIMapPreview` plus texture-path string and returns one success
 * boolean from `CUIMapPreview::SetTexture`.
 */
int moho::cfunc_CUIMapPreviewSetTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIMapPreviewSetTextureHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }

  const bool success = mapPreview->SetTexture(texturePath);
  lua_pushboolean(state->m_state, success);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00851040 (FUN_00851040, cfunc_CUIMapPreviewSetTextureFromMap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewSetTextureFromMapL`.
 */
int moho::cfunc_CUIMapPreviewSetTextureFromMap(lua_State* const luaContext)
{
  return cfunc_CUIMapPreviewSetTextureFromMapL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00851060 (FUN_00851060, func_CUIMapPreviewSetTextureFromMap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:SetTextureFromMap(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewSetTextureFromMap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetTextureFromMap",
    &moho::cfunc_CUIMapPreviewSetTextureFromMap,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewSetTextureFromMapHelpText
  );
  return &binder;
}

/**
 * Address: 0x008510C0 (FUN_008510C0, cfunc_CUIMapPreviewSetTextureFromMapL)
 *
 * What it does:
 * Reads one `CUIMapPreview` plus map-path string and returns one success
 * boolean from `CUIMapPreview::SetTextureFromMap`.
 */
int moho::cfunc_CUIMapPreviewSetTextureFromMapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIMapPreviewSetTextureFromMapHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);

  LuaPlus::LuaStackObject mapArg(state, 2);
  const char* mapPath = lua_tostring(state->m_state, 2);
  if (mapPath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&mapArg, "string");
    mapPath = "";
  }

  const bool success = mapPreview->SetTextureFromMap(mapPath);
  lua_pushboolean(state->m_state, success);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008511B0 (FUN_008511B0, cfunc_CUIMapPreviewClearTexture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIMapPreviewClearTextureL`.
 */
int moho::cfunc_CUIMapPreviewClearTexture(lua_State* const luaContext)
{
  return cfunc_CUIMapPreviewClearTextureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008511D0 (FUN_008511D0, func_CUIMapPreviewClearTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIMapPreview:ClearTexture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIMapPreviewClearTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearTexture",
    &moho::cfunc_CUIMapPreviewClearTexture,
    &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
    "CUIMapPreview",
    kCUIMapPreviewClearTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x00851230 (FUN_00851230, cfunc_CUIMapPreviewClearTextureL)
 *
 * What it does:
 * Reads one `CUIMapPreview` and clears its currently bound preview texture.
 */
int moho::cfunc_CUIMapPreviewClearTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIMapPreviewClearTextureHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject mapPreviewObject(LuaPlus::LuaStackObject(state, 1));
  CUIMapPreview* const mapPreview = SCR_FromLua_CUIMapPreview(mapPreviewObject, state);
  mapPreview->ClearTexture();
  return 0;
}

/**
 * Address: 0x00873170 (FUN_00873170, cfunc_CUIWorldViewSetCartographic)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewSetCartographicL`.
 */
int moho::cfunc_CUIWorldViewSetCartographic(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewSetCartographicL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873190 (FUN_00873190, func_CUIWorldViewSetCartographic_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:SetCartographic(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewSetCartographic_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetCartographic",
    &moho::cfunc_CUIWorldViewSetCartographic,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewSetCartographicHelpText
  );
  return &binder;
}

/**
 * Address: 0x008731F0 (FUN_008731F0, cfunc_CUIWorldViewSetCartographicL)
 *
 * What it does:
 * Updates one world-view orthographic/cartographic render mode flag.
 */
int moho::cfunc_CUIWorldViewSetCartographicL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewSetCartographicHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject cartographicArg(state, 2);
  CUIWorldViewRuntimeView::FromWorldView(worldView)->mRenderWorldView.SetOrthographic(cartographicArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x008732C0 (FUN_008732C0, cfunc_CUIWorldViewIsCartographic)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsCartographicL`.
 */
int moho::cfunc_CUIWorldViewIsCartographic(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewIsCartographicL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008732E0 (FUN_008732E0, func_CUIWorldViewIsCartographic_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsCartographic()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsCartographic_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsCartographic",
    &moho::cfunc_CUIWorldViewIsCartographic,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsCartographicHelpText
  );
  return &binder;
}

/**
 * Address: 0x00873340 (FUN_00873340, cfunc_CUIWorldViewIsCartographicL)
 *
 * What it does:
 * Returns whether one world-view currently renders in orthographic mode.
 */
int moho::cfunc_CUIWorldViewIsCartographicL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewIsCartographicHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, CUIWorldViewRuntimeView::FromWorldView(worldView)->mRenderWorldView.IsOrthographic());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00873410 (FUN_00873410, cfunc_CUIWorldViewEnableResourceRendering)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewEnableResourceRenderingL`.
 */
int moho::cfunc_CUIWorldViewEnableResourceRendering(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewEnableResourceRenderingL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873430 (FUN_00873430, func_CUIWorldViewEnableResourceRendering_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:EnableResourceRendering(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewEnableResourceRendering_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EnableResourceRendering",
    &moho::cfunc_CUIWorldViewEnableResourceRendering,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewEnableResourceRenderingHelpText
  );
  return &binder;
}

/**
 * Address: 0x00873490 (FUN_00873490, cfunc_CUIWorldViewEnableResourceRenderingL)
 *
 * What it does:
 * Updates one world-view resource-rendering enable flag.
 */
int moho::cfunc_CUIWorldViewEnableResourceRenderingL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCUIWorldViewEnableResourceRenderingHelpText,
      2,
      argumentCount
    );
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject enabledArg(state, 2);
  CUIWorldViewRuntimeView::FromWorldView(worldView)->mEnableResourceRendering =
    enabledArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  return 0;
}

/**
 * Address: 0x00873550 (FUN_00873550, cfunc_CUIWorldViewIsResourceRenderingEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsResourceRenderingEnabledL`.
 */
int moho::cfunc_CUIWorldViewIsResourceRenderingEnabled(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewIsResourceRenderingEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00873570 (FUN_00873570, func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsResourceRenderingEnabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsResourceRenderingEnabled",
    &moho::cfunc_CUIWorldViewIsResourceRenderingEnabled,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsResourceRenderingEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x008735D0 (FUN_008735D0, cfunc_CUIWorldViewIsResourceRenderingEnabledL)
 *
 * What it does:
 * Returns whether one world-view has resource rendering enabled.
 */
int moho::cfunc_CUIWorldViewIsResourceRenderingEnabledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCUIWorldViewIsResourceRenderingEnabledHelpText,
      1,
      argumentCount
    );
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, CUIWorldViewRuntimeView::FromWorldView(worldView)->mEnableResourceRendering != 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008725B0 (FUN_008725B0, cfunc_CUIWorldViewZoomScale)
 *
 * What it does:
 * Unwraps the raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewZoomScaleL`.
 */
int moho::cfunc_CUIWorldViewZoomScale(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewZoomScaleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008725D0 (FUN_008725D0, func_CUIWorldViewZoomScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:ZoomScale(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewZoomScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ZoomScale",
    &moho::cfunc_CUIWorldViewZoomScale,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewZoomScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872630 (FUN_00872630, cfunc_CUIWorldViewZoomScaleL)
 *
 * What it does:
 * Reads `CUIWorldView:ZoomScale` Lua args and forwards anchor and wheel
 * zoom lanes into the active world-view camera.
 */
int moho::cfunc_CUIWorldViewZoomScaleL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewZoomScaleHelpText, 5, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  if (CameraZoomRuntimeView* const camera = worldViewView->mRenderWorldView.GetCamera(); camera != nullptr) {
    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&yArg, "number");
    }
    const float y = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&xArg, "number");
    }
    float zoomAnchor[2] = {static_cast<float>(lua_tonumber(state->m_state, 2)), y};
    camera->SetZoomAnchor(zoomAnchor);

    CameraZoomRuntimeView* const wheelCamera = worldViewView->mRenderWorldView.GetCamera();
    LuaPlus::LuaStackObject wheelDeltaArg(state, 5);
    if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelDeltaArg, "number");
    }
    const float wheelDelta = static_cast<float>(lua_tonumber(state->m_state, 5));

    LuaPlus::LuaStackObject wheelRotArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelRotArg, "number");
    }
    const float wheelRotation = static_cast<float>(lua_tonumber(state->m_state, 4));
    wheelCamera->ApplyWheelZoomRatio(wheelRotation / wheelDelta);
  }

  return 0;
}

/**
 * Address: 0x00872C60 (FUN_00872C60, cfunc_UnProject)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnProjectL`.
 */
int moho::cfunc_UnProject(lua_State* const luaContext)
{
  return cfunc_UnProjectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872C80 (FUN_00872C80, func_UnProject_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `UnProject(self, screenPos)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_UnProject_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UnProject",
    &moho::cfunc_UnProject,
    nullptr,
    "<global>",
    kUnProjectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872CE0 (FUN_00872CE0, cfunc_UnProjectL)
 *
 * What it does:
 * Resolves one world-view camera and converts a screen-space `Vector2` into
 * a world-space `Vector3` surface point.
 */
int moho::cfunc_UnProjectL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnProjectHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  CameraZoomRuntimeView* const camera = CUIWorldViewRuntimeView::FromWorldView(worldView)->mRenderWorldView.GetCamera();

  const LuaPlus::LuaObject screenPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector2f screenPoint = SCR_FromLuaCopy<Wm3::Vector2f>(screenPointObject);

  const Wm3::Vector3f worldPoint = camera->CameraScreenToSurface(screenPoint);
  LuaPlus::LuaObject worldPointObject = SCR_ToLua<Wm3::Vector3f>(state, worldPoint);
  worldPointObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00872E20 (FUN_00872E20, cfunc_CUIWorldViewProject)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewProjectL`.
 */
int moho::cfunc_CUIWorldViewProject(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewProjectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872E40 (FUN_00872E40, func_CUIWorldViewProject_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:Project(self, worldPos)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewProject_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Project",
    &moho::cfunc_CUIWorldViewProject,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewProjectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872EA0 (FUN_00872EA0, cfunc_CUIWorldViewProjectL)
 *
 * What it does:
 * Projects one world-space `Vector3` into world-view control-space
 * coordinates and returns one `Vector2` (or nil when camera is absent).
 */
int moho::cfunc_CUIWorldViewProjectL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewProjectHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  CameraZoomRuntimeView* const camera = worldViewView->mRenderWorldView.GetCamera();
  if (camera == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const LuaPlus::LuaObject worldPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f worldPoint = SCR_FromLuaCopy<Wm3::Vector3f>(worldPointObject);

  const CMauiControlRuntimeView* const controlView =
    CMauiControlRuntimeView::FromControl(reinterpret_cast<CMauiControl*>(worldView));
  const float height = CScriptLazyVar_float::GetValue(&controlView->mHeightLV);
  const float width = CScriptLazyVar_float::GetValue(&controlView->mWidthLV);

  const Wm3::Vector2f projectedPoint = camera->GetView().Project(worldPoint, 0.0f, width, height, 0.0f);
  LuaPlus::LuaObject projectedPointObject = SCR_ToLua<Wm3::Vector2f>(state, projectedPoint);
  projectedPointObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871A20 (FUN_00871A20, cfunc_CUIWorldViewCameraReset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewCameraResetL`.
 */
int moho::cfunc_CUIWorldViewCameraReset(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewCameraResetL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871A40 (FUN_00871A40, func_CUIWorldViewCameraReset_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:CameraReset()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewCameraReset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CameraReset",
    &moho::cfunc_CUIWorldViewCameraReset,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewCameraResetHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871AA0 (FUN_00871AA0, cfunc_CUIWorldViewCameraResetL)
 *
 * What it does:
 * Resets one world-view camera and returns the world-view Lua object.
 */
int moho::cfunc_CUIWorldViewCameraResetL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewCameraResetHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  if (CameraZoomRuntimeView* const camera = worldViewView->mRenderWorldView.GetCamera(); camera != nullptr) {
    camera->Reset();
  }

  CUIWorldViewLuaObjectRuntimeView::FromWorldView(worldView)->mLuaObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871B70 (FUN_00871B70, cfunc_CUIWorldViewGetsGlobalCameraCommands)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetsGlobalCameraCommandsL`.
 */
int moho::cfunc_CUIWorldViewGetsGlobalCameraCommands(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewGetsGlobalCameraCommandsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871B90 (FUN_00871B90, func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:GetsGlobalCameraCommands(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetsGlobalCameraCommands",
    &moho::cfunc_CUIWorldViewGetsGlobalCameraCommands,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetsGlobalCameraCommandsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871BF0 (FUN_00871BF0, cfunc_CUIWorldViewGetsGlobalCameraCommandsL)
 *
 * What it does:
 * Updates one world-view global-camera-command flag and returns the
 * world-view Lua object.
 */
int moho::cfunc_CUIWorldViewGetsGlobalCameraCommandsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCUIWorldViewGetsGlobalCameraCommandsHelpText,
      2,
      argumentCount
    );
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);

  LuaPlus::LuaStackObject getsCommandsArg(state, 2);
  CUIWorldViewRuntimeView::FromWorldView(worldView)->mGetsGlobalCameraCommands =
    getsCommandsArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);

  CUIWorldViewLuaObjectRuntimeView::FromWorldView(worldView)->mLuaObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00871CC0 (FUN_00871CC0, cfunc_CUIWorldViewGetRightMouseButtonOrder)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetRightMouseButtonOrderL`.
 */
int moho::cfunc_CUIWorldViewGetRightMouseButtonOrder(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewGetRightMouseButtonOrderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871CE0 (FUN_00871CE0, func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:GetRightMouseButtonOrder()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetRightMouseButtonOrder",
    &moho::cfunc_CUIWorldViewGetRightMouseButtonOrder,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetRightMouseButtonOrderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871D40 (FUN_00871D40, cfunc_CUIWorldViewGetRightMouseButtonOrderL)
 *
 * What it does:
 * Resolves the active right-click action from world-session cursor context
 * and returns the order lexical token string (or nil when no order applies).
 */
int moho::cfunc_CUIWorldViewGetRightMouseButtonOrderL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCUIWorldViewGetRightMouseButtonOrderHelpText,
      1,
      argumentCount
    );
  }

  LuaPlus::LuaObject unused;

  CWldSession* const activeSession = WLD_GetActiveSession();
  auto* const sessionView = CWldSessionCursorRuntimeView::FromSession(activeSession);
  if (sessionView->mCursorInfo.mHitValid != 0u) {
    CommandModeData commandMode{};
    (void)func_GetRightMouseButtonAction(&commandMode, &sessionView->mCursorInfo, 0, activeSession);

    if (commandMode.mMode == COMMOD_Order) {
      gpg::RRef commandCapRef{};
      (void)gpg::RRef_ERuleBPUnitCommandCaps(&commandCapRef, &commandMode.mCommandCaps);
      const msvc8::string commandLexical = commandCapRef.GetLexical();
      lua_pushstring(state->m_state, commandLexical.c_str());
      (void)lua_gettop(state->m_state);
      return 1;
    }
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00871EC0 (FUN_00871EC0, cfunc_CUIWorldViewHasHighlightCommand)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewHasHighlightCommandL`.
 */
int moho::cfunc_CUIWorldViewHasHighlightCommand(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewHasHighlightCommandL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871EE0 (FUN_00871EE0, func_CUIWorldViewHasHighlightCommand_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:HasHighlightCommand()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewHasHighlightCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HasHighlightCommand",
    &moho::cfunc_CUIWorldViewHasHighlightCommand,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewHasHighlightCommandHelpText
  );
  return &binder;
}

/**
 * Address: 0x00871F40 (FUN_00871F40, cfunc_CUIWorldViewHasHighlightCommandL)
 *
 * What it does:
 * Returns whether the active world-session cursor currently has one
 * highlight command id.
 */
int moho::cfunc_CUIWorldViewHasHighlightCommandL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewHasHighlightCommandHelpText, 1, argumentCount);
  }

  CWldSession* const activeSession = WLD_GetActiveSession();
  const auto* const sessionView = CWldSessionCursorRuntimeView::FromSession(activeSession);
  lua_pushboolean(state->m_state, sessionView->mCursorInfo.mIsDragger != -1);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00871FA0 (FUN_00871FA0, cfunc_CUIWorldShowConvertToPatrolCursor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldShowConvertToPatrolCursorL`.
 */
int moho::cfunc_CUIWorldShowConvertToPatrolCursor(lua_State* const luaContext)
{
  return cfunc_CUIWorldShowConvertToPatrolCursorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00871FC0 (FUN_00871FC0, func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:ShowConvertToPatrolCursor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ShowConvertToPatrolCursor",
    &moho::cfunc_CUIWorldShowConvertToPatrolCursor,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldShowConvertToPatrolCursorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872020 (FUN_00872020, cfunc_CUIWorldShowConvertToPatrolCursorL)
 *
 * What it does:
 * Returns one world-view flag controlling patrol-convert cursor display.
 */
int moho::cfunc_CUIWorldShowConvertToPatrolCursorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldShowConvertToPatrolCursorHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  const CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  lua_pushboolean(state->m_state, worldViewView->mShowConvertToPatrolCursor != 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008720E0 (FUN_008720E0, cfunc_CUIWorldViewUnlockInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewUnlockInputL`.
 */
int moho::cfunc_CUIWorldViewUnlockInput(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewUnlockInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872100 (FUN_00872100, func_CUIWorldViewUnlockInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:UnlockInput(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewUnlockInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UnlockInput",
    &moho::cfunc_CUIWorldViewUnlockInput,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewUnlockInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872160 (FUN_00872160, cfunc_CUIWorldViewUnlockInputL)
 *
 * What it does:
 * Decrements one world-view input-lock counter lane.
 */
int moho::cfunc_CUIWorldViewUnlockInputL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewUnlockInputHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  --CUIWorldViewRuntimeView::FromWorldView(worldView)->mInputLocks;
  return 0;
}

/**
 * Address: 0x00872200 (FUN_00872200, cfunc_CUIWorldViewLockInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewLockInputL`.
 */
int moho::cfunc_CUIWorldViewLockInput(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewLockInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872220 (FUN_00872220, func_CUIWorldViewLockInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:LockInput(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewLockInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "LockInput",
    &moho::cfunc_CUIWorldViewLockInput,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewLockInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00872280 (FUN_00872280, cfunc_CUIWorldViewLockInputL)
 *
 * What it does:
 * Increments one world-view input-lock counter lane.
 */
int moho::cfunc_CUIWorldViewLockInputL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewLockInputHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  ++CUIWorldViewRuntimeView::FromWorldView(worldView)->mInputLocks;
  return 0;
}

/**
 * Address: 0x00872330 (FUN_00872330, cfunc_CUIWorldViewIsInputLocked)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewIsInputLockedL`.
 */
int moho::cfunc_CUIWorldViewIsInputLocked(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewIsInputLockedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872350 (FUN_00872350, func_CUIWorldViewIsInputLocked_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:IsInputLocked(camera)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewIsInputLocked_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsInputLocked",
    &moho::cfunc_CUIWorldViewIsInputLocked,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewIsInputLockedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008723B0 (FUN_008723B0, cfunc_CUIWorldViewIsInputLockedL)
 *
 * What it does:
 * Returns whether one world-view input-lock counter lane is positive.
 */
int moho::cfunc_CUIWorldViewIsInputLockedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewIsInputLockedHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  lua_pushboolean(state->m_state, CUIWorldViewRuntimeView::FromWorldView(worldView)->mInputLocks > 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00872470 (FUN_00872470, cfunc_CUIWorldViewSetHighlightEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewSetHighlightEnabledL`.
 */
int moho::cfunc_CUIWorldViewSetHighlightEnabled(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewSetHighlightEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872490 (FUN_00872490, func_CUIWorldViewSetHighlightEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUIWorldView:SetHighlightEnabled(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewSetHighlightEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetHighlightEnabled",
    &moho::cfunc_CUIWorldViewSetHighlightEnabled,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewSetHighlightEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x008724F0 (FUN_008724F0, cfunc_CUIWorldViewSetHighlightEnabledL)
 *
 * What it does:
 * Updates one world-view highlight-enabled boolean lane.
 */
int moho::cfunc_CUIWorldViewSetHighlightEnabledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewSetHighlightEnabledHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  LuaPlus::LuaStackObject enabledArg(state, 2);
  CUIWorldViewRuntimeView::FromWorldView(worldView)->mHighlightEnabled =
    enabledArg.GetBoolean() ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  return 0;
}

/**
 * Address: 0x0086A650 (FUN_0086A650, Moho::CLuaWldUIProvider::StartLoadingDialog)
 *
 * What it does:
 * Dispatches the `StartLoadingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StartLoadingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StartLoadingDialog");
}

/**
 * Address: 0x0086A660 (FUN_0086A660, Moho::CLuaWldUIProvider::UpdateLoadingDialog)
 *
 * What it does:
 * Dispatches the `UpdateLoadingDialog` Lua callback with one float argument.
 */
void moho::CLuaWldUIProvider::UpdateLoadingDialog(const float deltaSeconds)
{
  static_cast<CScriptObject*>(this)->RunScriptNum("UpdateLoadingDialog", deltaSeconds);
}

/**
 * Address: 0x0086A680 (FUN_0086A680, Moho::CLuaWldUIProvider::StopLoadingDialog)
 *
 * What it does:
 * Dispatches the `StopLoadingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StopLoadingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StopLoadingDialog");
}

/**
 * Address: 0x0086A690 (FUN_0086A690, Moho::CLuaWldUIProvider::StartWaitingDialog)
 *
 * What it does:
 * Dispatches the `StartWaitingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StartWaitingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StartWaitingDialog");
}

/**
 * Address: 0x0086A6A0 (FUN_0086A6A0, Moho::CLuaWldUIProvider::UpdateWaitingDialog)
 *
 * What it does:
 * Dispatches the `UpdateWaitingDialog` Lua callback with one float argument.
 */
void moho::CLuaWldUIProvider::UpdateWaitingDialog(const float deltaSeconds)
{
  static_cast<CScriptObject*>(this)->RunScriptNum("UpdateWaitingDialog", deltaSeconds);
}

/**
 * Address: 0x0086A6C0 (FUN_0086A6C0, Moho::CLuaWldUIProvider::StopWaitingDialog)
 *
 * What it does:
 * Dispatches the `StopWaitingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StopWaitingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StopWaitingDialog");
}

/**
 * Address: 0x0086A6D0 (FUN_0086A6D0, Moho::CLuaWldUIProvider::OnStart)
 *
 * What it does:
 * Dispatches the `OnStart` Lua callback on the embedded script object base
 * lane.
 */
void moho::CLuaWldUIProvider::OnStart()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("OnStart");
}

/**
 * Address: 0x0086A8C0 (FUN_0086A8C0, Moho::CLuaWldUIProvider::DestroyGameInterface)
 *
 * What it does:
 * Dispatches the `DestroyGameInterface` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::DestroyGameInterface()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("DestroyGameInterface");
}

/**
 * Address: 0x0086A8D0 (FUN_0086A8D0, cfunc_InternalCreateWldUIProvider)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateWldUIProviderL`.
 */
int moho::cfunc_InternalCreateWldUIProvider(lua_State* const luaContext)
{
  return cfunc_InternalCreateWldUIProviderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086A8F0 (FUN_0086A8F0, func_InternalCreateWldUIProvider_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateWldUIProvider(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateWldUIProvider_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateWldUIProvider",
    &moho::cfunc_InternalCreateWldUIProvider,
    nullptr,
    "<global>",
    kInternalCreateWldUIProviderHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086A950 (FUN_0086A950, cfunc_InternalCreateWldUIProviderL)
 *
 * What it does:
 * Builds one `CLuaWldUIProvider` from one Lua object lane, pushes the
 * script-object handle to Lua, and updates global world-ui-provider ownership.
 */
int moho::cfunc_InternalCreateWldUIProviderL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateWldUIProviderHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CLuaWldUIProvider* const provider = new CLuaWldUIProvider(&luaObject);
  CScriptObject* const providerScriptObject = static_cast<CScriptObject*>(provider);
  providerScriptObject->mLuaObj.PushStack(state);

  if (sWldUIProvider != provider && sWldUIProvider != nullptr) {
    delete sWldUIProvider;
  }
  sWldUIProvider = provider;
  return 1;
}

/**
 * Address: 0x0086BB30 (FUN_0086BB30, cfunc_InternalCreateWorldMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateWorldMeshL`.
 */
int moho::cfunc_InternalCreateWorldMesh(lua_State* const luaContext)
{
  return cfunc_InternalCreateWorldMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BB50 (FUN_0086BB50, func_InternalCreateWorldMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateWorldMesh(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateWorldMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "InternalCreateWorldMesh",
    &moho::cfunc_InternalCreateWorldMesh,
    nullptr,
    "<global>",
    kInternalCreateWorldMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BBB0 (FUN_0086BBB0, cfunc_InternalCreateWorldMeshL)
 *
 * What it does:
 * Builds one `CUIWorldMesh` from one Lua object lane and pushes the
 * script-object handle to Lua.
 */
int moho::cfunc_InternalCreateWorldMeshL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInternalCreateWorldMeshHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = new CUIWorldMesh(luaObject);
  static_cast<CScriptObject*>(worldMesh)->mLuaObj.PushStack(state);
  return 1;
}
/**
 * Address: 0x0086AA50 (FUN_0086AA50, cfunc_CLuaWldUIProviderDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CLuaWldUIProviderDestroyL`.
 */
int moho::cfunc_CLuaWldUIProviderDestroy(lua_State* const luaContext)
{
  return cfunc_CLuaWldUIProviderDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086AA70 (FUN_0086AA70, func_CLuaWldUIProviderDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WldUIProvider:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CLuaWldUIProviderDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CLuaWldUIProviderDestroy,
    &moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance(),
    "CLuaWldUIProvider",
    kCLuaWldUIProviderDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086AAD0 (FUN_0086AAD0, cfunc_CLuaWldUIProviderDestroyL)
 *
 * What it does:
 * Resolves one optional world-ui provider object and destroys it when alive.
 */
int moho::cfunc_CLuaWldUIProviderDestroyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCLuaWldUIProviderDestroyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject providerObject(LuaPlus::LuaStackObject(state, 1));
  CLuaWldUIProvider* const provider = ResolveCLuaWldUIProviderOptionalOrError(providerObject, state);
  if (provider != nullptr) {
    delete static_cast<IWldUIProvider*>(provider);
    if (sWldUIProvider != nullptr) {
      delete sWldUIProvider;
      sWldUIProvider = nullptr;
    }
  }
  return 0;
}

/**
 * Address: 0x0086BC90 (FUN_0086BC90, cfunc_CUIWorldMeshDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshDestroyL`.
 */
int moho::cfunc_CUIWorldMeshDestroy(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BCB0 (FUN_0086BCB0, func_CUIWorldMeshDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CUIWorldMeshDestroy,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BDC0 (FUN_0086BDC0, cfunc_CUIWorldMeshSetMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetMeshL`.
 */
int moho::cfunc_CUIWorldMeshSetMesh(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BDE0 (FUN_0086BDE0, func_CUIWorldMeshSetMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetMesh",
    &moho::cfunc_CUIWorldMeshSetMesh,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BF50 (FUN_0086BF50, cfunc_CUIWorldMeshSetStance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetStanceL`.
 */
int moho::cfunc_CUIWorldMeshSetStance(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetStanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BF70 (FUN_0086BF70, func_CUIWorldMeshSetStance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetStance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetStance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetStance",
    &moho::cfunc_CUIWorldMeshSetStance,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetStanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C1D0 (FUN_0086C1D0, cfunc_CUIWorldMeshSetHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetHiddenL`.
 */
int moho::cfunc_CUIWorldMeshSetHidden(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C1F0 (FUN_0086C1F0, func_CUIWorldMeshSetHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetHidden(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetHidden",
    &moho::cfunc_CUIWorldMeshSetHidden,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C310 (FUN_0086C310, cfunc_CUIWorldMeshIsHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshIsHiddenL`.
 */
int moho::cfunc_CUIWorldMeshIsHidden(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshIsHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C330 (FUN_0086C330, func_CUIWorldMeshIsHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `bool WorldMesh:IsHidden()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshIsHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsHidden",
    &moho::cfunc_CUIWorldMeshIsHidden,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshIsHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C450 (FUN_0086C450, cfunc_CUIWorldMeshSetAuxiliaryParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetAuxiliaryParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetAuxiliaryParameter(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetAuxiliaryParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C470 (FUN_0086C470, func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetAuxiliaryParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAuxiliaryParameter",
    &moho::cfunc_CUIWorldMeshSetAuxiliaryParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetAuxiliaryParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C5D0 (FUN_0086C5D0, cfunc_CUIWorldMeshSetFractionCompleteParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetFractionCompleteParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetFractionCompleteParameter(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetFractionCompleteParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C5F0 (FUN_0086C5F0, func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetFractionCompleteParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFractionCompleteParameter",
    &moho::cfunc_CUIWorldMeshSetFractionCompleteParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetFractionCompleteParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C750 (FUN_0086C750, cfunc_CUIWorldMeshSetFractionHealthParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetFractionHealthParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetFractionHealthParameter(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetFractionHealthParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C770 (FUN_0086C770, func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetFractionHealthParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFractionHealthParameter",
    &moho::cfunc_CUIWorldMeshSetFractionHealthParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetFractionHealthParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C8D0 (FUN_0086C8D0, cfunc_CUIWorldMeshSetLifetimeParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetLifetimeParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetLifetimeParameter(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetLifetimeParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C8F0 (FUN_0086C8F0, func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetLifetimeParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetLifetimeParameter",
    &moho::cfunc_CUIWorldMeshSetLifetimeParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetLifetimeParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CA50 (FUN_0086CA50, cfunc_CUIWorldMeshSetColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetColorL`.
 */
int moho::cfunc_CUIWorldMeshSetColor(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CA70 (FUN_0086CA70, func_CUIWorldMeshSetColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetColor",
    &moho::cfunc_CUIWorldMeshSetColor,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CBB0 (FUN_0086CBB0, cfunc_CUIWorldMeshSetScale)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetScaleL`.
 */
int moho::cfunc_CUIWorldMeshSetScale(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshSetScaleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CBD0 (FUN_0086CBD0, func_CUIWorldMeshSetScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetScale(vector scale)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetScale",
    &moho::cfunc_CUIWorldMeshSetScale,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BD10 (FUN_0086BD10, cfunc_CUIWorldMeshDestroyL)
 *
 * What it does:
 * Resolves one optional `CUIWorldMesh` and destroys it when still alive.
 */
int moho::cfunc_CUIWorldMeshDestroyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshDestroyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = ResolveCUIWorldMeshOptionalOrError(worldMeshObject, state);
  if (worldMesh != nullptr) {
    CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(worldMeshObject);
    if (scriptObjectSlot != nullptr && *scriptObjectSlot != nullptr) {
      delete *scriptObjectSlot;
    }
  }
  return 1;
}

/**
 * Address: 0x0086BE40 (FUN_0086BE40, cfunc_CUIWorldMeshSetMeshL)
 *
 * What it does:
 * Resolves one `CUIWorldMesh` plus descriptor-table argument and forwards the
 * table into `CUIWorldMesh::SetMesh`.
 */
int moho::cfunc_CUIWorldMeshSetMeshL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetMeshHelpText, 2, argumentCount);
  }

  if (lua_type(state->m_state, 2) != LUA_TTABLE) {
    gpg::Warnf("WorldMesh: Expected second parameter to be table");
    return 0;
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  const LuaPlus::LuaObject meshDescriptorObject(LuaPlus::LuaStackObject(state, 2));
  if (worldMesh != nullptr) {
    worldMesh->SetMesh(meshDescriptorObject);
  }
  return 0;
}

/**
 * Address: 0x0086BFD0 (FUN_0086BFD0, cfunc_CUIWorldMeshSetStanceL)
 *
 * What it does:
 * Updates world-mesh stance from `(position[, orientation])` by forwarding
 * one identical start/end transform to mesh-instance stance state.
 */
int moho::cfunc_CUIWorldMeshSetStanceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedBetweenArgsWarning, kCUIWorldMeshSetStanceHelpText, 2, 3, argumentCount);
  }

  Wm3::Quaternionf orientation = Wm3::Quaternionf::Identity();
  if (lua_gettop(state->m_state) >= 3) {
    LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
    orientation = SCR_FromLuaCopy<Wm3::Quaternionf>(orientationObject);
  }

  LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3f>(positionObject);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);
  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    VTransform stance{};
    stance.orient_ = orientation;
    stance.pos_ = position;
    meshInstance->SetStance(stance, stance);
  }
  return 0;
}

/**
 * Address: 0x0086C250 (FUN_0086C250, cfunc_CUIWorldMeshSetHiddenL)
 *
 * What it does:
 * Writes hidden flag lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetHiddenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetHiddenHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject hiddenArg(state, 2);
  const bool hidden = LuaPlus::LuaStackObject::GetBoolean(&hiddenArg);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->isHidden = hidden ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  }
  return 0;
}

/**
 * Address: 0x0086C390 (FUN_0086C390, cfunc_CUIWorldMeshIsHiddenL)
 *
 * What it does:
 * Pushes current hidden flag from underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshIsHiddenL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshIsHiddenHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  bool isHidden = false;
  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    isHidden = meshInstance->isHidden != 0;
  }

  lua_pushboolean(state->m_state, isHidden ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 0;
}

/**
 * Address: 0x0086C4D0 (FUN_0086C4D0, cfunc_CUIWorldMeshSetAuxiliaryParameterL)
 *
 * What it does:
 * Writes auxiliary scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetAuxiliaryParameterL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetAuxiliaryParameterHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->auxiliaryParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C650 (FUN_0086C650, cfunc_CUIWorldMeshSetFractionCompleteParameterL)
 *
 * What it does:
 * Writes fraction-complete scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetFractionCompleteParameterL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetFractionCompleteParameterHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->fractionCompleteParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C7D0 (FUN_0086C7D0, cfunc_CUIWorldMeshSetFractionHealthParameterL)
 *
 * What it does:
 * Writes fraction-health scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetFractionHealthParameterL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetFractionHealthParameterHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->fractionHealthParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C950 (FUN_0086C950, cfunc_CUIWorldMeshSetLifetimeParameterL)
 *
 * What it does:
 * Writes lifetime scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetLifetimeParameterL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetLifetimeParameterHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->lifetimeParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086CAD0 (FUN_0086CAD0, cfunc_CUIWorldMeshSetColorL)
 *
 * What it does:
 * Decodes one Lua color payload and writes packed color lane on underlying
 * `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetColorL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetColorHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->color = static_cast<std::int32_t>(color);
  }
  return 0;
}

/**
 * Address: 0x0086CC30 (FUN_0086CC30, cfunc_CUIWorldMeshSetScaleL)
 *
 * What it does:
 * Writes local scale vector lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetScaleL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshSetScaleHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaObject scaleObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f scale = SCR_FromLuaCopy<Wm3::Vector3f>(scaleObject);

  MeshInstance* const meshInstance = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh)->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->scale = scale;
  }
  return 0;
}

/**
 * Address: 0x0086CD40 (FUN_0086CD40, cfunc_CUIWorldMeshGetInterpolatedPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedPositionL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedPosition(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshGetInterpolatedPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CD60 (FUN_0086CD60, func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedPosition()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInterpolatedPosition",
    &moho::cfunc_CUIWorldMeshGetInterpolatedPosition,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CDC0 (FUN_0086CDC0, cfunc_CUIWorldMeshGetInterpolatedPositionL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated world position
 * vector from underlying `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedPositionL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshGetInterpolatedPositionHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Vector3f interpolatedPosition{};
  if (worldMesh != nullptr) {
    const CUIWorldMeshRuntimeView* const worldMeshView = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh);
    MeshInstance* const meshInstance = worldMeshView->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      interpolatedPosition = meshInstance->interpolatedPosition;
    }
  }

  LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3f>(state, interpolatedPosition);
  positionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086CF00 (FUN_0086CF00, cfunc_CUIWorldMeshGetInterpolatedSphere)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedSphereL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedSphere(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshGetInterpolatedSphereL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CF20 (FUN_0086CF20, func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedSphere()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInterpolatedSphere",
    &moho::cfunc_CUIWorldMeshGetInterpolatedSphere,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedSphereHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CF80 (FUN_0086CF80, cfunc_CUIWorldMeshGetInterpolatedSphereL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated bounding sphere
 * payload (`vector` center + `radius`) from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedSphereL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshGetInterpolatedSphereHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Vector3f center{};
  float radius = 0.0f;
  if (worldMesh != nullptr) {
    const CUIWorldMeshRuntimeView* const worldMeshView = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh);
    MeshInstance* const meshInstance = worldMeshView->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      center = meshInstance->sphere.Center;
      radius = meshInstance->sphere.Radius;
    }
  }

  LuaPlus::LuaObject sphereObject;
  sphereObject.AssignNewTable(state, 2, 0);
  LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3f>(state, center);
  sphereObject.SetObject("vector", centerObject);
  sphereObject.SetNumber("radius", radius);
  sphereObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D0F0 (FUN_0086D0F0, cfunc_CUIWorldMeshGetInterpolatedAlignedBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBox(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D110 (FUN_0086D110, func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedAlignedBox()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInterpolatedAlignedBox",
    &moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBox,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedAlignedBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D170 (FUN_0086D170, cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated axis-aligned
 * bounds payload from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshGetInterpolatedAlignedBoxHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  float xMin = 0.0f;
  float yMin = 0.0f;
  float zMin = 0.0f;
  float xMax = 0.0f;
  float yMax = 0.0f;
  float zMax = 0.0f;
  if (worldMesh != nullptr) {
    const CUIWorldMeshRuntimeView* const worldMeshView = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh);
    MeshInstance* const meshInstance = worldMeshView->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      xMin = meshInstance->xMin;
      yMin = meshInstance->yMin;
      zMin = meshInstance->zMin;
      xMax = meshInstance->xMax;
      yMax = meshInstance->yMax;
      zMax = meshInstance->zMax;
    }
  }

  LuaPlus::LuaObject alignedBoxObject;
  alignedBoxObject.AssignNewTable(state, 6, 0);
  alignedBoxObject.SetNumber("xMin", xMin);
  alignedBoxObject.SetNumber("yMin", yMin);
  alignedBoxObject.SetNumber("zMin", zMin);
  alignedBoxObject.SetNumber("xMax", xMax);
  alignedBoxObject.SetNumber("xMax", yMax);
  alignedBoxObject.SetNumber("xMax", zMax);
  alignedBoxObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D320 (FUN_0086D320, cfunc_CUIWorldMeshGetInterpolatedOrientedBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBox(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D340 (FUN_0086D340, func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedOrientedBox()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInterpolatedOrientedBox",
    &moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBox,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedOrientedBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D3A0 (FUN_0086D3A0, cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated oriented-box
 * payload from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshGetInterpolatedOrientedBoxHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Box3f box{};
  if (worldMesh != nullptr) {
    const CUIWorldMeshRuntimeView* const worldMeshView = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh);
    MeshInstance* const meshInstance = worldMeshView->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      box = meshInstance->box;
    }
  }

  const Wm3::Vector3f center(box.Center[0], box.Center[1], box.Center[2]);
  const Wm3::Vector3f xAxis(box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]);
  const Wm3::Vector3f yAxis(box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]);
  const Wm3::Vector3f zAxis(box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]);

  LuaPlus::LuaObject orientedBoxObject;
  orientedBoxObject.AssignNewTable(state, 7, 0);

  LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3f>(state, center);
  orientedBoxObject.SetObject("center", centerObject);

  LuaPlus::LuaObject xAxisObject = SCR_ToLua<Wm3::Vector3f>(state, xAxis);
  orientedBoxObject.SetObject("xAxis", xAxisObject);

  LuaPlus::LuaObject yAxisObject = SCR_ToLua<Wm3::Vector3f>(state, yAxis);
  orientedBoxObject.SetObject("yAxis", yAxisObject);

  LuaPlus::LuaObject zAxisObject = SCR_ToLua<Wm3::Vector3f>(state, zAxis);
  orientedBoxObject.SetObject("zAxis", zAxisObject);

  orientedBoxObject.SetNumber("xExtent", box.Extent[0]);
  orientedBoxObject.SetNumber("yExtent", box.Extent[1]);
  orientedBoxObject.SetNumber("zExtent", box.Extent[2]);
  orientedBoxObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D5E0 (FUN_0086D5E0, cfunc_CUIWorldMeshGetInterpolatedScroll)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedScrollL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedScroll(lua_State* const luaContext)
{
  return cfunc_CUIWorldMeshGetInterpolatedScrollL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D600 (FUN_0086D600, func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedScroll()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInterpolatedScroll",
    &moho::cfunc_CUIWorldMeshGetInterpolatedScroll,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedScrollHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D660 (FUN_0086D660, cfunc_CUIWorldMeshGetInterpolatedScrollL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated UV scroll vector
 * from underlying `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedScrollL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldMeshGetInterpolatedScrollHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Vector2f interpolatedScroll{};
  if (worldMesh != nullptr) {
    const CUIWorldMeshRuntimeView* const worldMeshView = CUIWorldMeshRuntimeView::FromWorldMesh(worldMesh);
    MeshInstance* const meshInstance = worldMeshView->mMeshInstance;
    if (meshInstance != nullptr) {
      const float t = MeshInstance::sCurrentInterpolant;
      interpolatedScroll.x = meshInstance->scroll1.x + (t * (meshInstance->scroll2.x - meshInstance->scroll1.x));
      interpolatedScroll.y = meshInstance->scroll1.y + (t * (meshInstance->scroll2.y - meshInstance->scroll1.y));
    }
  }

  LuaPlus::LuaObject interpolatedScrollObject = SCR_ToLua<Wm3::Vector2f>(state, interpolatedScroll);
  interpolatedScrollObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086EF40 (FUN_0086EF40, Moho::CUIWorldView::Draw)
 *
 * What it does:
 * Refreshes world-view viewport lazy-var bounds when drawing world content,
 * otherwise dispatches optional overlay draw callback state.
 *
 * Notes:
 * Recovered as a free function while `CUIWorldView` remains forward-declared.
 */
void moho::UIWorldViewDraw(
  CUIWorldView* const worldView,
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  if (drawMask == 1) {
    const float left = CScriptLazyVar_float::GetValue(&worldViewView->mViewLeft);
    const float top = CScriptLazyVar_float::GetValue(&worldViewView->mViewTop);
    const float right = CScriptLazyVar_float::GetValue(&worldViewView->mViewRight);
    const float bottom = CScriptLazyVar_float::GetValue(&worldViewView->mViewBottom);

    if (worldViewView->mCachedViewLeft != left || worldViewView->mCachedViewTop != top ||
        worldViewView->mCachedViewRight != right || worldViewView->mCachedViewBottom != bottom) {
      worldViewView->mCachedViewLeft = left;
      worldViewView->mCachedViewTop = top;
      worldViewView->mCachedViewRight = right;
      worldViewView->mCachedViewBottom = bottom;

      CRenderWorldViewViewportRuntimeView* const viewport = worldViewView->mViewportCallback;
      if (viewport != nullptr) {
        const Wm3::Vector2f minPoint{left, top};
        const Wm3::Vector2f maxPoint{right, bottom};
        viewport->SetViewRect(minPoint, maxPoint);
      }
    }
    return;
  }

  const std::uint32_t overlayToken = worldViewView->mOverlayDrawToken;
  if (overlayToken != 0u && overlayToken != 4u) {
    auto* const overlay =
      reinterpret_cast<CUIWorldViewOverlayRuntimeView*>(static_cast<std::uintptr_t>(overlayToken) - 4u);
    overlay->Draw(primBatcher);
  }
}

/**
 * Address: 0x008728B0 (FUN_008728B0, cfunc_CUIWorldViewGetScreenPosL)
 *
 * What it does:
 * Projects one `UserUnit` world position through the world-view camera and
 * returns one screen-space `Vector2` when the unit mesh intersects camera
 * frustum; otherwise pushes nil.
 */
int moho::cfunc_CUIWorldViewGetScreenPosL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewGetScreenPosHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 2));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  CameraZoomRuntimeView* const camera = worldViewView->mRenderWorldView.GetCamera();

  const UserUnitScreenPosRuntimeView* const userUnitView = UserUnitScreenPosRuntimeView::FromUserUnit(userUnit);
  MeshInstance* const meshInstance = userUnitView->mMeshInstance;
  if (meshInstance == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  meshInstance->UpdateInterpolatedFields();

  const GeomCamera3& cameraView = camera->GetView();
  const Wm3::AxisAlignedBox3f meshBounds{
    {meshInstance->xMin, meshInstance->yMin, meshInstance->zMin},
    {meshInstance->xMax, meshInstance->yMax, meshInstance->zMax},
  };
  if (!cameraView.solid2.Intersects(meshBounds)) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const Wm3::Vec3f& unitPosition = userUnitView->GetIUnitBridge()->GetPosition();
  const Wm3::Vector2f normalizedPoint = cameraView.Project(unitPosition, -1.0f, 1.0f, -1.0f, 1.0f);

  const float viewportWidth = cameraView.viewport.r[3].z;
  const float viewportHeight = cameraView.viewport.r[3].w;
  const Wm3::Vector3f screenPoint =
    ProjectNormalizedScreenPointToViewportFloor(normalizedPoint, viewportWidth, viewportHeight);

  if (screenPoint.x < 0.0f || screenPoint.x > viewportWidth || screenPoint.y < 0.0f || screenPoint.y > viewportHeight) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  const Wm3::Vector2f screenPoint2{screenPoint.x, screenPoint.y};
  LuaPlus::LuaObject screenPointObject = SCR_ToLua<Wm3::Vector2f>(state, screenPoint2);
  screenPointObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00872830 (FUN_00872830, cfunc_CUIWorldViewGetScreenPos)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewGetScreenPosL`.
 */
int moho::cfunc_CUIWorldViewGetScreenPos(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewGetScreenPosL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872850 (FUN_00872850, func_CUIWorldViewGetScreenPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the `GetScreenPos(unit)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldViewGetScreenPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetScreenPos",
    &moho::cfunc_CUIWorldViewGetScreenPos,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
    "CUIWorldView",
    kCUIWorldViewGetScreenPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782E90 (FUN_00782E90, Moho::CMauiControl::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection type for `CMauiControl`, resolving via RTTI on
 * first use.
 */
gpg::RType* moho::CMauiControl::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiControl));
  }
  return sType;
}

/**
 * Address: 0x007867B0 (FUN_007867B0, Moho::CMauiControl::CMauiControl)
 *
 * What it does:
 * Initializes one control root lane from Lua object + parent, builds lazy-var
 * wrappers for layout fields, links into parent child-list when present, and
 * binds Lua field aliases (`Left/Right/Top/Bottom/Width/Height/Depth`).
 */
moho::CMauiControl::CMauiControl(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent,
  msvc8::string controlKind
)
{
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  new (&scriptObject->cObject) LuaPlus::LuaObject();
  new (&scriptObject->mLuaObj) LuaPlus::LuaObject();

  CMauiControlHierarchyRuntimeView* const hierarchyView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControlExtendedRuntimeView* const extendedView = CMauiControlExtendedRuntimeView::FromControl(this);

  new (&hierarchyView->mParentList) CMauiControlListNode();
  hierarchyView->mParent = parent;
  new (&hierarchyView->mChildrenList) TDatList<CMauiControl, void>();

  LuaPlus::LuaState* const activeState = luaObject != nullptr ? luaObject->m_state : nullptr;
  new (&hierarchyView->mLeftLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mRightLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mTopLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mBottomLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mWidthLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mHeightLV) CScriptLazyVar_float(activeState);
  new (&hierarchyView->mDepthLV) CScriptLazyVar_float(activeState);

  extendedView->mDepth = 0.0f;
  new (&extendedView->mRenderedChildren) msvc8::vector<CMauiControl*>();
  hierarchyView->mInvalidated = true;
  hierarchyView->mDisableHitTest = false;
  hierarchyView->mIsHidden = false;
  hierarchyView->mNeedsFrameUpdate = false;
  extendedView->mInvisible = false;
  extendedView->mAlpha = 1.0f;
  extendedView->mVertexAlpha = static_cast<std::uint32_t>(-1);
  extendedView->mRenderPass = 0;
  extendedView->mRootFrame = nullptr;
  new (&extendedView->mDebugName) msvc8::string();
  extendedView->mDebugName = controlKind;

  if (luaObject != nullptr) {
    scriptObject->SetLuaObject(*luaObject);
  }

  if (parent != nullptr) {
    CMauiControlHierarchyRuntimeView* const parentView = CMauiControlHierarchyRuntimeView::FromControl(parent);
    hierarchyView->mParentList.ListLinkBefore(static_cast<CMauiControlListNode*>(&parentView->mChildrenList));
    SetHidden(parent->IsHidden());

    const CMauiControlExtendedRuntimeView* const parentExtendedView = CMauiControlExtendedRuntimeView::FromControl(parent);
    extendedView->mRenderPass = parentExtendedView->mRenderPass;
    extendedView->mRootFrame = parentExtendedView->mRootFrame;
  }

  LuaPlus::LuaObject& controlLuaObject = scriptObject->mLuaObj;
  controlLuaObject.SetObject("Left", &AsLazyVarObject(hierarchyView->mLeftLV));
  controlLuaObject.SetObject("Right", &AsLazyVarObject(hierarchyView->mRightLV));
  controlLuaObject.SetObject("Top", &AsLazyVarObject(hierarchyView->mTopLV));
  controlLuaObject.SetObject("Bottom", &AsLazyVarObject(hierarchyView->mBottomLV));
  controlLuaObject.SetObject("Width", &AsLazyVarObject(hierarchyView->mWidthLV));
  controlLuaObject.SetObject("Height", &AsLazyVarObject(hierarchyView->mHeightLV));
  controlLuaObject.SetObject("Depth", &AsLazyVarObject(hierarchyView->mDepthLV));

  extendedView->mDepth = CScriptLazyVar_float::GetValue(&hierarchyView->mDepthLV);
  if (extendedView->mRenderedChildren.begin() != extendedView->mRenderedChildren.end()) {
    extendedView->mRenderedChildren.clear();
  }
}

/**
 * Address: 0x00786D00 (FUN_00786D00, Moho::CMauiControl::~CMauiControl)
 *
 * What it does:
 * Invalidates parent ownership, destroys/unlinks child controls, tears down
 * control runtime lanes, then destroys embedded script-object state.
 */
moho::CMauiControl::~CMauiControl()
{
  CMauiControlHierarchyRuntimeView* const hierarchyView = CMauiControlHierarchyRuntimeView::FromControl(this);
  hierarchyView->mInvalidated = true;

  if (CMauiControl* const parentControl = hierarchyView->mParent; parentControl != nullptr) {
    parentControl->Invalidate();
  }

  CMauiControlListNode* const childSentinel = static_cast<CMauiControlListNode*>(&hierarchyView->mChildrenList);
  while (childSentinel->mNext != childSentinel) {
    CMauiControlListNode* const childNode = childSentinel->mPrev;
    childNode->ListUnlink();
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      delete childControl;
    }
  }

  CMauiControlExtendedRuntimeView* const extendedView = CMauiControlExtendedRuntimeView::FromControl(this);
  extendedView->mDebugName.~string();
  extendedView->mRenderedChildren.~vector();

  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mDepthLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mHeightLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mWidthLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mBottomLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mTopLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mRightLV)->~LuaObject();
  reinterpret_cast<LuaPlus::LuaObject*>(&hierarchyView->mLeftLV)->~LuaObject();

  childSentinel->ListUnlink();

  CMauiControlListNode* const parentListNode = &hierarchyView->mParentList;
  parentListNode->ListUnlink();

  reinterpret_cast<CScriptObject*>(this)->~CScriptObject();
}

/**
 * Address: 0x0077F690 (FUN_0077F690, Moho::CMauiControl::Left)
 *
 * What it does:
 * Returns writable reference to the left-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Left()
{
  return CMauiControlRuntimeView::FromControl(this)->mLeftLV;
}

/**
 * Address: 0x0077F6A0 (FUN_0077F6A0, Moho::CMauiControl::Right)
 *
 * What it does:
 * Returns writable reference to the right-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Right()
{
  return CMauiControlRuntimeView::FromControl(this)->mRightLV;
}

/**
 * Address: 0x0077F6B0 (FUN_0077F6B0, Moho::CMauiControl::Top)
 *
 * What it does:
 * Returns writable reference to the top-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Top()
{
  return CMauiControlRuntimeView::FromControl(this)->mTopLV;
}

/**
 * Address: 0x0077F6C0 (FUN_0077F6C0, Moho::CMauiControl::Bottom)
 *
 * What it does:
 * Returns writable reference to the bottom-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Bottom()
{
  return CMauiControlRuntimeView::FromControl(this)->mBottomLV;
}

/**
 * Address: 0x0077F6D0 (FUN_0077F6D0, Moho::CMauiControl::GetVertexAlpha)
 *
 * What it does:
 * Returns packed ARGB vertex-alpha color lane.
 */
std::uint32_t moho::CMauiControl::GetVertexAlpha()
{
  return CMauiControlExtendedRuntimeView::FromControl(this)->mVertexAlpha;
}

/**
 * Address: 0x0077F6E0 (FUN_0077F6E0, Moho::CMauiControl::SetNeedsFrameUpdate)
 *
 * What it does:
 * Updates frame-update-needed flag lane.
 */
void moho::CMauiControl::SetNeedsFrameUpdate(const bool needsFrameUpdate)
{
  CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = needsFrameUpdate;
}

/**
 * Address: 0x00786380 (FUN_00786380, Moho::CMauiControl::GetParent)
 *
 * What it does:
 * Returns owning parent control lane.
 */
moho::CMauiControl* moho::CMauiControl::GetParent() const
{
  return CMauiControlRuntimeView::FromControl(this)->mParent;
}

/**
 * Address: 0x00786390 (FUN_00786390, Moho::CMauiControl::GetRootFrame)
 *
 * What it does:
 * Returns cached root-frame owner lane.
 */
moho::CMauiFrame* moho::CMauiControl::GetRootFrame()
{
  return reinterpret_cast<CMauiFrame*>(CMauiControlExtendedRuntimeView::FromControl(this)->mRootFrame);
}

/**
 * Address: 0x007863F0 (FUN_007863F0, Moho::CMauiControl::SetAlpha)
 *
 * What it does:
 * Stores scalar alpha and updates packed vertex-alpha color lane.
 */
void moho::CMauiControl::SetAlpha(const float alpha)
{
  CMauiControlExtendedRuntimeView* const controlView = CMauiControlExtendedRuntimeView::FromControl(this);
  controlView->mAlpha = alpha;
  controlView->mVertexAlpha = PackVertexAlphaFromScalar(alpha);
}

/**
 * Address: 0x0078EC10 (FUN_0078EC10, Moho::CMauiControl::AdjustARGBAlpha)
 *
 * What it does:
 * Replaces the input ARGB alpha channel with this control's current alpha lane
 * while preserving RGB channels.
 */
std::uint32_t moho::CMauiControl::AdjustARGBAlpha(const std::uint32_t color)
{
  const float alpha = CMauiControlExtendedRuntimeView::FromControl(this)->mAlpha;
  const std::int32_t alphaByteLane = static_cast<std::int32_t>(alpha * -255.0f);
  return (color & 0x00FFFFFFu) - (static_cast<std::uint32_t>(alphaByteLane) << 24u);
}

/**
 * Address: 0x00786440 (FUN_00786440, Moho::CMauiControl::GetAlpha)
 *
 * What it does:
 * Returns current alpha lane used by control rendering.
 */
float moho::CMauiControl::GetAlpha()
{
  return CMauiControlExtendedRuntimeView::FromControl(this)->mAlpha;
}

/**
 * Address: 0x00786450 (FUN_00786450, Moho::CMauiControl::IsInvisible)
 *
 * What it does:
 * Returns whether this control is currently marked invisible.
 */
bool moho::CMauiControl::IsInvisible()
{
  return CMauiControlExtendedRuntimeView::FromControl(this)->mInvisible;
}

/**
 * Address: 0x00786460 (FUN_00786460, Moho::CMauiControl::SetRenderPass)
 *
 * What it does:
 * Updates integer render-pass lane.
 */
void moho::CMauiControl::SetRenderPass(const std::int32_t renderPass)
{
  CMauiControlExtendedRuntimeView::FromControl(this)->mRenderPass = renderPass;
}

/**
 * Address: 0x00786470 (FUN_00786470, Moho::CMauiControl::GetRenderPass)
 *
 * What it does:
 * Returns integer render-pass lane.
 */
std::int32_t moho::CMauiControl::GetRenderPass()
{
  return CMauiControlExtendedRuntimeView::FromControl(this)->mRenderPass;
}

/**
 * Address: 0x00786480 (FUN_00786480, Moho::CMauiControl::NeedsFrameUpdate)
 *
 * What it does:
 * Returns current frame-update-needed flag lane.
 */
bool moho::CMauiControl::NeedsFrameUpdate()
{
  return CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate;
}

/**
 * Address: 0x00786AA0 (FUN_00786AA0, Moho::CMauiControl::Invalidate)
 *
 * What it does:
 * Marks this control and its parent chain as invalidated.
 */
void moho::CMauiControl::Invalidate()
{
  CMauiControl* controlCursor = this;
  while (controlCursor != nullptr) {
    CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(controlCursor);
    controlView->mInvalidated = true;
    controlCursor = controlView->mParent;
  }
}

/**
 * Address: 0x00786AD0 (FUN_00786AD0, Moho::CMauiControl::SetParent)
 *
 * What it does:
 * Reparents this control into a new parent-child intrusive list lane and
 * invalidates affected controls.
 */
void moho::CMauiControl::SetParent(CMauiControl* const newParent)
{
  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControl* const currentParent = controlView->mParent;
  if (newParent == currentParent) {
    return;
  }

  controlView->mInvalidated = true;
  if (currentParent != nullptr) {
    currentParent->Invalidate();
  }

  controlView->mParentList.ListUnlink();
  controlView->mParent = newParent;

  if (newParent != nullptr) {
    CMauiControlHierarchyRuntimeView* const parentView = CMauiControlHierarchyRuntimeView::FromControl(newParent);
    controlView->mParentList.ListLinkBefore(&parentView->mChildrenList);
    Invalidate();
  }
}

/**
 * Address: 0x00786E90 (FUN_00786E90, Moho::CMauiControl::DoInit)
 *
 * What it does:
 * Invokes script callback `OnInit` on this control object.
 */
void moho::CMauiControl::DoInit()
{
  (void)reinterpret_cast<CScriptObject*>(this)->RunScript("OnInit");
}

/**
 * Address: 0x00786EF0 (FUN_00786EF0, Moho::CMauiControl::Destroy)
 *
 * What it does:
 * Marks this control invalid/invisible, detaches parent ownership, moves the
 * control into the root-frame deleted-control list, dispatches `OnDestroy`,
 * and destroys all direct/indirect children.
 */
void moho::CMauiControl::Destroy()
{
  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControl* const parentControl = controlView->mParent;

  controlView->mInvalidated = true;
  if (parentControl != nullptr) {
    parentControl->Invalidate();
  }

  CMauiControlExtendedRuntimeView* const extendedView = CMauiControlExtendedRuntimeView::FromControl(this);
  CMauiFrame* const rootFrame = reinterpret_cast<CMauiFrame*>(extendedView->mRootFrame);
  extendedView->mInvisible = true;
  controlView->mParent = nullptr;

  if (this != rootFrame) {
    moho::CMauiFrameRuntimeView* const rootFrameView = moho::CMauiFrameRuntimeView::FromFrame(rootFrame);
    controlView->mParentList.ListLinkBefore(static_cast<CMauiControlListNode*>(&rootFrameView->mDeletedControlList));
  }

  (void)reinterpret_cast<CScriptObject*>(this)->RunScript("OnDestroy");
  ClearChildren();
}

/**
 * Address: 0x00786F60 (FUN_00786F60, Moho::CMauiControl::ClearChildren)
 *
 * What it does:
 * Unlinks direct children one by one and dispatches virtual destroy on each.
 */
void moho::CMauiControl::ClearChildren()
{
  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);

  while (sentinel->mNext != sentinel) {
    CMauiControlListNode* const childNode = sentinel->mNext;
    childNode->ListUnlink();
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      childControl->Destroy();
    }
  }
}

/**
 * Address: 0x00786FA0 (FUN_00786FA0, Moho::CMauiControl::Render)
 *
 * What it does:
 * Refreshes depth lanes for visible controls in this subtree and, when depth
 * changed or invalidated, rebuilds + depth-sorts the rendered-children lane.
 */
void moho::CMauiControl::Render()
{
  CMauiControlExtendedRuntimeView* const rootView = CMauiControlExtendedRuntimeView::FromControl(this);
  if (rootView->mInvisible) {
    return;
  }

  CMauiControlHierarchyRuntimeView* const rootHierarchy = CMauiControlHierarchyRuntimeView::FromControl(this);
  const bool depthChanged = RefreshDepthLaneForSubtree(this);
  if (!depthChanged && !rootHierarchy->mInvalidated) {
    return;
  }

  RebuildRenderedChildrenLane(this);
  SortRenderedChildrenByDepth(rootView->mRenderedChildren);
  rootHierarchy->mInvalidated = false;
}

/**
 * Address: 0x00786EA0 (FUN_00786EA0, Moho::CMauiControl::DepthFirstSuccessor)
 *
 * What it does:
 * Returns the next control in depth-first order, constrained to one root
 * subtree.
 */
moho::CMauiControl* moho::CMauiControl::DepthFirstSuccessor(CMauiControl* const subtreeRoot)
{
  if (CMauiControl* const childControl = FirstChildControl(this); childControl != nullptr) {
    return childControl;
  }

  const CMauiControl* rootCursor = subtreeRoot;
  CMauiControl* traversalCursor = this;
  while (traversalCursor != nullptr && traversalCursor != rootCursor) {
    if (CMauiControl* const siblingControl = NextSiblingControl(traversalCursor); siblingControl != nullptr) {
      return siblingControl;
    }
    traversalCursor = CMauiControlHierarchyRuntimeView::FromControl(traversalCursor)->mParent;
  }

  return nullptr;
}

/**
 * Address: 0x007870F0 (FUN_007870F0, Moho::CMauiFrame::DoRender)
 *
 * What it does:
 * Walks the rendered-child lane and dispatches `DoRender` for each visible
 * child whose render-pass mask intersects the requested draw mask.
 */
void moho::CMauiFrame::DoRender(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  if (CMauiControlExtendedRuntimeView::FromControl(this)->mInvisible) {
    return;
  }

  for (std::uint32_t childIndex = 0; ; ++childIndex) {
    const CMauiControlExtendedRuntimeView* const frameView = CMauiControlExtendedRuntimeView::FromControl(this);
    CMauiControl* const* const renderedBegin = frameView->mRenderedChildren.begin();
    if (renderedBegin == nullptr) {
      break;
    }

    const std::int32_t renderedCount = static_cast<std::int32_t>(frameView->mRenderedChildren.end() - renderedBegin);
    if (childIndex >= static_cast<std::uint32_t>(renderedCount)) {
      break;
    }

    CMauiControl* const childControl = renderedBegin[childIndex];
    if (childControl == nullptr || childControl->IsHidden()) {
      continue;
    }

    const CMauiControlExtendedRuntimeView* const childView = CMauiControlExtendedRuntimeView::FromControl(childControl);
    if ((drawMask & childView->mRenderPass) == 0) {
      continue;
    }

    childControl->DoRender(primBatcher, drawMask);
  }
}

/**
 * Address: 0x00787170 (FUN_00787170, Moho::CMauiControl::SetHidden)
 *
 * What it does:
 * Calls `OnHide(hidden)` and, when callback does not consume the event,
 * updates hidden-state lane and applies the same value to children.
 */
void moho::CMauiControl::SetHidden(const bool hidden)
{
  if (OnHide(hidden)) {
    return;
  }

  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  controlView->mIsHidden = hidden;

  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);
  for (CMauiControlListNode* childNode = controlView->mChildrenList.mNext; childNode != sentinel; childNode = childNode->mNext) {
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      childControl->SetHidden(hidden);
    }
  }
}

/**
 * Address: 0x0078A700 (FUN_0078A700, Moho::CMauiControl::OnHide)
 *
 * What it does:
 * Invokes `OnHide(self, hidden)` Lua callback and returns callback bool result.
 */
bool moho::CMauiControl::OnHide(const bool& hidden)
{
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  ScriptCallbackWeakGuard weakGuard(scriptObject);

  LuaPlus::LuaObject callbackObject{};
  scriptObject->FindScript(&callbackObject, "OnHide");
  if (!callbackObject) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<bool> callback(callbackObject);
    return callback(CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj, hidden);
  } catch (const std::exception& exception) {
    LogOnHideCallbackException(weakGuard.ResolveObjectForWarning(), exception);
  }

  return false;
}

/**
 * Address: 0x007876D0 (FUN_007876D0, Moho::CMauiControl::IsScrollable)
 *
 * What it does:
 * Converts axis enum to lexical token and forwards to `GetIsScrollable`.
 */
bool moho::CMauiControl::IsScrollable(const EMauiScrollAxis axis)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axisCopy);
  const msvc8::string axisLexical = axisRef.GetLexical();
  return GetIsScrollable(axisLexical.c_str());
}

/**
 * Address: 0x0078AA00 (FUN_0078AA00, Moho::CMauiControl::GetIsScrollable)
 *
 * What it does:
 * Invokes `IsScrollable(self, axisText)` callback and returns its bool result.
 */
bool moho::CMauiControl::GetIsScrollable(const char* const axisLexical)
{
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  WeakObject::ScopedWeakLinkGuard weakGuard(static_cast<WeakObject*>(scriptObject));

  LuaPlus::LuaObject callbackObject{};
  scriptObject->FindScript(&callbackObject, "IsScrollable");
  if (!callbackObject) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<bool> callback(callbackObject);
    return callback(CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj, axisLexical != nullptr ? axisLexical : "");
  } catch (const std::exception& exception) {
    LogIsScrollableCallbackException(scriptObject, exception);
  } catch (...) {
    scriptObject->LogScriptWarning(scriptObject, "IsScrollable", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x00787160 (FUN_00787160, Moho::CMauiControl::DoRender)
 *
 * What it does:
 * Default render lane for controls without concrete drawing logic.
 */
void moho::CMauiControl::DoRender(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  (void)primBatcher;
  (void)drawMask;
}

/**
 * Address: 0x007871C0 (FUN_007871C0, Moho::CMauiControl::IsHidden)
 *
 * What it does:
 * Returns hidden-state lane for this control.
 */
bool moho::CMauiControl::IsHidden()
{
  return CMauiControlHierarchyRuntimeView::FromControl(this)->mIsHidden;
}

/**
 * Address: 0x007871D0 (FUN_007871D0, Moho::CMauiControl::OnMinimized)
 *
 * What it does:
 * Propagates minimized-state notifications to direct/indirect children.
 */
void moho::CMauiControl::OnMinimized(const bool minimized)
{
  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);
  for (CMauiControlListNode* childNode = controlView->mChildrenList.mNext; childNode != sentinel; childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      childControl->OnMinimized(minimized);
    }
  }
}

/**
 * Address: 0x00787210 (FUN_00787210, Moho::CMauiControl::DisableHitTest)
 *
 * What it does:
 * Sets hit-test disabled state and optionally applies it recursively to child
 * controls.
 */
void moho::CMauiControl::DisableHitTest(const bool disableHitTest, const bool applyChildren)
{
  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  controlView->mDisableHitTest = disableHitTest;

  if (!applyChildren) {
    return;
  }

  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);
  for (CMauiControlListNode* childNode = controlView->mChildrenList.mNext; childNode != sentinel; childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      childControl->DisableHitTest(disableHitTest, true);
    }
  }
}

/**
 * Address: 0x00787260 (FUN_00787260, Moho::CMauiControl::IsHitTestDisabled)
 *
 * What it does:
 * Returns hit-test disabled state for this control.
 */
bool moho::CMauiControl::IsHitTestDisabled()
{
  return CMauiControlHierarchyRuntimeView::FromControl(this)->mDisableHitTest;
}

/**
 * Address: 0x00787780 (FUN_00787780, Moho::CMauiControl::ScrollLines)
 *
 * What it does:
 * Invokes script callback `ScrollLines(axisText, amount)`.
 */
void moho::CMauiControl::ScrollLines(const EMauiScrollAxis axis, const float amount)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axisCopy);
  const msvc8::string axisLexical = axisRef.GetLexical();
  reinterpret_cast<CScriptObject*>(this)->RunScriptStringNum("ScrollLines", axisLexical.c_str(), amount);
}

/**
 * Address: 0x00787830 (FUN_00787830, Moho::CMauiControl::ScrollPages)
 *
 * What it does:
 * Invokes script callback `ScrollLines(axisText, amount)` for page-scroll
 * requests (binary callback name lane).
 */
void moho::CMauiControl::ScrollPages(const EMauiScrollAxis axis, const float amount)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axisCopy);
  const msvc8::string axisLexical = axisRef.GetLexical();
  reinterpret_cast<CScriptObject*>(this)->RunScriptStringNum("ScrollLines", axisLexical.c_str(), amount);
}

/**
 * Address: 0x007878E0 (FUN_007878E0, Moho::CMauiControl::ScrollSetTop)
 *
 * What it does:
 * Invokes script callback `ScrollSetTop(axisText, amount)`.
 */
void moho::CMauiControl::ScrollSetTop(const EMauiScrollAxis axis, const float amount)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axisCopy);
  const msvc8::string axisLexical = axisRef.GetLexical();
  reinterpret_cast<CScriptObject*>(this)->RunScriptStringNum("ScrollSetTop", axisLexical.c_str(), amount);
}

/**
 * Address: 0x00787270 (FUN_00787270, Moho::CMauiControl::HitTest)
 *
 * What it does:
 * Returns whether `(x,y)` lies inside the control bounds.
 */
bool moho::CMauiControl::HitTest(const float x, const float y)
{
  const CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  return x >= CScriptLazyVar_float::GetValue(&controlView->mLeftLV)
      && CScriptLazyVar_float::GetValue(&controlView->mRightLV) > x
      && y >= CScriptLazyVar_float::GetValue(&controlView->mTopLV)
      && CScriptLazyVar_float::GetValue(&controlView->mBottomLV) > y;
}

/**
 * Address: 0x007872E0 (FUN_007872E0, Moho::CMauiControl::GetTopmostControl)
 *
 * What it does:
 * Scans one control subtree and returns topmost depth-matching visible control
 * under `(x,y)`.
 */
moho::CMauiControl* moho::CMauiControl::GetTopmostControl(CMauiControl* const root, const float x, const float y)
{
  CMauiControl* topmostControl = nullptr;
  float topmostDepth = -std::numeric_limits<float>::infinity();
  for (CMauiControl* controlCursor = root; controlCursor != nullptr; controlCursor = controlCursor->DepthFirstSuccessor(root)) {
    if (controlCursor->IsHidden() || controlCursor->IsHitTestDisabled() || !controlCursor->HitTest(x, y)) {
      continue;
    }

    const CMauiControlRuntimeView* const controlView = CMauiControlRuntimeView::FromControl(controlCursor);
    const float controlDepth = CScriptLazyVarFloatCachedValueView::FromLazyVar(&controlView->mDepthLV)->mCachedValue;
    if (controlDepth > topmostDepth) {
      topmostControl = controlCursor;
      topmostDepth = controlDepth;
    }
  }

  return topmostControl;
}

/**
 * Address: 0x00787370 (FUN_00787370, Moho::CMauiControl::PostEvent)
 *
 * What it does:
 * Dispatches one event to this control and then walks parent controls until
 * one handler returns true.
 */
void moho::CMauiControl::PostEvent(const SMauiEventData& eventData)
{
  CMauiControl* parentControl = CMauiControlHierarchyRuntimeView::FromControl(this)->mParent;
  if (HandleEvent(eventData)) {
    return;
  }

  while (parentControl != nullptr) {
    CMauiControl* const controlCursor = parentControl;
    parentControl = CMauiControlHierarchyRuntimeView::FromControl(parentControl)->mParent;
    if (controlCursor->HandleEvent(eventData)) {
      break;
    }
  }
}

/**
 * Address: 0x007873A0 (FUN_007873A0, Moho::CMauiControl::HandleEvent)
 *
 * What it does:
 * Builds one Lua event payload object and invokes `HandleEvent(self,event)`.
 */
bool moho::CMauiControl::HandleEvent(const SMauiEventData& eventData)
{
  LuaPlus::LuaState* const activeState = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj.GetActiveState();
  LuaPlus::LuaObject eventObject{};
  CreateLuaEventObject(const_cast<SMauiEventData*>(&eventData), &eventObject, activeState);
  return InvokeControlScriptObjectBool(this, "HandleEvent", eventObject);
}

/**
 * Address: 0x00787420 (FUN_00787420, Moho::CMauiControl::Frame)
 *
 * What it does:
 * Invokes script callback `OnFrame(deltaSeconds)` on this control object.
 */
void moho::CMauiControl::Frame(const float deltaSeconds)
{
  reinterpret_cast<CScriptObject*>(this)->RunScriptNum("OnFrame", deltaSeconds);
}

/**
 * Address: 0x00787440 (FUN_00787440, Moho::CMauiControl::LosingKeyboardFocus)
 *
 * What it does:
 * Invokes `OnLoseKeyboardFocus` callback on this control script object.
 */
void moho::CMauiControl::LosingKeyboardFocus()
{
  (void)reinterpret_cast<CScriptObject*>(this)->RunScript("OnLoseKeyboardFocus");
}

/**
 * Address: 0x00787450 (FUN_00787450, Moho::CMauiControl::OnKeyboardFocusChange)
 *
 * What it does:
 * Invokes `OnKeyboardFocusChange` callback on this control script object.
 */
void moho::CMauiControl::OnKeyboardFocusChange()
{
  (void)reinterpret_cast<CScriptObject*>(this)->RunScript("OnKeyboardFocusChange");
}

/**
 * Address: 0x00787460 (FUN_00787460, Moho::CMauiControl::AcquireKeyboardFocus)
 *
 * What it does:
 * Routes one focus-acquire request through global MAUI focus owner lane.
 */
void moho::CMauiControl::AcquireKeyboardFocus(const bool blocksKeyDown)
{
  MAUI_SetKeyboardFocus(this, blocksKeyDown);
}

/**
 * Address: 0x00787480 (FUN_00787480, Moho::CMauiControl::AbandonKeyboardFocus)
 *
 * What it does:
 * Clears global focus owner when this control currently owns focus.
 */
void moho::CMauiControl::AbandonKeyboardFocus()
{
  if (Maui_CurrentFocusControl.ResolveFocusedControl() == this) {
    MAUI_SetKeyboardFocus(nullptr, true);
  }
}

/**
 * Address: 0x007874B0 (FUN_007874B0, Moho::CMauiControl::GetScrollValues)
 *
 * What it does:
 * Calls script callback `GetScrollValues(axisLexical)` and returns
 * `{minRange,maxRange,minVisible,maxVisible}` numeric lanes when all four
 * results are provided.
 */
moho::SMauiScrollValues moho::CMauiControl::GetScrollValues(const EMauiScrollAxis axis)
{
  SMauiScrollValues values{};
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  LuaPlus::LuaState* const activeState = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj.GetActiveState();
  if (scriptObject == nullptr || activeState == nullptr || activeState->m_state == nullptr) {
    return values;
  }

  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  gpg::RRef_EMauiScrollAxis(&axisRef, &axisCopy);
  const auto axisLexical = axisRef.GetLexical();

  LuaPlus::LuaObject axisArg{};
  axisArg.AssignString(activeState, axisLexical.c_str());

  LuaPlus::LuaObject arg2{};
  LuaPlus::LuaObject arg3{};
  LuaPlus::LuaObject arg4{};
  LuaPlus::LuaObject arg5{};
  gpg::core::FastVector<LuaPlus::LuaObject> results{};
  scriptObject->RunScriptMultiRet("GetScrollValues", results, axisArg, arg2, arg3, arg4, arg5);

  const auto resultCount = results.size();
  if (resultCount == 4) {
    values.mMinRange = static_cast<float>(results[0].ToNumber());
    values.mMaxRange = static_cast<float>(results[1].ToNumber());
    values.mMinVisible = static_cast<float>(results[2].ToNumber());
    values.mMaxVisible = static_cast<float>(results[3].ToNumber());
  } else {
    gpg::Warnf(kGetScrollValuesResultWarning);
  }

  return values;
}

/**
 * Address: 0x00787990 (FUN_00787990, Moho::CMauiControl::ApplyFunction)
 *
 * What it does:
 * Calls one Lua function with this control and each direct child control.
 */
void moho::CMauiControl::ApplyFunction(const LuaPlus::LuaObject& functionObject)
{
  LuaPlus::LuaFunction<void> callback(functionObject);
  callback(CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj);

  CMauiControlHierarchyRuntimeView* const controlView = CMauiControlHierarchyRuntimeView::FromControl(this);
  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&controlView->mChildrenList);
  for (CMauiControlListNode* childNode = controlView->mChildrenList.mNext; childNode != sentinel; childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      callback(CMauiControlScriptObjectRuntimeView::FromControl(childControl)->mLuaObj);
    }
  }
}

/**
 * Address: 0x0077F6F0 (FUN_0077F6F0, Moho::CMauiControl::GetDebugName)
 *
 * What it does:
 * Returns one copied debug-name string from the control runtime lane.
 */
msvc8::string moho::CMauiControl::GetDebugName()
{
  return CMauiControlExtendedRuntimeView::FromControl(this)->mDebugName;
}

/**
 * Address: 0x0077F720 (FUN_0077F720, Moho::CMauiControl::SetDebugName)
 *
 * What it does:
 * Copies one debug-name string into the control debug-name lane.
 */
void moho::CMauiControl::SetDebugName(msvc8::string debugName)
{
  CMauiControlExtendedRuntimeView::FromControl(this)->mDebugName = debugName;
}

namespace
{
  [[nodiscard]] std::int32_t GetBitmapTextureBatchCount(const moho::CMauiBitmapRuntimeView* const bitmapView) noexcept
  {
    const boost::shared_ptr<moho::CD3DBatchTexture>* const textureStart = bitmapView->mTextureBatches.begin();
    return textureStart != nullptr ? static_cast<std::int32_t>(bitmapView->mTextureBatches.end() - textureStart) : 0;
  }

  /**
   * Address: 0x0077F7F0 (FUN_0077F7F0)
   *
   * What it does:
   * Stores one alpha-hit-test boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmapRuntimeView* SetBitmapAlphaHitTestEnabled(
    moho::CMauiBitmapRuntimeView* const bitmapView,
    const bool enabled
  ) noexcept
  {
    bitmapView->mUseAlphaHitTest = enabled;
    return bitmapView;
  }

  /**
   * Address: 0x0077F7E0 (FUN_0077F7E0)
   *
   * What it does:
   * Stores one tiled-render boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmapRuntimeView* SetBitmapTiledEnabled(
    moho::CMauiBitmapRuntimeView* const bitmapView,
    const bool enabled
  ) noexcept
  {
    bitmapView->mIsTiled = enabled;
    return bitmapView;
  }

  /**
   * Address: 0x00780100 (FUN_00780100)
   *
   * What it does:
   * Stores one loop-enabled boolean lane into one bitmap runtime view.
   */
  [[maybe_unused]] moho::CMauiBitmapRuntimeView* SetBitmapLoopEnabled(
    moho::CMauiBitmapRuntimeView* const bitmapView,
    const bool enabled
  ) noexcept
  {
    bitmapView->mDoLoop = enabled;
    return bitmapView;
  }

  /**
   * Address: 0x00780220 (FUN_00780220)
   *
   * What it does:
   * Reads one current-frame index lane from one bitmap runtime view.
   */
  [[maybe_unused]] std::int32_t ReadBitmapCurrentFrame(
    const moho::CMauiBitmapRuntimeView* const bitmapView
  ) noexcept
  {
    return bitmapView->mCurrentFrame;
  }

  /**
   * Address: 0x00780230 (FUN_00780230)
   *
   * What it does:
   * Returns frame count from one bitmap frame-pattern vector lane.
   */
  [[maybe_unused]] std::int32_t CountBitmapFramePatternEntries(
    const moho::CMauiBitmapRuntimeView* const bitmapView
  ) noexcept
  {
    const std::int32_t* const frameStart = bitmapView->mFrames.begin();
    if (frameStart == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(bitmapView->mFrames.end() - frameStart);
  }

  /**
   * Address: 0x00780090 (FUN_00780090)
   *
   * What it does:
   * Enables bitmap animation/frame updates when there are at least two queued
   * textures; returns remaining texture-slot count.
   */
  [[maybe_unused]] std::uint32_t EnableBitmapAnimationIfMultipleTextures(
    moho::CMauiBitmapRuntimeView* const bitmapView
  ) noexcept
  {
    const auto* const batchCursor = bitmapView->mTextureBatches.end();
    if (batchCursor == nullptr) {
      return 0u;
    }

    const std::uint32_t remainingSlots = static_cast<std::uint32_t>(
      bitmapView->mTextureBatches.capacity() - bitmapView->mTextureBatches.size()
    );
    if (remainingSlots > 1u) {
      bitmapView->mIsPlaying = true;
      reinterpret_cast<moho::CMauiControlFrameUpdateRuntimeView*>(bitmapView)->mNeedsFrameUpdate = true;
    }
    return remainingSlots;
  }

}

/**
 * Address: 0x0077F950 (FUN_0077F950, Moho::CMauiBitmap::CMauiBitmap)
 *
 * What it does:
 * Constructs one bitmap control from Lua object + parent, initializes texture
 * sequence/state lanes, and binds bitmap width/height lazy-vars into Lua.
 */
moho::CMauiBitmap::CMauiBitmap(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "Bitmap")
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  new (&bitmapView->mTextureBatches) msvc8::vector<boost::shared_ptr<CD3DBatchTexture>>();

  LuaPlus::LuaState* const activeState = luaObject != nullptr ? luaObject->m_state : nullptr;
  new (&bitmapView->mBitmapWidthLV) CScriptLazyVar_float(activeState);
  new (&bitmapView->mBitmapHeightLV) CScriptLazyVar_float(activeState);

  bitmapView->mU1 = 1.0f;
  bitmapView->mV1 = 1.0f;
  bitmapView->mU0 = 0.0f;
  bitmapView->mV0 = 0.0f;
  bitmapView->mHitMask = nullptr;
  bitmapView->mUseAlphaHitTest = false;
  bitmapView->mIsTiled = false;
  bitmapView->mFrameDurationSeconds = 1.0f / 12.0f;
  bitmapView->mIsPlaying = false;
  bitmapView->mDoLoop = false;
  bitmapView->mCurrentFrame = 0;
  bitmapView->mCurrentFrameTimeSeconds = 0.0f;
  for (std::uint8_t& lane : bitmapView->mUnknown17CTo17F) {
    lane = 0;
  }
  new (&bitmapView->mFrames) msvc8::vector<std::int32_t>();

  LuaPlus::LuaObject& controlLuaObject = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj;
  controlLuaObject.SetObject("BitmapWidth", &AsLazyVarObject(bitmapView->mBitmapWidthLV));
  controlLuaObject.SetObject("BitmapHeight", &AsLazyVarObject(bitmapView->mBitmapHeightLV));
}

/**
 * Address: 0x0077FBF0 (FUN_0077FBF0, Moho::CMauiBitmap::~CMauiBitmap body)
 * Deleting thunk: 0x0077FAA0 (FUN_0077FAA0, Moho::CMauiBitmap::dtr)
 *
 * What it does:
 * Releases hit-mask/animation/lazy-var/runtime texture lanes before base
 * `CMauiControl` teardown.
 */
moho::CMauiBitmap::~CMauiBitmap()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);

  if (bitmapView->mHitMask != nullptr) {
    gpg::BitArray2D* const hitMask = static_cast<gpg::BitArray2D*>(bitmapView->mHitMask);
    hitMask->~BitArray2D();
    ::operator delete(hitMask);
    bitmapView->mHitMask = nullptr;
  }

  bitmapView->mFrames.~vector();
  AsLazyVarObject(bitmapView->mBitmapHeightLV).~LuaObject();
  AsLazyVarObject(bitmapView->mBitmapWidthLV).~LuaObject();
  bitmapView->mTextureBatches.~vector();
}

/**
 * Address: 0x0077FF70 (FUN_0077FF70, Moho::CMauiBitmap::HitTest)
 *
 * What it does:
 * Applies base bounds hit-testing first, then uses packed hit-mask lanes when
 * present; otherwise optionally checks texture alpha at the local pixel.
 */
bool moho::CMauiBitmap::HitTest(const float x, const float y)
{
  const bool baseHit = CMauiControl::HitTest(x, y);
  if (!baseHit) {
    return false;
  }

  const CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  const float localX = x - CScriptLazyVar_float::GetValue(&bitmapView->mLeftLV);
  const float localY = y - CScriptLazyVar_float::GetValue(&bitmapView->mTopLV);

  const auto* const hitMask = static_cast<const gpg::BitArray2D*>(bitmapView->mHitMask);
  if (hitMask != nullptr) {
    const int sampleX = static_cast<int>(localX);
    const int sampleY = static_cast<int>(localY);
    const std::uint32_t bitMask = 1u << (static_cast<std::uint32_t>(sampleY) & 0x1Fu);
    const int wordRow = static_cast<int>(static_cast<std::uint32_t>(sampleY) >> 5u);
    const int wordIndex = sampleX + (hitMask->width * wordRow);
    return (hitMask->ptr[wordIndex] & static_cast<std::int32_t>(bitMask)) != 0;
  }

  if (!bitmapView->mUseAlphaHitTest) {
    return baseHit;
  }

  const std::int32_t* const frameStart = bitmapView->mFrames.begin();
  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = bitmapView->mTextureBatches.begin();
  const std::int32_t frameTextureIndex = frameStart[bitmapView->mCurrentFrame];
  const boost::shared_ptr<CD3DBatchTexture>& texture = textureStart[frameTextureIndex];
  if (!texture) {
    return baseHit;
  }

  const std::int32_t pixelX = static_cast<std::int32_t>(localX);
  const std::int32_t pixelY = static_cast<std::int32_t>(localY);
  return texture->GetAlphaAt(static_cast<std::uint32_t>(pixelX), static_cast<std::uint32_t>(pixelY)) != 0u;
}

/**
 * Address: 0x0077FCF0 (FUN_0077FCF0, Moho::CMauiBitmap::ShareTextures)
 *
 * What it does:
 * Copies texture-batch lanes from `sourceBitmap` into this bitmap and refreshes
 * bitmap width/height lazy-vars from frame `0`.
 */
void moho::CMauiBitmap::ShareTextures(CMauiBitmap* const sourceBitmap)
{
  CMauiBitmapRuntimeView* const destinationView = CMauiBitmapRuntimeView::FromBitmap(this);
  const CMauiBitmapRuntimeView* const sourceView = CMauiBitmapRuntimeView::FromBitmap(sourceBitmap);

  destinationView->mTextureBatches = sourceView->mTextureBatches;

  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = destinationView->mTextureBatches.begin();
  CScriptLazyVar_float::SetValue(&destinationView->mBitmapWidthLV, static_cast<float>(textureStart->get()->mWidth));
  CScriptLazyVar_float::SetValue(&destinationView->mBitmapHeightLV, static_cast<float>(textureStart->get()->mHeight));
}

/**
 * Address: 0x0077FD90 (FUN_0077FD90, Moho::CMauiBitmap::SetTexture)
 *
 * What it does:
 * Appends one texture lane to this bitmap texture-batch list and updates width
 * and height lazy-vars for single-frame paths.
 */
void moho::CMauiBitmap::SetTexture(const boost::shared_ptr<CD3DBatchTexture>& texture)
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  AppendBitmapTextureBatch(bitmapView->mTextureBatches, texture);

  const boost::shared_ptr<CD3DBatchTexture>* const textureStart = bitmapView->mTextureBatches.begin();
  if (textureStart != nullptr && (bitmapView->mTextureBatches.end() - textureStart) == 1) {
    CScriptLazyVar_float::SetValue(&bitmapView->mBitmapWidthLV, static_cast<float>(texture->mWidth));
    CScriptLazyVar_float::SetValue(&bitmapView->mBitmapHeightLV, static_cast<float>(texture->mHeight));
    return;
  }

  const boost::shared_ptr<CD3DBatchTexture>* const parentTexture = bitmapView->mTextureBatches.begin();
  const CD3DBatchTexture* const addedTexture = texture.get();
  if (addedTexture->mWidth != (*parentTexture)->mWidth || addedTexture->mHeight != (*parentTexture)->mHeight) {
    gpg::Warnf(
      "CMauiBitmap:SetTexture - bitmap #%d in sequence does not have same width and height as parent.",
      GetBitmapTextureBatchCount(bitmapView)
    );
  }
}

/**
 * Address: 0x007802D0 (FUN_007802D0, Moho::CMauiBitmap::SetFramePattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes from caller-provided frame indices, warning on
 * negative or out-of-range values.
 */
void moho::CMauiBitmap::SetFramePattern(const msvc8::vector<std::int32_t>& framePattern)
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  bitmapView->mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(bitmapView);
  const std::int32_t* const frameStart = framePattern.begin();
  if (frameStart == nullptr) {
    return;
  }

  const std::int32_t frameCount = static_cast<std::int32_t>(framePattern.end() - frameStart);
  for (std::int32_t frameCursor = 0; frameCursor < frameCount; ++frameCursor) {
    const std::int32_t requestedFrame = frameStart[frameCursor];
    if (requestedFrame >= 0) {
      if (requestedFrame > textureCount - 1) {
        gpg::Warnf(
          "Bitmap:SetFramePattern - Frame index %d found in frame pattern which is larger than number of textures(%d).",
          requestedFrame,
          textureCount
        );
      }
    } else {
      gpg::Warnf("Bitmap:SetFramePattern - Negative frame index %d found in frame pattern.", requestedFrame);
    }

    std::int32_t clampedFrame = textureCount - 1;
    if (requestedFrame < clampedFrame) {
      clampedFrame = requestedFrame;
    }
    if (clampedFrame < 0) {
      clampedFrame = 0;
    }
    bitmapView->mFrames.push_back(clampedFrame);
  }
}

/**
 * Address: 0x00780420 (FUN_00780420, Moho::CMauiBitmap::SetForwardPattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes to play texture batches forward.
 */
void moho::CMauiBitmap::SetForwardPattern()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  bitmapView->mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(bitmapView);
  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    bitmapView->mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x007804E0 (FUN_007804E0, Moho::CMauiBitmap::SetBackwardPattern)
 *
 * What it does:
 * Rebuilds frame-pattern lanes to play texture batches backward.
 */
void moho::CMauiBitmap::SetBackwardPattern()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  bitmapView->mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(bitmapView);
  for (std::int32_t remaining = textureCount; remaining > 0; --remaining) {
    bitmapView->mFrames.push_back(remaining - 1);
  }
}

/**
 * Address: 0x007805B0 (FUN_007805B0, Moho::CMauiBitmap::SetPingPongPattern)
 *
 * What it does:
 * Rebuilds one ping-pong frame sequence that returns to frame `0`.
 */
void moho::CMauiBitmap::SetPingPongPattern()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  bitmapView->mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(bitmapView);
  if (textureCount <= 0) {
    return;
  }

  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    bitmapView->mFrames.push_back(frameIndex);
  }

  if (textureCount == 1) {
    return;
  }

  for (std::int32_t frameIndex = textureCount - 2; frameIndex >= 0; --frameIndex) {
    bitmapView->mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x00780700 (FUN_00780700, Moho::CMauiBitmap::SetLoopPingPongPattern)
 *
 * What it does:
 * Rebuilds one loop-friendly ping-pong sequence that excludes endpoint
 * duplicates.
 */
void moho::CMauiBitmap::SetLoopPingPongPattern()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  bitmapView->mFrames.clear();

  const std::int32_t textureCount = GetBitmapTextureBatchCount(bitmapView);
  for (std::int32_t frameIndex = 0; frameIndex < textureCount; ++frameIndex) {
    bitmapView->mFrames.push_back(frameIndex);
  }

  if (textureCount <= 2) {
    return;
  }

  for (std::int32_t frameIndex = textureCount - 2; frameIndex > 0; --frameIndex) {
    bitmapView->mFrames.push_back(frameIndex);
  }
}

/**
 * Address: 0x007800C0 (FUN_007800C0)
 *
 * What it does:
 * Stops animated playback and dispatches `OnAnimationStopped` when active
 * multi-frame texture state is present.
 */
void moho::CMauiBitmap::StopAnimationPlayback()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  const auto* const batchBegin = bitmapView->mTextureBatches.begin();
  if (batchBegin == nullptr) {
    return;
  }

  const std::ptrdiff_t batchCount = bitmapView->mTextureBatches.end() - batchBegin;
  if (batchCount <= 1) {
    return;
  }

  bitmapView->mIsPlaying = false;
  CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = false;
  reinterpret_cast<CScriptObject*>(this)->RunScript("OnAnimationStopped");
}

/**
 * Address: 0x00780110 (FUN_00780110, Moho::CMauiBitmap::SetFrame)
 *
 * What it does:
 * Clamps requested frame index to available frame range and stores it.
 */
std::int32_t moho::CMauiBitmap::SetFrame(const std::int32_t frameIndex)
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);

  std::int32_t selectedFrame = 0;
  const std::int32_t* const frameStart = bitmapView->mFrames.begin();
  if (frameStart != nullptr) {
    const std::int32_t frameCount = static_cast<std::int32_t>(bitmapView->mFrames.end() - frameStart);
    if (frameCount > 0) {
      selectedFrame = frameCount - 1;
    }
  }

  if (frameIndex < selectedFrame) {
    selectedFrame = frameIndex;
  }
  if (selectedFrame < 0) {
    selectedFrame = 0;
  }

  bitmapView->mCurrentFrame = selectedFrame;
  return selectedFrame;
}

/**
 * Address: 0x00780270 (FUN_00780270, Moho::CMauiBitmap::Frame)
 *
 * What it does:
 * Dispatches the bitmap `OnFrame` script callback, advances the frame timer
 * when playback is active, and wraps back to frame-end handling once the
 * current frame duration is exceeded.
 */
void moho::CMauiBitmap::Frame(const float deltaSeconds)
{
  reinterpret_cast<CScriptObject*>(this)->RunScriptNum("OnFrame", deltaSeconds);

  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  if (!bitmapView->mIsPlaying) {
    return;
  }

  const float nextFrameTime = deltaSeconds + bitmapView->mCurrentFrameTimeSeconds;
  bitmapView->mCurrentFrameTimeSeconds = nextFrameTime;
  if (nextFrameTime <= bitmapView->mFrameDurationSeconds) {
    return;
  }

  bitmapView->mCurrentFrameTimeSeconds = 0.0f;
  OnPatternEnd();
}

/**
 * Address: 0x00780160 (FUN_00780160, Moho::CMauiBitmap::OnPatternEnd)
 *
 * What it does:
 * Advances frame-pattern playback, handles loop/end behavior, and emits
 * `OnAnimationFinished`/`OnAnimationFrame` callbacks.
 */
void moho::CMauiBitmap::OnPatternEnd()
{
  CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);
  const std::int32_t* const frameStart = bitmapView->mFrames.begin();
  if (frameStart == nullptr) {
    return;
  }

  const std::int32_t frameCount = static_cast<std::int32_t>(bitmapView->mFrames.end() - frameStart);
  if (frameCount <= 1) {
    return;
  }

  ++bitmapView->mCurrentFrame;
  if (bitmapView->mCurrentFrame < 0) {
    bitmapView->mCurrentFrame = 0;
  }

  const std::int32_t* const currentFrameStart = bitmapView->mFrames.begin();
  const std::int32_t currentFrameCount = currentFrameStart != nullptr
    ? static_cast<std::int32_t>(bitmapView->mFrames.end() - currentFrameStart)
    : 0;
  if (bitmapView->mCurrentFrame >= currentFrameCount) {
    if (bitmapView->mDoLoop) {
      bitmapView->mCurrentFrame = 0;
    } else {
      const std::int32_t* const terminalFrameStart = bitmapView->mFrames.begin();
      const std::int32_t terminalFrameCount = terminalFrameStart != nullptr
        ? static_cast<std::int32_t>(bitmapView->mFrames.end() - terminalFrameStart)
        : 0;
      bitmapView->mCurrentFrame = terminalFrameCount - 1;
      bitmapView->mIsPlaying = false;
      CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = false;
    }

    reinterpret_cast<CScriptObject*>(this)->RunScript("OnAnimationFinished");
  }

  reinterpret_cast<CScriptObject*>(this)->CallbackInt("OnAnimationFrame", bitmapView->mCurrentFrame);
}

/**
 * Address: 0x0078F1B0 (FUN_0078F1B0, Moho::CMauiEdit::~CMauiEdit)
 * Mangled: ??1CMauiEdit@Moho@@QAE@XZ
 *
 * What it does:
 * Releases edit text/font ownership lanes, clears click-dragger intrusive
 * link nodes, and then tears down the `CMauiControl` base.
 */
moho::CMauiEdit::~CMauiEdit()
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  editView->mText.tidy(true, 0U);
  ReleaseIntrusiveFont(editView->mFont);

  CMauiEditClickDraggerRuntimeView* const clickDragger = ResolveEditClickDraggerRuntime(editView);
  for (DraggerLink* node = clickDragger->mListHead; node != nullptr; node = clickDragger->mListHead) {
    clickDragger->mListHead = node->mNext;
    node->mPrev = nullptr;
    node->mNext = nullptr;
  }
}

/**
 * Address: 0x0078F720 (FUN_0078F720, Moho::CMauiEdit::Frame)
 *
 * What it does:
 * Dispatches script `OnFrame(delta)` and updates the caret blink-phase alpha
 * lane from configured on/off alpha cycle parameters.
 */
void moho::CMauiEdit::Frame(const float deltaSeconds)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  reinterpret_cast<CScriptObject*>(this)->RunScriptNum("OnFrame", deltaSeconds);

  const float cycleSeconds = editView->mCaretCycleSeconds;
  const float nextCycleTime = editView->mCaretCycleTime + deltaSeconds;
  editView->mCaretCycleTime = nextCycleTime;
  if (nextCycleTime > cycleSeconds) {
    editView->mCaretCycleTime = 0.0f;
  }

  const float cycleBlendFactor = editView->mCaretCycleTime <= (cycleSeconds * 0.5f)
    ? ((editView->mCaretCycleTime / cycleSeconds) * 2.0f)
    : (((cycleSeconds - editView->mCaretCycleTime) / cycleSeconds) * 2.0f);

  const int offAlpha = static_cast<int>(editView->mCaretCycleOffAlpha);
  const int alphaDelta = static_cast<int>(editView->mCaretCycleOnAlpha) - offAlpha;
  const int blendedAlpha = static_cast<int>(
    (static_cast<double>(alphaDelta) * static_cast<double>(cycleBlendFactor)) + static_cast<double>(offAlpha)
  );
  editView->mCaretCycleCurrentAlpha = static_cast<std::uint32_t>(blendedAlpha);
}

/**
 * Address: 0x00790470 (FUN_00790470, Moho::CMauiEdit::HandleEvent)
 *
 * What it does:
 * Routes button press/double-click lanes to click handling and dispatches
 * character events into edit-key processing.
 */
bool moho::CMauiEdit::HandleEvent(const SMauiEventData& eventData)
{
  if (eventData.mEventType < MET_ButtonPress) {
    return false;
  }

  if (eventData.mEventType <= MET_ButtonDClick) {
    HandleClickEvent(const_cast<SMauiEventData*>(&eventData));
  } else if (eventData.mEventType == MET_Char) {
    HandleKeyEvent(const_cast<SMauiEventData*>(&eventData));
  }

  return false;
}

/**
 * Address: 0x0078F330 (FUN_0078F330, Moho::CMauiEdit::AbandonKeyboardFocus)
 *
 * What it does:
 * Hides caret rendering and clears keyboard focus when this edit currently
 * owns the global focus lane.
 */
void moho::CMauiEdit::AbandonKeyboardFocus()
{
  (void)WriteEditCaretVisibleLane(CMauiEditRuntimeView::FromEdit(this), false);
  if (Maui_CurrentFocusControl.ResolveFocusedControl() == this) {
    MAUI_SetKeyboardFocus(nullptr, true);
  }
}
/**
 * Address: 0x007915A0 (FUN_007915A0, Moho::CMauiEdit::LosingKeyboardFocus)
 *
 * What it does:
 * Drops keyboard focus through the virtual abandon lane and emits
 * OnLoseKeyboardFocus.
 */
void moho::CMauiEdit::LosingKeyboardFocus()
{
  CMauiControl* const control = this;
  control->AbandonKeyboardFocus();
  (void)reinterpret_cast<CScriptObject*>(this)->RunScript("OnLoseKeyboardFocus");
}

/**
 * Address: 0x007906F0 (FUN_007906F0, Moho::CMauiEdit::GetSelection)
 *
 * What it does:
 * Returns the currently selected UTF-8 substring from the edit text lane.
 */
msvc8::string moho::CMauiEdit::GetSelection()
{
  msvc8::string selectionText{};
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);

  const int selectionStart = editView->mSelectionStart;
  const int selectionEnd = editView->mSelectionEnd;
  if (HasEditSelectionRange(editView)) {
    selectionText = gpg::STR_Utf8SubString(editView->mText.c_str(), selectionStart, selectionEnd - selectionStart);
  }

  return selectionText;
}

/**
 * Address: 0x007904D0 (FUN_007904D0, Moho::CMauiEdit::EnterPressed)
 *
 * What it does:
 * Invokes `OnEnterPressed(self, text)` and returns the script bool result.
 */
bool moho::CMauiEdit::EnterPressed()
{
  const CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  return reinterpret_cast<CScriptObject*>(this)->RunScriptStringBool("OnEnterPressed", std::string(editView->mText.c_str()));
}

/**
 * Address: 0x007904F0 (FUN_007904F0, Moho::CMauiEdit::EscPressed)
 *
 * What it does:
 * Invokes `OnEscPressed(self, text)` and returns the script bool result.
 */
bool moho::CMauiEdit::EscPressed()
{
  const CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  return reinterpret_cast<CScriptObject*>(this)->RunScriptStringBool("OnEscPressed", std::string(editView->mText.c_str()));
}

/**
 * Address: 0x007907B0 (FUN_007907B0, Moho::CMauiEdit::ClearSelection)
 *
 * What it does:
 * Replaces the active selection with one empty UTF-8 string lane.
 */
void moho::CMauiEdit::ClearSelection()
{
  ReplaceSelection(gpg::STR_WideToUtf8(L""));
}

/**
 * Address: 0x00790830 (FUN_00790830, Moho::CMauiEdit::ReplaceSelection)
 *
 * What it does:
 * Deletes current selection and inserts replacement UTF-8 text (clamped to
 * max-char lane), then emits `OnTextChanged` when callback guard allows.
 */
void moho::CMauiEdit::ReplaceSelection(const msvc8::string& replacementText)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);

  msvc8::string insertText{};
  const int replacementLength = gpg::STR_Utf8Len(replacementText.c_str());
  const int currentLength = gpg::STR_Utf8Len(editView->mText.c_str());
  if ((currentLength + replacementLength) <= editView->mMaxChars) {
    insertText = replacementText;
  } else {
    if (currentLength >= editView->mMaxChars) {
      return;
    }

    const int maxInsertChars = editView->mMaxChars - currentLength;
    insertText = gpg::STR_Utf8SubString(replacementText.c_str(), 0, maxInsertChars);
  }

  DeleteSelection(false);
  const msvc8::string oldText = editView->mText;

  if (insertText.size() != 0u) {
    const int caretPosition = editView->mCaretPosition;
    if (caretPosition == gpg::STR_Utf8Len(editView->mText.c_str())) {
      editView->mText += insertText;
      const int insertedLength = gpg::STR_Utf8Len(insertText.c_str());
      editView->mCaretPosition += insertedLength;
      editView->mClipLength += insertedLength;
      SetEditClipOffsetRight(editView, 0);
    } else {
      const int caretByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), caretPosition);
      (void)editView->mText.replace(static_cast<std::size_t>(caretByteOffset), 0u, insertText.view());

      editView->mCaretPosition += gpg::STR_Utf8Len(insertText.c_str());
      if (editView->mCaretPosition >= (editView->mClipOffset + editView->mClipLength)) {
        const int nextTextLength = gpg::STR_Utf8Len(editView->mText.c_str());
        SetEditClipOffsetRight(editView, nextTextLength - editView->mCaretPosition);
      } else {
        SetEditClipOffsetLeft(editView, editView->mClipOffset);
      }
    }
  }

  if (!editView->mTextChangeCallbackInProgress) {
    editView->mTextChangeCallbackInProgress = true;
    TextChanged(editView->mText, oldText);
    editView->mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x00790510 (FUN_00790510, Moho::CMauiEdit::NonTextKeyPressed)
 *
 * What it does:
 * Builds one Lua event payload and invokes `OnNonTextKeyPressed(key,event)`.
 */
void moho::CMauiEdit::NonTextKeyPressed(const int keyCode, SMauiEventData* const eventData)
{
  LuaPlus::LuaState* const activeState = CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj.GetActiveState();
  LuaPlus::LuaObject eventObject{};
  const LuaPlus::LuaObject* const createdEvent = CreateLuaEventObject(eventData, &eventObject, activeState);
  reinterpret_cast<CScriptObject*>(this)->RunScriptIntObject("OnNonTextKeyPressed", keyCode, *createdEvent);
}

/**
 * Address: 0x00790590 (FUN_00790590, Moho::CMauiEdit::DeleteSelection)
 *
 * What it does:
 * Deletes the current UTF-8 selection range, updates caret/clip lanes, and
 * emits `OnTextChanged` unless callback suppression is requested.
 */
void moho::CMauiEdit::DeleteSelection(const bool suppressCallback)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  if (editView->mSelectionStart == editView->mSelectionEnd) {
    return;
  }

  const msvc8::string oldText = editView->mText;
  const int textLength = gpg::STR_Utf8Len(editView->mText.c_str());
  if (editView->mSelectionEnd > textLength) {
    editView->mSelectionEnd = textLength;
  }

  const int selectionStart = editView->mSelectionStart;
  editView->mCaretPosition = selectionStart;

  const int selectionStartByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), selectionStart);
  const int selectionEndByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), editView->mSelectionEnd);
  editView->mText.erase(selectionStartByteOffset, selectionEndByteOffset - selectionStartByteOffset);

  if (editView->mCaretPosition < editView->mClipOffset) {
    editView->mClipOffset = editView->mCaretPosition;
  }

  editView->mSelectionStart = 0;
  editView->mSelectionEnd = 0;

  if (!suppressCallback && !editView->mTextChangeCallbackInProgress) {
    editView->mTextChangeCallbackInProgress = true;
    TextChanged(editView->mText, oldText);
    editView->mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078EDD0 (FUN_0078EDD0, Moho::CMauiEdit::GetText)
 *
 * What it does:
 * Returns one copy of the current edit text lane.
 */
msvc8::string moho::CMauiEdit::GetText()
{
  return CMauiEditRuntimeView::FromEdit(this)->mText;
}

/**
 * Address: 0x00790B40 (FUN_00790B40, Moho::CMauiEdit::DeleteCharAtCaret)
 *
 * What it does:
 * Deletes either the selected range or one UTF-8 character at/left of the
 * caret, then refreshes clip state and emits `OnTextChanged`.
 */
void moho::CMauiEdit::DeleteCharAtCaret(const bool deleteToRight)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  const msvc8::string oldText = editView->mText;

  if (editView->mSelectionStart != editView->mSelectionEnd) {
    DeleteSelection(false);
    SetEditClipOffsetLeft(editView, editView->mClipOffset);
  } else if (deleteToRight) {
    const int caretPosition = editView->mCaretPosition;
    if (caretPosition != gpg::STR_Utf8Len(editView->mText.c_str())) {
      const int deleteStartByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), caretPosition);
      const int deleteEndByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), caretPosition + 1);
      editView->mText.erase(deleteStartByteOffset, deleteEndByteOffset - deleteStartByteOffset);
    }

    SetEditClipOffsetLeft(editView, editView->mClipOffset);
  } else if (editView->mCaretPosition != 0) {
    const int deleteStartCharIndex = editView->mCaretPosition - 1;
    const int deleteStartByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), deleteStartCharIndex);
    const int deleteEndByteOffset = gpg::STR_Utf8ByteOffset(editView->mText.c_str(), editView->mCaretPosition);
    editView->mText.erase(deleteStartByteOffset, deleteEndByteOffset - deleteStartByteOffset);

    const int currentCaretPosition = editView->mCaretPosition;
    if (currentCaretPosition != 0) {
      int caretStep = 1;
      if (currentCaretPosition <= 1) {
        caretStep = currentCaretPosition;
      }
      SetCaretPosition(currentCaretPosition - caretStep);
    }

    if (editView->mCaretPosition != 0 && editView->mCaretPosition == editView->mClipOffset) {
      SetEditClipOffsetLeft(editView, editView->mClipOffset - 1);
    }
  }

  if (!editView->mTextChangeCallbackInProgress) {
    editView->mTextChangeCallbackInProgress = true;
    TextChanged(editView->mText, oldText);
    editView->mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x007911B0 (FUN_007911B0, Moho::CMauiEdit::SetCaretPosition)
 *
 * What it does:
 * Updates caret position and adjusts clip-left/right window when the caret
 * crosses the visible text range.
 */
void moho::CMauiEdit::SetCaretPosition(int position)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);

  if (position < editView->mCaretPosition) {
    editView->mCaretPosition = position;
    if (position < editView->mClipOffset) {
      SetEditClipOffsetLeft(editView, position);
    }
    return;
  }

  if (position <= editView->mCaretPosition) {
    return;
  }

  const int textLength = gpg::STR_Utf8Len(editView->mText.c_str());
  if (position >= textLength) {
    position = textLength;
  }

  const int clipEnd = editView->mClipOffset + editView->mClipLength;
  editView->mCaretPosition = position;
  if (position >= clipEnd) {
    SetEditClipOffsetRight(editView, textLength - editView->mCaretPosition);
  }
}

/**
 * Address: 0x00791250 (FUN_00791250, Moho::CMauiEdit::MoveCaretLeft)
 *
 * What it does:
 * Moves caret left by `amount` characters, clamped to the start-of-text lane.
 */
void moho::CMauiEdit::MoveCaretLeft(int amount)
{
  const int caretPosition = CMauiEditRuntimeView::FromEdit(this)->mCaretPosition;
  if (caretPosition == 0) {
    return;
  }

  if (amount >= caretPosition) {
    amount = caretPosition;
  }

  SetCaretPosition(caretPosition - amount);
}

/**
 * Address: 0x00791270 (FUN_00791270, Moho::CMauiEdit::MoveCaretRight)
 *
 * What it does:
 * Moves caret right by `amount` UTF-8 characters through `SetCaretPosition`.
 */
void moho::CMauiEdit::MoveCaretRight(const int amount)
{
  const int caretPosition = CMauiEditRuntimeView::FromEdit(this)->mCaretPosition;
  SetCaretPosition(caretPosition + amount);
}

/**
 * Address: 0x00791290 (FUN_00791290, Moho::CMauiEdit::MoveSelectionLeft)
 *
 * What it does:
 * Extends/contracts current selection toward the left by `amount` while
 * preserving anchor semantics used by keyboard-shift navigation.
 */
void moho::CMauiEdit::MoveSelectionLeft(int amount)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  if (editView->mSelectionStart == editView->mSelectionEnd) {
    const int caretPosition = editView->mCaretPosition;
    editView->mSelectionStart = caretPosition;
    editView->mSelectionEnd = caretPosition;
  }

  const int oldCaretPosition = editView->mCaretPosition;
  if (oldCaretPosition != 0) {
    if (amount >= oldCaretPosition) {
      amount = oldCaretPosition;
    }
    SetCaretPosition(oldCaretPosition - amount);
  }

  const int newCaretPosition = editView->mCaretPosition;
  if (oldCaretPosition == newCaretPosition) {
    return;
  }

  if (editView->mSelectionStart == newCaretPosition) {
    editView->mSelectionStart = 0;
    editView->mSelectionEnd = 0;
  } else if (editView->mSelectionStart >= newCaretPosition) {
    editView->mSelectionStart = newCaretPosition;
  } else {
    editView->mSelectionEnd = newCaretPosition;
  }
}

/**
 * Address: 0x00791310 (FUN_00791310, Moho::CMauiEdit::MoveSelectionRight)
 *
 * What it does:
 * Extends/contracts current selection toward the right by `amount` while
 * preserving anchor semantics used by keyboard-shift navigation.
 */
void moho::CMauiEdit::MoveSelectionRight(const int amount)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  if (editView->mSelectionStart == editView->mSelectionEnd) {
    const int caretPosition = editView->mCaretPosition;
    editView->mSelectionStart = caretPosition;
    editView->mSelectionEnd = caretPosition;
  }

  const int oldCaretPosition = editView->mCaretPosition;
  SetCaretPosition(oldCaretPosition + amount);

  const int newCaretPosition = editView->mCaretPosition;
  if (oldCaretPosition == newCaretPosition) {
    return;
  }

  if (editView->mSelectionEnd == newCaretPosition) {
    editView->mSelectionStart = 0;
    editView->mSelectionEnd = 0;
  } else if (editView->mSelectionEnd <= newCaretPosition) {
    editView->mSelectionEnd = newCaretPosition;
  } else {
    editView->mSelectionStart = newCaretPosition;
  }
}

/**
 * Address: 0x007915C0 (FUN_007915C0, Moho::CMauiEdit::HandleClickEvent)
 *
 * What it does:
 * Handles left-button click/double-click lanes by focusing the control,
 * posting dragger capture, and updating caret/word-selection lanes.
 */
void moho::CMauiEdit::HandleClickEvent(SMauiEventData* const eventData)
{
  if ((eventData->mModifiers & MEM_Left) == 0) {
    return;
  }

  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  if (editView->mIsEnabled) {
    editView->mCaretVisible = true;
    MAUI_SetKeyboardFocus(this, true);
  }

  const float localMouseX = eventData->mMousePos.x - CScriptLazyVar_float::GetValue(&editView->mLeftLV);
  msvc8::string clippedText = gpg::STR_Utf8SubString(editView->mText.c_str(), editView->mClipOffset, editView->mClipLength);
  const int nearestCharacterIndex = editView->mFont->GetNearestCharacterIndex(clippedText.c_str(), localMouseX);

  if (eventData->mEventType == MET_ButtonPress) {
    func_PostDragger(GetRootFrame(), ResolveEditClickDragger(editView), eventData);

    const int caretPosition = editView->mClipOffset + nearestCharacterIndex;
    editView->mDragStart = caretPosition;
    SetCaretPosition(caretPosition);
    return;
  }

  const int wordStartIndex = gpg::STR_GetWordStartIndex(clippedText, nearestCharacterIndex);
  const int selectionEndOffset = gpg::STR_GetNextWordStartIndex(clippedText, wordStartIndex);

  const int selectionStart = editView->mClipOffset + wordStartIndex;
  const int selectionEnd = editView->mClipOffset + selectionEndOffset;
  editView->mSelectionStart = selectionStart;
  editView->mSelectionEnd = selectionEnd;
  SetCaretPosition(selectionEnd);
}

/**
 * Address: 0x00791780 (FUN_00791780, Moho::CMauiEdit::HandleKeyEvent)
 *
 * What it does:
 * Processes edit keyboard lanes: caret/selection movement, delete/backspace,
 * clipboard shortcuts, and text/non-text callback dispatch.
 */
void moho::CMauiEdit::HandleKeyEvent(SMauiEventData* const eventData)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  const int keyCode = eventData->mKeyCode;

  auto processDefaultKeyPath = [&]() {
    if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
      constexpr int kCtrlCChar = 3;
      constexpr int kCtrlVChar = 22;
      constexpr int kCtrlXChar = 24;

      switch (keyCode) {
      case kCtrlCChar:
        CopyEditSelectionToClipboard(this);
        break;
      case kCtrlVChar:
        ReplaceSelection(moho::WIN_GetClipboardText());
        break;
      case kCtrlXChar:
        CopyEditSelectionToClipboard(this);
        DeleteSelection(true);
        break;
      default:
        break;
      }
      return;
    }

    if (keyCode <= MKEY_START) {
      if (!RunScriptOnCharPressedThunk(reinterpret_cast<CScriptObject*>(this), keyCode)) {
        ClearSelection();
      }
      return;
    }

    [[maybe_unused]] bool isSpecial = false;
    const int translatedKeyCode = wxCharCodeWXToMSW(keyCode, &isSpecial);
    NonTextKeyPressed(translatedKeyCode, eventData);
  };

  if (keyCode > MKEY_END) {
    switch (static_cast<EMauiKeyCode>(keyCode)) {
    case MKEY_HOME:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        const int moveAmount = editView->mCaretPosition;
        if (moveAmount != 0) {
          MoveSelectionLeft(moveAmount);
        }
      } else {
        editView->mCaretPosition = 0;
        editView->mSelectionStart = 0;
        editView->mSelectionEnd = 0;
        SetEditClipOffsetLeft(editView, 0);
      }
      break;

    case MKEY_LEFT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int moveAmount = editView->mCaretPosition - gpg::STR_GetWordStartIndex(editView->mText, editView->mCaretPosition);
          if (moveAmount != 0) {
            MoveSelectionLeft(moveAmount);
          }
        } else {
          MoveSelectionLeft(1);
        }
      } else {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int wordStart = gpg::STR_GetWordStartIndex(editView->mText, editView->mCaretPosition);
          SetCaretPosition(wordStart);
        } else {
          MoveCaretLeft(1);
        }
        editView->mSelectionStart = 0;
        editView->mSelectionEnd = 0;
      }
      break;

    case MKEY_RIGHT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int nextWordStart = gpg::STR_GetNextWordStartIndex(editView->mText, editView->mCaretPosition);
          const int moveAmount = nextWordStart - editView->mCaretPosition;
          if (moveAmount != 0) {
            MoveSelectionRight(moveAmount);
          }
        } else {
          MoveSelectionRight(1);
        }
      } else {
        int nextCaretPosition = editView->mCaretPosition + 1;
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          nextCaretPosition = gpg::STR_GetNextWordStartIndex(editView->mText, editView->mCaretPosition);
        }

        SetCaretPosition(nextCaretPosition);
        editView->mSelectionStart = 0;
        editView->mSelectionEnd = 0;
      }
      break;

    case MKEY_INSERT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        ReplaceSelection(moho::WIN_GetClipboardText());
      } else if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
        CopyEditSelectionToClipboard(this);
      }
      break;

    default:
      processDefaultKeyPath();
      break;
    }

    return;
  }

  if (keyCode == MKEY_END) {
    if ((eventData->mModifiers & MEM_Shift) != 0u) {
      const int textLength = gpg::STR_Utf8Len(editView->mText.c_str());
      const int moveAmount = textLength - editView->mCaretPosition;
      if (moveAmount != 0) {
        MoveSelectionRight(moveAmount);
      }
    } else {
      editView->mCaretPosition = gpg::STR_Utf8Len(editView->mText.c_str());
      editView->mSelectionStart = 0;
      editView->mSelectionEnd = 0;
      SetEditClipOffsetRight(editView, 0);
    }
    return;
  }

  switch (static_cast<EMauiKeyCode>(keyCode)) {
  case MKEY_BACK:
    if ((eventData->mModifiers & MEM_Alt) != 0u) {
      return;
    }

    if ((eventData->mModifiers & MEM_Ctrl) == 0u) {
      DeleteCharAtCaret(false);
      DeleteSelection(true);
      return;
    }

    {
      const int moveAmount = editView->mCaretPosition - gpg::STR_GetWordStartIndex(editView->mText, editView->mCaretPosition);
      if (moveAmount != 0) {
        MoveSelectionLeft(moveAmount);
      }
    }
    DeleteSelection(true);
    return;

  case MKEY_RETURN:
    if (!EnterPressed()) {
      if (editView->mText.size() != 0u) {
        ClearText();
      } else {
        AbandonKeyboardFocus();
      }
    }
    return;

  case MKEY_ESCAPE:
    if (EscPressed()) {
      return;
    }

    if (editView->mText.size() != 0u) {
      ClearText();
    } else {
      AbandonKeyboardFocus();
    }
    return;

  case MKEY_DELETE:
    if ((eventData->mModifiers & MEM_Shift) != 0u) {
      CopyEditSelectionToClipboard(this);
      DeleteSelection(true);
      return;
    }

    if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
      const int moveAmount = gpg::STR_GetNextWordStartIndex(editView->mText, editView->mCaretPosition) - editView->mCaretPosition;
      if (moveAmount != 0) {
        MoveSelectionRight(moveAmount);
      }
      DeleteSelection(true);
      return;
    }

    DeleteCharAtCaret(true);
    DeleteSelection(true);
    return;

  default:
    processDefaultKeyPath();
    return;
  }
}

/**
 * Address: 0x007914C0 (FUN_007914C0, Moho::CMauiEdit::DragRelease)
 *
 * What it does:
 * Computes the clipped text hit-test for a release event and clears selection
 * when the release landed back on the original drag start lane.
 */
void moho::CMauiEdit::DragRelease(const SMauiEventData* const eventData)
{
  const float left = CScriptLazyVar_float::GetValue(&CMauiEditRuntimeView::FromEdit(this)->mLeftLV);
  const float releaseX = eventData->mMousePos.x - left;
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);

  msvc8::string clippedText = gpg::STR_Utf8SubString(editView->mText.c_str(), editView->mClipOffset, editView->mClipLength);
  const int releaseCaret = editView->mFont->GetNearestCharacterIndex(clippedText.c_str(), releaseX) + editView->mClipOffset;

  if (releaseCaret == editView->mDragStart) {
    editView->mSelectionStart = 0;
    editView->mSelectionEnd = 0;
  }
}

/**
 * Address: 0x00794F20 (FUN_00794F20, Moho::CMauiEdit::TextChanged)
 *
 * What it does:
 * Invokes script callback `OnTextChanged(self, newText, oldText)` when present
 * while holding weak-object callback guard state.
 */
void moho::CMauiEdit::TextChanged(const msvc8::string& newText, const msvc8::string& oldText)
{
  CScriptObject* const scriptObject = reinterpret_cast<CScriptObject*>(this);
  WeakObject::ScopedWeakLinkGuard weakGuard(static_cast<WeakObject*>(scriptObject));

  LuaPlus::LuaObject callbackObject{};
  scriptObject->FindScript(&callbackObject, "OnTextChanged");
  if (!callbackObject) {
    return;
  }

  LuaPlus::LuaFunction<void> callback(callbackObject);
  callback(CMauiControlScriptObjectRuntimeView::FromControl(this)->mLuaObj, newText.c_str(), oldText.c_str());
}

/**
 * Address: 0x0078F380 (FUN_0078F380, Moho::CMauiEdit::SetText)
 *
 * What it does:
 * Applies one UTF-8 text lane (clamped by max chars), refreshes caret/clip
 * state, and emits `OnTextChanged` callback when reentrancy guard allows.
 */
void moho::CMauiEdit::SetText(const msvc8::string& text)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  const msvc8::string previousText = editView->mText;

  editView->mText = gpg::STR_Utf8SubString(text.c_str(), 0, editView->mMaxChars);
  editView->mCaretPosition = gpg::STR_Utf8Len(editView->mText.c_str());
  editView->mClipOffset = 0;
  editView->mClipLength = gpg::STR_Utf8Len(editView->mText.c_str());
  SetEditClipOffsetRight(editView, 0);

  if (!editView->mTextChangeCallbackInProgress) {
    editView->mTextChangeCallbackInProgress = true;
    TextChanged(editView->mText, previousText);
    editView->mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078F4C0 (FUN_0078F4C0, Moho::CMauiEdit::ClearText)
 *
 * What it does:
 * Clears current edit text/caret/selection lanes and emits `OnTextChanged`
 * when callback reentrancy guard allows.
 */
void moho::CMauiEdit::ClearText()
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  const msvc8::string previousText = editView->mText;

  editView->mText.clear();
  editView->mCaretPosition = 0;
  editView->mClipLength = 0;
  editView->mClipOffset = 0;
  editView->mSelectionStart = 0;
  editView->mSelectionEnd = 0;

  if (!editView->mTextChangeCallbackInProgress) {
    editView->mTextChangeCallbackInProgress = true;
    TextChanged(editView->mText, previousText);
    editView->mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078F570 (FUN_0078F570, Moho::CMauiEdit::SetMaxChars)
 *
 * What it does:
 * Stores one max-char limit and truncates current edit text to that UTF-8
 * character count when needed.
 */
void moho::CMauiEdit::SetMaxChars(const int newMaxChars)
{
  CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  editView->mMaxChars = newMaxChars;

  const int textLength = gpg::STR_Utf8Len(editView->mText.c_str());
  if (newMaxChars < textLength) {
    editView->mText = gpg::STR_Utf8SubString(editView->mText.c_str(), 0, newMaxChars);
  }
}

/**
 * Address: 0x0077FAD0 (FUN_0077FAD0, Moho::CMauiBitmap::Dump)
 *
 * What it does:
 * Logs base CMauiControl state, then logs CMauiBitmap-specific texture batch
 * count, current bitmap width/height (from script lazy vars), UV rectangle,
 * alpha hit-test flag, animation frame count, frame rate, playback state,
 * and current frame index.
 */
void moho::CMauiBitmap::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiBitmap");

  const CMauiBitmapRuntimeView* const bitmapView = CMauiBitmapRuntimeView::FromBitmap(this);

  const int textureCount = static_cast<int>(bitmapView->mTextureBatches.size());

  // The binary fetches height first then width on the FPU stack — preserve order.
  const float bitmapHeight = CScriptLazyVar_float::GetValue(&bitmapView->mBitmapHeightLV);
  const float bitmapWidth = CScriptLazyVar_float::GetValue(&bitmapView->mBitmapWidthLV);
  gpg::Logf("Num Textures = %d Width = %.3f Height = %.3f", textureCount, bitmapWidth, bitmapHeight);
  gpg::Logf("uv = %.3f,%.3f %.3f,%.3f", bitmapView->mU0, bitmapView->mV0, bitmapView->mU1, bitmapView->mV1);

  const char* const alphaHitTest = bitmapView->mUseAlphaHitTest ? "true" : "false";
  gpg::Logf("Alpha Hit Test = %s", alphaHitTest);

  const char* const playing = bitmapView->mIsPlaying ? "true" : "false";
  const int frameCount = static_cast<int>(bitmapView->mFrames.size());
  gpg::Logf(
    "Num frames = %d Frame rate = %.3f Playing = %s Current Frame = %d",
    frameCount,
    bitmapView->mFrameDurationSeconds,
    playing,
    bitmapView->mCurrentFrame
  );
}

/**
 * Address: 0x0078F280 (FUN_0078F280, Moho::CMauiEdit::Dump)
 *
 * What it does:
 * Logs the base CMauiControl state, then logs CMauiEdit-specific colors,
 * background visibility, max-char limit, and the current text content.
 */
void moho::CMauiEdit::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiEdit");

  const CMauiEditRuntimeView* const editView = CMauiEditRuntimeView::FromEdit(this);
  const char* const showBackground = ReadEditBackgroundVisibleLane(editView) ? "true" : "false";
  gpg::Logf(
    "FG Color = %#08X BG Color = %#08X HLFG Color = %#08X HLBG Color = %#08X Show BG = %s MaxChars = %d",
    editView->mForegroundColor,
    editView->mBackgroundColor,
    editView->mHighlightForegroundColor,
    editView->mHighlightBackgroundColor,
    showBackground,
    editView->mMaxChars
  );
  gpg::Logf("Current Text = %s", editView->mText.c_str());
}

/**
 * Address: 0x00786B40 (FUN_00786B40, Moho::CMauiControl::Dump)
 *
 * What it does:
 * Logs debug identity/state and resolved layout lazy-vars for this control.
 */
void moho::CMauiControl::Dump()
{
  gpg::Logf("--");

  const CMauiControlExtendedRuntimeView* const controlView = CMauiControlExtendedRuntimeView::FromControl(this);
  const char* parentName = "no parent";
  msvc8::string parentNameStorage{};
  if (controlView->mParent != nullptr) {
    parentNameStorage = controlView->mParent->GetDebugName();
    parentName = parentNameStorage.c_str();
  }

  gpg::Logf("CMauiControl name = %s, parent = %s", controlView->mDebugName.c_str(), parentName);

  const char* const frameUpdateLabel = controlView->mNeedsFrameUpdate ? "true" : "false";
  const char* const hiddenLabel = controlView->mIsHidden ? "true" : "false";
  const char* const disabledHitTestLabel = controlView->mDisableHitTest ? "true" : "false";
  gpg::Logf(
    "Disabled hit test = %s Hidden = %s Frame Update = %s Render Pass = %d Alpha = %.3f",
    disabledHitTestLabel,
    hiddenLabel,
    frameUpdateLabel,
    controlView->mRenderPass,
    controlView->mAlpha
  );

  if (!controlView->mIsHidden) {
    const float depth = CScriptLazyVar_float::GetValue(&controlView->mDepthLV);
    const float height = CScriptLazyVar_float::GetValue(&controlView->mHeightLV);
    const float width = CScriptLazyVar_float::GetValue(&controlView->mWidthLV);
    const float bottom = CScriptLazyVar_float::GetValue(&controlView->mBottomLV);
    const float top = CScriptLazyVar_float::GetValue(&controlView->mTopLV);
    const float right = CScriptLazyVar_float::GetValue(&controlView->mRightLV);
    const float left = CScriptLazyVar_float::GetValue(&controlView->mLeftLV);
    gpg::Logf(
      "Left = %f Right = %.3f Top = %.3f Bottom = %.3f Width = %.3f Height = %.3f Depth = %.3f",
      left,
      right,
      top,
      bottom,
      width,
      height,
      depth
    );
  }
}

/**
 * Address: 0x00796360 (FUN_00796360, ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z)
 * Mangled: ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z
 *
 * LuaPlus::LuaObject* luaObject, CMauiControl* parent
 *
 * IDA signature:
 * Moho::CMauiFrame *__stdcall Moho::CMauiFrame::CMauiFrame(Moho::CMauiFrame *this, LuaPlus::LuaObject *luaObject, Moho::CMauiControl *parent);
 *
 * What it does:
 * Builds one frame control lane, seeds weak-self + deleted-control sentinel
 * fields, creates one frame-owned wx event mapper, and marks this control as
 * requiring one frame update from itself as root owner.
 */
moho::CMauiFrame::CMauiFrame(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
  : CMauiControl(luaObject, parent, "frame")
{
  CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(this);
  frameView->mSelfWeak = boost::weak_ptr<CMauiFrame>{};

  auto* const deletedListHead = static_cast<CMauiControlListNode*>(&frameView->mDeletedControlList);
  frameView->mDeletedControlList.mNext = deletedListHead;
  frameView->mDeletedControlList.mPrev = deletedListHead;

  frameView->mEventHandler = nullptr;
  frameView->mTargetHead = 0;

  auto* const eventMapper = new (std::nothrow) CMauiWxEventMapperRuntime{};
  if (eventMapper != nullptr) {
    eventMapper->mWindowRuntime = nullptr;
    eventMapper->mFrame = this;
    frameView->mEventHandler = eventMapper;
  }

  CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = true;
  CMauiControlExtendedRuntimeView::FromControl(this)->mRootFrame = this;
}

/**
 * Address: 0x00796460 (FUN_00796460, ??1CMauiFrame@Moho@@UAE@XZ)
 * Deleting thunk: 0x00796440 (FUN_00796440, Moho::CMauiFrame::dtr)
 *
 * What it does:
 * Purges pending deleted controls, releases one frame-owned wx event mapper,
 * unlinks the deleted-control sentinel, and then tears down base control
 * state.
 */
moho::CMauiFrame::~CMauiFrame()
{
  PurgeDeleted();

  CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(this);
  if (frameView->mEventHandler != nullptr) {
    delete frameView->mEventHandler;
    frameView->mEventHandler = nullptr;
  }

  static_cast<CMauiControlListNode*>(&frameView->mDeletedControlList)->ListUnlink();
  frameView->mSelfWeak = boost::weak_ptr<CMauiFrame>{};
}

/**
 * Address: 0x00796510 (FUN_00796510, Moho::CMauiFrame::PurgeDeleted)
 *
 * What it does:
 * Deletes all controls queued in this frame's deleted-control intrusive list
 * and restores the list to empty-sentinel state.
 */
void moho::CMauiFrame::PurgeDeleted()
{
  auto* const deletedListHead = static_cast<CMauiControlListNode*>(&CMauiFrameRuntimeView::FromFrame(this)->mDeletedControlList);
  while (deletedListHead->mNext != deletedListHead) {
    CMauiControlListNode* const deletedNode = deletedListHead->mPrev;
    deletedNode->ListUnlink();

    if (CMauiControl* const deletedControl = ControlFromParentListNode(deletedNode); deletedControl != nullptr) {
      delete deletedControl;
    }
  }
}

/**
 * Address: 0x00796680 (FUN_00796680, Moho::CMauiFrame::GetTopmostDepth)
 *
 * What it does:
 * Scans descendants and returns maximum control depth lane.
 */
float moho::CMauiFrame::GetTopmostDepth()
{
  float topmostDepth = -std::numeric_limits<float>::infinity();
  for (CMauiControl* controlCursor = DepthFirstSuccessor(this); controlCursor != nullptr;
       controlCursor = controlCursor->DepthFirstSuccessor(this)) {
    const float controlDepth = CScriptLazyVar_float::GetValue(&CMauiControlRuntimeView::FromControl(controlCursor)->mDepthLV);
    if (topmostDepth <= controlDepth) {
      topmostDepth = controlDepth;
    }
  }
  return topmostDepth;
}

/**
 * Address: 0x007966F0 (FUN_007966F0, ?DumpGraph@CMauiFrame@Moho@@QAEXXZ)
 *
 * What it does:
 * Walks this frame subtree depth-first and invokes `Dump()` on each control.
 */
void moho::CMauiFrame::DumpGraph()
{
  for (CMauiControl* controlCursor = this; controlCursor != nullptr;
       controlCursor = controlCursor->DepthFirstSuccessor(this)) {
    controlCursor->Dump();
  }
}

/**
 * Address: 0x00796720 (FUN_00796720, Moho::CMauiFrame::Dump)
 *
 * What it does:
 * Logs base control debug state and this frame's event-handler lane id.
 */
void moho::CMauiFrame::Dump()
{
  CMauiControl::Dump();
  const CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(this);
  gpg::Logf("Root Frame, head#d\n", static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(frameView->mEventHandler)));
}

/**
 * Address: 0x00796550 (FUN_00796550, Moho::CMauiFrame::SetBounds)
 *
 * What it does:
 * Resets frame origin to `(0,0)` and stores integer client-size bounds into
 * width/height lazy-var lanes.
 */
void moho::CMauiFrame::SetBounds(const int width, const int height)
{
  CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(this);
  CScriptLazyVar_float::SetValue(&frameView->mLeftLV, 0.0f);
  CScriptLazyVar_float::SetValue(&frameView->mTopLV, 0.0f);
  CScriptLazyVar_float::SetValue(&frameView->mWidthLV, static_cast<float>(width));
  CScriptLazyVar_float::SetValue(&frameView->mHeightLV, static_cast<float>(height));
}

/**
 * Address: 0x007961B0 (FUN_007961B0, Moho::CMauiFrame::Create)
 *
 * What it does:
 * Imports `/lua/maui/frame.lua`, calls `Frame()`, converts the return payload
 * to `CMauiFrame*`, and initializes the frame's weak self-owner lane.
 */
boost::shared_ptr<moho::CMauiFrame> moho::CMauiFrame::Create(LuaPlus::LuaState* const state)
{
  boost::shared_ptr<CMauiFrame> outFrame{};
  if (state == nullptr || state->m_state == nullptr) {
    return outFrame;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/maui/frame.lua");
  LuaPlus::LuaObject frameFactory = moduleObject.GetByName("Frame");
  frameFactory.PushStack(state);

  const int callStatus = lua_pcall(rawState, 0, 1, 0);
  if (callStatus != 0) {
    const char* errorText = lua_tostring(rawState, -1);
    if (errorText == nullptr) {
      LuaPlus::LuaStackObject errorObject(state, -1);
      errorObject.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in CMauiFrame::Create(): %s", errorText);
    lua_settop(rawState, savedTop);
    return outFrame;
  }

  LuaPlus::LuaObject frameLuaObject(state, -1);
  CMauiFrame* const frame = ResolveFrameFromLuaObjectOrError(frameLuaObject, state);
  if (frame != nullptr) {
    outFrame = boost::shared_ptr<CMauiFrame>(frame);
    CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(frame);
    (void)AssignFrameWeakSelfFromSharedOwner(outFrame, &frameView->mSelfWeak);
  }

  lua_settop(rawState, savedTop);
  return outFrame;
}

/**
 * Address: 0x00796740 (FUN_00796740, Moho::CMauiFrame::DumpControlsUnder)
 *
 * What it does:
 * Walks one frame subtree depth-first, hit-tests each control at `(x, y)`,
 * and calls `Dump()` on every control that matches.
 */
void moho::CMauiFrame::DumpControlsUnder(CMauiFrame* const frame, const float x, const float y)
{
  for (CMauiControl* control = frame; control != nullptr; control = control->DepthFirstSuccessor(frame)) {
    if (control->HitTest(x, y)) {
      control->Dump();
    }
  }
}

/**
 * Address: 0x00784840 (FUN_00784840, Moho::CMauiBorder::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `CMauiBorder`.
 */
gpg::RType* moho::CMauiBorder::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiBorder));
  }
  return sType;
}

/**
 * Address: 0x00784860 (FUN_00784860, Moho::CMauiBorder::GetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for this `CMauiBorder` instance.
 */
gpg::RType* moho::CMauiBorder::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x00784880 (FUN_00784880, Moho::CMauiBorder::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiBorder::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x00784D60 (FUN_00784D60, Moho::CMauiBorder::SetTextures)
 *
 * What it does:
 * Replaces any non-null border texture lanes and updates border width/height
 * lazy-vars from the vertical and horizontal texture dimensions.
 */
void moho::CMauiBorder::SetTextures(
  const boost::shared_ptr<CD3DBatchTexture>& vert,
  const boost::shared_ptr<CD3DBatchTexture>& horz,
  const boost::shared_ptr<CD3DBatchTexture>& ul,
  const boost::shared_ptr<CD3DBatchTexture>& ur,
  const boost::shared_ptr<CD3DBatchTexture>& ll,
  const boost::shared_ptr<CD3DBatchTexture>& lr
)
{
  CMauiBorderRuntimeView* const border = CMauiBorderRuntimeView::FromBorder(this);
  if (vert) {
    border->mTex1 = vert;
    CScriptLazyVar_float::SetValue(&border->mBorderWidthLV, static_cast<float>(vert->mWidth));
  }

  if (horz) {
    border->mTexHorz = horz;
    CScriptLazyVar_float::SetValue(&border->mBorderHeightLV, static_cast<float>(horz->mHeight));
  }

  if (ul) {
    border->mTexUL = ul;
  }

  if (ur) {
    border->mTexUR = ur;
  }

  if (ll) {
    border->mTexLL = ll;
  }

  if (lr) {
    border->mTexLR = lr;
  }
}

/**
 * Address: 0x00784D00 (FUN_00784D00, Moho::CMauiBorder::Dump)
 *
 * What it does:
 * Logs this border label and current border width/height lazy-var values.
 */
void moho::CMauiBorder::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiBorder");

  const CMauiBorderRuntimeView* const border = CMauiBorderRuntimeView::FromBorder(this);
  const double borderHeight = static_cast<double>(CScriptLazyVar_float::GetValue(&border->mBorderHeightLV));
  const double borderWidth = static_cast<double>(CScriptLazyVar_float::GetValue(&border->mBorderWidthLV));
  gpg::Logf("BorderWidth = %.3f BorderHeight = %.3f", borderWidth, borderHeight);
}

/**
 * Address: 0x00784F50 (FUN_00784F50, Moho::CMauiBorder::Draw)
 *
 * What it does:
 * Draws border corner quads, then optional horizontal and vertical body strips
 * using border lazy-var geometry and retained border textures.
 */
void moho::CMauiBorder::Draw(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  (void)drawMask;
  if (primBatcher == nullptr) {
    return;
  }

  const CMauiBorderRuntimeView* const border = CMauiBorderRuntimeView::FromBorder(this);
  if (!border->mTex1 || !border->mTexHorz || !border->mTexUL || !border->mTexUR || !border->mTexLL || !border->mTexLR) {
    return;
  }

  const float left = CScriptLazyVar_float::GetValue(&border->mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&border->mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&border->mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&border->mBottomLV);
  const float borderWidth = static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&border->mBorderWidthLV)));
  const float borderHeight = static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&border->mBorderHeightLV)));

  const float innerLeft = left + borderWidth;
  const float innerRight = right - borderWidth;
  const float innerTop = top + borderHeight;
  const float innerBottom = bottom - borderHeight;

  const std::uint32_t color = border->mVertexAlpha;

  primBatcher->SetTexture(border->mTexUL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexUR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexLL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexLR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  if ((right - left) > (borderWidth * 2.0f)) {
    primBatcher->SetTexture(border->mTexHorz);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, top, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, top, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, innerTop, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, bottom, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, bottom, color, 0.0f, 0.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }

  if ((bottom - top) > (borderHeight * 2.0f)) {
    primBatcher->SetTexture(border->mTex1);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }
}

/**
 * Address: 0x00795BD0 (FUN_00795BD0, func_CreateLuaEvent)
 *
 * What it does:
 * Builds one script-visible event payload table from one `SMauiEventData`
 * packet, including event type text, mouse/key lanes, modifier flags, and
 * optional source control object.
 */
LuaPlus::LuaObject* moho::CreateLuaEventObject(
  SMauiEventData* const eventData,
  LuaPlus::LuaObject* const outEvent,
  LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject modifiers;
  modifiers.AssignNewTable(state, 6, 0);

  if ((eventData->mModifiers & MEM_Shift) != 0u) {
    modifiers.SetBoolean("Shift", true);
  }
  if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
    modifiers.SetBoolean("Ctrl", true);
  }
  if ((eventData->mModifiers & MEM_Alt) != 0u) {
    modifiers.SetBoolean("Alt", true);
  }
  if ((eventData->mModifiers & MEM_Left) != 0u) {
    modifiers.SetBoolean("Left", true);
  }
  if ((eventData->mModifiers & MEM_Middle) != 0u) {
    modifiers.SetBoolean("Middle", true);
  }
  if ((eventData->mModifiers & MEM_Right) != 0u) {
    modifiers.SetBoolean("Right", true);
  }

  new (outEvent) LuaPlus::LuaObject();
  outEvent->AssignNewTable(state, 0, 8u);

  gpg::RRef eventTypeRef{};
  gpg::RRef_EMauiEventType(&eventTypeRef, &eventData->mEventType);
  const auto eventTypeLexical = eventTypeRef.GetLexical();
  outEvent->SetString("Type", eventTypeLexical.c_str());

  outEvent->SetNumber("MouseX", eventData->mMousePos.x);
  outEvent->SetNumber("MouseY", eventData->mMousePos.y);
  outEvent->SetInteger("WheelRotation", eventData->mWheelRotation);
  outEvent->SetInteger("WheelDelta", eventData->mWheelData);
  outEvent->SetInteger("KeyCode", eventData->mKeyCode);
  outEvent->SetInteger("RawKeyCode", eventData->mRawKeyCode);
  outEvent->SetObject("Modifiers", modifiers);

  if (eventData->mSource != nullptr) {
    outEvent->SetObject("Control", eventData->mSource->mLuaObj);
  }

  return outEvent;
}

/**
 * Address: 0x008C65B0 (FUN_008C65B0, Moho::USER_GetLuaState)
 *
 * What it does:
 * Lazily initializes process-global user Lua state/runtime stage, installs
 * debug hook wiring when the script debug window is active, attaches one
 * `ScrDiskWatcherTask`, and runs core/user Lua init-form chains.
 */
LuaPlus::LuaState* moho::USER_GetLuaState()
{
  LuaPlus::LuaState* state = gUserLuaState;
  if (state != nullptr) {
    return state;
  }

  if ((gUserLuaStateInitGuard & 0x1u) == 0u) {
    new (GetUserLuaStateStorageObject()) LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);
    gUserLuaStateInitGuard |= 0x1u;
    (void)std::atexit(&CleanupUserLuaStateStorageAtExit);
  }

  if ((gUserLuaStateInitGuard & 0x2u) == 0u) {
    new (GetUserStageStorageObject()) CTaskStage();
    gUserLuaStateInitGuard |= 0x2u;
    (void)std::atexit(&CleanupUserStageStorageAtExit);
  }

  sUserStage = GetUserStageStorageObject();
  gUserLuaState = GetUserLuaStateStorageObject();

  if (SCR_IsDebugWindowActive()) {
    lua_sethook(gUserLuaState->m_state, &DebugLuaHook, 4, 0);
  }

  gUserLuaState->m_luaTask = reinterpret_cast<CLuaTask*>(sUserStage);

  ScrDiskWatcherTask* const diskWatcherTask = new (std::nothrow) ScrDiskWatcherTask(gUserLuaState);
  AttachTaskToStage(diskWatcherTask, sUserStage, true);

  RunLuaInitFormSetIfPresent("core", gUserLuaState);
  RunLuaInitFormSetIfPresent("user", gUserLuaState);

  return gUserLuaState;
}

/**
 * Address: 0x0083CD30 (FUN_0083CD30, Moho::MAUI_StartMainScript)
 *
 * What it does:
 * Imports `/lua/ui/uimain.lua`, resolves `SetupUI`, and executes the entry
 * callback against the active UI Lua state.
 */
bool moho::MAUI_StartMainScript()
{
  LuaPlus::LuaState* const state = ResolveUiManagerLuaState();
  if (state == nullptr || state->m_state == nullptr) {
    return false;
  }

  return InvokeUiLuaCallback(
    state,
    "/lua/ui/uimain.lua",
    "SetupUI",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

/**
 * Address: 0x0083D810 (FUN_0083D810, Moho::MAUI_ToggleConsole)
 *
 * What it does:
 * Imports `/lua/ui/uimain.lua`, resolves `ToggleConsole`, and executes the
 * callback against the active UI Lua state.
 */
void moho::MAUI_ToggleConsole()
{
  LuaPlus::LuaState* const state = ResolveUiManagerLuaState();
  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  (void)InvokeUiLuaCallback(
    state,
    "/lua/ui/uimain.lua",
    "ToggleConsole",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

/**
 * Address: 0x0078CEF0 (FUN_0078CEF0, sub_78CEF0)
 *
 * What it does:
 * Commits pending cursor texture/visibility state to the active D3D device.
 */
void moho::MAUI_UpdateCursor(CMauiCursor* const cursor)
{
  if (cursor == nullptr) {
    return;
  }

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  if (!cursorView->mIsDefaultTexture) {
    return;
  }

  CD3DDevice* const device = D3D_GetDevice();
  if (device == nullptr) {
    return;
  }

  cursorView->mIsDefaultTexture = false;

  gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const deviceContext = galDevice != nullptr ? galDevice->GetDeviceContext() : nullptr;
  const gpg::gal::Head* primaryHead = nullptr;
  if (deviceContext != nullptr && deviceContext->GetHeadCount() > 0) {
    primaryHead = &deviceContext->GetHead(0u);
  }

  if (cursorView->mTexture.get() != nullptr) {
    (void)device->SetCursor(cursorView->mHotspotX, cursorView->mHotspotY, cursorView->mTexture);
  }

  const bool shouldShowCursor = cursorView->mIsShowing
    || (primaryHead != nullptr && !primaryHead->mWindowed && ui_WindowedAlwaysShowsCursor);
  (void)device->ShowCursor(shouldShowCursor);
}

void moho::MAUI_ReleaseCursor(CMauiCursor* const cursor)
{
  (void)cursor;
}

/**
 * Address: 0x0083D670 (FUN_0083D670)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:NoteGameSpeedChanged(slotPlusOne, speed)` on
 * the active UI Lua state.
 */
void moho::UI_NoteGameSpeedChanged(const std::int32_t slotZeroBased, const std::int32_t gameSpeed)
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "NoteGameSpeedChanged",
    [slotZeroBased, gameSpeed](LuaPlus::LuaFunction<void>& callbackFunction) {
      callbackFunction(slotZeroBased + 1, gameSpeed);
    }
  );
}

/**
 * Address: 0x0088BA50 (FUN_0088BA50, func_DriverNoteGameSpeedChanged)
 *
 * What it does:
 * Forwards game-speed UI callback only while one active simulation driver
 * instance exists.
 */
void moho::UI_DriverNoteGameSpeedChanged(const std::int32_t slotZeroBased, const std::int32_t gameSpeed)
{
  if (SIM_GetActiveDriver() != nullptr) {
    UI_NoteGameSpeedChanged(slotZeroBased, gameSpeed);
  }
}

/**
 * Address: 0x0088B9B0 (FUN_0088B9B0, Moho::CWldUiInterface::ReportBottleneck)
 *
 * What it does:
 * Forwards one client-bottleneck snapshot to the GPGNet reporting lane.
 */
void moho::UI_ReportBottleneck(const SClientBottleneckInfo& info)
{
  GPGNET_ReportBottleneck(info);
}

/**
 * Address: 0x0088B9C0 (FUN_0088B9C0, Moho::CWldUiInterface::ReportBottleneckCleared)
 *
 * What it does:
 * Forwards one bottleneck-cleared notification to the GPGNet reporting lane.
 */
void moho::UI_ReportBottleneckCleared()
{
  GPGNET_ReportBottleneckCleared();
}

/**
 * Address: 0x0083D740 (FUN_0083D740, ?UI_NoteGameOver@Moho@@YAXXZ)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:NoteGameOver()` on the active UI Lua state.
 */
void moho::UI_NoteGameOver()
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "NoteGameOver",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

/**
 * Address: 0x0083D9C0 (FUN_0083D9C0)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:OnApplicationResize(frameIdx, width, height)`.
 */
void moho::MAUI_OnApplicationResize(const std::int32_t frameIdx, const std::int32_t width, const std::int32_t height)
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "OnApplicationResize",
    [frameIdx, width, height](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(frameIdx, width, height); }
  );
}

/**
 * Address: 0x0079D7A0 (FUN_0079D7A0, cfunc_IsKeyDown)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsKeyDownL`.
 */
int moho::cfunc_IsKeyDown(lua_State* const luaContext)
{
  return cfunc_IsKeyDownL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079D7C0 (FUN_0079D7C0, func_IsKeyDown_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IsKeyDown(keyCode)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IsKeyDown_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsKeyDown",
    &moho::cfunc_IsKeyDown,
    nullptr,
    "<global>",
    kIsKeyDownHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079D820 (FUN_0079D820, cfunc_IsKeyDownL)
 *
 * What it does:
 * Resolves one `EMauiKeyCode` enum string and pushes key-down boolean state.
 */
int moho::cfunc_IsKeyDownL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsKeyDownHelpText, 1, argumentCount);
  }

  gpg::RRef enumRef{};
  EMauiKeyCode keyCode = static_cast<EMauiKeyCode>(0);
  gpg::RRef_EMauiKeyCode(&enumRef, &keyCode);

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  const char* keyCodeName = lua_tostring(state->m_state, 1);
  if (keyCodeName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "string");
    keyCodeName = "";
  }

  SCR_GetEnum(state, keyCodeName, enumRef);
  lua_pushboolean(state->m_state, MAUI_KeyIsDown(keyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079D8D0 (FUN_0079D8D0, cfunc_KeycodeMauiToMSW)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_KeycodeMauiToMSWL`.
 */
int moho::cfunc_KeycodeMauiToMSW(lua_State* const luaContext)
{
  return cfunc_KeycodeMauiToMSWL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079D8F0 (FUN_0079D8F0, func_KeycodeMauiToMSW_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `KeycodeMauiToMSW(int)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_KeycodeMauiToMSW_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "KeycodeMauiToMSW",
    &moho::cfunc_KeycodeMauiToMSW,
    nullptr,
    "<global>",
    kKeycodeMauiToMSWHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079D950 (FUN_0079D950, cfunc_KeycodeMauiToMSWL)
 *
 * What it does:
 * Converts one Maui key code to MS Windows key code and pushes numeric result.
 */
int moho::cfunc_KeycodeMauiToMSWL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kKeycodeMauiToMSWHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
  }

  const int mauiKeyCode = static_cast<int>(lua_tonumber(state->m_state, 1));
  bool isSpecial = false;
  const int mswKeyCode = wxCharCodeWXToMSW(mauiKeyCode, &isSpecial);
  (void)isSpecial;

  lua_pushnumber(state->m_state, static_cast<float>(mswKeyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079D9F0 (FUN_0079D9F0, cfunc_KeycodeMSWToMaui)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_KeycodeMSWToMauiL`.
 */
int moho::cfunc_KeycodeMSWToMaui(lua_State* const luaContext)
{
  return cfunc_KeycodeMSWToMauiL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079DA10 (FUN_0079DA10, func_KeycodeMSWToMaui_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `KeycodeMSWToMaui(int)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_KeycodeMSWToMaui_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "KeycodeMSWToMaui",
    &moho::cfunc_KeycodeMSWToMaui,
    nullptr,
    "<global>",
    kKeycodeMSWToMauiHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079DA70 (FUN_0079DA70, cfunc_KeycodeMSWToMauiL)
 *
 * What it does:
 * Converts one MS Windows key code to Maui key code and pushes numeric result.
 */
int moho::cfunc_KeycodeMSWToMauiL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kKeycodeMSWToMauiHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject keyCodeArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
  }

  const int mswKeyCode = static_cast<int>(lua_tonumber(state->m_state, 1));
  const int mauiKeyCode = wxCharCodeMSWToWX(mswKeyCode);
  lua_pushnumber(state->m_state, static_cast<float>(mauiKeyCode));
  (void)lua_gettop(state->m_state);
  return 1;
}

bool moho::UI_InitKeyHandler()
{
  return true;
}

/**
 * Address: 0x007A5190 (FUN_007A5190, cfunc_AnyInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_AnyInputCaptureL`.
 */
int moho::cfunc_AnyInputCapture(lua_State* const luaContext)
{
  return cfunc_AnyInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A51B0 (FUN_007A51B0, func_AnyInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `AnyInputCapture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_AnyInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AnyInputCapture",
    &moho::cfunc_AnyInputCapture,
    nullptr,
    "<global>",
    kAnyInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5210 (FUN_007A5210, cfunc_AnyInputCaptureL)
 *
 * What it does:
 * Returns whether the global input-capture stack currently has any valid
 * control.
 */
int moho::cfunc_AnyInputCaptureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAnyInputCaptureHelpText, 0, argumentCount);
  }

  const bool hasCapture = ResolveTopInputCaptureControl() != nullptr;
  lua_pushboolean(state->m_state, hasCapture);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007A5280 (FUN_007A5280, cfunc_GetInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetInputCaptureL`.
 */
int moho::cfunc_GetInputCapture(lua_State* const luaContext)
{
  return cfunc_GetInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A52A0 (FUN_007A52A0, func_GetInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetInputCapture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetInputCapture",
    &moho::cfunc_GetInputCapture,
    nullptr,
    "<global>",
    kGetInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5300 (FUN_007A5300, cfunc_GetInputCaptureL)
 *
 * What it does:
 * Returns the top control on the global input-capture stack, or `nil` when
 * no capture exists.
 */
int moho::cfunc_GetInputCaptureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetInputCaptureHelpText, 0, argumentCount);
  }

  if (CMauiControl* const control = ResolveTopInputCaptureControl()) {
    CMauiControlScriptObjectRuntimeView::FromControl(control)->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x007A53B0 (FUN_007A53B0, func_AddInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `func_AddInputCaptureL`.
 */
int moho::func_AddInputCapture(lua_State* const luaContext)
{
  return func_AddInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A53D0 (FUN_007A53D0, func_AddInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `AddInputCapture(control)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_AddInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddInputCapture",
    &moho::func_AddInputCapture,
    nullptr,
    "<global>",
    kAddInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5430 (FUN_007A5430, func_AddInputCaptureL)
 *
 * What it does:
 * Reads one control arg and pushes it onto the global input-capture stack.
 */
int moho::func_AddInputCaptureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddInputCaptureHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  AddInputCaptureControl(control);
  return 0;
}

/**
 * Address: 0x007A45D0 (FUN_007A45D0, func_RemoveInputCapture)
 *
 * What it does:
 * Removes the first matching control from the back of the global
 * input-capture stack.
 */
void moho::func_RemoveInputCapture(CMauiControl* const control)
{
  if (control == nullptr) {
    return;
  }

  CompactInputCaptureStack();

  const auto& view = AsWeakPtrVectorRuntimeView(sInputCapture);
  const std::size_t count = InputCaptureCount();
  if (view.begin == nullptr || count == 0) {
    return;
  }

  for (std::size_t i = count; i > 0; --i) {
    const std::size_t index = i - 1u;
    if (view.begin[index].GetObjectPtr() == control) {
      RemoveInputCaptureAt(index);
      return;
    }
  }
}

/**
 * Address: 0x007A54E0 (FUN_007A54E0, cfunc_RemoveInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_RemoveInputCaptureL`.
 */
int moho::cfunc_RemoveInputCapture(lua_State* const luaContext)
{
  return cfunc_RemoveInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A5500 (FUN_007A5500, func_RemoveInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `RemoveInputCapture(control)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_RemoveInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveInputCapture",
    &moho::cfunc_RemoveInputCapture,
    nullptr,
    "<global>",
    kRemoveInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5560 (FUN_007A5560, cfunc_RemoveInputCaptureL)
 *
 * What it does:
 * Reads one control arg and removes it from the global input-capture stack.
 */
int moho::cfunc_RemoveInputCaptureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveInputCaptureHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  func_RemoveInputCapture(control);
  return 0;
}

void moho::UI_ClearInputCapture()
{
  while (InputCaptureCount() > 0) {
    RemoveInputCaptureAt(InputCaptureCount() - 1u);
  }
}

void moho::UI_ClearCurrentDragger()
{
  if (func_GetCurrentDraggerKeycode() != 0) {
    sCurrentDraggerKeycode = 0;
  }
  (void)func_UnlinkCurrentDraggerLink();
  (void)func_ResetCurrentDraggerLink();
  sCurrentDraggerKeycode = 0;
}

namespace
{
  struct FactoryCommandQueueItemRuntimeView
  {
    msvc8::string blueprintId;    // +0x00
    std::int32_t count;           // +0x1C
    msvc8::vector<void*> commandData; // +0x20
  };
  static_assert(
    offsetof(FactoryCommandQueueItemRuntimeView, commandData) == 0x20,
    "FactoryCommandQueueItemRuntimeView::commandData offset must be 0x20"
  );
  static_assert(sizeof(FactoryCommandQueueItemRuntimeView) == 0x30, "FactoryCommandQueueItemRuntimeView size must be 0x30");

  struct CurrentBuildFactoryRuntimeView
  {
    std::uintptr_t* start = nullptr;  // +0x00
    std::uintptr_t* finish = nullptr; // +0x04
  };
  static_assert(sizeof(CurrentBuildFactoryRuntimeView) == 0x08, "CurrentBuildFactoryRuntimeView size must be 0x08");

  struct CurrentBuildQueueRuntimeView
  {
    FactoryCommandQueueItemRuntimeView* start = nullptr; // +0x00
    FactoryCommandQueueItemRuntimeView* end = nullptr;   // +0x04
  };
  static_assert(sizeof(CurrentBuildQueueRuntimeView) == 0x08, "CurrentBuildQueueRuntimeView size must be 0x08");

  CurrentBuildFactoryRuntimeView sCurrentBuildFactory{};
  CurrentBuildQueueRuntimeView sCurrentBuildQueue{};

  /**
   * Address: 0x00837AA0 (FUN_00837AA0, func_CpyBuildQueueItems)
   *
   * What it does:
   * Copies one half-open range of factory build-queue items using `msvc8`
   * string assignment and command-data vector copy semantics.
   */
  [[maybe_unused]] FactoryCommandQueueItemRuntimeView* CopyBuildQueueItems(
    FactoryCommandQueueItemRuntimeView* destination,
    FactoryCommandQueueItemRuntimeView* source,
    FactoryCommandQueueItemRuntimeView* end
  )
  {
    auto* sourceCursor = source;
    auto* destinationCursor = destination;
    while (sourceCursor != end) {
      destinationCursor->blueprintId.assign(sourceCursor->blueprintId, 0u, msvc8::string::npos);
      destinationCursor->count = sourceCursor->count;
      destinationCursor->commandData = sourceCursor->commandData;
      ++sourceCursor;
      ++destinationCursor;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x008378B0 (FUN_008378B0)
   *
   * What it does:
   * Adapts one thiscall lane into `CopyBuildQueueItems(destination, begin,
   * end)` and returns the advanced destination lane.
   */
  [[maybe_unused]] FactoryCommandQueueItemRuntimeView* CopyBuildQueueItemsThiscallAdapter(
    FactoryCommandQueueItemRuntimeView* const sourceEnd,
    FactoryCommandQueueItemRuntimeView* const sourceBegin,
    FactoryCommandQueueItemRuntimeView* const destinationBegin
  )
  {
    return CopyBuildQueueItems(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00837B00 (FUN_00837B00, func_DeleteRangeBuildQueueItems)
   *
   * What it does:
   * Destroys one half-open range of factory queue display items by releasing
   * per-item command payload buffers and resetting embedded `msvc8::string`
   * storage back to empty SSO state.
   */
  [[maybe_unused]] void DeleteRangeBuildQueueItems(
    FactoryCommandQueueItemRuntimeView* begin,
    FactoryCommandQueueItemRuntimeView* end
  )
  {
    while (begin != end) {
      auto& commandDataView = msvc8::AsVectorRuntimeView(begin->commandData);
      if (commandDataView.begin != nullptr) {
        ::operator delete(commandDataView.begin);
      }
      commandDataView.begin = nullptr;
      commandDataView.end = nullptr;
      commandDataView.capacityEnd = nullptr;

      if (begin->blueprintId.myRes >= 0x10u) {
        ::operator delete(begin->blueprintId.bx.ptr);
      }
      begin->blueprintId.myRes = 0x0Fu;
      begin->blueprintId.mySize = 0u;
      begin->blueprintId.bx.buf[0] = '\0';

      ++begin;
    }
  }

  /**
   * Address: 0x00837120 (FUN_00837120)
   *
   * What it does:
   * Adapts one thiscall queue-range destroy lane into
   * `DeleteRangeBuildQueueItems(begin, end)`.
   */
  [[maybe_unused]] void DeleteRangeBuildQueueItemsThiscallAdapter(
    FactoryCommandQueueItemRuntimeView* const rangeEnd,
    FactoryCommandQueueItemRuntimeView* const rangeBegin
  )
  {
    DeleteRangeBuildQueueItems(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x00837070 (FUN_00837070, sub_837070)
   *
   * What it does:
   * Compacts one in-place factory queue window by moving the half-open tail
   * `[sourceBegin, currentQueueEnd)` onto `destinationBegin`, destroys the
   * vacated tail range, and updates the caller-provided queue-end lane.
   */
  [[maybe_unused]] FactoryCommandQueueItemRuntimeView** RebaseFactoryQueueRangeAndTrimTail(
    FactoryCommandQueueItemRuntimeView** const outBegin,
    FactoryCommandQueueItemRuntimeView* const destinationBegin,
    FactoryCommandQueueItemRuntimeView* const sourceBegin
  )
  {
    if (destinationBegin != sourceBegin) {
      FactoryCommandQueueItemRuntimeView* const newEnd =
        CopyBuildQueueItems(destinationBegin, sourceBegin, sCurrentBuildQueue.end);
      DeleteRangeBuildQueueItems(newEnd, sCurrentBuildQueue.end);
      sCurrentBuildQueue.end = newEnd;
    }

    *outBegin = destinationBegin;
    return outBegin;
  }
} // namespace

void moho::UI_FactoryCommandQueueHandlerBeat()
{
}

/**
 * Address: 0x0083DCC0 (FUN_0083DCC0, ?UI_LuaBeat@Moho@@YA_NXZ)
 *
 * What it does:
 * Invokes `/lua/ui/game/gamemain.lua:OnBeat()` and returns false when the Lua
 * callback throws.
 */
bool moho::UI_LuaBeat()
{
  return InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/game/gamemain.lua",
    "OnBeat",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

/**
 * Address: 0x0083EDF0 (FUN_0083EDF0, ?UI_StopCursorText@Moho@@YAXXZ)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:StopCursorText()` on the active UI Lua state.
 */
void moho::UI_StopCursorText()
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "StopCursorText",
    [](LuaPlus::LuaFunction<void>& callbackFunction) { callbackFunction(); }
  );
}

namespace moho
{
  SSelectionSetUserEntity sSelectionBrackets{};
}

namespace
{
  struct BlinkyBoxRuntimeView final : moho::TDatListItem<BlinkyBoxRuntimeView, void>
  {
    moho::SSelectionWeakRefUserEntity mUnit; // +0x08
    std::uint8_t mIsOn;                      // +0x10
    std::uint8_t pad_11_13[3]{};             // +0x11
    float mCurDuration;                      // +0x14
    float mCurCycleTime;                     // +0x18
    float mOnTime;                           // +0x1C
    float mOffTime;                          // +0x20
    float mTotalTime;                        // +0x24
  };

  static_assert(sizeof(BlinkyBoxRuntimeView) == 0x28, "BlinkyBoxRuntimeView size must be 0x28");
  static_assert(offsetof(BlinkyBoxRuntimeView, mUnit) == 0x08, "BlinkyBoxRuntimeView::mUnit offset must be 0x08");
  static_assert(offsetof(BlinkyBoxRuntimeView, mIsOn) == 0x10, "BlinkyBoxRuntimeView::mIsOn offset must be 0x10");
  static_assert(
    offsetof(BlinkyBoxRuntimeView, mCurDuration) == 0x14, "BlinkyBoxRuntimeView::mCurDuration offset must be 0x14"
  );
  static_assert(
    offsetof(BlinkyBoxRuntimeView, mCurCycleTime) == 0x18, "BlinkyBoxRuntimeView::mCurCycleTime offset must be 0x18"
  );
  static_assert(offsetof(BlinkyBoxRuntimeView, mOnTime) == 0x1C, "BlinkyBoxRuntimeView::mOnTime offset must be 0x1C");
  static_assert(offsetof(BlinkyBoxRuntimeView, mOffTime) == 0x20, "BlinkyBoxRuntimeView::mOffTime offset must be 0x20");
  static_assert(offsetof(BlinkyBoxRuntimeView, mTotalTime) == 0x24, "BlinkyBoxRuntimeView::mTotalTime offset must be 0x24");

  moho::TDatListItem<BlinkyBoxRuntimeView, void> sBlinkyBoxes{};
  /**
   * Address: 0x007FC7F0 (FUN_007FC7F0)
   *
   * What it does:
   * Unlinks the global blinky-box intrusive list sentinel from its neighbors,
   * restores self-links, and returns the sentinel node.
   */
  [[maybe_unused]] [[nodiscard]] moho::TDatListItem<BlinkyBoxRuntimeView, void>*
  ResetGlobalBlinkyBoxListSentinelRuntimeLaneAlpha() noexcept
  {
    sBlinkyBoxes.mPrev->mNext = sBlinkyBoxes.mNext;
    sBlinkyBoxes.mNext->mPrev = sBlinkyBoxes.mPrev;
    sBlinkyBoxes.mNext = &sBlinkyBoxes;
    sBlinkyBoxes.mPrev = &sBlinkyBoxes;
    return &sBlinkyBoxes;
  }

  void LinkBlinkyBoxUnitOwner(
    moho::UserEntity* const entity,
    moho::SSelectionWeakRefUserEntity& weakRef
  ) noexcept
  {
    if (entity == nullptr) {
      weakRef.mOwnerLinkSlot = nullptr;
      weakRef.mNextOwner = nullptr;
      return;
    }

    auto** const ownerLinkSlot = reinterpret_cast<moho::SSelectionWeakRefUserEntity**>(&entity->mIUnitChainHead);
    weakRef.mOwnerLinkSlot = ownerLinkSlot;
    weakRef.mNextOwner = *ownerLinkSlot;
    *ownerLinkSlot = &weakRef;
  }
}

/**
 * Address: 0x007FD9F0 (FUN_007FD9F0, func_PushBlinkyBox)
 *
 * What it does:
 * Allocates one blinky-box runtime node, links its weak unit owner lane, and
 * inserts it at the tail of the global blinky-box intrusive list.
 */
void moho::func_PushBlinkyBox(UserEntity* const entity, const float onTime, const float offTime, const float totalTime)
{
  auto* const blinkyBox = new BlinkyBoxRuntimeView{};

  LinkBlinkyBoxUnitOwner(entity, blinkyBox->mUnit);
  blinkyBox->mCurDuration = 0.0f;
  blinkyBox->mCurCycleTime = 0.0f;
  blinkyBox->mOnTime = onTime;
  blinkyBox->mOffTime = offTime;
  blinkyBox->mIsOn = 0u;
  blinkyBox->mTotalTime = totalTime;

  blinkyBox->ListLinkBefore(&sBlinkyBoxes);
}

/**
 * Address: 0x007FDA90 (FUN_007FDA90)
 *
 * What it does:
 * Adds one user-unit lane into the global selection-bracket weak-set and
 * returns the raw register lane value from WeakSet_UserEntity::Add.
 */
std::int32_t moho::func_AddSelectionBracketUserUnit(UserUnit* const unit)
{
  SSelectionSetUserEntity::AddResult addResult;
  return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(
    SSelectionSetUserEntity::Add(&addResult, &sSelectionBrackets, reinterpret_cast<UserEntity*>(unit))
  ));
}

/**
 * Address: 0x007FDAB0 (FUN_007FDAB0)
 *
 * What it does:
 * Drops all nodes from the global selection-bracket weak-set by taking the
 * full-range erase path, then returns the head-sentinel lane value.
 */
std::int32_t moho::func_ClearSelectionBracketUserUnits()
{
  SSelectionNodeUserEntity* cursor = sSelectionBrackets.mHead != nullptr ? sSelectionBrackets.mHead->mLeft : nullptr;
  (void)sSelectionBrackets.EraseRange(&cursor, cursor, sSelectionBrackets.mHead);
  return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sSelectionBrackets.mHead));
}

/**
 * Address: 0x007FDAF0 (FUN_007FDAF0, cfunc_AddBlinkyBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_AddBlinkyBoxL`.
 */
int moho::cfunc_AddBlinkyBox(lua_State* const luaContext)
{
  return cfunc_AddBlinkyBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007FDB10 (FUN_007FDB10, func_AddBlinkyBox_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AddBlinkyBox(entityId, onTime, offTime, totalTime)` Lua
 * binder metadata.
 */
moho::CScrLuaInitForm* moho::func_AddBlinkyBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddBlinkyBox",
    &moho::cfunc_AddBlinkyBox,
    nullptr,
    "<global>",
    kAddBlinkyBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x007FDB70 (FUN_007FDB70, cfunc_AddBlinkyBoxL)
 *
 * What it does:
 * Parses one entity-id plus three timing args and appends one blinky-box node
 * for the resolved live user-entity.
 */
int moho::cfunc_AddBlinkyBoxL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddBlinkyBoxHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    entityIdArg.TypeError("integer");
  }

  const EntId entityId = static_cast<EntId>(static_cast<std::int32_t>(lua_tonumber(state->m_state, 1)));
  CWldSession* const session = WLD_GetActiveSession();
  UserEntity* const entity = session != nullptr ? session->LookupEntityId(entityId) : nullptr;
  if (entity == nullptr) {
    LuaPlus::LuaState::Error(state, "Invalid entity id");
    return 0;
  }

  const LuaPlus::LuaStackObject totalTimeArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    totalTimeArg.TypeError("number");
  }
  const float totalTime = static_cast<float>(lua_tonumber(state->m_state, 4));

  const LuaPlus::LuaStackObject offTimeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    offTimeArg.TypeError("number");
  }
  const float offTime = static_cast<float>(lua_tonumber(state->m_state, 3));

  const LuaPlus::LuaStackObject onTimeArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    onTimeArg.TypeError("number");
  }
  const float onTime = static_cast<float>(lua_tonumber(state->m_state, 2));

  func_PushBlinkyBox(entity, onTime, offTime, totalTime);
  return 0;
}

namespace
{
  struct CommandFeedbackBlipRuntimeView final
  {
    moho::MeshInstance* mMeshInstance; // +0x00
    float mDuration;                   // +0x04
    float mCurTime;                    // +0x08
  };

  static_assert(
    offsetof(CommandFeedbackBlipRuntimeView, mDuration) == 0x04,
    "CommandFeedbackBlipRuntimeView::mDuration offset must be 0x04"
  );
  static_assert(
    offsetof(CommandFeedbackBlipRuntimeView, mCurTime) == 0x08,
    "CommandFeedbackBlipRuntimeView::mCurTime offset must be 0x08"
  );
  static_assert(sizeof(CommandFeedbackBlipRuntimeView) == 0x0C, "CommandFeedbackBlipRuntimeView size must be 0x0C");

  msvc8::list<CommandFeedbackBlipRuntimeView> sCommandFeedbackBlips;

  struct CommandFeedbackListNodeRuntimeView
  {
    CommandFeedbackListNodeRuntimeView* mNext; // +0x00
    CommandFeedbackListNodeRuntimeView* mPrev; // +0x04
    CommandFeedbackBlipRuntimeView mValue;     // +0x08
  };
  static_assert(sizeof(CommandFeedbackListNodeRuntimeView) == 0x14, "CommandFeedbackListNodeRuntimeView size must be 0x14");
  static_assert(
    offsetof(CommandFeedbackListNodeRuntimeView, mValue) == 0x08,
    "CommandFeedbackListNodeRuntimeView::mValue offset must be 0x08"
  );

  struct CommandFeedbackListRuntimeView
  {
    msvc8::_Container_proxy* mProxy;              // +0x00
    CommandFeedbackListNodeRuntimeView* mHead;    // +0x04
    std::uint32_t mSize;                          // +0x08
  };
  static_assert(sizeof(CommandFeedbackListRuntimeView) == 0x0C, "CommandFeedbackListRuntimeView size must be 0x0C");

  /**
   * Address: 0x00858340 (FUN_00858340)
   *
   * What it does:
   * Stores the first live command-feedback list node into `outNode`.
   */
  [[maybe_unused]] [[nodiscard]] CommandFeedbackListNodeRuntimeView** StoreCommandFeedbackFirstNodeLane(
    CommandFeedbackListNodeRuntimeView** const outNode
  ) noexcept
  {
    auto* const listView = reinterpret_cast<CommandFeedbackListRuntimeView*>(&sCommandFeedbackBlips);
    *outNode = listView->mHead->mNext;
    return outNode;
  }

  /**
   * Address: 0x00858350 (FUN_00858350)
   *
   * What it does:
   * Stores the command-feedback list sentinel node into `outNode`.
   */
  [[maybe_unused]] [[nodiscard]] CommandFeedbackListNodeRuntimeView** StoreCommandFeedbackSentinelNodeLane(
    CommandFeedbackListNodeRuntimeView** const outNode
  ) noexcept
  {
    auto* const listView = reinterpret_cast<CommandFeedbackListRuntimeView*>(&sCommandFeedbackBlips);
    *outNode = listView->mHead;
    return outNode;
  }
  /**
   * Address: 0x008584F0 (FUN_008584F0)
   *
   * What it does:
   * Allocates one command-feedback list node and seeds next/prev/value lanes.
   */
  [[maybe_unused]] [[nodiscard]] CommandFeedbackListNodeRuntimeView* AllocateCommandFeedbackBlipNodeLane(
    const CommandFeedbackBlipRuntimeView* const value,
    CommandFeedbackListNodeRuntimeView* const next,
    CommandFeedbackListNodeRuntimeView* const prev
  )
  {
    auto* const inserted = static_cast<CommandFeedbackListNodeRuntimeView*>(
      ::operator new(sizeof(CommandFeedbackListNodeRuntimeView))
    );
    if (inserted != nullptr) {
      inserted->mNext = next;
    }
    if (inserted != nullptr) {
      inserted->mPrev = prev;
    }
    if (inserted != nullptr) {
      inserted->mValue = *value;
    }
    return inserted;
  }

  /**
   * Address: 0x00858530 (FUN_00858530, sCommandFeedbackBlips::inc)
   *
   * What it does:
   * Performs VC8-style list-size overflow guard and increments command-feedback
   * list size.
   */
  void IncrementCommandFeedbackListSizeChecked()
  {
    auto* const listView = reinterpret_cast<CommandFeedbackListRuntimeView*>(&sCommandFeedbackBlips);
    if (listView->mSize == 0x15555555u) {
      throw std::length_error("list<T> too long");
    }
    ++listView->mSize;
  }

  /**
   * Address: 0x008583D0 (FUN_008583D0)
   *
   * What it does:
   * Inserts one command-feedback blip node immediately before `position`,
   * increments list size with VC8 overflow behavior, and relinks predecessor
   * and successor lanes.
   *
   * Notes:
   * Inlines allocation/size-check helpers from `FUN_008584F0` and
   * `FUN_00858530`.
   */
  [[maybe_unused]] void InsertCommandFeedbackBlipBeforeNode(
    const CommandFeedbackBlipRuntimeView* const value,
    CommandFeedbackListNodeRuntimeView* const position
  )
  {
    auto* const inserted = AllocateCommandFeedbackBlipNodeLane(value, position, position->mPrev);
    IncrementCommandFeedbackListSizeChecked();
    position->mPrev = inserted;
    inserted->mPrev->mNext = inserted;
  }

  [[nodiscard]] const char* LuaStringOrEmpty(const LuaPlus::LuaObject& object) noexcept
  {
    const char* const value = object.GetString();
    return value != nullptr ? value : "";
  }

  [[nodiscard]] boost::shared_ptr<moho::RScmResource> ResolveCommandFeedbackModelResource(const char* const modelPath)
  {
    if (moho::RScmResource::sType == nullptr) {
      moho::RScmResource::sType = gpg::LookupRType(typeid(moho::RScmResource));
    }

    boost::weak_ptr<moho::RScmResource> weakResource{};
    (void)moho::RES_GetResource(
      &weakResource,
      modelPath != nullptr ? modelPath : "",
      nullptr,
      moho::RScmResource::sType
    );
    return weakResource.lock();
  }

  [[nodiscard]] boost::shared_ptr<moho::RScmResource> ResolveCommandFeedbackModelFromDescriptor(
    const LuaPlus::LuaObject& meshDescriptor,
    moho::CWldSession* const worldSession,
    float* const outUniformScale
  )
  {
    const LuaPlus::LuaObject meshNameObject = meshDescriptor.GetByName("MeshName");
    if (!meshNameObject.IsNil()) {
      if (outUniformScale != nullptr) {
        *outUniformScale = static_cast<float>(meshDescriptor.GetByName("UniformScale").GetNumber());
      }
      return ResolveCommandFeedbackModelResource(LuaStringOrEmpty(meshNameObject));
    }

    if (worldSession == nullptr || worldSession->mRules == nullptr) {
      return {};
    }

    msvc8::string blueprintId(LuaStringOrEmpty(meshDescriptor.GetByName("BlueprintID")));
    moho::RResId normalizedBlueprintId{};
    gpg::STR_CopyFilename(&normalizedBlueprintId.name, &blueprintId);

    moho::RUnitBlueprint* const unitBlueprint = worldSession->mRules->GetUnitBlueprint(normalizedBlueprintId);
    if (unitBlueprint == nullptr) {
      return {};
    }

    if (outUniformScale != nullptr) {
      *outUniformScale = unitBlueprint->Display.UniformScale;
    }

    moho::RMeshBlueprint* const meshBlueprint = worldSession->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
    if (meshBlueprint == nullptr) {
      return {};
    }

    const moho::RMeshBlueprintLOD* const lodBegin = meshBlueprint->mLods.begin();
    if (lodBegin == nullptr || lodBegin == meshBlueprint->mLods.end()) {
      return {};
    }

    return ResolveCommandFeedbackModelResource(lodBegin->mMeshName.c_str());
  }

  void DestroyCommandFeedbackBlipMeshInstance(moho::MeshInstance*& meshInstance) noexcept
  {
    if (meshInstance == nullptr) {
      return;
    }

    delete meshInstance;
    meshInstance = nullptr;
  }
} // namespace

/**
 * Address: 0x008586C0 (FUN_008586C0, Moho::RemoveCommandFeedbackBlips)
 *
 * What it does:
 * Removes every command-feedback blip whose `mCurTime >= mDuration`.
 *
 * Notes:
 * The binary uses one unused stdcall argument lane (`push 0`).
 */
void moho::RemoveCommandFeedbackBlips(const std::int32_t unused)
{
  (void)unused;

  for (msvc8::list<CommandFeedbackBlipRuntimeView>::iterator it = sCommandFeedbackBlips.begin();
       it != sCommandFeedbackBlips.end();) {
    if (it->mCurTime < it->mDuration) {
      ++it;
      continue;
    }

    it = sCommandFeedbackBlips.erase(it);
  }
}

/**
 * Address: 0x00857B00 (FUN_00857B00, Moho::UpdateCommandFeedbackBlips)
 *
 * What it does:
 * Advances command-feedback blip timers, destroys expired meshes, then
 * compacts expired blip nodes from the global blip list.
 */
void moho::UI_UpdateCommandFeedbackBlips(const float deltaSeconds)
{
  (void)moho::MeshRenderer::GetInstance();

  for (msvc8::list<CommandFeedbackBlipRuntimeView>::iterator it = sCommandFeedbackBlips.begin();
       it != sCommandFeedbackBlips.end();
       ++it) {
    CommandFeedbackBlipRuntimeView& blip = *it;
    const float updatedTime = blip.mCurTime + deltaSeconds;
    blip.mCurTime = updatedTime;
    if (updatedTime >= blip.mDuration) {
      DestroyCommandFeedbackBlipMeshInstance(blip.mMeshInstance);
    }
  }

  RemoveCommandFeedbackBlips(0);
}

/**
 * Address: 0x00857BE0 (FUN_00857BE0, cfunc_AddCommandFeedbackBlipL)
 *
 * What it does:
 * Reads one descriptor table `(MeshName|BlueprintID, Position, TextureName,
 * ShaderName[, UniformScale])` plus duration, creates one transient mesh
 * marker, and pushes it onto the command-feedback blip list.
 */
int moho::cfunc_AddCommandFeedbackBlipL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddCommandFeedbackBlipHelpText, 2, argumentCount);
  }

  CWldSession* const worldSession = moho::WLD_GetSession();
  if (worldSession == nullptr) {
    gpg::Warnf("AddCommandFeedbackBlip: No user session, unable to add blip");
    return 0;
  }

  if (lua_type(state->m_state, 1) != LUA_TTABLE) {
    gpg::Warnf("AddCommandFeedbackBlip: Expecting lua table as argument");
    return 0;
  }

  const LuaPlus::LuaObject meshDescriptor(LuaPlus::LuaStackObject(state, 1));

  float uniformScale = 1.0f;
  const boost::shared_ptr<RScmResource> modelResource =
    ResolveCommandFeedbackModelFromDescriptor(meshDescriptor, worldSession, &uniformScale);
  if (!modelResource) {
    return 0;
  }

  const Wm3::Vector3f worldPosition = SCR_FromLuaCopy<Wm3::Vector3f>(meshDescriptor.GetByName("Position"));

  const msvc8::string textureName(LuaStringOrEmpty(meshDescriptor.GetByName("TextureName")));
  const msvc8::string shaderName(LuaStringOrEmpty(meshDescriptor.GetByName("ShaderName")));
  const msvc8::string emptyTextureName{};

  const boost::shared_ptr<MeshMaterial> material = MeshMaterial::Create(
    shaderName,
    textureName,
    emptyTextureName,
    emptyTextureName,
    emptyTextureName,
    emptyTextureName,
    nullptr
  );

  boost::shared_ptr<Mesh> mesh(new Mesh(modelResource, material));

  MeshRenderer* const renderer = MeshRenderer::GetInstance();
  const Wm3::Vector3f meshScale{uniformScale, uniformScale, uniformScale};
  MeshInstance* const meshInstance =
    renderer != nullptr ? renderer->CreateMeshInstance(worldSession->mGameTick, -1, meshScale, false, mesh) : nullptr;
  if (meshInstance == nullptr) {
    return 0;
  }

  CommandFeedbackBlipRuntimeView blip{};
  blip.mMeshInstance = meshInstance;
  blip.mDuration = static_cast<float>(lua_tonumber(state->m_state, 2));
  blip.mCurTime = 0.0f;

  auto* const listView = reinterpret_cast<CommandFeedbackListRuntimeView*>(&sCommandFeedbackBlips);
  InsertCommandFeedbackBlipBeforeNode(&blip, listView->mHead);

  meshInstance->lifetimeParameter = blip.mDuration * 10.0f;

  VTransform transform{};
  transform.orient_.x = 1.0f;
  transform.orient_.y = 0.0f;
  transform.orient_.z = 0.0f;
  transform.orient_.w = 0.0f;
  transform.pos_.x = worldPosition.x;
  transform.pos_.y = worldPosition.y;
  transform.pos_.z = worldPosition.z;
  meshInstance->SetStance(transform, transform);

  return 0;
}

/**
 * Address: 0x00857B60 (FUN_00857B60, cfunc_AddCommandFeedbackBlip)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_AddCommandFeedbackBlipL`.
 */
int moho::cfunc_AddCommandFeedbackBlip(lua_State* const luaContext)
{
  return cfunc_AddCommandFeedbackBlipL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00857B80 (FUN_00857B80, func_AddCommandFeedbackBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AddCommandFeedbackBlip(meshInfoTable, duration)` Lua
 * binder metadata.
 */
moho::CScrLuaInitForm* moho::func_AddCommandFeedbackBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddCommandFeedbackBlip",
    &moho::cfunc_AddCommandFeedbackBlip,
    nullptr,
    "<global>",
    kAddCommandFeedbackBlipHelpText
  );
  return &binder;
}
void moho::UI_DumpCurrentInputCapture()
{
}

/**
 * Address: 0x00838C60 (FUN_00838C60, sub_838C60)
 *
 * What it does:
 * Runs one key-handler teardown lane and then executes base
 * `wxEvtHandlerRuntime` destruction.
 */
moho::CUIKeyHandlerRuntime::~CUIKeyHandlerRuntime() = default;
namespace
{
  [[nodiscard]] std::string ToUpperAscii(std::string token)
  {
    std::transform(
      token.begin(),
      token.end(),
      token.begin(),
      [](unsigned char value) { return static_cast<char>(std::toupper(value)); }
    );
    return token;
  }

  [[nodiscard]] int ParsePrimaryKeyToken(const std::string& primaryToken)
  {
    if (primaryToken.empty()) {
      return 0;
    }

    const std::string key = ToUpperAscii(primaryToken);
    if (key.size() == 1u) {
      return static_cast<int>(key[0]);
    }

    if (key[0] == 'F' && key.size() <= 3u) {
      const int functionIndex = std::atoi(key.c_str() + 1);
      if (functionIndex >= 1 && functionIndex <= 24) {
        return moho::MKEY_F1 + (functionIndex - 1);
      }
    }

    if (key == "SPACE") {
      return moho::MKEY_SPACE;
    }
    if (key == "TAB") {
      return moho::MKEY_TAB;
    }
    if (key == "ENTER" || key == "RETURN") {
      return moho::MKEY_RETURN;
    }
    if (key == "ESC" || key == "ESCAPE") {
      return moho::MKEY_ESCAPE;
    }
    if (key == "LEFT") {
      return moho::MKEY_LEFT;
    }
    if (key == "RIGHT") {
      return moho::MKEY_RIGHT;
    }
    if (key == "UP") {
      return moho::MKEY_UP;
    }
    if (key == "DOWN") {
      return moho::MKEY_DOWN;
    }
    if (key == "HOME") {
      return moho::MKEY_HOME;
    }
    if (key == "END") {
      return moho::MKEY_END;
    }
    if (key == "PGUP" || key == "PAGEUP" || key == "PRIOR") {
      return moho::MKEY_PRIOR;
    }
    if (key == "PGDN" || key == "PAGEDOWN" || key == "NEXT") {
      return moho::MKEY_NEXT;
    }

    return 0;
  }
} // namespace

/**
 * Address: 0x00839920 (FUN_00839920, Moho::IN_ParseKeyModifiers)
 *
 * What it does:
 * Parses one key-binding token string (key[-modifier[-modifier...]]) into
 * one packed keycode/modifier mask lane.
 */
/**
 * Address: 0x008365B0 (FUN_008365B0, cfunc_ClearCurrentFactoryForQueueDisplay)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to
 * `cfunc_ClearCurrentFactoryForQueueDisplayL`.
 */
int moho::cfunc_ClearCurrentFactoryForQueueDisplay(lua_State* const luaContext)
{
  return cfunc_ClearCurrentFactoryForQueueDisplayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008365D0 (FUN_008365D0, func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `ClearCurrentFactoryForQueueDisplay()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearCurrentFactoryForQueueDisplay",
    &moho::cfunc_ClearCurrentFactoryForQueueDisplay,
    nullptr,
    "<global>",
    kClearCurrentFactoryForQueueDisplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00836630 (FUN_00836630, cfunc_ClearCurrentFactoryForQueueDisplayL)
 *
 * What it does:
 * Validates zero-arg Lua call shape, unlinks current factory-owner lane from
 * its intrusive owner chain, clears current-factory pointers, and compacts the
 * current build-queue range.
 */
int moho::cfunc_ClearCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kClearCurrentFactoryForQueueDisplayHelpText, 0, argumentCount);
  }

  std::uintptr_t* cursor = sCurrentBuildFactory.start;
  if (cursor != nullptr) {
    if (*cursor != reinterpret_cast<std::uintptr_t>(&sCurrentBuildFactory)) {
      do {
        cursor = reinterpret_cast<std::uintptr_t*>(*cursor + 4u);
      } while (*cursor != reinterpret_cast<std::uintptr_t>(&sCurrentBuildFactory));
    }

    *cursor = reinterpret_cast<std::uintptr_t>(sCurrentBuildFactory.finish);
    sCurrentBuildFactory.start = nullptr;
    sCurrentBuildFactory.finish = nullptr;
  }

  FactoryCommandQueueItemRuntimeView* rebasedBegin = nullptr;
  RebaseFactoryQueueRangeAndTrimTail(&rebasedBegin, sCurrentBuildQueue.start, sCurrentBuildQueue.end);
  return 0;
}

/**
 * Address: 0x00BE4690 (FUN_00BE4690, register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  return func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef();
}

/**
 * Address: 0x0083A190 (FUN_0083A190, cfunc_IN_AddKeyMapTable)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to `cfunc_IN_AddKeyMapTableL`.
 */
int moho::cfunc_IN_AddKeyMapTable(lua_State* const luaContext)
{
  return cfunc_IN_AddKeyMapTableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083A210 (FUN_0083A210, cfunc_IN_AddKeyMapTableL)
 *
 * What it does:
 * Validates one key-map table argument and merges action/repeat entries into
 * the runtime key-map stores.
 */
int moho::cfunc_IN_AddKeyMapTableL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kINAddKeyMapTableHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject keyMapTable(LuaPlus::LuaStackObject(state, 1));
  AddUiKeyMapEntries(keyMapTable);
  return 0;
}

/**
 * Address: 0x0083A1B0 (FUN_0083A1B0, func_IN_AddKeyMapTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_AddKeyMapTable(keyMapTable)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_AddKeyMapTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IN_AddKeyMapTable",
    &moho::cfunc_IN_AddKeyMapTable,
    nullptr,
    "<global>",
    kINAddKeyMapTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE4950 (FUN_00BE4950, register_IN_AddKeyMapTable_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_AddKeyMapTable_LuaFuncDef()
{
  return func_IN_AddKeyMapTable_LuaFuncDef();
}

/**
 * Address: 0x0083A2B0 (FUN_0083A2B0, cfunc_IN_RemoveKeyMapTable)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to `cfunc_IN_RemoveKeyMapTableL`.
 */
int moho::cfunc_IN_RemoveKeyMapTable(lua_State* const luaContext)
{
  return cfunc_IN_RemoveKeyMapTableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083A330 (FUN_0083A330, cfunc_IN_RemoveKeyMapTableL)
 *
 * What it does:
 * Validates one key-map table argument and removes each key binding from the
 * runtime action/repeat key-map stores.
 */
int moho::cfunc_IN_RemoveKeyMapTableL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kINRemoveKeyMapTableHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject keyMapTable(LuaPlus::LuaStackObject(state, 1));
  RemoveUiKeyMapEntries(keyMapTable);
  return 0;
}

/**
 * Address: 0x0083A2D0 (FUN_0083A2D0, func_IN_RemoveKeyMapTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_RemoveKeyMapTable(keyMapTable)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_RemoveKeyMapTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IN_RemoveKeyMapTable",
    &moho::cfunc_IN_RemoveKeyMapTable,
    nullptr,
    "<global>",
    kINRemoveKeyMapTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE4960 (FUN_00BE4960, register_IN_RemoveKeyMapTable_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_RemoveKeyMapTable_LuaFuncDef()
{
  return func_IN_RemoveKeyMapTable_LuaFuncDef();
}

/**
 * Address: 0x0083A3D0 (FUN_0083A3D0, cfunc_IN_ClearKeyMap)
 *
 * What it does:
 * Validates the zero-argument lane and clears all runtime key-map bindings.
 */
int moho::cfunc_IN_ClearKeyMap(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kINClearKeyMapHelpText, 0, argumentCount);
  }

  ClearUiKeyMaps();
  return 0;
}

/**
 * Address: 0x0083A410 (FUN_0083A410, func_IN_ClearKeyMap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `IN_ClearKeyMap()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_IN_ClearKeyMap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IN_ClearKeyMap",
    &moho::cfunc_IN_ClearKeyMap,
    nullptr,
    "<global>",
    kINClearKeyMapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE4970 (FUN_00BE4970, register_IN_ClearKeyMap_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_ClearKeyMap_LuaFuncDef()
{
  return func_IN_ClearKeyMap_LuaFuncDef();
}

int moho::IN_ParseKeyModifiers(const std::string& keyBindingSpec)
{
  if (keyBindingSpec.empty()) {
    return 0;
  }

  std::vector<std::string> tokens{};
  std::size_t start = 0u;
  while (start <= keyBindingSpec.size()) {
    const std::size_t split = keyBindingSpec.find('-', start);
    const std::size_t tokenLength =
      (split == std::string::npos) ? (keyBindingSpec.size() - start) : (split - start);
    if (tokenLength > 0u) {
      tokens.emplace_back(keyBindingSpec.substr(start, tokenLength));
    }
    if (split == std::string::npos) {
      break;
    }
    start = split + 1u;
  }

  if (tokens.empty()) {
    return 0;
  }

  int keyMask = ParsePrimaryKeyToken(tokens.front());
  for (std::size_t tokenIndex = 1u; tokenIndex < tokens.size(); ++tokenIndex) {
    const std::string modifier = ToUpperAscii(tokens[tokenIndex]);
    if (modifier == "ALT") {
      keyMask |= static_cast<int>(0x80000000u);
      continue;
    }
    if (modifier == "CTRL" || modifier == "CONTROL") {
      keyMask |= static_cast<int>(0x40000000u);
      continue;
    }
    if (modifier == "SHIFT") {
      keyMask |= static_cast<int>(0x20000000u);
      continue;
    }

    gpg::Warnf("Key map contains unrecognized modifier string: %s\n", tokens[tokenIndex].c_str());
  }

  return keyMask;
}

moho::wxEvtHandlerRuntime* moho::UI_CreateKeyHandler()
{
  return new CUIKeyHandlerRuntime{};
}

void moho::WX_PushEventHandler(wxWindowBase* const window, wxEvtHandlerRuntime* const handler)
{
  if (window == nullptr || handler == nullptr) {
    return;
  }

  auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end()) {
    gWindowEventHandlerChains.push_back(WindowEventHandlerChain{window, {}});
    chainIt = gWindowEventHandlerChains.end() - 1;
  }

  chainIt->handlers.push_back(handler);
}

moho::wxEvtHandlerRuntime* moho::WX_PopEventHandler(wxWindowBase* const window, const bool deleteHandler)
{
  if (window == nullptr) {
    return nullptr;
  }

  const auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end() || chainIt->handlers.empty()) {
    return nullptr;
  }

  wxEvtHandlerRuntime* const popped = chainIt->handlers.back();
  chainIt->handlers.pop_back();

  if (chainIt->handlers.empty()) {
    gWindowEventHandlerChains.erase(chainIt);
  }

  if (deleteHandler && popped != nullptr) {
    delete popped;
    return nullptr;
  }

  return popped;
}

void moho::WX_GetClientSize(wxWindowBase* const window, std::int32_t& outWidth, std::int32_t& outHeight)
{
  if (window == nullptr) {
    outWidth = 0;
    outHeight = 0;
    return;
  }

  window->DoGetClientSize(&outWidth, &outHeight);
}

void moho::WX_ScreenToClient(wxWindowBase* const window, std::int32_t& inOutX, std::int32_t& inOutY)
{
  if (window == nullptr) {
    return;
  }

  const HWND handle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window->GetHandle()));
  if (handle == nullptr) {
    return;
  }

  POINT point{};
  point.x = inOutX;
  point.y = inOutY;
  if (::ScreenToClient(handle, &point) == FALSE) {
    return;
  }

  inOutX = point.x;
  inOutY = point.y;
}

bool moho::WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY)
{
  POINT cursorPosition{};
  if (::GetCursorPos(&cursorPosition) == FALSE) {
    outX = 0;
    outY = 0;
    return false;
  }

  outX = cursorPosition.x;
  outY = cursorPosition.y;
  return true;
}

const moho::VMatrix4& moho::UI_IdentityMatrix()
{
  static const VMatrix4 kIdentity = VMatrix4::Identity();
  return kIdentity;
}
namespace
{
  /**
   * Address: 0x00858440 (FUN_00858440)
   *
   * What it does:
   * Returns the global command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::list<CommandFeedbackBlipRuntimeView>*
  GetCommandFeedbackBlipsLaneA(const int /*unused*/) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x008585C0 (FUN_008585C0)
   *
   * What it does:
   * Secondary entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::list<CommandFeedbackBlipRuntimeView>*
  GetCommandFeedbackBlipsLaneB(const int /*unused*/) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x00858670 (FUN_00858670)
   *
   * What it does:
   * Third entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::list<CommandFeedbackBlipRuntimeView>*
  GetCommandFeedbackBlipsLaneC(const int /*unused*/) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x008587A0 (FUN_008587A0)
   *
   * What it does:
   * Fourth entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::list<CommandFeedbackBlipRuntimeView>* GetCommandFeedbackBlipsLaneD() noexcept
  {
    return &sCommandFeedbackBlips;
  }
} // namespace









