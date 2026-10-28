// Engine addition (dedicated-server plan WPL.4, WPR.11): the client-only part of
// moho/misc/StartupHelpers.cpp, moved unchanged: window and device options, the
// movie manager and its volume, adapter, fidelity, shadow and anti-aliasing
// setup, the user Lua state's command-line, texture, movie-volume, options and
// preference functions, and the range/vision renderer init that follows sim
// creation. Listed in sources.cmake right after StartupHelpers.cpp; its
// bootstrap registers its user-set forms in the order StartupHelpers.cpp did.

#include "moho/movie/sfd/IndependentSfdBackend.h"
#include "moho/misc/StartupHelpers.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/Set.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <ios>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <vector>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <direct.h>
#include <Windows.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <dsound.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/d3d10/DeviceD3D10.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaTableIterator.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/misc/XFileError.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/VisionRenderer.h"
#include "moho/render/WRenViewport.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/task/CTaskThread.h"
#include "moho/ui/CUIManager.h"
#include "lua/LuaCrashDump.h"
extern int __argc;
extern char** __argv;

using namespace moho;

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  constexpr char kApplyMethodName[] = "Apply";
  constexpr char kCreateProfileMethodName[] = "CreateProfile";
  constexpr char kGetCurrentProfileMethodName[] = "GetCurrentProfile";
  constexpr char kGetOptionMethodName[] = "GetOption";
  constexpr char kOptionsApplyLuaRunErrorPrefix[] = "Error running '/lua/options/optionslogic.lua':Apply %s";
  constexpr char kOptionsLogicModulePath[] = "/lua/options/optionslogic.lua";
  constexpr char kOptionsSetCustomDataLuaRunErrorPrefix[] =
    "Error running '/lua/options/optionslogic.lua':OPTIONS_SetCustomData %s";
  constexpr char kProfileCurrentIndexKey[] = "current";
  constexpr char kProfileNameFieldName[] = "Name";
  constexpr char kProfileNetNameFieldName[] = "NetName";
  constexpr char kProfileProfilesPath[] = "profile.profiles";
  constexpr char kProfileRootKey[] = "profile";
  constexpr char kProfilesExistMethodName[] = "ProfilesExist";
  constexpr char kSetCustomDataMethodName[] = "SetCustomData";
  constexpr char kUserPrefsGetOptionLuaRunErrorPrefix[] = "Error running '/lua/user/prefs.lua:GetOption' : %s";
  constexpr char kUserPrefsLuaRunErrorPrefix[] = "Error running '/lua/user/prefs.lua' : %s";
  constexpr char kUserPrefsModulePath[] = "/lua/user/prefs.lua";
  [[nodiscard]] const msvc8::string& ReplayDirName()
  {
    static const msvc8::string kReplayDir("replays");
    return kReplayDir;
  }
  [[nodiscard]] const msvc8::string& SaveGameDirName()
  {
    static const msvc8::string kSaveGameDir("savegames");
    return kSaveGameDir;
  }
  [[nodiscard]] const msvc8::string& ScreenshotDirName()
  {
    static const msvc8::string kScreenshotDir("screenshots");
    return kScreenshotDir;
  }
  /**
   * Address: 0x008CB600 (FUN_008CB600)
   *
   * IDA signature:
   * _DWORD *__usercall sub_8CB600@<eax>(std::string *key@<ecx>, std::map *map@<ebx>);
   *
   * What it does:
   * Out-of-line specialization of
   * `std::map<std::string, std::vector<std::string>>::operator[]`. Calls
   * `_Tree::lower_bound` on the key; when the lookup either returns the
   * sentinel head or a node whose key compares greater than the requested key,
   * it allocates a new node (default-constructed value), splices it into the
   * tree, then returns a reference to the value slot at node offset +0x28.
   *
   * Wired here so the linker preserves the binary's per-type
   * `vector_string::operator[]` symbol shape; the natural `map[key]` idiom
   * the compiler would inline does not guarantee the out-of-line emission.
   *
   * DB-integrity fix: this was originally typed over `std::map`/
   * `std::vector`/`std::string` (modern STL), which compiles to a
   * completely different, unrelated set of symbols -- not the
   * `msvc8::map<msvc8::string, msvc8::vector<msvc8::string>>` `_Tree`
   * insert/lower_bound bodies this binary actually links (FUN_008CB860 /
   * FUN_008CBA70, `legacy/containers/RbTree.h` + `Map.h`). Retyped to the
   * legacy ABI containers so the template family is instantiated again.
   */
  msvc8::vector<msvc8::string>& SubscriptStringToStringVectorMap(
    msvc8::map<msvc8::string, msvc8::vector<msvc8::string>>& map,
    const msvc8::string& key
  )
  {
    return map[key];
  }

  /**
   * Ordering for the adapter-mode dedup tree: width, then height, then refresh
   * rate. `0x008D6170` walks the tree with exactly this three-step compare.
   */
  struct ResolutionLess
  {
    [[nodiscard]] bool operator()(const moho::Resolution& lhs, const moho::Resolution& rhs) const noexcept
    {
      if (lhs.width != rhs.width) {
        return lhs.width < rhs.width;
      }
      if (lhs.height != rhs.height) {
        return lhs.height < rhs.height;
      }
      return lhs.framesPerSecond < rhs.framesPerSecond;
    }
  };

  // The shipped dedup is an RB-tree of `Resolution` (node 0x20: the 0x10
  // element at +0x0C, colour and nil at +0x1C/+0x1D), built on the stack by
  // `SetupPrimaryAdapterSettings` and `SetupSecondaryAdapterSettings` and torn
  // down when they return. The tree only suppresses repeats -- the option
  // states are published in the adapter's own order as the scan walks it.
  using AdapterModeDedup = msvc8::set<moho::Resolution, ResolutionLess>;

  [[nodiscard]] bool IsModeAboveWindowMinimum(const gpg::gal::HeadAdapterMode& mode)
  {
    return mode.width >= static_cast<std::uint32_t>(moho::wnd_DefaultCreateWidth) &&
      mode.height >= static_cast<std::uint32_t>(moho::wnd_DefaultCreateHeight);
  }

  void AddOptionStateInteger(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const statesTable,
    const std::int32_t index,
    const char* const text,
    const std::int32_t key
  )
  {
    if (state == nullptr || statesTable == nullptr) {
      return;
    }

    LuaPlus::LuaObject stateEntry(state);
    stateEntry.AssignNewTable(state, 0, 0);
    stateEntry.SetString("text", text != nullptr ? text : "");
    stateEntry.SetInteger("key", key);
    statesTable->SetObject(index, stateEntry);
  }
  void AddOptionStateString(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const statesTable,
    const std::int32_t index,
    const char* const text,
    const char* const key
  )
  {
    if (state == nullptr || statesTable == nullptr) {
      return;
    }

    LuaPlus::LuaObject stateEntry(state);
    stateEntry.AssignNewTable(state, 0, 0);
    stateEntry.SetString("text", text != nullptr ? text : "");
    stateEntry.SetString("key", key != nullptr ? key : "");
    statesTable->SetObject(index, stateEntry);
  }
  [[nodiscard]] msvc8::string BuildModeKey(const gpg::gal::HeadAdapterMode& mode)
  {
    return gpg::STR_Printf("%u,%u,%u", mode.width, mode.height, mode.refreshRate);
  }
  /**
   * Address: 0x008CD4F0 (FUN_008CD4F0)
   *
   * What it does:
   * Formats one adapter mode label as `"<width>x<height>(<refresh>)"` for
   * startup option state text.
   */
  [[nodiscard]] msvc8::string BuildModeLabel(const gpg::gal::HeadAdapterMode& mode)
  {
    std::ostringstream stream;
    stream << mode.width << 'x' << mode.height << '(' << mode.refreshRate << ')';
    return msvc8::string(stream.str().c_str());
  }
  [[nodiscard]] LuaPlus::LuaObject BuildOptionRoot(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject root(state);
    root.AssignNewTable(state, 0, 0);

    LuaPlus::LuaObject states(state);
    states.AssignNewTable(state, 0, 0);
    root.SetObject("states", states);

    return root;
  }
  /**
   * The list both adapter option builders publish: the device's display modes
   * for `adapterIndex` (gal::Device slot 5 - adapter 0 at 0x008D22F7, adapter 1
   * at 0x008D2807), less the modes under the minimum window size and repeats.
   * The recovered version read the head's own `adapterModes` copy instead and
   * gave up when the context had no head at that index; the binary asks the
   * device and has neither the head lookup nor the guards.
   */
  [[nodiscard]] msvc8::vector<gpg::gal::HeadAdapterMode> CollectAdapterModes(const int adapterIndex)
  {
    msvc8::vector<gpg::gal::HeadAdapterMode> adapterModes;
    gpg::gal::Device::GetInstance()->GetModesForAdapter(adapterModes, adapterIndex);

    msvc8::vector<gpg::gal::HeadAdapterMode> modes;
    AdapterModeDedup published;
    for (const gpg::gal::HeadAdapterMode& adapterMode : adapterModes) {
      if (!IsModeAboveWindowMinimum(adapterMode)) {
        continue;
      }
      const moho::Resolution mode(
        static_cast<std::int32_t>(adapterMode.width),
        static_cast<std::int32_t>(adapterMode.height),
        static_cast<std::int32_t>(adapterMode.refreshRate)
      );
      if (published.find(mode) != published.end()) {
        continue;
      }
      (void)published.insert(mode);
      modes.push_back(adapterMode);
    }

    return modes;
  }
  /**
   * Address: 0x00874C10 (FUN_00874C10, `func_GpgSofDecError`)
   *
   * IDA signature:
   * int __cdecl func_GpgSofDecError(char* ignored, const char* message);
   *
   * What it does:
   * Routes Sofdec middleware errors into gpg warning logs.
   */
  int __cdecl GpgSofDecError(std::uint32_t /*ignored*/, const char* const message)
  {
    gpg::Warnf("SofDec error: %s", message);
    return 0;
  }
  constexpr char kAntiAliasingKey[] = "antialiasing";
  constexpr char kCommandLineOverrideModeKey[] = "overridden";
  constexpr char kDebugFacilitiesEnabledHelpText[] =
    "bool DebugFacilitiesEnabled() - returns true if debug facilities are enabled.";
  constexpr char kDisabledModeKey[] = "disabled";
  constexpr char kFidelityKey[] = "fidelity";
  constexpr char kGetAntiAliasingOptionsHelpText[] = "obj GetAntiAliasingOptions()";
  constexpr char kGetCommandLineArgHelpText[] = "CommandArgTable GetCommandLineArg(option, number)";
  constexpr char kGetMovieVolumeHelpText[] = "GetMovieVolume()";
  constexpr char kGetOptionsHelpText[] = "obj GetOptions()";
  constexpr char kGetPreferenceHelpText[] = "obj GetPreference(string, [default])";
  constexpr char kGetTextureDimensionsHelpText[] = "width, height GetTextureDimensions(filename, border = 1)";
  constexpr char kHasCommandLineArgHelpText[] = "HasCommandLineArg(option)";
  constexpr char kLuaExpectedArgRangeWarning[] = "%s\n  expected between %d and %d args, but got %d";
  constexpr float kMovieSofdecVideoRefreshHz = 59.939999f;
  /** The top of `SetMovieVolume`'s "0.0 - 2.0" range (0x00DFEB0C). */
  constexpr float kMovieVolumeScriptMax = 2.0f;
  constexpr char kPrimaryAdapterKey[] = "primary_adapter";
  constexpr char kSavePreferencesHelpText[] = "SavePreferences()";
  constexpr char kSecondaryAdapterKey[] = "secondary_adapter";
  constexpr char kSetMovieVolumeHelpText[] = "SetMovieVolume(volume): 0.0 - 2.0";
  constexpr char kSetPreferenceHelpText[] = "SetPreference(string, obj)";
  constexpr char kShadowQualityKey[] = "shadow_quality";
  constexpr char kWindowedModeKey[] = "windowed";
  void RefreshFidelitySupportLanes(const gpg::gal::DeviceContext* const context)
  {
    if (context == nullptr) {
      return;
    }

    moho::graphics_FidelitySupported = context->mPixelShaderProfile > 5 ? 2 : 1;
    moho::shadow_FidelitySupported = context->mPixelShaderProfile > 5 ? 3 : 2;
  }
  [[nodiscard]] LuaPlus::LuaState* ResolveBindingLuaState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }
  [[nodiscard]] LuaPlus::LuaState* ResolveStartupLuaState()
  {
    if (moho::g_UIManager != nullptr && moho::g_UIManager->mLuaState != nullptr) {
      return moho::g_UIManager->mLuaState;
    }

    return moho::USER_GetLuaState();
  }
  /**
   * The one `CMovieManager` (0x010C4AF0). `SetupBasicMovieManager` is its
   * `reset(new CMovieManager)` and `DestroyMovieManagerSingleton` its
   * `reset()`; the CRT destroys it at exit through the `atexit` destructor
   * 0x00BE6C80 registers.
   */
  msvc8::auto_ptr<moho::CMovieManager> sMovieManager;
  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    // Every file that wants this set must resolve the one that already
    // exists. Declaring a fresh static here creates a second set with the
    // same name, and SCR_FindLuaInitFormSet returns only the first - so
    // half the binders never get run.
    if (moho::CScrLuaInitFormSet* const existing = moho::SCR_FindLuaInitFormSet("User"); existing != nullptr) {
      return *existing;
    }

    static moho::CScrLuaInitFormSet sSet("User");
    return sSet;
  }
} // namespace


std::int32_t moho::wnd_MinCmdLineWidth = 1024;
std::int32_t moho::wnd_MinCmdLineHeight = 720;
std::int32_t moho::wnd_MinDragWidth = 1024;
std::int32_t moho::wnd_MinDragHeight = 768;
std::int32_t moho::wnd_DefaultCreateWidth = 1024;
std::int32_t moho::wnd_DefaultCreateHeight = 768;

// graphics_Fidelity: moho/misc/StartupHelpers.cpp (CEffectManagerImpl reads it).
// Shipped .data 0x00F58E8C..0x00F58E94; device caps and the options apply later.
std::int32_t moho::graphics_FidelitySupported = 2;
std::int32_t moho::shadow_Fidelity = 2;
std::int32_t moho::shadow_FidelitySupported = 3;
bool moho::d3d_UseRefRast = false;
bool moho::d3d_ForceSoftwareVP = false;
bool moho::d3d_NoPureDevice = false;
bool moho::d3d_ForceDirect3DDebugEnabled = false;
bool moho::d3d_WindowsCursor = false;
std::uint32_t moho::sAdapterNotCLOverridden = 1;
bool moho::sDeviceLock = false;

/**
 * Address: 0x0041B810 (FUN_0041B810, cfunc_GetCommandLineArgL)
 *
 * What it does:
 * Resolves one command-line option with requested argument count. Returns a
 * Lua array table of copied argument strings when found, otherwise returns
 * boolean false.
 */
int moho::cfunc_GetCommandLineArgL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetCommandLineArgHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject optionArg(state, 1);
  const char* const optionText = optionArg.GetString();
  gpg::Logf(optionText != nullptr ? optionText : "");

  LuaPlus::LuaStackObject requestedCountArg(state, 2);
  const int requestedArgCount = requestedCountArg.GetInteger();

  msvc8::vector<msvc8::string> optionValues;
  const bool foundOption = CFG_GetArgOption(optionText, static_cast<std::uint32_t>(requestedArgCount), &optionValues);

  LuaPlus::LuaObject result(state);
  if (foundOption) {
    result.AssignNewTable(state, requestedArgCount, 0);

    if (requestedArgCount > 0) {
      const int cappedCount = std::min(requestedArgCount, static_cast<int>(optionValues.size()));
      for (int index = 0; index < cappedCount; ++index) {
        LuaPlus::LuaObject value(state);
        value.AssignString(state, optionValues[static_cast<std::size_t>(index)].c_str());
        // 0x0041B998: `LuaObject::Insert(i, value)` (Lua `table.insert`), not a raw store.
        result.Insert(index + 1, value);
      }
    }
  } else {
    result.AssignBoolean(state, false);
  }

  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x0041B790 (FUN_0041B790, cfunc_GetCommandLineArg)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetCommandLineArgL`.
 */
int moho::cfunc_GetCommandLineArg(lua_State* const luaContext)
{
  return cfunc_GetCommandLineArgL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x0041B7B0 (FUN_0041B7B0, func_GetCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetCommandLineArg`.
 */
moho::CScrLuaInitForm* moho::func_GetCommandLineArg_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCommandLineArg",
    &moho::cfunc_GetCommandLineArg,
    nullptr,
    "<global>",
    kGetCommandLineArgHelpText
  );
  return &binder;
}

/**
 * Address: 0x0041BAA0 (FUN_0041BAA0, cfunc_HasCommandLineArgL)
 *
 * What it does:
 * Resolves one command-line option and pushes whether it is present.
 */
int moho::cfunc_HasCommandLineArgL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kHasCommandLineArgHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject optionArg(state, 1);
  const char* const optionText = optionArg.GetString();

  msvc8::vector<msvc8::string> optionValues;
  const bool foundOption = CFG_GetArgOption(optionText, 0, &optionValues);
  lua_pushboolean(rawState, foundOption ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0041BA20 (FUN_0041BA20, cfunc_HasCommandLineArg)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_HasCommandLineArgL`.
 */
int moho::cfunc_HasCommandLineArg(lua_State* const luaContext)
{
  return cfunc_HasCommandLineArgL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x0041BA40 (FUN_0041BA40, func_HasCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `HasCommandLineArg`.
 */
moho::CScrLuaInitForm* moho::func_HasCommandLineArg_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HasCommandLineArg",
    &moho::cfunc_HasCommandLineArg,
    nullptr,
    "<global>",
    kHasCommandLineArgHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC3800 (FUN_00BC3800, register_GetCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_GetCommandLineArg_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_GetCommandLineArg_LuaFuncDef()
{
  return func_GetCommandLineArg_LuaFuncDef();
}

/**
 * Address: 0x00BC3810 (FUN_00BC3810, register_HasCommandLineArg_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_HasCommandLineArg_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_HasCommandLineArg_LuaFuncDef()
{
  return func_HasCommandLineArg_LuaFuncDef();
}

/**
 * Address: 0x00780AF0 (FUN_00780AF0, cfunc_GetTextureDimensionsL)
 *
 * What it does:
 * Loads one texture by filename and optional border and returns
 * `(width, height)` on success, otherwise `nil`.
 */
int moho::cfunc_GetTextureDimensionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kGetTextureDimensionsHelpText, 1, 2, argumentCount);
  }

  std::uint32_t border = 1u;
  if (lua_gettop(rawState) >= 2) {
    LuaPlus::LuaStackObject borderArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&borderArg, "integer");
    }

    const double borderAsDouble = lua_tonumber(rawState, 3);
    const auto borderAsSignedInt = static_cast<int>(borderAsDouble);
    border = static_cast<std::uint32_t>(borderAsSignedInt);
  }

  LuaPlus::LuaStackObject filenameArg(state, 1);
  const char* filename = lua_tostring(rawState, 1);
  if (filename == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&filenameArg, "string");
    filename = "";
  }

  boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromFile(filename, border);
  if (texture) {
    lua_pushnumber(rawState, static_cast<float>(static_cast<int>(texture->mWidth)));
    (void)lua_gettop(rawState);
    lua_pushnumber(rawState, static_cast<float>(static_cast<int>(texture->mHeight)));
    (void)lua_gettop(rawState);
    return 2;
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00780A70 (FUN_00780A70, cfunc_GetTextureDimensions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetTextureDimensionsL`.
 */
int moho::cfunc_GetTextureDimensions(lua_State* const luaContext)
{
  return cfunc_GetTextureDimensionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00780A90 (FUN_00780A90, func_GetTextureDimensions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `GetTextureDimensions` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetTextureDimensions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetTextureDimensions",
    &moho::cfunc_GetTextureDimensions,
    nullptr,
    "<global>",
    kGetTextureDimensionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00874FA0 (FUN_00874FA0, cfunc_SetMovieVolume)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_SetMovieVolumeL`.
 */
int moho::cfunc_SetMovieVolume(lua_State* const luaContext)
{
  return cfunc_SetMovieVolumeL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00874FC0 (FUN_00874FC0, func_SetMovieVolume_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SetMovieVolume`.
 */
moho::CScrLuaInitForm* moho::func_SetMovieVolume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetMovieVolume",
    &moho::cfunc_SetMovieVolume,
    nullptr,
    "<global>",
    kSetMovieVolumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00875020 (FUN_00875020, cfunc_SetMovieVolumeL)
 *
 * What it does:
 * Reads one volume argument, validates numeric type, and hands it to
 * `MOV_SetVolume`, which the binary carries inline.
 */
int moho::cfunc_SetMovieVolumeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetMovieVolumeHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject volumeArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    volumeArg.TypeError("number");
  }

  MOV_SetVolume(static_cast<float>(lua_tonumber(rawState, 1)));
  return 0;
}

/**
 * Address: 0x00875100 (FUN_00875100, cfunc_GetMovieVolume)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetMovieVolumeL`.
 */
int moho::cfunc_GetMovieVolume(lua_State* const luaContext)
{
  return cfunc_GetMovieVolumeL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x00875120 (FUN_00875120, func_GetMovieVolume_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetMovieVolume`.
 */
moho::CScrLuaInitForm* moho::func_GetMovieVolume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMovieVolume",
    &moho::cfunc_GetMovieVolume,
    nullptr,
    "<global>",
    kGetMovieVolumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00875180 (FUN_00875180, cfunc_GetMovieVolumeL)
 *
 * What it does:
 * Validates zero-argument call shape and pushes `MOV_GetVolume()`, which the
 * binary carries inline.
 */
int moho::cfunc_GetMovieVolumeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetMovieVolumeHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, MOV_GetVolume());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C9660 (FUN_008C9660, cfunc_GetAntiAliasingOptions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetAntiAliasingOptionsL`.
 */
int moho::cfunc_GetAntiAliasingOptions(lua_State* const luaContext)
{
  return cfunc_GetAntiAliasingOptionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9680 (FUN_008C9680, func_GetAntiAliasingOptions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `GetAntiAliasingOptions` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetAntiAliasingOptions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAntiAliasingOptions",
    &moho::cfunc_GetAntiAliasingOptions,
    nullptr,
    "<global>",
    kGetAntiAliasingOptionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C96E0 (FUN_008C96E0, cfunc_GetAntiAliasingOptionsL)
 *
 * What it does:
 * Builds and returns a Lua array-like table of anti-aliasing option keys from
 * active head sample modes (`0` disabled plus packed mode entries).
 */
int moho::cfunc_GetAntiAliasingOptionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kGetAntiAliasingOptionsHelpText, 0, argumentCount
    );
  }

  LuaPlus::LuaObject optionsTable(state);
  optionsTable.AssignNewTable(state, 0, 0);
  optionsTable.SetInteger(1, 0);

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device ? device->GetDeviceContext() : nullptr;
  const gpg::gal::Head* const head =
    (context != nullptr && context->GetHeadCount() > 0) ? &context->GetHead(0) : nullptr;

  if (head != nullptr) {
    const gpg::gal::HeadSampleOption* const begin = head->mStrs.begin();
    const gpg::gal::HeadSampleOption* const end = head->mStrs.end();
    if (begin != nullptr && end != nullptr) {
      std::int32_t tableIndex = 2;
      for (const gpg::gal::HeadSampleOption* it = begin; it != end; ++it) {
        const std::uint32_t packedMode =
          static_cast<std::uint32_t>(it->sampleType) | (static_cast<std::uint32_t>(it->sampleQuality) << 5u);
        optionsTable.SetInteger(tableIndex++, static_cast<std::int32_t>(packedMode));
      }
    }
  }

  optionsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9490 (FUN_008C9490, cfunc_GetOptions)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetOptionsL`.
 */
int moho::cfunc_GetOptions(lua_State* const luaContext)
{
  return cfunc_GetOptionsL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C94B0 (FUN_008C94B0, func_GetOptions_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetOptions` in the
 * user init set.
 */
moho::CScrLuaInitForm* moho::func_GetOptions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetOptions",
    &moho::cfunc_GetOptions,
    nullptr,
    "<global>",
    "obj GetOptions()"
  );
  return &binder;
}

/**
 * Address: 0x008C9510 (FUN_008C9510, cfunc_GetOptionsL)
 *
 * What it does:
 * Reads one options key string and pushes the current preference value.
 */
int moho::cfunc_GetOptionsL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kGetOptionsHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string optionKey{};
  optionKey.assign_owned(keyText);

  // 0x008C95BF..0x008C95DE: the option object lives on the preferences state;
  // SCR_Copy rebuilds it on the caller's state so numbers stay numbers.
  const LuaPlus::LuaObject valueObject = SCR_Copy(
    USER_GetPreferences()->LookupCurrentOption(optionKey), state
  );
  valueObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9850 (FUN_008C9850, cfunc_GetPreference)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_GetPreferenceL`.
 */
int moho::cfunc_GetPreference(lua_State* const luaContext)
{
  return cfunc_GetPreferenceL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9870 (FUN_008C9870, func_GetPreference_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `GetPreference`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GetPreference_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetPreference",
    &moho::cfunc_GetPreference,
    nullptr,
    "<global>",
    kGetPreferenceHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C98D0 (FUN_008C98D0, cfunc_GetPreferenceL)
 *
 * What it does:
 * Resolves one preference key and returns its Lua object value, with optional
 * default object fallback from arg #2.
 */
int moho::cfunc_GetPreferenceL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kGetPreferenceHelpText, 1, 2, argumentCount);
  }

  lua_settop(rawState, 2);

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string key;
  key.assign_owned(keyText);

  LuaPlus::LuaObject preferenceObject(state);
  preferenceObject.AssignNil(state);

  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    // The preferences table lives on the preferences LuaState, so the looked-up
    // value is bound to that state and cannot be pushed onto the caller's -
    // PushStack rejects it on `state->l_G == m_state->m_state->l_G`, which is a
    // check the binary has too. The binary copies across first: 0x008C9991
    // dispatches vtable slot 16 (LookupKey), then 0x008C99AE calls
    // SCR_Copy(&result, looked_up, callerState) before the push.
    preferenceObject = SCR_Copy(preferences->LookupKey(key), state);
  }

  if (preferenceObject.IsNil()) {
    preferenceObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 2));
  }

  preferenceObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C9A50 (FUN_008C9A50, cfunc_SetPreference)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_SetPreferenceL`.
 */
int moho::cfunc_SetPreference(lua_State* const luaContext)
{
  return cfunc_SetPreferenceL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008C9A70 (FUN_008C9A70, func_SetPreference_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SetPreference`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_SetPreference_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetPreference",
    &moho::cfunc_SetPreference,
    nullptr,
    "<global>",
    kSetPreferenceHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C9AD0 (FUN_008C9AD0, cfunc_SetPreferenceL)
 *
 * What it does:
 * Reads `(key, value)` from Lua and stores the preference object under `key`.
 */
int moho::cfunc_SetPreferenceL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetPreferenceHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));

  LuaPlus::LuaStackObject keyArg(state, 1);
  const char* keyText = lua_tostring(rawState, 1);
  if (keyText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&keyArg, "string");
    keyText = "";
  }

  msvc8::string key;
  key.assign_owned(keyText);

  if (IUserPrefs* const preferences = USER_GetPreferences(); preferences != nullptr) {
    // The value arrives on the caller's Lua state, and the preference tree
    // lives on the preferences' own one, so it has to be copied across before
    // it can be stored. LuaObject::SetObject asserts that a table and the
    // value written into it share a state, and passing the caller's object
    // straight through tripped that on every SetPreference - which is as far
    // as userInit.lua got.
    auto* const prefsState = static_cast<LuaPlus::LuaState*>(preferences->GetState());
    LuaPlus::LuaObject copiedValue = moho::SCR_Copy(valueObject, prefsState);
    preferences->SetObject(key, &copiedValue);
  }

  return 0;
}

/**
 * Address: 0x008C9C30 (FUN_008C9C30, cfunc_SavePreferences)
 *
 * What it does:
 * Validates zero-argument call shape and persists current user preferences.
 */
int moho::cfunc_SavePreferences(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSavePreferencesHelpText, 0, argumentCount);
  }

  USER_SavePreferences();
  return 0;
}

/**
 * Address: 0x008C9C70 (FUN_008C9C70, func_SavePreferences_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `SavePreferences`
 * in the user init set.
 */
moho::CScrLuaInitForm* moho::func_SavePreferences_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SavePreferences",
    &moho::cfunc_SavePreferences,
    nullptr,
    "<global>",
    kSavePreferencesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE8BF0 (FUN_00BE8BF0, register_SavePreferences_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_SavePreferences_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_SavePreferences_LuaFuncDef()
{
  return func_SavePreferences_LuaFuncDef();
}

/**
 * Address: 0x008CAEA0 (FUN_008CAEA0, cfunc_DebugFacilitiesEnabled)
 *
 * What it does:
 * Lua C callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DebugFacilitiesEnabledL`.
 */
int moho::cfunc_DebugFacilitiesEnabled(lua_State* const luaContext)
{
  return cfunc_DebugFacilitiesEnabledL(ResolveBindingLuaState(luaContext));
}

/**
 * Address: 0x008CAEC0 (FUN_008CAEC0, func_DebugFacilitiesEnabled_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for
 * `DebugFacilitiesEnabled` in the user init set.
 */
moho::CScrLuaInitForm* moho::func_DebugFacilitiesEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DebugFacilitiesEnabled",
    &moho::cfunc_DebugFacilitiesEnabled,
    nullptr,
    "<global>",
    kDebugFacilitiesEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE8CE0 (FUN_00BE8CE0, j_func_DebugFacilitiesEnabled_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_DebugFacilitiesEnabled_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_DebugFacilitiesEnabled_LuaFuncDef()
{
  return func_DebugFacilitiesEnabled_LuaFuncDef();
}

/**
 * Address: 0x008CAF20 (FUN_008CAF20, cfunc_DebugFacilitiesEnabledL)
 *
 * What it does:
 * Validates zero-argument call shape and returns whether debug facilities
 * are enabled.
 */
int moho::cfunc_DebugFacilitiesEnabledL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kDebugFacilitiesEnabledHelpText, 0, argumentCount
    );
  }

  lua_pushboolean(rawState, USER_DebugFacilitiesEnabled() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00874AF0 (FUN_00874AF0, `Moho::CMovieManager::CMovieManager`)
 *
 * What it does:
 * Opens DirectSound, hands it to the ADX middleware along with the default
 * file system and thread setup, routes middleware errors to the log, and
 * initialises Sofdec for a 59.94 Hz display. The volume starts at 0: full
 * volume, in DirectSound's attenuation units.
 */
moho::CMovieManager::CMovieManager()
  : mDirectSound(nullptr)
  , mPrimaryBuffer(nullptr)
{
  CreateDirectSound();

  ::ADXPC_SetupSoundDirectSound8(mDirectSound);
  ::ADXPC_SetupFileSystem(nullptr);
  ::ADXM_SetupThrd(nullptr);

  MwsfdInitPrm initParams{};
  initParams.vhz = kMovieSofdecVideoRefreshHz;
  initParams.disp_cycle = 1;
  initParams.disp_latency = 1;
  initParams.dec_svr = MWSFD_DEC_SVR_MAIN;

  ::ADXM_SetCbErr(&GpgSofDecError, 0);
  ::mwPlyInitSfdFx(&initParams);
  mVolume = 0.0f;
}

/**
 * Address: 0x00874990 (FUN_00874990, `func_CreateDirectSound`)
 *
 * What it does:
 * Unless `/nosound` is given, creates the DirectSound device at priority
 * level on the main window and a 48 kHz 16-bit stereo buffer with volume
 * control. Either later failure releases the device again, so the middleware
 * runs without sound.
 */
void moho::CMovieManager::CreateDirectSound()
{
  if (CFG_GetArgOption("/nosound", 0, nullptr)) {
    return;
  }

  if (FAILED(::DirectSoundCreate(nullptr, &mDirectSound, nullptr))) {
    gpg::Logf("Failed to create DirectSound.");
    return;
  }

  const HWND mainWindow = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(sMainWindow->GetHandle()));
  if (FAILED(mDirectSound->SetCooperativeLevel(mainWindow, DSSCL_PRIORITY))) {
    gpg::Warnf("Failed to set cooperative level.");
    mDirectSound->Release();
    mDirectSound = nullptr;
    return;
  }

  WAVEFORMATEX waveFormat{};
  waveFormat.wFormatTag = WAVE_FORMAT_PCM;
  waveFormat.nChannels = 2;
  waveFormat.nSamplesPerSec = 48000;
  waveFormat.nAvgBytesPerSec = 192000;
  waveFormat.nBlockAlign = 4;
  waveFormat.wBitsPerSample = 16;

  DSBUFFERDESC bufferDesc{};
  bufferDesc.dwSize = sizeof(bufferDesc);
  bufferDesc.dwFlags = DSBCAPS_CTRLVOLUME;
  bufferDesc.dwBufferBytes = 576000;
  bufferDesc.lpwfxFormat = &waveFormat;
  if (FAILED(mDirectSound->CreateSoundBuffer(&bufferDesc, &mPrimaryBuffer, nullptr))) {
    gpg::Warnf("Failed to create primary sound buffer.");
    mDirectSound->Release();
    mDirectSound = nullptr;
  }
}

/**
 * Address: 0x00874B90 (FUN_00874B90, ??1CMovieManager@Moho@@QAE@XZ)
 * Address: 0x00875290 (FUN_00875290, the scalar deleting destructor: this
 * body inlined, then `operator delete`)
 *
 * What it does:
 * Shuts Sofdec and the ADX manager down, releases the sound buffer and the
 * DirectSound device, and runs the ADX PC shutdown hook last.
 */
moho::CMovieManager::~CMovieManager()
{
  ::mwPlyFinishSfdFx();
  ::ADXM_Finish();
  ReleaseDirectSound();
  ::ADXPC_NoOpShutdownCallback();
}

/**
 * Address: 0x00874AC0 (FUN_00874AC0)
 *
 * What it does:
 * Releases the sound buffer, then the DirectSound device, nulling each. The
 * destructor (0x00874B9A) and its deleting copy carry it inline; this is the
 * linker-retained out-of-line copy.
 */
void moho::CMovieManager::ReleaseDirectSound()
{
  ::ADXPC_SetupSoundDirectSound8(nullptr);
  if (mPrimaryBuffer != nullptr) {
    mPrimaryBuffer->Release();
    mPrimaryBuffer = nullptr;
  }
  if (mDirectSound != nullptr) {
    mDirectSound->Release();
    mDirectSound = nullptr;
  }
}

/**
 * Address: 0x00874BD0 (FUN_00874BD0)
 *
 * What it does:
 * Stores a linear volume, capped at 1, as DirectSound attenuation in
 * hundredths of a decibel: `DSBVOLUME_MIN` (-100 dB) for 0 up to 0 for full
 * volume, truncated to a whole unit.
 */
void moho::CMovieManager::SetVolume(float volume)
{
  volume = std::min(1.0f, volume);
  mVolume = static_cast<float>(static_cast<std::int32_t>(DSBVOLUME_MIN - volume * DSBVOLUME_MIN));
  moho::sfd::SetVolume(static_cast<long>(mVolume));
}

/**
 * Address: 0x008D21E0 (FUN_008D21E0)
 *
 * What it does:
 * Publishes primary-adapter option states and default selection data for the
 * startup options UI.
 */
void moho::SetupPrimaryAdapterSettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  if (gpg::gal::Device* const device = gpg::gal::Device::GetInstance()) {
    RefreshFidelitySupportLanes(device->GetDeviceContext());
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  if (sAdapterNotCLOverridden != 0) {
    AddOptionStateString(state, &statesTable, 1, "<LOC OPTIONS_0070>Windowed", kWindowedModeKey);

    msvc8::vector<gpg::gal::HeadAdapterMode> modes = CollectAdapterModes(0);
    std::int32_t nextStateIndex = 2;
    const gpg::gal::HeadAdapterMode* const begin = modes.begin();
    const gpg::gal::HeadAdapterMode* const end = modes.end();
    if (begin != nullptr && end != nullptr) {
      for (const gpg::gal::HeadAdapterMode* it = begin; it != end; ++it) {
        const msvc8::string label = BuildModeLabel(*it);
        const msvc8::string value = BuildModeKey(*it);
        AddOptionStateString(state, &statesTable, nextStateIndex, label.c_str(), value.c_str());
        ++nextStateIndex;
      }
    }

    LuaPlus::LuaObject defaultValue(state);
    defaultValue.AssignString(state, "1024,768,60");
    OPTIONS_SetCustomData(kPrimaryAdapterKey, optionRoot, defaultValue);
    return;
  }

  AddOptionStateString(state, &statesTable, 1, "<LOC _Command_Line_Override>", kCommandLineOverrideModeKey);

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignString(state, kCommandLineOverrideModeKey);
  OPTIONS_SetCustomData(kPrimaryAdapterKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D26D0 (FUN_008D26D0)
 *
 * What it does:
 * Publishes secondary-adapter option states. When command-line adapter
 * override is active, publishes only the override lane.
 */
void moho::SetupSecondaryAdapterSettings(const bool adapterNotCommandLineOverridden)
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  if (sAdapterNotCLOverridden == 0) {
    AddOptionStateString(state, &statesTable, 1, "<LOC _Command_Line_Override>", kCommandLineOverrideModeKey);

    LuaPlus::LuaObject defaultValue(state);
    defaultValue.AssignString(state, kCommandLineOverrideModeKey);
    OPTIONS_SetCustomData(kSecondaryAdapterKey, optionRoot, defaultValue);
    return;
  }

  AddOptionStateString(state, &statesTable, 1, "<LOC _Disabled>", kDisabledModeKey);
  std::int32_t nextStateIndex = 2;

  if (!adapterNotCommandLineOverridden) {
    msvc8::vector<gpg::gal::HeadAdapterMode> modes = CollectAdapterModes(1);
    const gpg::gal::HeadAdapterMode* const begin = modes.begin();
    const gpg::gal::HeadAdapterMode* const end = modes.end();
    if (begin != nullptr && end != nullptr) {
      for (const gpg::gal::HeadAdapterMode* it = begin; it != end; ++it) {
        const msvc8::string label = BuildModeLabel(*it);
        const msvc8::string value = BuildModeKey(*it);
        AddOptionStateString(state, &statesTable, nextStateIndex, label.c_str(), value.c_str());
        ++nextStateIndex;
      }
    }
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignString(state, kDisabledModeKey);
  OPTIONS_SetCustomData(kSecondaryAdapterKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D2E20 (FUN_008D2E20)
 *
 * What it does:
 * Publishes fidelity option states and default selection.
 */
void moho::SetupFidelitySettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  RefreshFidelitySupportLanes(context);

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  AddOptionStateInteger(state, &statesTable, 1, "<LOC _Low>", 0);
  AddOptionStateInteger(state, &statesTable, 2, "<LOC _Medium>", 1);

  if (graphics_FidelitySupported > 1) {
    AddOptionStateInteger(state, &statesTable, 3, "<LOC _High>", 2);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OPTIONS_SetCustomData(kFidelityKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D3010 (FUN_008D3010)
 *
 * What it does:
 * Publishes shadow-quality option states and default selection.
 */
void moho::SetupShadowQualitySettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  RefreshFidelitySupportLanes(context);

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");

  AddOptionStateInteger(state, &statesTable, 1, "<LOC _Off>", 0);
  AddOptionStateInteger(state, &statesTable, 2, "<LOC _Low>", 1);
  AddOptionStateInteger(state, &statesTable, 3, "<LOC _Medium>", 2);

  if (shadow_FidelitySupported > 2) {
    AddOptionStateInteger(state, &statesTable, 4, "<LOC _High>", 3);
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 1.0);
  OPTIONS_SetCustomData(kShadowQualityKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D3250 (FUN_008D3250)
 *
 * What it does:
 * Publishes anti-aliasing option states from active head sample-options list.
 */
void moho::SetupAntiAliasingSettings()
{
  LuaPlus::LuaState* const state = ResolveStartupLuaState();
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject optionRoot = BuildOptionRoot(state);
  LuaPlus::LuaObject statesTable = optionRoot.GetByName("states");
  AddOptionStateInteger(state, &statesTable, 1, "<LOC OPTIONS_0029>Off", 0);

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
  if (context != nullptr && context->GetHeadCount() > 0) {
    const gpg::gal::Head& head = context->GetHead(0);
    const gpg::gal::HeadSampleOption* const begin = head.mStrs.begin();
    const gpg::gal::HeadSampleOption* const end = head.mStrs.end();
    if (begin != nullptr && end != nullptr) {
      std::int32_t nextStateIndex = 2;
      for (const gpg::gal::HeadSampleOption* it = begin; it != end; ++it) {
        const std::uint32_t packedMode = it->sampleType | (it->sampleQuality << 5);
        AddOptionStateInteger(
          state, &statesTable, nextStateIndex, it->label.c_str(), static_cast<std::int32_t>(packedMode)
        );
        ++nextStateIndex;
      }
    }
  }

  LuaPlus::LuaObject defaultValue(state);
  defaultValue.AssignNumber(state, 0.0);
  OPTIONS_SetCustomData(kAntiAliasingKey, optionRoot, defaultValue);
}

/**
 * Address: 0x008D3FF0 (FUN_008D3FF0, sub_8D3FF0)
 *
 * What it does:
 * Emits one executable build timestamp line to the in-game console.
 */
namespace moho
{
  // Declared in StartupHelpers.h. Derived by Sim::Create_exxt from the loaded
  // heightmap's sample range and read by RangeRenderer::Init (0x007EE2B8 /
  // 0x007EE336) and VisionRenderer::Init (0x0081C38A / 0x0081C3C1) when they
  // build their ring geometry.
  float patch_maxMapHeight = 0.0f;
  float patch_minMapHeight = 0.0f;

  void PrintExecutableTimestampToConsole()
  {
    CON_Printf("Exe timestamp : %s", "Mon Jun 22 14:06:14 2009");
  }
}

/**
 * Address: 0x00874C20 (FUN_00874C20, func_SetupBasicMovieManager)
 *
 * What it does:
 * Creates the movie manager, destroying any previous one first.
 */
void moho::SetupBasicMovieManager()
{
  sMovieManager.reset(new CMovieManager());
}

/**
 * Address: 0x00874CA0 (FUN_00874CA0)
 *
 * What it does:
 * Destroys the movie manager. `CScApp::Destroy` carries this inline
 * (0x008D0F9C).
 */
void moho::DestroyMovieManagerSingleton()
{
  sMovieManager.reset();
}

/**
 * Address: 0x00874F20 (FUN_00874F20)
 *
 * What it does:
 * Clamps a script volume to [0, 2] and hands it to the movie manager, if
 * there is one. `cfunc_SetMovieVolumeL` (0x00875020) carries this inline.
 */
void moho::MOV_SetVolume(float volume)
{
  volume = std::max(std::min(kMovieVolumeScriptMax, volume), 0.0f);
  if (CMovieManager* const manager = sMovieManager.get(); manager != nullptr) {
    manager->SetVolume(volume);
  }
}

/**
 * Address: 0x00874F80 (FUN_00874F80)
 *
 * What it does:
 * Returns the movie manager's stored volume, or 1 without a manager.
 * `cfunc_GetMovieVolumeL` (0x00875180) carries this inline.
 *
 * The stored value is DirectSound attenuation (-10000..0), not the 0..2 that
 * `MOV_SetVolume` took, so `GetMovieVolume()` does not return what
 * `SetMovieVolume()` was given. That is the binary's behaviour.
 */
float moho::MOV_GetVolume()
{
  const CMovieManager* const manager = sMovieManager.get();
  return manager != nullptr ? manager->GetVolume() : 1.0f;
}

namespace
{
  /**
   * The client half of Sim_Create_exxt (FUN_0128E4AC, StartupHelpers.cpp): scans
   * the terrain heightfield for its extreme 16-bit samples, publishes the
   * map-height lanes the range and vision renderers build their rings from,
   * and initializes the active viewport's range and vision renderers.
   */
  void InitRenderersForCreatedSim(moho::Sim& sim)
  {
    // Scan the terrain heightfield for its extreme 16-bit samples.
    moho::CHeightField* const heightField = sim.mMapData->mHeightField.get();
    const std::int32_t sampleCount = heightField->height * heightField->width;
    const std::uint16_t* const samples = heightField->data;

    std::uint16_t minSample = 0xFFFFu;
    std::uint16_t maxSample = 0u;
    for (std::int32_t i = 0; i < sampleCount; ++i) {
      const std::uint16_t sample = samples[i];
      if (minSample > sample) {
        minSample = sample;
      }
      if (maxSample < sample) {
        maxSample = sample;
      }
    }

    // Binary mapping: the max-height lane is derived from the smallest sample
    // (minus a 5-unit offset) and the min-height lane from the largest sample.
    moho::patch_maxMapHeight = (static_cast<float>(minSample) * 0.0078125f) - 5.0f;
    moho::patch_minMapHeight = static_cast<float>(maxSample) * 0.0078125f;

    // Initialize the active viewport's range/vision renderers.
    if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
      if (moho::WRenViewport* const viewport = device->GetViewport(); viewport != nullptr) {
        viewport->mRangeRenderer.Init();
        viewport->mVisionRenderer.Init();
      }
    }
  }

  [[maybe_unused]] const bool gSimCreatedRenderHookSet = (moho::sSimCreatedRenderHook = &InitRenderersForCreatedSim, true);

  /** MOV_GetDuration's `sMovieManager.get() != nullptr` (StartupHelpers.cpp). */
  bool MovieManagerPresent()
  {
    return sMovieManager.get() != nullptr;
  }

  [[maybe_unused]] const bool gMovieManagerPresentSet = (moho::sMovieManagerPresent = &MovieManagerPresent, true);
} // namespace

namespace
{
  /**
   * Engine addition (dedicated-server plan WPL.4): this file's Lua binders, the
   * calls StartupHelpers.cpp's StartupHelpersLuaFunctionBootstrap made for them,
   * in the same order (see that object for why a bootstrap is needed).
   */
  struct StartupClientHelpersLuaFunctionBootstrap
  {
    StartupClientHelpersLuaFunctionBootstrap()
    {
      (void)moho::register_GetCommandLineArg_LuaFuncDef();
      (void)moho::register_HasCommandLineArg_LuaFuncDef();
      (void)moho::func_GetTextureDimensions_LuaFuncDef();
      (void)moho::func_SetMovieVolume_LuaFuncDef();
      (void)moho::func_GetMovieVolume_LuaFuncDef();
      (void)moho::func_GetAntiAliasingOptions_LuaFuncDef();
      (void)moho::func_GetOptions_LuaFuncDef();
      (void)moho::func_GetPreference_LuaFuncDef();
      (void)moho::func_SetPreference_LuaFuncDef();
      (void)moho::func_SavePreferences_LuaFuncDef();
      (void)moho::func_DebugFacilitiesEnabled_LuaFuncDef();
    }
  };

  const StartupClientHelpersLuaFunctionBootstrap gStartupClientHelpersLuaFunctionBootstrap{};
} // namespace

/**
 * Address: 0x008C8760 (FUN_008C8760, USER_SetCurrentProfile)
 * Mangled:
 * ?USER_SetCurrentProfile@Moho@@YAXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
 *
 * What it does:
 * Selects one profile by name from `profile.profiles`, updates that profile's
 * `NetName`, and sets `profile.current`; when the profile name is missing,
 * imports `/lua/user/prefs.lua` and invokes `CreateProfile(profileName)`.
 */
void moho::USER_SetCurrentProfile(const msvc8::string& profileName)
{
  try {
    IUserPrefs* const preferences = USER_GetPreferences();
    if (preferences == nullptr) {
      return;
    }

    LuaPlus::LuaObject rootPreferences = preferences->GetPreferenceTable();
    LuaPlus::LuaObject profileTable = rootPreferences.Lookup(kProfileProfilesPath);

    int selectedProfileIndex = -1;
    if (profileTable.IsTable()) {
      LuaPlus::LuaTableIterator iter(&profileTable, 1);
      while (!iter.m_isDone) {
        LuaPlus::LuaObject profileObject = iter.GetValue();
        LuaPlus::LuaObject nameObject = profileObject[kProfileNameFieldName];
        if (nameObject.IsString()) {
          const char* const candidateName = nameObject.GetString();
          if (profileName == (candidateName != nullptr ? candidateName : "")) {
            selectedProfileIndex = iter.GetKey().GetInteger();
            break;
          }
        }
        iter.Next();
      }
    }

    if (selectedProfileIndex == -1) {
      LuaPlus::LuaState* const state = USER_GetLuaState();
      LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
      LuaPlus::LuaObject createProfileFnObject = prefsModule[kCreateProfileMethodName];
      LuaPlus::LuaFunction<LuaPlus::LuaObject> createProfileFn(createProfileFnObject);
      LuaPlus::LuaObject createdProfile = createProfileFn(profileName.c_str());
      (void)createdProfile;
      return;
    }

    LuaPlus::LuaObject selectedProfile = profileTable[selectedProfileIndex];
    selectedProfile.SetString(kProfileNetNameFieldName, profileName.c_str());

    LuaPlus::LuaObject profileRoot = rootPreferences[kProfileRootKey];
    profileRoot.SetInteger(kProfileCurrentIndexKey, selectedProfileIndex);
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008CAF70 (FUN_008CAF70, func_OpenDocuments)
 *
 * What it does:
 * Ensures user documents directories exist for:
 * `<Documents>\\My Games\\<Company>\\<Product>`.
 */
void moho::USER_EnsureDocumentDirectories()
{
  wchar_t documentsPath[MAX_PATH]{};
  if (::SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath) < 0) {
    gpg::Warnf("Unable to get My Documents root");
    return;
  }

  std::wstring documentPath(documentsPath);

  const std::wstring myGamesName = gpg::STR_Utf8ToWide(
    moho::Loc(moho::USER_GetLuaState(), "<LOC Engine0020>My Games").c_str()
  );
  documentPath.append(L"\\");
  documentPath.append(myGamesName);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }

  const std::wstring companyNameWide = gpg::STR_Utf8ToWide(APP_GetCompanyName().c_str());
  documentPath.append(L"\\");
  documentPath.append(companyNameWide);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }

  const std::wstring productNameWide = gpg::STR_Utf8ToWide(APP_GetProductName().c_str());
  documentPath.append(L"\\");
  documentPath.append(productNameWide);
  if (::CreateDirectoryW(documentPath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    gpg::Warnf("Unable to create document path: %s", reinterpret_cast<const char*>(documentPath.c_str()));
  }
}

/**
 * Address: 0x008C9E20 (FUN_008C9E20)
 *
 * What it does:
 * Returns user documents path suffix:
 * `<Documents>\\My Games\\<Company>\\<Product>\\`.
 */
msvc8::string moho::USER_GetAppDocDir()
{
  msvc8::string outDir;

  wchar_t documentsPath[MAX_PATH]{};
  if (::SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath) < 0) {
    return outDir;
  }

  outDir = gpg::STR_WideToUtf8(documentsPath);
  outDir.push_back('\\');
  (void)outDir.append(moho::Loc(moho::USER_GetLuaState(), "<LOC Engine0020>My Games").view());
  outDir.push_back('\\');
  (void)outDir.append(APP_GetCompanyName().view());
  outDir.push_back('\\');
  (void)outDir.append(APP_GetProductName().view());
  outDir.push_back('\\');
  return outDir;
}

/**
 * Address: 0x008CA2D0 (FUN_008CA2D0)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "savegames\\"`.
 */
msvc8::string moho::USER_GetSaveGameDir()
{
  return USER_GetAppDocDir() + SaveGameDirName() + "\\";
}

/**
 * Address: 0x008CA3A0 (FUN_008CA3A0)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "replays\\"`.
 */
msvc8::string moho::USER_GetReplayDir()
{
  return USER_GetAppDocDir() + ReplayDirName() + "\\";
}

/**
 * Address: 0x008CA490 (FUN_008CA490)
 *
 * What it does:
 * Returns `<USER_GetAppDocDir()> + "screenshots\\"` and ensures the
 * screenshot directory exists.
 */
msvc8::string moho::USER_GetScreenshotDir()
{
  msvc8::string outDir = USER_GetAppDocDir() + ScreenshotDirName() + "\\";
  const std::wstring widePath = gpg::STR_Utf8ToWide(outDir.c_str());
  if (::CreateDirectoryW(widePath.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    throw std::runtime_error(gpg::STR_Printf("Unable to create directory %s", outDir.c_str()).to_std());
  }
  return outDir;
}

/**
 * Address: 0x008CA650 (FUN_008CA650, USER_GetSpecialFiles)
 *
 * ESpecialFileType, std::string &, std::string &,
 * std::map<std::string,std::vector<std::string>> &
 *
 * What it does:
 * Resolves the special-file directory/extension pair, ensures the root
 * folder exists, then groups profile-scoped files by profile directory.
 */
void moho::USER_GetSpecialFiles(
  const ESpecialFileType specialFileType,
  std::string& outDirectory,
  std::string& outExtension,
  msvc8::map<msvc8::string, msvc8::vector<msvc8::string>>& outFilesByProfile
)
{
  switch (specialFileType) {
    case ESpecialFileType::SaveGame:
      outDirectory = USER_GetSaveGameDir().to_std();
      outExtension = USER_GetSaveGameExt().to_std();
      break;
    case ESpecialFileType::Replay:
      outDirectory = USER_GetReplayDir().to_std();
      outExtension = USER_GetReplayExt().to_std();
      break;
    case ESpecialFileType::CampaignSave:
      outDirectory = USER_GetSaveGameDir().to_std();
      outExtension = USER_GetCampaignSaveExt().to_std();
      break;
    case ESpecialFileType::Screenshot:
    default:
      {
        ESpecialFileType reflectedType = specialFileType;
        gpg::RRef enumRef{};
        enumRef = gpg::MakeRRef<moho::ESpecialFileType>(&reflectedType);
        const msvc8::string lexical = enumRef.GetLexical();
        throw std::runtime_error(gpg::STR_Printf("Invalid special file type %s", lexical.c_str()).to_std());
      }
  }

  const std::wstring wideDirectory = gpg::STR_Utf8ToWide(outDirectory.c_str());
  if (::CreateDirectoryW(wideDirectory.c_str(), nullptr) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS) {
    throw std::runtime_error(gpg::STR_Printf("Unable to create directory %s", outDirectory.c_str()).to_std());
  }

  const std::wstring profilePattern = gpg::STR_Utf8ToWide((outDirectory + "*").c_str());
  WIN32_FIND_DATAW profileFindData{};
  const HANDLE profileFindHandle = ::FindFirstFileW(profilePattern.c_str(), &profileFindData);
  if (profileFindHandle == INVALID_HANDLE_VALUE) {
    return;
  }

  do {
    if ((profileFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0u) {
      continue;
    }

    const std::string profileName = gpg::STR_WideToUtf8(profileFindData.cFileName).to_std();
    const std::string filePattern = outDirectory + profileName + "\\*." + outExtension;
    const std::wstring wideFilePattern = gpg::STR_Utf8ToWide(filePattern.c_str());

    WIN32_FIND_DATAW fileFindData{};
    const HANDLE fileFindHandle = ::FindFirstFileW(wideFilePattern.c_str(), &fileFindData);
    if (fileFindHandle == INVALID_HANDLE_VALUE) {
      continue;
    }

    do {
      const std::string fileName = gpg::STR_WideToUtf8(fileFindData.cFileName).to_std();
      SubscriptStringToStringVectorMap(outFilesByProfile, profileName.c_str()).push_back(fileName.c_str());
    } while (::FindNextFileW(fileFindHandle, &fileFindData) != FALSE);

    if (::GetLastError() != ERROR_NO_MORE_FILES) {
      ::FindClose(fileFindHandle);
      throw std::runtime_error("Error finding files");
    }

    ::FindClose(fileFindHandle);
  } while (::FindNextFileW(profileFindHandle, &profileFindData) != FALSE);

  if (::GetLastError() != ERROR_NO_MORE_FILES) {
    ::FindClose(profileFindHandle);
    throw std::runtime_error("Error finding prefs directories");
  }

  ::FindClose(profileFindHandle);
}

/**
 * Address: 0x008C68A0 (FUN_008C68A0)
 * Mangled: ?OPTIONS_GetInt@Moho@@YAHVStrArg@gpg@@@Z
 *
 * What it does:
 * Reads one options value from `/lua/user/prefs.lua:GetOption` and returns it
 * as an integer lane.
 */
std::int32_t moho::OPTIONS_GetInt(const gpg::StrArg key)
{
  // 0x008C68C1-0x008C6939: the option is resolved through the Lua helper, not
  // read straight off the preference root - `GetOption` looks the key up
  // inside the *current profile's* `options` table. A direct
  // `IUserPrefs::GetInteger(key)` used to stand here, which searches the top
  // level of `Game.prefs` where no option key exists at all, so every engine
  // option read as 0 (and, in OPTIONS_GetString below, as "") for the whole
  // session regardless of what the player had configured.
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getOptionFnObject = prefsModule[kGetOptionMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionFn(getOptionFnObject);
    LuaPlus::LuaObject optionValue = getOptionFn(key);
    return optionValue.GetInteger();
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsGetOptionLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
    return 0;
  }
}

/**
 * Address: 0x008C69A0 (FUN_008C69A0)
 * Mangled: ?OPTIONS_GetFloat@Moho@@YAMVStrArg@gpg@@@Z
 *
 * What it does:
 * Invokes `/lua/user/prefs.lua:GetOption(key)` and returns the resulting Lua
 * value as one floating-point lane.
 */
float moho::OPTIONS_GetFloat(const gpg::StrArg key)
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getOptionFnObject = prefsModule[kGetOptionMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionFn(getOptionFnObject);
    LuaPlus::LuaObject optionValue = getOptionFn(key);
    return optionValue.GetNumber();
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsGetOptionLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
    return 0.0f;
  }
}

/**
 * Address: 0x008C6AB0 (FUN_008C6AB0)
 * Mangled:
 * ?OPTIONS_GetString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VStrArg@gpg@@@Z
 *
 * What it does:
 * Reads one options value from `/lua/user/prefs.lua:GetOption` and returns it
 * as an owned `msvc8::string`.
 */
msvc8::string moho::OPTIONS_GetString(const gpg::StrArg key)
{
  // 0x008C6AD9-0x008C6B72: same `/lua/user/prefs.lua:GetOption` bridge as
  // OPTIONS_GetInt above; the binary takes `LuaObject::GetString()` and builds
  // the result with an inlined strlen. Reading the preference root directly
  // instead (what used to be here) never finds an option key, so
  // `primary_adapter` came back empty and `CScApp` could not tell windowed
  // mode from a resolution triple - it fell through to the two-head branch
  // and built the render head at the default size no matter what the player
  // had chosen.
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getOptionFnObject = prefsModule[kGetOptionMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionFn(getOptionFnObject);
    LuaPlus::LuaObject optionValue = getOptionFn(key);
    const char* const optionText = optionValue.GetString();
    msvc8::string result;
    result.assign_owned(optionText != nullptr ? optionText : "");
    return result;
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsGetOptionLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
    msvc8::string fallback;
    fallback.assign_owned("");
    return fallback;
  }
}

/**
 * Address: 0x008C6BF0 (FUN_008C6BF0)
 * Mangled: ?OPTIONS_GetBool@Moho@@YA_NVStrArg@gpg@@@Z
 *
 * What it does:
 * Invokes `/lua/user/prefs.lua:GetOption(key)` and returns the value as one
 * boolean lane; on Lua bridge failure logs a warning and returns `false`.
 */
bool moho::OPTIONS_GetBool(const gpg::StrArg key)
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getOptionFnObject = prefsModule[kGetOptionMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getOptionFn(getOptionFnObject);
    LuaPlus::LuaObject optionValue = getOptionFn(key);
    return optionValue.GetBoolean();
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsGetOptionLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
    return false;
  }
}

/**
 * Address: 0x008C6CF0 (FUN_008C6CF0)
 * Mangled: ?OPTIONS_Apply@Moho@@YAXXZ
 *
 * What it does:
 * Invokes `/lua/options/optionslogic.lua:Apply(true)` and discards the return
 * object. Lua bridge failures are logged without aborting startup flow.
 */
void moho::OPTIONS_Apply()
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject optionsModule = SCR_Import(state, kOptionsLogicModulePath);
    LuaPlus::LuaObject applyFnObject = optionsModule[kApplyMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> applyFn(applyFnObject);
    // 0x008C6D76 `call LuaPlus__LuaFunction__Call_True_Obj`: the single
    // argument is the boolean `true` - Apply's `startup` flag. Calling it with
    // no arguments (what used to be here) made `startup` false, and
    // `/lua/options/options.lua`'s primary_adapter handler is written as
    //
    //     set = function(key, value, startup)
    //         if not startup then ConExecute("SC_PrimaryAdapter " .. value) end
    //
    // so every launch re-ran the adapter console command. In windowed mode
    // that command resizes the frame to `Windows.Main.Previous.width/height`,
    // a pair of keys nothing in the engine or in lua/ ever writes, so it fell
    // back to wnd_DefaultCreateWidth/Height and shrank the window to 1024x768
    // on startup no matter what size the player had saved.
    LuaPlus::LuaObject callResult = applyFn(true);
    (void)callResult;
  } catch (const std::exception& exception) {
    gpg::Warnf(kOptionsApplyLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C6DC0 (FUN_008C6DC0)
 * Mangled: ?OPTIONS_SetCustomData@Moho@@YAXVStrArg@gpg@@ABVLuaObject@LuaPlus@@1@Z
 *
 * What it does:
 * Invokes `/lua/options/optionslogic.lua:SetCustomData` for one option key
 * using `(customData, defaultValue)` Lua object lanes.
 */
void moho::OPTIONS_SetCustomData(
  const gpg::StrArg key,
  const LuaPlus::LuaObject& customData,
  const LuaPlus::LuaObject& defaultValue
)
{
  try {
    LuaPlus::LuaState* const state = customData.GetActiveState();
    LuaPlus::LuaObject optionsModule = SCR_Import(state, kOptionsLogicModulePath);
    LuaPlus::LuaObject setCustomDataFnObject = optionsModule[kSetCustomDataMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> setCustomDataFn(setCustomDataFnObject);
    LuaPlus::LuaObject callResult = setCustomDataFn(key, customData, defaultValue);
    (void)callResult;
  } catch (const std::exception& exception) {
    gpg::Warnf(kOptionsSetCustomDataLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C6EC0 (FUN_008C6EC0)
 * Mangled: ?OPTIONS_CreateInitialProfileIfNeeded@Moho@@YAXVStrArg@gpg@@@Z
 *
 * What it does:
 * Executes `/lua/user/prefs.lua` profile bootstrap:
 * - `ProfilesExist()`
 * - `CreateProfile(profileName)` when profiles are missing.
 */
void moho::OPTIONS_CreateInitialProfileIfNeeded(const gpg::StrArg profileName)
{
  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject profilesExistFnObject = prefsModule[kProfilesExistMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> profilesExistFn(profilesExistFnObject);
    LuaPlus::LuaObject profilesExistResult = profilesExistFn();

    if (!profilesExistResult.GetBoolean()) {
      prefsModule = SCR_Import(state, kUserPrefsModulePath);
      LuaPlus::LuaObject createProfileFnObject = prefsModule[kCreateProfileMethodName];
      LuaPlus::LuaFunction<LuaPlus::LuaObject> createProfileFn(createProfileFnObject);
      LuaPlus::LuaObject createProfileResult = createProfileFn(profileName);
      (void)createProfileResult;
    }
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }
}

/**
 * Address: 0x008C7040 (FUN_008C7040)
 * Mangled:
 * ?OPTIONS_GetCurrentProfileName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
 *
 * What it does:
 * Invokes `/lua/user/prefs.lua:GetCurrentProfile()` and returns the profile
 * `Name` field.
 */
msvc8::string moho::OPTIONS_GetCurrentProfileName()
{
  msvc8::string profileName{};
  profileName.assign_owned("");

  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    LuaPlus::LuaObject prefsModule = SCR_Import(state, kUserPrefsModulePath);
    LuaPlus::LuaObject getCurrentProfileFnObject = prefsModule[kGetCurrentProfileMethodName];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> getCurrentProfileFn(getCurrentProfileFnObject);
    LuaPlus::LuaObject currentProfileObject = getCurrentProfileFn();
    LuaPlus::LuaObject profileNameObject = currentProfileObject[kProfileNameFieldName];

    const char* const profileNameText = profileNameObject.GetString();
    profileName.assign_owned(profileNameText != nullptr ? profileNameText : "");
  } catch (const std::exception& exception) {
    gpg::Warnf(kUserPrefsLuaRunErrorPrefix, exception.what() != nullptr ? exception.what() : "");
  }

  return profileName;
}

/**
 * Address: 0x008CE2A0 (FUN_008CE2A0, func_StartCommandLineSession)
 *
 * What it does:
 * Imports `/lua/SinglePlayerLaunch.lua` and invokes
 * `StartCommandLineSession(mapName, isPerfTest)`.
 */
bool moho::StartCommandLineSession(const gpg::StrArg mapName, const bool isPerfTest)
{
  const char* const effectiveMapName = mapName != nullptr ? mapName : "";

  try {
    LuaPlus::LuaState* const state = USER_GetLuaState();
    if (state == nullptr) {
      throw std::runtime_error("USER_GetLuaState() returned null.");
    }

    const LuaPlus::LuaObject launchModule = SCR_ImportLuaModule(state, "/lua/SinglePlayerLaunch.lua");
    if (launchModule.IsNil()) {
      throw std::runtime_error("Unable to import '/lua/SinglePlayerLaunch.lua'.");
    }

    const LuaPlus::LuaObject launchFunction = SCR_GetLuaTableField(state, launchModule, "StartCommandLineSession");
    if (launchFunction.IsNil()) {
      throw std::runtime_error("Missing StartCommandLineSession Lua entrypoint.");
    }

    LuaPlus::LuaFunction<void> startCommandLineSession(launchFunction);
    startCommandLineSession(effectiveMapName, isPerfTest);
    return true;
  } catch (const std::exception& exception) {
    const msvc8::string message = gpg::STR_Printf(
      "Unable to launch %s:\n%s", effectiveMapName, exception.what() != nullptr ? exception.what() : ""
    );
    WIN_OkBox("Ack!", message.c_str());
    return false;
  } catch (...) {
    const msvc8::string message = gpg::STR_Printf("Unable to launch %s:\nunknown error", effectiveMapName);
    WIN_OkBox("Ack!", message.c_str());
    return false;
  }
}
