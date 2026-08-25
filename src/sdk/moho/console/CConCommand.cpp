#include "moho/console/CConCommand.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/animation/CAniSkel.h"
#include "moho/app/WEmitterWx.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/audio/IUserSoundManager.h"
#include "moho/client/Localization.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/console/CConFunc.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/core/Thread.h"
#include "moho/entity/Entity.h"
#include "moho/entity/UserEntity.h"
#include "moho/math/MathReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_String.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/misc/IConOutputHandler.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/RCamManager.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/CRandomStream.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UserArmy.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/IUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

namespace moho
{
  void CON_WxInputBox(void* commandArgs);
  extern bool sPathDebuggerEnabled;
  extern CWinLogTarget sLogWindowTarget;
}

namespace moho
{
  [[nodiscard]] msvc8::string ToString(const Wm3::Vec3f& value);
}

bool moho::con_TestVarBool = false;
int moho::con_TestVar = 0;
std::uint8_t moho::con_TestVarUByte = 0;
float moho::con_TestVarFloat = 0.0f;
msvc8::string moho::con_TestVarStr;
bool moho::snd_ExtraDoWorkCalls = false;
int moho::recon_debug = 0;
bool moho::sPathDebuggerEnabled = false;
int moho::rule_Paranoid = 0;
float moho::rule_BlueprintReloadDelay = 0.0f;

// Issue-thread pacing convars, read by `CSimDriver::ThreadRun`. `net_Lag` is
// subtracted from how far ahead of the last executed beat the thread is
// willing to run, so raising it issues beats earlier; the debug level gates
// the thread's running/waiting/exiting trace.
int moho::sim_IssueThreadDebugLevel = 0;
float moho::net_Lag = 0.0f;

// AI economy tuning convars referenced by `moho::CEconomy::Reset`. The
// console-startup registration (FUN_00BC8DC0 / FUN_00BC8DE0 family) wires
// these up as `TConVar<float>` instances at static-init time; the storage
// definitions live here alongside the other engine convars. Initial values
// mirror the binary's seed (0.0f at definition; engine config overrides at
// startup before any `Sim` ticks consume them).
float moho::ai_InitialEnergyCurrency = 0.0f;
float moho::ai_InitialMassCurrency = 0.0f;
float moho::ai_InitialEnergyCurrencyMax = 0.0f;
float moho::ai_InitialMassCurrencyMax = 0.0f;

namespace
{
  constexpr std::size_t kSavedConsoleCommandLimit = 0x64u;
  constexpr const char* kConTextMatchesHelpText = "strings ContextMatches(string)";
  constexpr const char* kConExecuteHelpText = "ConExecute('command string') -- Perform a console command";
  constexpr const char* kConExecuteSaveHelpText =
    "ConExecuteSave('command string') -- Perform a console command, saved to stack";
  constexpr const char* kNoSessionLocToken = "<LOC _No_session>";
  constexpr const char* kUIRenameSelectionRequiredLocToken =
    "<LOC Engine0024>You must have a unit selected to rename.";
  constexpr const char* kUIRenameSingleSelectionLocToken =
    "<LOC Engine0025>You may only name one unit at a time, please limit your selection to one unit.";
  constexpr const char* kRenameUnitSelectionRequiredLocToken =
    "<LOC Engine0021>You must have a unit selected to name it.";
  constexpr const char* kRenameUnitSingleSelectionLocToken =
    "<LOC Engine0022>Naming a unit requires you only have one unit selected.";
  constexpr const char* kRenameUnitNoCustomNameLocToken = "<LOC Engine0023>Unit has no custom name";
  constexpr const char* kRenameUnitInfoKey = "CustomName";
  constexpr const char* kRenameUnitPrintFormat = "Unit name: %s";
  constexpr const char* kCreateUnitInvalidArmyFormat = "Invalid army index (%d) -- must be less than %d";
  constexpr const char* kCreateUnitWorldCameraName = "WorldCamera";
  constexpr const char* kCreateUnitErrorSoundBank = "Interface";
  constexpr const char* kCreateUnitErrorSoundCue = "UI_Menu_Error_01";
  constexpr const char* kPlaceholderPropBlueprintPath = "/props/rplaceholder/rplaceholder_prop";
  constexpr int kLotsOfPropsDefaultCount = 100;
  constexpr const char* kUIMakeSelectionSetUsageText =
    "USAGE: UI_MakeSelectionSet [name] - create a named selection set based on the current selection";
  constexpr const char* kUIApplySelectionSetUsageText =
    "USAGE: UI_ApplySelectionSet [name] - apply a named selections et";
  constexpr const char* kPathDebuggerModulePath = "/lua/debug/pathdebugger.lua";
  constexpr const char* kPathDebuggerLoadErrorText = "failed to load \"/lua/debug/pathdebugger.lua\" module";
  constexpr const char* kPathDebuggerCreateUiMethodName = "CreateUI";
  constexpr const char* kPathDebuggerDestroyUiMethodName = "DestroyUI";
  constexpr const char* kConsoleStartupSkipUIChecksDescription = "Don't perform any command validation in UI";
  constexpr const char* kConsoleStartupWLDRestartBeatDescription = "Restart rendering the current beat.";
  constexpr const char* kConsoleStartupWLDAdvanceBeatDescription = "Advance the sim one beat.";
  constexpr const char* kConsoleStartupWLDSingleStepDescription = "Single-step the sim one tick.";
  constexpr const char* kConsoleStartupWLDGameSpeedDescription = "Set a new game speed";
  constexpr const char* kConsoleStartupConFindUnitDescription =
    "Find a unit by a (case insensitive) string contained in its description.";
  constexpr const char* kConsoleStartupSCLuaDebuggerDescription = "Open Lua debugger window";
  constexpr const char* kConsoleStartupDoSimCommandDescription = "do a sim command.";

  msvc8::vector<msvc8::string> gSavedConsoleCommands;

  /**
   * Address: 0x0041FA70 (FUN_0041FA70, ??0ConVar_con_TestVarUByte@Moho@@QAE@@Z)
   *
   * What it does:
   * Registers legacy test uint8 console variable (`con_TestVarUByte`).
   */
  struct ConVar_con_TestVarUByte
  {
    ConVar_con_TestVarUByte() noexcept
      : mConVar("con_TestVarUByte", "Test variable - not used.", &moho::con_TestVarUByte)
    {
      RegisterConCommand(mConVar);
    }

    moho::TConVar<std::uint8_t> mConVar;
  };

  alignas(ConVar_con_TestVarUByte) std::byte gConVar_con_TestVarUByteStorage[sizeof(ConVar_con_TestVarUByte)]{};

  [[nodiscard]] ConVar_con_TestVarUByte& StartupConVar_con_TestVarUByte() noexcept
  {
    return *reinterpret_cast<ConVar_con_TestVarUByte*>(gConVar_con_TestVarUByteStorage);
  }

  struct ConCommandArgsWireView
  {
    void* vftable;
    msvc8::string* begin;
    msvc8::string* end;
    msvc8::string* cap;
  };

  struct CameraImplDumpRuntimeView
  {
    std::uint8_t mUnknown00To343[0x344]{};
    float mFarPitch = 0.0f; // +0x344
    std::uint8_t mUnknown348To34B[0x4]{};
    float mHeading = 0.0f; // +0x34C
    std::uint8_t mUnknown350To353[0x4]{};
    float mTargetZoom = 0.0f; // +0x354
    std::uint8_t mUnknown358To37F[0x28]{};
    Wm3::Vec3f mTargetLocation{}; // +0x380

    [[nodiscard]] static const CameraImplDumpRuntimeView* FromCamera(const moho::CameraImpl* const camera) noexcept
    {
      return reinterpret_cast<const CameraImplDumpRuntimeView*>(camera);
    }
  };

  static_assert(
    offsetof(CameraImplDumpRuntimeView, mFarPitch) == 0x344,
    "CameraImplDumpRuntimeView::mFarPitch offset must be 0x344"
  );
  static_assert(
    offsetof(CameraImplDumpRuntimeView, mHeading) == 0x34C,
    "CameraImplDumpRuntimeView::mHeading offset must be 0x34C"
  );
  static_assert(
    offsetof(CameraImplDumpRuntimeView, mTargetZoom) == 0x354,
    "CameraImplDumpRuntimeView::mTargetZoom offset must be 0x354"
  );
  static_assert(
    offsetof(CameraImplDumpRuntimeView, mTargetLocation) == 0x380,
    "CameraImplDumpRuntimeView::mTargetLocation offset must be 0x380"
  );

  struct WWinLogWindowVisibilityRuntimeView
  {
    std::uint8_t mUnknown00ToCB[0xCC]{};
    std::uint8_t mBitfields = 0;

    [[nodiscard]] bool IsShown() const noexcept
    {
      return (mBitfields & 0x02u) != 0u;
    }
  };

  static_assert(
    offsetof(WWinLogWindowVisibilityRuntimeView, mBitfields) == 0xCC,
    "WWinLogWindowVisibilityRuntimeView::mBitfields offset must be 0xCC"
  );

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
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

  [[nodiscard]]
  bool TokenEq(const msvc8::string* token, const std::string_view text) noexcept
  {
    return token != nullptr && token->view() == text;
  }

  [[nodiscard]]
  bool TokenEqNoCase(const msvc8::string* token, const char* text) noexcept
  {
    return token != nullptr && token->equals_no_case(text);
  }

  [[nodiscard]]
  const char* TokenDataOrEmpty(const msvc8::string* token) noexcept
  {
    return token != nullptr ? token->c_str() : "";
  }

  [[nodiscard]]
  int ParseIntToken(const msvc8::string* token) noexcept
  {
    return std::atoi(TokenDataOrEmpty(token));
  }

  [[nodiscard]]
  std::uint32_t ParseUInt32Token(const msvc8::string* token) noexcept
  {
    return static_cast<std::uint32_t>(gpg::STR_ParseUInt32(TokenDataOrEmpty(token)));
  }

  [[nodiscard]]
  float ParseFloatToken(const msvc8::string* token) noexcept
  {
    return static_cast<float>(std::atof(TokenDataOrEmpty(token)));
  }

  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const userUnit) noexcept
  {
    return userUnit ? static_cast<IUnit*>(userUnit) : nullptr;
  }

  [[nodiscard]] UserEntity* ResolveUserEntityView(UserUnit* const userUnit) noexcept
  {
    return reinterpret_cast<UserEntity*>(userUnit);
  }

  /**
   * The session's terrain map header. Every console command that needs it walks
   * the same two hops the binary does (`mWldMap` -> `mTerrainRes` -> the
   * terrain-owned `STIMap`); the recovered `IWldTerrainRes` types that lane as
   * `mPlayableRectSource`, which is the same word.
   */
  [[nodiscard]] const STIMap* ResolveSessionTerrainMap(const CWldSession* const session) noexcept
  {
    return reinterpret_cast<const STIMap*>(session->mWldMap->mTerrainRes->mPlayableRectSource);
  }

  /**
   * `UserUnit::GetCustomName` (vtable slot +0x60) hands back the address of the
   * unit's in-object custom-name storage; the recovered declaration types that
   * anchor as `char*`, but the binary reads it as an `msvc8::string` (it tests
   * `+0x14` for the size and picks the SSO buffer or heap pointer off `+0x04`).
   * Recover the string the engine actually reads through.
   */
  [[nodiscard]] const msvc8::string& CustomNameStorage(UserUnit* const userUnit) noexcept
  {
    return *reinterpret_cast<const msvc8::string*>(userUnit->GetCustomName());
  }

  /**
   * One uniformly distributed index in `[0, extent)` drawn from the process
   * global Mersenne stream under `math_GlobalRandomMutex`.
   *
   * The binary inlines the twister extraction and scales it with a 32x32->64
   * `mul` keeping only the high dword, which is the classic bias-free
   * multiply-shift bucketing rather than a modulo - preserved verbatim here
   * because the bucket boundaries (and therefore the spawn pattern) differ from
   * `%`.
   */
  [[nodiscard]] std::uint32_t RandomIndexBelowExtent(const std::uint32_t extent)
  {
    boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
    const std::uint64_t sample = math_GlobalRandomStream.twister.NextUInt32();
    return static_cast<std::uint32_t>((sample * static_cast<std::uint64_t>(extent)) >> 32);
  }

  void PrintLocalizedConsoleLine(const char* const locToken)
  {
    const msvc8::string localizedText = Loc(USER_GetLuaState(), locToken != nullptr ? locToken : "");
    CON_Printf("%s", localizedText.c_str());
  }

  /**
   * Address: 0x0083EAF0 (FUN_0083EAF0)
   *
   * What it does:
   * Imports `/lua/ui/game/rename.lua` and invokes
   * `ShowRenameDialog(currentName)` while in `UIS_game`.
   */
  void ShowRenameDialogLua(const char* const currentName)
  {
    if (sUIState != UIS_game) {
      return;
    }

    CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
    LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
    if (state == nullptr) {
      return;
    }

    try {
      LuaPlus::LuaObject renameModule = SCR_Import(state, "/lua/ui/game/rename.lua");
      LuaPlus::LuaObject showRenameDialogObject = renameModule["ShowRenameDialog"];
      LuaPlus::LuaFunction<void> showRenameDialogFn(showRenameDialogObject);
      showRenameDialogFn(currentName != nullptr ? currentName : "");
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/rename.lua: %s",
        exception.what() != nullptr ? exception.what() : ""
      );
    }
  }

  /**
   * Address: 0x0047BB90 (FUN_0047BB90, func_AppendStrings)
   *
   * What it does:
   * Resets output string, appends first string in `[begin,end)`, then appends
   * `separator` + each subsequent item.
   */
  [[nodiscard]]
  msvc8::string AppendJoinedStringRange(
    const msvc8::string* const begin, const msvc8::string* const end, const char* separator
  )
  {
    std::string joined;
    if (separator == nullptr) {
      separator = "";
    }

    if (begin != nullptr && end != nullptr && begin < end) {
      joined.append(begin->view());
      for (const msvc8::string* cursor = begin + 1; cursor < end; ++cursor) {
        joined.append(separator);
        joined.append(cursor->view());
      }
    }

    msvc8::string out;
    out.assign_owned(joined);
    return out;
  }

  struct LowercasedCopyResult
  {
    char* begin;
    char* end;
  };

  /// The screen point `CON_CreateUnit` last projected through the world camera.
  /// Repeating the same point makes the command fall back to the live cursor
  /// world position instead of re-projecting.
  Wm3::Vector2f lastMouseScreenPos{};
  static_assert(sizeof(Wm3::Vector2f) == 0x8, "Wm3::Vector2f size must be 0x8");

  /**
   * Address: 0x00835C80 (FUN_00835C80, cmp_LastMouseScreenPos)
   *
   * What it does:
   * Byte-compares one screen-space cursor point against the cached
   * create-unit cursor point and returns `-1`, `0`, or `1`.
   */
  [[nodiscard]]
  int cmp_LastMouseScreenPos(const Wm3::Vector2f& mouseScreenPos) noexcept
  {
    const int rawCompare = std::memcmp(&mouseScreenPos, &lastMouseScreenPos, sizeof(Wm3::Vector2f));
    if (rawCompare > 0) {
      return 1;
    }
    if (rawCompare < 0) {
      return -1;
    }
    return 0;
  }

  /**
   * Address: 0x00835D10 (FUN_00835D10, func_tolower)
   *
   * What it does:
   * Copies one byte range into an output buffer while lowercasing each source
   * byte.
   * Returns the original output begin and the advanced output cursor.
   */
  [[nodiscard]]
  LowercasedCopyResult CopyLowercasedRange(char* outputBegin, const char* inputBegin, const char* inputEnd) noexcept
  {
    char* outputCursor = outputBegin;
    for (const char* inputCursor = inputBegin; inputCursor != inputEnd; ++inputCursor) {
      *outputCursor++ = static_cast<char>(std::tolower(static_cast<unsigned char>(*inputCursor)));
    }

    return {outputBegin, outputCursor};
  }

  /**
   * Address: 0x00835AF0 (FUN_00835AF0)
   *
   * What it does:
   * Writes one lowercased copy result into caller-provided result storage and
   * returns that same storage slot.
   */
  [[maybe_unused]]
  [[nodiscard]]
  LowercasedCopyResult* CopyLowercasedRangeIntoOutSlot(
    LowercasedCopyResult* const outResult,
    char* const outputBegin,
    const char* const inputBegin,
    const char* const inputEnd
  ) noexcept
  {
    if (outResult != nullptr) {
      *outResult = CopyLowercasedRange(outputBegin, inputBegin, inputEnd);
    }
    return outResult;
  }

  [[nodiscard]]
  msvc8::string JoinConCommandTokens(const ConCommandArgsView& args, const std::size_t firstTokenIndex)
  {
    if (args.begin == nullptr || args.end == nullptr || args.end < args.begin) {
      return {};
    }

    const std::size_t count = args.Count();
    if (firstTokenIndex >= count) {
      return {};
    }

    const msvc8::string* const start = args.begin + firstTokenIndex;
    return AppendJoinedStringRange(start, args.end, " ");
  }

  template <typename TValue, typename ParseFn>
  void ApplyIntegralConVarCommand(const ConCommandArgsView& args, TValue* value, ParseFn parseFn)
  {
    if (value == nullptr) {
      return;
    }

    const msvc8::string* const op = args.At(1);
    const msvc8::string* const rhs = args.At(2);

    if (TokenEq(op, "=") && rhs != nullptr) {
      *value = static_cast<TValue>(parseFn(rhs));
      return;
    }
    if (TokenEq(op, "+=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value + static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "-=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value - static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "*=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value * static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "/=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value / static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "%=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value % static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "&=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value & static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "|=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value | static_cast<TValue>(parseFn(rhs)));
      return;
    }
    if (TokenEq(op, "^=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value ^ static_cast<TValue>(parseFn(rhs)));
      return;
    }

    if (TokenEqNoCase(op, "on") || TokenEqNoCase(op, "true")) {
      *value = static_cast<TValue>(1);
      return;
    }
    if (TokenEqNoCase(op, "off") || TokenEqNoCase(op, "false")) {
      *value = static_cast<TValue>(0);
      return;
    }
    if (TokenEqNoCase(op, "tog")) {
      *value = static_cast<TValue>((*value == static_cast<TValue>(0)) ? 1 : 0);
      return;
    }

    if (op != nullptr) {
      *value = static_cast<TValue>(parseFn(op));
    }
  }

  /**
   * Address: 0x0041D470 (FUN_0041D470, sub_41D470)
   * Address: 0x1001CB40 (FUN_1001CB40)
   *
   * What it does:
   * Parses bool convar commands (`=`, on/off/true/false/show/tog, numeric fallback).
   */
  void HandleBoolConVarCommand(const ConCommandArgsView& args, const char* name, bool* value)
  {
    if (value == nullptr) {
      return;
    }

    if (args.Count() < 2) {
      *value = !*value;
      gpg::Logf("toggled %s is now %s", name ? name : "", *value ? "on" : "off");
      return;
    }

    const msvc8::string* const op = args.At(1);
    const msvc8::string* const rhs = args.At(2);

    if (TokenEq(op, "=") && rhs != nullptr) {
      *value = ParseIntToken(rhs) != 0;
      return;
    }
    if (TokenEqNoCase(op, "on") || TokenEqNoCase(op, "true")) {
      *value = true;
      return;
    }
    if (TokenEqNoCase(op, "off") || TokenEqNoCase(op, "false")) {
      *value = false;
      return;
    }
    if (TokenEqNoCase(op, "show")) {
      gpg::Logf("bool %s is %s", name ? name : "", *value ? "on" : "off");
      return;
    }
    if (TokenEqNoCase(op, "tog")) {
      *value = !*value;
      return;
    }

    *value = ParseIntToken(op) != 0;
  }

  /**
   * Address: 0x0041D660 (FUN_0041D660, sub_41D660)
   * Address: 0x1001CD20 (FUN_1001CD20)
   *
   * What it does:
   * Parses int convar commands with arithmetic/bitwise operators and aliases.
   */
  void HandleIntConVarCommand(const ConCommandArgsView& args, int* value)
  {
    ApplyIntegralConVarCommand<int>(args, value, ParseIntToken);
  }

  /**
   * Address: 0x0041DD90 (FUN_0041DD90, sub_41DD90)
   * Address: 0x1001D420 (FUN_1001D420)
   *
   * What it does:
   * Parses uint8 convar commands with arithmetic/bitwise operators and aliases.
   */
  void HandleUInt8ConVarCommand(const ConCommandArgsView& args, std::uint8_t* value)
  {
    ApplyIntegralConVarCommand<std::uint8_t>(args, value, ParseIntToken);
  }

  /**
   * Address: 0x0041D9E0 (FUN_0041D9E0, func_ConProcessUintArgs)
   * Address: 0x103C8880 -> 0x1001D0C0 (FUN_1001D0C0 parser helper)
   *
   * What it does:
   * Parses uint32 convar commands; supports decimal and `0x` numeric formats.
   */
  void HandleUInt32ConVarCommand(const ConCommandArgsView& args, std::uint32_t* value)
  {
    ApplyIntegralConVarCommand<std::uint32_t>(args, value, ParseUInt32Token);
  }

  /**
   * Address: 0x0041E100 (FUN_0041E100, Moho::CON_ChangeFloatFromArgs)
   * Address: 0x1001D7C0 (FUN_1001D7C0)
   *
   * What it does:
   * Parses float convar commands (`=`, `+=`, `-=`, `*=`, `/=`, direct numeric).
   */
  void HandleFloatConVarCommand(const ConCommandArgsView& args, float* value)
  {
    if (value == nullptr) {
      return;
    }

    const msvc8::string* const op = args.At(1);
    const msvc8::string* const rhs = args.At(2);

    if (TokenEq(op, "=") && rhs != nullptr) {
      *value = ParseFloatToken(rhs);
      return;
    }
    if (TokenEq(op, "+=") && rhs != nullptr) {
      *value += ParseFloatToken(rhs);
      return;
    }
    if (TokenEq(op, "-=") && rhs != nullptr) {
      *value -= ParseFloatToken(rhs);
      return;
    }
    if (TokenEq(op, "*=") && rhs != nullptr) {
      *value *= ParseFloatToken(rhs);
      return;
    }
    if (TokenEq(op, "/=") && rhs != nullptr) {
      *value /= ParseFloatToken(rhs);
      return;
    }

    *value = ParseFloatToken(op);
  }

  /**
   * Address: 0x0041E290 (FUN_0041E290, sub_41E290)
   * Address: 0x1001D960 (FUN_1001D960)
   *
   * What it does:
   * Parses string convar commands (`= value` or direct assignment); prints current value when no args.
   */
  void HandleStringConVarCommand(const ConCommandArgsView& args, const char* name, msvc8::string* value)
  {
    if (value == nullptr) {
      return;
    }

    if (args.Count() >= 2) {
      const msvc8::string* const op = args.At(1);
      const msvc8::string* const rhs = args.At(2);

      if (TokenEq(op, "=") && rhs != nullptr) {
        *value = TokenDataOrEmpty(rhs);
      } else {
        *value = TokenDataOrEmpty(op);
      }
      return;
    }

    gpg::Logf("string %s == %s", name ? name : "", value->c_str());
  }

  struct ConsoleCommandNameLess
  {
    [[nodiscard]]
    bool operator()(const std::string& lhs, const std::string& rhs) const noexcept
    {
      return _stricmp(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  using ConsoleCommandMap = std::map<std::string, CConCommand*, ConsoleCommandNameLess>;

  struct ConsoleCommandRegistry
  {
    ConsoleCommandMap commandsByName;
    std::mutex lock;
  };

  /**
   * Address: 0x0041BEB0 (FUN_0041BEB0)
   * Address: 0x00420370 (FUN_00420370, sub_420370)
   * Address: 0x004204C0 (FUN_004204C0, sub_4204C0)
   * Address: 0x00420630 (FUN_00420630, sub_420630)
   * Address: 0x00420650 (FUN_00420650, sub_420650)
   *
   * What it does:
   * Returns the process-global command-name map.
   */
  ConsoleCommandRegistry& GetConsoleCommandRegistry()
  {
    static ConsoleCommandRegistry sRegistry;
    return sRegistry;
  }

  [[nodiscard]]
  std::string ToStdName(const char* const name)
  {
    return (name == nullptr) ? std::string{} : std::string{name};
  }

  [[nodiscard]]
  std::string ToStdName(const std::string_view name)
  {
    return std::string{name};
  }

  /**
   * Address: 0x0041FF10 (FUN_0041FF10, std::map_string_CConCommand::_Lbound)
   *
   * What it does:
   * Returns the first command-map node whose key compares >= target using the
   * case-insensitive command-name comparator.
   */
  [[nodiscard]]
  ConsoleCommandMap::const_iterator LowerBoundCommandByName(
    const ConsoleCommandMap& commandsByName, const std::string_view commandName
  )
  {
    return commandsByName.lower_bound(ToStdName(commandName));
  }

  /**
    * Alias of FUN_004203D0 (non-canonical helper lane).
   *
   * What it does:
   * Moves one command-map iterator to the next in-order entry.
   */
  template <typename TIter>
  void AdvanceCommandIterator(TIter& it)
  {
    ++it;
  }

  [[nodiscard]]
  bool IsConsoleWhitespace(const char ch) noexcept
  {
    return ch == ' ' || ch == '\t';
  }

  void PushTokenFromRange(
    const std::string& text,
    const std::size_t begin,
    const std::size_t end,
    msvc8::vector<msvc8::string>& outTokens
  )
  {
    if (begin == std::string::npos || end < begin) {
      return;
    }

    const std::size_t len = end - begin;
    outTokens.push_back(msvc8::string(text.data() + begin, len));
  }

  void ParseCommandLine(
    const char* const commandText, msvc8::vector<msvc8::string>& tokens, msvc8::string& remainder
  )
  {
    tokens.clear();
    remainder.clear();

    if (commandText == nullptr || commandText[0] == '\0') {
      return;
    }

    std::string text(commandText);
    bool inQuotes = false;
    int tokenStart = -1;
    std::size_t tokenEnd = text.size();

    for (std::size_t index = 0; index < text.size(); ++index) {
      const char ch = text[index];

      if (inQuotes) {
        if (ch == '"') {
          PushTokenFromRange(text, static_cast<std::size_t>(tokenStart), index, tokens);
          tokenStart = -1;
          inQuotes = false;
          continue;
        }

        if (ch == '\\' && index + 1 < text.size() && (text[index + 1] == '"' || text[index + 1] == '\\')) {
          text.erase(index, 1);
          continue;
        }

        continue;
      }

      if (ch == '#') {
        tokenEnd = index;
        break;
      }

      if (ch == ';') {
        tokenEnd = index;
        if (index + 1 < text.size()) {
          remainder = msvc8::string(text.c_str() + index + 1, text.size() - (index + 1));
        }
        break;
      }

      if (ch == '/' && index + 1 < text.size() && text[index + 1] == '/') {
        tokenEnd = index;
        break;
      }

      if (IsConsoleWhitespace(ch)) {
        if (tokenStart != -1) {
          PushTokenFromRange(text, static_cast<std::size_t>(tokenStart), index, tokens);
          tokenStart = -1;
        }
        continue;
      }

      if (tokenStart == -1) {
        tokenStart = static_cast<int>(index);

        if (ch == '"') {
          inQuotes = true;
          tokenStart = static_cast<int>(index + 1);
          continue;
        }

        if (ch == '\\' && index + 1 < text.size() && text[index + 1] == '"') {
          text.erase(index, 1);
          continue;
        }
      }
    }

    if (tokenStart != -1) {
      PushTokenFromRange(text, static_cast<std::size_t>(tokenStart), tokenEnd, tokens);
    }
  }

  /**
   * Address: 0x0041C400 (FUN_0041C400, func_Stringify)
   *
   * What it does:
   * Builds a quoted token and escapes embedded `"` and `\\`.
   */
  [[nodiscard]]
  msvc8::string StringifyToken(const msvc8::string& token)
  {
    std::string out;
    out.reserve(token.size() + 2);
    out.push_back('"');

    for (const char ch : token.view()) {
      if (ch == '"' || ch == '\\') {
        out.push_back('\\');
      }
      out.push_back(ch);
    }

    out.push_back('"');
    return msvc8::string(out.data(), out.size());
  }

  [[nodiscard]]
  bool TokenNeedsStringify(const msvc8::string& token) noexcept
  {
    const std::string_view text = token.view();
    if (text.empty()) {
      return true;
    }
    if (text.find("//") != std::string_view::npos) {
      return true;
    }
    return text.find_first_of("#; \t\"") != std::string_view::npos;
  }

  /**
   * Address: 0x0041CC60 (FUN_0041CC60, func_DecStringChars)
   *
   * What it does:
   * Decrements each character in-place by one.
   */
  void DecStringChars(msvc8::string& text)
  {
    std::string decoded = text.to_std();
    for (char& ch : decoded) {
      --ch;
    }
    text = msvc8::string(decoded.data(), decoded.size());
  }

  /**
   * Address: 0x0041C910 (FUN_0041C910, func_OutputToConHandlers)
   *
   * What it does:
   * Dispatches one formatted console line to each registered output handler.
   */
  void OutputToConHandlers(const msvc8::string& line)
  {
    for (IConOutputHandler* handler : CON_GetOutputHandlers()) {
      if (handler != nullptr) {
        handler->Handle(line.c_str());
      }
    }
  }

  /**
   * Address: 0x0041F7B0 (FUN_0041F7B0, std::map_string_CConCommand::find)
   * Address: 0x0041E360 (FUN_0041E360, sub_41E360)
   *
   * What it does:
   * Finds one command in the command map by case-insensitive key.
   */
  [[nodiscard]]
  CConCommand* FindCommandInMap(const ConsoleCommandMap& commandsByName, const std::string_view commandName)
  {
    const std::string key = ToStdName(commandName);
    const auto it = LowerBoundCommandByName(commandsByName, key);
    if (it == commandsByName.end()) {
      return nullptr;
    }

    if (_stricmp(it->first.c_str(), key.c_str()) != 0) {
      return nullptr;
    }

    return it->second;
  }

  /**
   * Address: 0x0041F390 (FUN_0041F390, sub_41F390)
   * Address: 0x0041FD60 (FUN_0041FD60, map insertion + rebalance internals)
   *
   * What it does:
   * Inserts command by case-insensitive key when absent; reports duplicates.
   */
  void InsertCommandByName(ConsoleCommandMap& commandsByName, CConCommand& command)
  {
    const std::string key = ToStdName(command.mName);
    if (key.empty()) {
      return;
    }

    const auto [it, inserted] = commandsByName.emplace(key, &command);
    if (inserted) {
      return;
    }

    if (it->second == nullptr) {
      it->second = &command;
      return;
    }

    gpg::Warnf("Duplicate definition of console command \"%s\"", command.mName ? command.mName : "");
  }

  /**
   * Address: 0x0041F190 (FUN_0041F190, sub_41F190)
   *
   * What it does:
   * Copies one `vector<string>` lane into another.
   */
  msvc8::vector<msvc8::string>& CopyStringVector(
    msvc8::vector<msvc8::string>& dst, const msvc8::vector<msvc8::string>& src
  )
  {
    dst.clear();
    for (const msvc8::string& token : src) {
      dst.push_back(token);
    }
    return dst;
  }

  [[nodiscard]]
  CConCommand* FindRegisteredConCommand(const std::string_view commandName)
  {
    auto& registry = GetConsoleCommandRegistry();
    std::scoped_lock lock{registry.lock};
    return FindCommandInMap(registry.commandsByName, commandName);
  }
} // namespace

std::size_t moho::ConCommandArgsView::Count() const noexcept
{
  if (begin == nullptr || end == nullptr || end < begin) {
    return 0;
  }

  return static_cast<std::size_t>(end - begin);
}

const msvc8::string* moho::ConCommandArgsView::At(const std::size_t index) const noexcept
{
  const auto count = Count();
  if (index >= count) {
    return nullptr;
  }

  return begin + index;
}

moho::ConCommandArgsView moho::GetConCommandArgsView(const void* commandArgs) noexcept
{
  if (commandArgs == nullptr) {
    return {};
  }

  const auto& raw = *static_cast<const ConCommandArgsWireView*>(commandArgs);
  return {raw.begin, raw.end};
}

/**
 * Address: 0x0041E580 (FUN_0041E580)
 *
 * const char* name, const char* description
 *
 * What it does:
 * Initializes base command metadata and auto-registers when name is present.
 */
moho::CConCommand::CConCommand(const char* const name, const char* const description) noexcept
  : mName(name)
  , mDescription(description)
  , mHandlerOrValue(0u)
{
  if (mName != nullptr) {
    RegisterConCommand(*this);
  }
}

/**
 * Address: 0x0041E390 (FUN_0041E390)
 *
 * What it does:
 * Registers one command by exact key and warns on duplicate definitions.
 */
void moho::RegisterConCommand(CConCommand& command)
{
  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};
  InsertCommandByName(registry.commandsByName, command);
}

/**
 * Address: 0x0041E4E0 (FUN_0041E4E0)
 *
 * What it does:
 * Removes one command from the global map and warns when the key is unknown.
 */
void moho::UnregisterConCommand(CConCommand& command)
{
  const std::string key = ToStdName(command.mName);
  if (key.empty()) {
    return;
  }

  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};

  const auto it = registry.commandsByName.find(key);
  if (it == registry.commandsByName.end()) {
    gpg::Warnf("Deregistering an unknown console command: \"%s\"", command.mName ? command.mName : "");
    return;
  }

  registry.commandsByName.erase(it);
}

/**
 * Address: 0x0041E5A0 (FUN_0041E5A0)
 *
 * What it does:
 * Base teardown helper that unregisters command metadata when name is set.
 */
void moho::TeardownConCommandRegistration(CConCommand& command)
{
  if (command.mName != nullptr) {
    UnregisterConCommand(command);
  }
}

/**
 * Address: 0x0041BFF0 (FUN_0041BFF0, ?CON_ParseCommand@Moho@@YAXVStrArg@gpg@@AAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@AAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@5@@Z)
 * Address: 0x00420E30 (FUN_00420E30, sub_420E30 helper lane)
 *
 * What it does:
 * Parses one console command lane into tokens and remainder text.
 */
void moho::CON_ParseCommand(
  const char* const commandText, msvc8::vector<msvc8::string>& tokens, msvc8::string& remainder
)
{
  ParseCommandLine(commandText, tokens, remainder);
}

/**
 * Address: 0x0041C4D0 (FUN_0041C4D0, ?CON_UnparseCommand@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@3@@Z)
 *
 * What it does:
 * Rebuilds one command string from parsed tokens with quote escaping.
 */
msvc8::string moho::CON_UnparseCommand(const msvc8::vector<msvc8::string>& tokens)
{
  std::string out;
  for (std::size_t index = 0; index < tokens.size(); ++index) {
    if (index != 0u) {
      out.push_back(' ');
    }

    const msvc8::string& token = tokens[index];
    if (TokenNeedsStringify(token)) {
      const msvc8::string escaped = StringifyToken(token);
      out.append(escaped.view());
    } else {
      out.append(token.view());
    }
  }

  return msvc8::string(out.data(), out.size());
}

/**
 * Address: 0x0041C600 (FUN_0041C600, ?CON_GetCommandList@Moho@@YAXAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z)
 * Address: 0x004203D0 (FUN_004203D0, std::map_string_CConCommand::Iterator::inc)
 * Address: 0x007E42F0 (FUN_007E42F0)
 * Address: 0x00592FE0 (FUN_00592FE0)
 * Address: 0x0052EEC0 (FUN_0052EEC0)
 * Address: 0x00531C90 (FUN_00531C90)
 * Address: 0x00531CE0 (FUN_00531CE0)
 *
 * What it does:
 * Appends command listing text into `outText`.
 */
void moho::CON_GetCommandList(msvc8::string& outText, const bool includeDescriptions)
{
  std::string merged = outText.to_std();

  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};

  if (includeDescriptions) {
    merged.append(
      gpg::STR_Printf("%d console commands available:\n", static_cast<int>(registry.commandsByName.size())).view()
    );
  }

  for (
    auto it = registry.commandsByName.begin(); it != registry.commandsByName.end(); AdvanceCommandIterator(it)
  ) {
    const auto& [name, command] = *it;
    (void)name;
    if (command == nullptr) {
      continue;
    }

    if (includeDescriptions) {
      merged.append(
        gpg::STR_Printf("  %s - %s\n", command->mName ? command->mName : "", command->mDescription ? command->mDescription : "")
          .view()
      );
    } else {
      merged.append(gpg::STR_Printf("%s\n", command->mName ? command->mName : "").view());
    }
  }

  outText = msvc8::string(merged.data(), merged.size());
}

/**
 * Address: 0x0041C770 (FUN_0041C770, ?CON_GetFindTextMatches@Moho@@YA?BV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PBD@Z)
  * Alias of FUN_0041FF10 (non-canonical helper lane).
  * Alias of FUN_004203D0 (non-canonical helper lane).
 *
 * What it does:
 * Returns command names starting with `prefix` (case-insensitive).
 */
msvc8::vector<msvc8::string> moho::CON_GetFindTextMatches(const char* const prefix)
{
  msvc8::vector<msvc8::string> matches;
  if (prefix == nullptr || prefix[0] == '\0') {
    return matches;
  }

  const std::string needle(prefix);
  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};

  auto it = LowerBoundCommandByName(registry.commandsByName, needle);
  const std::size_t needleSize = needle.size();

  for (; it != registry.commandsByName.cend(); AdvanceCommandIterator(it)) {
    if (_strnicmp(prefix, it->first.c_str(), needleSize) != 0) {
      break;
    }
    matches.push_back(msvc8::string(it->first.data(), it->first.size()));
  }

  msvc8::vector<msvc8::string> out;
  return CopyStringVector(out, matches);
}

/**
 * Address: 0x0041C990 (FUN_0041C990, ?CON_Printf@Moho@@YAXPBDZZ)
 * Address: 0x00420690 (FUN_00420690, boost::bind_OutputToConHandlers helper lane)
 * Address: 0x00420750 (FUN_00420750, boost::function1_void_string ctor wrapper lane)
 * Address: 0x00420EF0 (FUN_00420EF0, boost::function1_void_string ctor lane)
 * Address: 0x00421800 (FUN_00421800, boost::function1_void_string::assign_to lane)
 *
 * What it does:
 * Formats one output line and dispatches it to console handlers.
 */
void moho::CON_Printf(const char* const format, ...)
{
  if (format == nullptr) {
    return;
  }

  va_list args;
  va_start(args, format);
  const char* formatRef = format;
  const msvc8::string line = gpg::STR_Va(formatRef, args);
  va_end(args);

  if (::GetCurrentThreadId() == THREAD_GetMainThreadId()) {
    OutputToConHandlers(line);
    return;
  }

  const msvc8::string captured(line);
  boost::function<void(), std::allocator<void>> callback = [captured]() { OutputToConHandlers(captured); };
  THREAD_InvokeAsync(callback, 0u);
}

/**
 * Address: 0x0041D3C0 (FUN_0041D3C0, ?CON_GetExecuteStack@Moho@@YAABV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@XZ)
 *
 * What it does:
 * Returns the global saved execute stack.
 */
const msvc8::vector<msvc8::string>& moho::CON_GetExecuteStack()
{
  return gSavedConsoleCommands;
}

/**
 * Address: 0x0041D3D0 (FUN_0041D3D0, ?CON_FindCommand@Moho@@YAPAVCConCommand@1@PBD@Z)
 *
 * What it does:
 * Looks up command metadata by exact command key.
 */
moho::CConCommand* moho::CON_FindCommand(const char* const commandName)
{
  if (commandName == nullptr) {
    return nullptr;
  }
  return FindRegisteredConCommand(commandName);
}

/**
 * Address: 0x0041CC90 (FUN_0041CC90)
 *
 * What it does:
 * Executes a semicolon-chain of console command text.
 */
void moho::ExecuteConsoleCommandText(const char* commandText)
{
  if (commandText == nullptr || commandText[0] == '\0') {
    return;
  }

  msvc8::string pending(commandText);
  while (!pending.empty()) {
    msvc8::vector<msvc8::string> parsedTokens;
    msvc8::string remainder;
    CON_ParseCommand(pending.c_str(), parsedTokens, remainder);

    if (!parsedTokens.empty()) {
      CConCommand* const command = CON_FindCommand(parsedTokens[0].c_str());
      if (command != nullptr) {
        ConCommandArgsWireView wireArgs{};
        wireArgs.vftable = nullptr;
        wireArgs.begin = parsedTokens.data();
        wireArgs.end = parsedTokens.data() + parsedTokens.size();
        wireArgs.cap = wireArgs.end;
        command->Handle(&wireArgs);
      } else {
        msvc8::string easterEgg("ipdlfz");
        DecStringChars(easterEgg);
        if (parsedTokens[0] == easterEgg) {
          msvc8::string go("Hp");
          msvc8::string tips("Ujqt");
          msvc8::string sens("Tfot");
          DecStringChars(go);
          DecStringChars(tips);
          DecStringChars(sens);
          CON_Printf("%s %s   %s %s", go.c_str(), tips.c_str(), go.c_str(), sens.c_str());
        } else {
          CON_Printf("Unknown console command \"%s\"", parsedTokens[0].c_str());
        }
      }
    }

    if (parsedTokens.empty() && remainder == pending) {
      break;
    }
    pending = remainder;
  }
}

/**
  * Alias of FUN_0041CC90 (non-canonical helper lane).
 *
 * What it does:
 * Public console execution entry point used by Lua and UI helpers.
 */
void moho::CON_Execute(const char* commandText)
{
  ExecuteConsoleCommandText(commandText);
}

/**
 * Address: 0x0041D100 (FUN_0041D100, ?CON_Executef@Moho@@YAXPBDZZ)
 *
 * What it does:
 * Formats a command string with varargs and forwards to `CON_Execute`.
 */
void moho::CON_Executef(const char* format, ...)
{
  if (format == nullptr) {
    return;
  }

  va_list args;
  va_start(args, format);
  const msvc8::string rendered = gpg::STR_Va(format, args);
  va_end(args);
  CON_Execute(rendered.c_str());
}

/**
 * Address: 0x0041D270 (FUN_0041D270, ?CON_ExecuteSave@Moho@@YAXPBD@Z)
 *
 * What it does:
 * Pushes command text to history stack (front-insert, capped to 0x64 entries),
 * then executes the command.
 */
void moho::CON_ExecuteSave(const char* commandText)
{
  if (commandText == nullptr || commandText[0] == '\0') {
    return;
  }

  gSavedConsoleCommands.push_back(msvc8::string(commandText));
  for (std::size_t index = gSavedConsoleCommands.size() - 1; index != 0u; --index) {
    gSavedConsoleCommands[index] = gSavedConsoleCommands[index - 1];
  }
  gSavedConsoleCommands[0] = msvc8::string(commandText);
  while (gSavedConsoleCommands.size() > kSavedConsoleCommandLimit) {
    gSavedConsoleCommands.pop_back();
  }

  CON_Execute(commandText);
}

/**
 * Address: 0x0041D370 (FUN_0041D370, ?CON_ExecuteLastCommand@Moho@@YAXXZ)
 *
 * What it does:
 * Executes the most-recent saved command when command history is non-empty.
 */
void moho::CON_ExecuteLastCommand()
{
  if (gSavedConsoleCommands.empty()) {
    return;
  }

  CON_Execute(gSavedConsoleCommands.front().c_str());
}

/**
 * Address: 0x0041EE10 (FUN_0041EE10, Moho::CON_Echo)
 *
 * What it does:
 * Emits joined command arguments (`arg1..argN`) through console output.
 */
void moho::CON_Echo(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  std::string text(args.At(1)->view());
  for (std::size_t index = 2; index < args.Count(); ++index) {
    const msvc8::string* const token = args.At(index);
    if (token == nullptr) {
      continue;
    }
    text.push_back(' ');
    text.append(token->view());
  }

  CON_Printf("%s", text.c_str());
}

/**
 * Address: 0x0041EF40 (FUN_0041EF40, Moho::CON_ListCommands)
  * Alias of FUN_004203D0 (non-canonical helper lane).
 *
 * What it does:
 * Emits one formatted line per registered command.
 */
void moho::CON_ListCommands(void* const commandArgs)
{
  (void)commandArgs;

  msvc8::vector<msvc8::string> lines;
  {
    auto& registry = GetConsoleCommandRegistry();
    std::scoped_lock lock{registry.lock};
    for (
      auto it = registry.commandsByName.begin(); it != registry.commandsByName.end(); AdvanceCommandIterator(it)
    ) {
      const auto& [name, command] = *it;
      (void)name;
      if (command == nullptr) {
        continue;
      }
      lines.push_back(
        gpg::STR_Printf("  %-25s %s", command->mName ? command->mName : "", command->mDescription ? command->mDescription : "")
      );
    }
  }

  for (const msvc8::string& line : lines) {
    CON_Printf("%s", line.c_str());
  }
}

/**
 * Address: 0x004D3FC0 (FUN_004D3FC0, Moho::CON_GetVersion)
 *
 * What it does:
 * Prints the current engine-version string to console output.
 */
void moho::CON_GetVersion(void* const commandArgs)
{
  (void)commandArgs;
  const msvc8::string engineVersion = moho::GetEngineVersion();
  CON_Printf("%s", engineVersion.c_str());
}

/**
 * Address: 0x004CDC90 (FUN_004CDC90, Moho::CON_LUADOC)
 *
 * What it does:
 * Iterates all registered Lua init-form sets and dumps their binder docs.
 */
void moho::CON_LUADOC(void* const commandArgs)
{
  (void)commandArgs;

  for (CScrLuaInitFormSet* initSet = CScrLuaInitFormSet::sSets; initSet != nullptr; initSet = initSet->mNextSet) {
    initSet->DumpDocs();
  }
}

/**
 * Address: 0x008C6740 (FUN_008C6740, Moho::Con_LUA)
 *
 * What it does:
 * Joins command tokens from index 1 into one Lua chunk, echoes it to console,
 * and executes it in the user Lua state.
 */
void moho::CON_LUA(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  const msvc8::string scriptText = JoinConCommandTokens(args, 1u);
  CON_Printf("%s", scriptText.c_str());
  (void)SCR_LuaDoString(scriptText.c_str(), USER_GetLuaState());
}

/**
 * Address: 0x0047A670 (FUN_0047A670, Moho::CON_Log)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and emits one info-severity
 * log line.
 */
void moho::CON_Log(void* const commandArgs)
{
  const msvc8::string message = JoinConCommandTokens(GetConCommandArgsView(commandArgs), 1u);
  gpg::Logf("%s", message.c_str());
}

/**
 * Address: 0x0047A700 (FUN_0047A700, Moho::CON_Debug_Warn)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and emits one warn-severity
 * log line.
 */
void moho::CON_Debug_Warn(void* const commandArgs)
{
  const msvc8::string message = JoinConCommandTokens(GetConCommandArgsView(commandArgs), 1u);
  gpg::Warnf("%s", message.c_str());
}

/**
 * Address: 0x0047A790 (FUN_0047A790, Moho::CON_Debug_Error)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and terminates through
 * `gpg::Die("%s", ...)`.
 */
void moho::CON_Debug_Error(void* const commandArgs)
{
  const msvc8::string message = JoinConCommandTokens(GetConCommandArgsView(commandArgs), 1u);
  gpg::Die("%s", message.c_str());
}

/**
 * Address: 0x0047A810 (FUN_0047A810, Moho::CON_Debug_Assert)
 *
 * What it does:
 * Debug no-op callback slot.
 */
void moho::CON_Debug_Assert(void* const commandArgs)
{
  (void)commandArgs;
}

/**
 * Address: 0x0047A820 (FUN_0047A820, Moho::CON_Debug_Crash)
 *
 * What it does:
 * Intentionally crashes by writing zero to absolute address 0.
 */
void moho::CON_Debug_Crash(void* const commandArgs)
{
  (void)commandArgs;
  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
}

/**
 * Address: 0x0047A830 (FUN_0047A830, Moho::CON_Debug_Throw)
 *
 * What it does:
 * Throws `std::exception` with fixed debug text.
 */
void moho::CON_Debug_Throw(void* const commandArgs)
{
  (void)commandArgs;
  throw std::exception("Hope you really wanted to do this...");
}

/**
 * Address: 0x00500AF0 (FUN_00500AF0, Moho::CON_p4_Edit)
 *
 * What it does:
 * Emits one no-support line when called with a filespec argument; otherwise
 * prints command usage.
 */
void moho::CON_p4_Edit(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const msvc8::string* const commandToken = args.At(0u);
  GPG_ASSERT(commandToken != nullptr);

  if (commandToken != nullptr && args.Count() >= 2u) {
    CON_Printf("No P4 support in this build.");
    return;
  }

  CON_Printf("usage: %s <filespec>", commandToken->c_str());
}

/**
 * Address: 0x00500B60 (FUN_00500B60, Moho::CON_p4_IsOpenedForEdit)
 *
 * What it does:
 * Emits one no-support line when called with a filespec argument; otherwise
 * prints command usage.
 */
void moho::CON_p4_IsOpenedForEdit(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const msvc8::string* const commandToken = args.At(0u);
  GPG_ASSERT(commandToken != nullptr);

  if (commandToken != nullptr && args.Count() >= 2u) {
    CON_Printf("No P4 support in this build.");
    return;
  }

  CON_Printf("usage: %s <filespec> [user]", commandToken->c_str());
}

/**
 * Address: 0x007ADFC0 (FUN_007ADFC0, Moho::CAM_SetLOD)
 *
 * What it does:
 * Parses `cam_SetLOD <cameraName> <lodScale>` and applies the parsed LOD
 * scale to the named camera view lane.
 */
void moho::CAM_SetLOD(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 3u) {
    return;
  }

  const msvc8::string* const cameraName = args.At(1u);
  const msvc8::string* const lodScaleToken = args.At(2u);
  if (cameraName == nullptr || lodScaleToken == nullptr) {
    return;
  }

  RCamManager* const manager = CAM_GetManager();
  CameraImpl* const camera = (manager != nullptr) ? manager->GetCamera(cameraName->c_str()) : nullptr;
  if (camera == nullptr) {
    return;
  }

  GeomCamera3& cameraView = const_cast<GeomCamera3&>(camera->CameraGetView());
  cameraView.SetLODScale(ParseFloatToken(lodScaleToken));
}

/**
 * Address: 0x007AE040 (FUN_007AE040, Moho::CON_DumpCamera)
 *
 * What it does:
 * Logs active world-camera target position, heading/far-pitch orientation,
 * and target zoom.
 */
void moho::CON_DumpCamera(void* const commandArgs)
{
  (void)commandArgs;

  RCamManager* const cameraManager = CAM_GetManager();
  CameraImpl* const camera = cameraManager != nullptr ? cameraManager->GetCamera("WorldCamera") : nullptr;
  if (camera == nullptr) {
    return;
  }

  gpg::Logf("Camera:");

  const CameraImplDumpRuntimeView* const cameraView = CameraImplDumpRuntimeView::FromCamera(camera);
  const msvc8::string targetPositionText = moho::ToString(cameraView->mTargetLocation);
  gpg::Logf("  TargetPos: %s", targetPositionText.c_str());
  gpg::Logf("  Orientation: %f, %f, 0.0", cameraView->mHeading, cameraView->mFarPitch);
  gpg::Logf("  Zoom: %f", cameraView->mTargetZoom);
}

/**
 * Address: 0x00834610 (FUN_00834610, Moho::CON_UI_SetSkin)
 *
 * What it does:
 * Imports `uiutil.lua` and invokes `SetCurrentSkin(name)` when a second
 * command token is present.
 */
void moho::CON_UI_SetSkin(void* const commandArgs)
{
  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  LuaPlus::LuaObject uiUtilModule = SCR_Import(state, "/lua/ui/uiutil.lua");
  LuaPlus::LuaObject setCurrentSkinObject = uiUtilModule["SetCurrentSkin"];
  LuaPlus::LuaFunction<void> setCurrentSkin(setCurrentSkinObject);

  const msvc8::string* const skinToken = args.At(1);
  setCurrentSkin(skinToken != nullptr ? skinToken->c_str() : "");
}

/**
 * Address: 0x00834700 (FUN_00834700, Moho::UI_RotateSkin)
 *
 * What it does:
 * Imports `uiutil.lua` and invokes `RotateSkin(direction)` where `direction`
 * defaults to `"+"` when no argument token is provided.
 */
void moho::UI_RotateSkin(void* const commandArgs)
{
  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject uiUtilModule = SCR_Import(state, "/lua/ui/uiutil.lua");
  LuaPlus::LuaObject rotateSkinObject = uiUtilModule["RotateSkin"];
  LuaPlus::LuaFunction<void> rotateSkin(rotateSkinObject);

  msvc8::string direction("+");
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (const msvc8::string* const argDirection = args.At(1); argDirection != nullptr) {
    direction.assign_owned(argDirection->c_str());
  }

  rotateSkin(direction.c_str());
}

/**
 * Address: 0x00834860 (FUN_00834860, Moho::UI_RotateLayout)
 *
 * What it does:
 * Imports `uiutil.lua` and invokes `RotateLayout(direction)` where
 * `direction` defaults to `"+"` when no argument token is provided.
 */
void moho::UI_RotateLayout(void* const commandArgs)
{
  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject uiUtilModule = SCR_Import(state, "/lua/ui/uiutil.lua");
  LuaPlus::LuaObject rotateLayoutObject = uiUtilModule["RotateLayout"];
  LuaPlus::LuaFunction<void> rotateLayout(rotateLayoutObject);

  msvc8::string direction("+");
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (const msvc8::string* const argDirection = args.At(1); argDirection != nullptr) {
    direction.assign_owned(argDirection->c_str());
  }

  rotateLayout(direction.c_str());
}

/**
 * Address: 0x008349D0 (FUN_008349D0, Moho::CON_UI_ToggleGamePanels)
 *
 * What it does:
 * Imports `gamemain.lua` and invokes `HideGameUI()` with no arguments.
 */
void moho::CON_UI_ToggleGamePanels(void* const commandArgs)
{
  (void)commandArgs;

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject gameMainModule = SCR_Import(state, "/lua/ui/game/gamemain.lua");
  LuaPlus::LuaObject hideGameUiObject = gameMainModule["HideGameUI"];
  LuaPlus::LuaFunction<void> hideGameUi(hideGameUiObject);
  hideGameUi();
}

/**
 * Address: 0x00834A80 (FUN_00834A80, Moho::UI_MakeSelectionSet)
 *
 * What it does:
 * Validates one selection-set name argument and calls
 * `/lua/ui/game/selection.lua:AddCurrentSelectionSet(name)`.
 */
void moho::UI_MakeSelectionSet(void* const commandArgs)
{
  if (WLD_GetActiveSession() == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf("%s", noSessionText.c_str());
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    CON_Printf("%s", kUIMakeSelectionSetUsageText);
    return;
  }

  LuaPlus::LuaState* const state = USER_GetLuaState();
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject selectionModule = SCR_Import(state, "/lua/ui/game/selection.lua");
  LuaPlus::LuaObject addCurrentSelectionSet = selectionModule["AddCurrentSelectionSet"];
  LuaPlus::LuaFunction<void> addCurrentSelectionSetFn(addCurrentSelectionSet);

  const msvc8::string* const setName = args.At(1);
  addCurrentSelectionSetFn(setName != nullptr ? setName->c_str() : "");
}

/**
 * Address: 0x00834C10 (FUN_00834C10, Moho::UI_ApplySelectionSet)
 *
 * What it does:
 * Validates one selection-set name argument and calls
 * `/lua/ui/game/selection.lua:ApplySelectionSet(name)`.
 */
void moho::UI_ApplySelectionSet(void* const commandArgs)
{
  if (WLD_GetActiveSession() == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf("%s", noSessionText.c_str());
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    CON_Printf("%s", kUIApplySelectionSetUsageText);
    return;
  }

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject selectionModule = SCR_Import(state, "/lua/ui/game/selection.lua");
  LuaPlus::LuaObject applySelectionSet = selectionModule["ApplySelectionSet"];
  LuaPlus::LuaFunction<void> applySelectionSetFn(applySelectionSet);

  msvc8::string selectionSetName;
  if (const msvc8::string* const setName = args.At(1); setName != nullptr) {
    selectionSetName.assign_owned(setName->c_str());
  }
  applySelectionSetFn(selectionSetName.c_str());
}

/**
 * Address: 0x008335F0 (FUN_008335F0, Moho::CON_IssueCommand)
 *
 * What it does:
 * Console debug command that issues one fixed unit command
 * (Stop/Pause/Dive/SiloBuildTactical/SiloBuildNuke) against the active
 * session's current selection. Stop/Pause additionally rebroadcast the
 * selection afterward; the other three do not (matches the binary's own
 * asymmetry - not a recovery oversight).
 */
void moho::CON_IssueCommand(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf("%s", noSessionText.c_str());
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  const msvc8::string* const subCommand = args.At(1);
  const char* const subCommandText = subCommand != nullptr ? subCommand->c_str() : "";

  if (_stricmp(subCommandText, "Stop") == 0) {
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Stop);
    ISSUE_Command(session->mSelection, commandIssueData, true);
    session->SetSelection(session->mSelection);
    return;
  }
  if (_stricmp(subCommandText, "Pause") == 0) {
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Pause);
    ISSUE_Command(session->mSelection, commandIssueData, true);
    session->SetSelection(session->mSelection);
    return;
  }
  if (_stricmp(subCommandText, "Dive") == 0) {
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Dive);
    ISSUE_Command(session->mSelection, commandIssueData, true);
    return;
  }
  if (_stricmp(subCommandText, "SiloBuildTactical") == 0) {
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_BuildSiloTactical);
    ISSUE_Command(session->mSelection, commandIssueData, false);
    return;
  }
  if (_stricmp(subCommandText, "SiloBuildNuke") == 0) {
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_BuildSiloNuke);
    ISSUE_Command(session->mSelection, commandIssueData, false);
    return;
  }
}

/**
 * Address: 0x00834DA0 (FUN_00834DA0, Moho::CON_UI_CreateHead1Map)
 *
 * What it does:
 * Imports `multihead.lua` and invokes `CreateSecondView()`.
 */
void moho::CON_UI_CreateHead1Map(void* const commandArgs)
{
  (void)commandArgs;

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager != nullptr ? uiManager->mLuaState : nullptr;
  if (state == nullptr) {
    return;
  }

  LuaPlus::LuaObject multiHeadModule = SCR_Import(state, "/lua/ui/game/multihead.lua");
  LuaPlus::LuaObject createSecondViewObject = multiHeadModule["CreateSecondView"];
  LuaPlus::LuaFunction<void> createSecondView(createSecondViewObject);
  createSecondView();
}

/**
 * Address: 0x008349C0 (FUN_008349C0, Moho::UI_Quit)
 *
 * What it does:
 * Shows the escape dialog through UI main callback lane.
 */
void moho::UI_Quit(void* const commandArgs)
{
  (void)commandArgs;
  (void)ShowEscapeDialog(false);
}

/**
 * Address: 0x007ADF50 (FUN_007ADF50, Moho::UI_ResetView)
 *
 * What it does:
 * Resolves each camera-name token from argument index 1 onward and resets
 * each camera that exists in the current camera manager.
 */
void moho::UI_ResetView(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() <= 1u) {
    return;
  }

  RCamManager* const cameraManager = CAM_GetManager();
  if (cameraManager == nullptr) {
    return;
  }

  for (std::size_t index = 1u; index < args.Count(); ++index) {
    const msvc8::string* const cameraName = args.At(index);
    if (cameraName == nullptr) {
      continue;
    }

    CameraImpl* const camera = cameraManager->GetCamera(cameraName->c_str());
    if (camera != nullptr) {
      camera->CameraReset();
    }
  }
}

/**
 * Address: 0x00834E50 (FUN_00834E50, Moho::SetFocusArmy)
 *
 * What it does:
 * Parses one focus-army index argument and requests focus update on active
 * world session; otherwise prints syntax/no-session feedback.
 */
void moho::SetFocusArmy(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() == 2u) {
    CWldSession* const session = WLD_GetActiveSession();
    if (session != nullptr) {
      session->RequestFocusArmy(ParseIntToken(args.At(1)));
      return;
    }

    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf("%s", noSessionText.c_str());
    return;
  }

  const msvc8::string* const commandNameToken = args.At(0);
  const char* const commandName = commandNameToken != nullptr ? commandNameToken->c_str() : "SetFocusArmy";
  CON_Printf("syntax: %s <zero based army index or -1>", commandName);
}

/**
 * Address: 0x00835370 (FUN_00835370, Moho::UI_Lua)
 *
 * What it does:
 * Joins command tokens from index 1 and executes the Lua text in the active
 * UI manager state.
 */
void moho::UI_Lua(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  const msvc8::string scriptText = JoinConCommandTokens(args, 1u);
  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager != nullptr && uiManager->mLuaState != nullptr) {
    (void)SCR_LuaDoString(scriptText.c_str(), uiManager->mLuaState);
  }
}

/**
 * Address: 0x00835830 (FUN_00835830, Moho::UI_ShowRenameDialog)
 *
 * What it does:
 * Validates world-session selection constraints, prints localized console
 * feedback for invalid selection states, and opens rename dialog for one
 * selected user-unit.
 */
void moho::UI_ShowRenameDialog()
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  if (session->mSelection.mSize == 0u) {
    PrintLocalizedConsoleLine(kUIRenameSelectionRequiredLocToken);
    return;
  }

  if (session->mSelection.mSize > 1u) {
    PrintLocalizedConsoleLine(kUIRenameSingleSelectionLocToken);
    return;
  }

  msvc8::vector<UserUnit*> selectedUnits;
  session->GetSelectionUnits(selectedUnits);

  UserUnit* const selectedUnit = selectedUnits.size() != 0u ? selectedUnits[0] : nullptr;
  if (selectedUnit == nullptr) {
    PrintLocalizedConsoleLine(kUIRenameSelectionRequiredLocToken);
    return;
  }

  // `GetCustomName` hands back the address of the unit's `msvc8::string`
  // storage, which the binary copies into a temporary before handing it to the
  // dialog helper; taking it as a `char*` directly would push the string
  // object's own bytes into Lua.
  ShowRenameDialogLua(CustomNameStorage(selectedUnit).c_str());
}

/**
 * Address: 0x00835A40 (FUN_00835A40, Moho::UI_DumpControls)
 *
 * What it does:
 * Walks each root UI frame and logs every control via depth-first traversal.
 */
void moho::UI_DumpControls(void* const commandArgs)
{
  (void)commandArgs;

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr) {
    return;
  }

  const std::size_t frameCount = uiManager->mFrames.Size();
  for (std::size_t frameIndex = 0u; frameIndex < frameCount; ++frameIndex) {
    CMauiControl* const frameRoot = uiManager->mFrames[frameIndex].get();
    if (frameRoot == nullptr) {
      continue;
    }

    for (CMauiControl* control = frameRoot; control != nullptr; control = control->DepthFirstSuccessor(frameRoot)) {
      control->Dump();
    }
  }
}

/**
 * Address: 0x00835AA0 (FUN_00835AA0, Moho::UI_DumpControlsUnderCursor)
 *
 * What it does:
 * Dispatches `DumpControlsUnderMouse()` on the active UI manager when one is
 * available.
 */
void moho::UI_DumpControlsUnderCursor(void* const commandArgs)
{
  (void)commandArgs;

  IUIManager* const uiManager = UI_GetManager();
  if (uiManager != nullptr) {
    uiManager->DumpControlsUnderMouse();
  }
}

/**
 * Address: 0x004F2B40 (FUN_004F2B40, ?WIN_AppRequestExit@Moho@@YAXXZ)
  * Alias of FUN_004F2400 (non-canonical helper lane).
 *
 * What it does:
 * Requests application main-loop exit through the active wx app object.
 */
void moho::WIN_AppRequestExit()
{
  wxTheApp->ExitMainLoop();
}

/**
 * Address: 0x004F3C30 (FUN_004F3C30, Moho::WIN_ToggleLogDialog)
 *
 * What it does:
 * Lazily creates the log window when needed and toggles its visible state.
 */
void moho::WIN_ToggleLogDialog()
{
  WWinLogWindow* dialog = sLogWindowTarget.dialog;
  if (dialog == nullptr) {
    WINX_PrecreateLogWindow();
    dialog = sLogWindowTarget.dialog;
  }

  const auto* const dialogView = reinterpret_cast<const WWinLogWindowVisibilityRuntimeView*>(dialog);
  dialog->Show(!dialogView->IsShown());
}

/**
 * Address: 0x004F3C60 (FUN_004F3C60, Moho::WIN_ShowLogDialog)
 *
 * What it does:
 * Parses one boolean visibility token (`"true"` => show, otherwise hide),
 * ensures the log-window runtime exists, and forwards the visibility toggle.
 */
void moho::WIN_ShowLogDialog(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  const msvc8::string* const showToken = args.At(1u);
  if (showToken == nullptr) {
    return;
  }

  const bool showDialog = std::strcmp(showToken->c_str(), "true") == 0;

  WWinLogWindow* dialog = sLogWindowTarget.dialog;
  if (dialog == nullptr) {
    WINX_PrecreateLogWindow();
    dialog = sLogWindowTarget.dialog;
  }

  dialog->Show(showDialog);
}

/**
 * Address: 0x007B5920 (FUN_007B5920, Moho::CON_ExecutePasteBuffer)
 *
 * What it does:
 * Reads UTF-8 clipboard text and executes it as Lua in active world-session
 * state (or user Lua state when no active session exists).
 */
void moho::CON_ExecutePasteBuffer()
{
  const msvc8::string clipboardText = WIN_GetClipboardText();

  LuaPlus::LuaState* state = USER_GetLuaState();
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    state = session->mState;
  }

  (void)SCR_LuaDoString(clipboardText.c_str(), state);
}

/**
 * Address: 0x007B5A40 (FUN_007B5A40, Moho::CON_PopupCreateUnitMenu)
 *
 * What it does:
 * Opens Lua create-unit dialog at current cursor screen coordinates, or prints
 * localized no-session text when no world session is active.
 */
void moho::CON_PopupCreateUnitMenu(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf("%s", noSessionText.c_str());
    return;
  }

  LuaPlus::LuaState* const state = session->mState;
  LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/ui/dialogs/createunit.lua");
  if (!moduleObject.IsTable()) {
    LuaPlus::LuaState::Error(state, "failed to load \"/lua/ui/dialogs/createunit.lua\" module");
  }

  LuaPlus::LuaObject createDialogObject = moduleObject["CreateDialog"];
  LuaPlus::LuaFunction<> createDialogFunction(createDialogObject);
  createDialogFunction(session->CursorScreenPos.x, session->CursorScreenPos.y);
}

/**
 * Address: 0x007B60F0 (FUN_007B60F0, Moho::CON_PathDebug)
 *
 * What it does:
 * Imports path debugger UI module and toggles between `CreateUI` and
 * `DestroyUI` based on persisted enable state.
 */
void moho::CON_PathDebug(void* const commandArgs)
{
  (void)commandArgs;

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  LuaPlus::LuaState* const state = uiManager->mLuaState;

  LuaPlus::LuaObject moduleObject = SCR_Import(state, kPathDebuggerModulePath);
  if (!moduleObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kPathDebuggerLoadErrorText);
  }

  const char* const methodName =
    sPathDebuggerEnabled ? kPathDebuggerDestroyUiMethodName : kPathDebuggerCreateUiMethodName;
  LuaPlus::LuaObject methodObject = moduleObject[methodName];
  LuaPlus::LuaFunction<> methodFunction(methodObject);
  methodFunction();

  sPathDebuggerEnabled = !sPathDebuggerEnabled;
}

/**
 * Address: 0x00833430 (FUN_00833430, Moho::CON_CreateProp)
 *
 * What it does:
 * Resolves one prop blueprint id from command arguments (fallbacks to
 * placeholder path), lowercases it, and dispatches prop creation at active
 * world-session cursor position.
 */
void moho::CON_CreateProp(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf(noSessionText.c_str());
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const msvc8::string* const blueprintToken = args.At(1u);

  const char* const blueprintPath =
    blueprintToken != nullptr ? blueprintToken->c_str() : "/props/rplaceholder/rplaceholder_prop";

  std::string normalizedBlueprintPath = blueprintPath != nullptr ? blueprintPath : "";
  for (char& character : normalizedBlueprintPath) {
    character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  }

  SIM_GetActiveDriver()->CreateProp(normalizedBlueprintPath.c_str(), session->CursorWorldPos);
}

/**
 * Address: 0x00832C50 (FUN_00832C50, Moho::CON_CreateUnit)
 *
 * IDA signature:
 * void __cdecl Moho::CON_CreateUnit(std::vector_string *arg0);
 *
 * What it does:
 * `CreateUnit <blueprintId> [armyIndex] [screenX screenY]`. Resolves the spawn
 * point from an explicit screen point through the world camera's
 * screen-to-surface projection (only when that point differs from the last one
 * this command used - repeating the same coordinates falls back to the live
 * cursor world position), resolves the army from the explicit index or the
 * session focus army, grid-snaps the position onto the blueprint's footprint,
 * and asks the sim driver to spawn the unit. An unresolvable blueprint id plays
 * the UI error cue instead.
 */
void moho::CON_CreateUnit(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const std::size_t tokenCount = args.Count();
  if (tokenCount < 2u) {
    return;
  }

  SCoordsVec2 spawnPos{session->CursorWorldPos.x, session->CursorWorldPos.z};

  // The binary gates the explicit-screen-point path on `tokenCount >= 4` while
  // reading tokens 3 *and* 4, so a four-token invocation reads one past the
  // argument vector. `ConCommandArgsView::At` is bounds-checked and yields an
  // absent token there, which `ParseIntToken` turns into 0 - the same value the
  // out-of-bounds read produced for every well-formed argument vector.
  if (tokenCount >= 4u) {
    const Wm3::Vector2f screenPoint{
      static_cast<float>(ParseIntToken(args.At(3u))),
      static_cast<float>(ParseIntToken(args.At(4u)))
    };

    if (cmp_LastMouseScreenPos(screenPoint) != 0) {
      CameraImpl* const worldCamera = CAM_GetCamera(kCreateUnitWorldCameraName);
      const Wm3::Vector3f surfacePoint = worldCamera->CameraScreenToSurface(screenPoint);
      spawnPos.x = surfacePoint.x;
      spawnPos.z = surfacePoint.z;
      lastMouseScreenPos = screenPoint;
    }
  }

  int armyIndex = 0;
  if (tokenCount >= 3u) {
    armyIndex = ParseIntToken(args.At(2u));

    const std::size_t armyCount = session->userArmies.size();
    if (static_cast<std::size_t>(armyIndex) >= armyCount) {
      CON_Printf(kCreateUnitInvalidArmyFormat, armyIndex, static_cast<int>(armyCount));
      return;
    }
  } else {
    armyIndex = session->FocusArmy;
    if (armyIndex < 0) {
      return;
    }
  }

  UserArmy* const spawnArmy = session->userArmies[static_cast<std::size_t>(armyIndex)];
  if (spawnArmy == nullptr) {
    return;
  }

  msvc8::string requestedBlueprint;
  requestedBlueprint.assign_owned(TokenDataOrEmpty(args.At(1u)));

  RResId requestedBlueprintId{};
  (void)gpg::STR_CopyFilename(&requestedBlueprintId.name, &requestedBlueprint);

  RUnitBlueprint* const blueprint = session->mRules->GetUnitBlueprint(requestedBlueprintId);
  requestedBlueprintId.name.clear();

  if (blueprint == nullptr) {
    USER_GetSound()->Play(msvc8::string(kCreateUnitErrorSoundCue), msvc8::string(kCreateUnitErrorSoundBank));
    return;
  }

  const Wm3::Vector3f snappedPos =
    COORDS_GridSnap(ResolveSessionTerrainMap(session), spawnPos, blueprint->mFootprint, LAYER_None);
  const SCoordsVec2 gridSnappedPos{snappedPos.x, snappedPos.z};

  RResId spawnBlueprintId{};
  (void)gpg::STR_CopyFilename(&spawnBlueprintId.name, &blueprint->mBlueprintId);

  SIM_GetActiveDriver()
    ->CreateUnit(static_cast<std::uint32_t>(spawnArmy->mArmyIndex), spawnBlueprintId, gridSnappedPos, 0.0f);

  spawnBlueprintId.name.clear();
}

/**
 * Address: 0x008330B0 (FUN_008330B0, Moho::CON_LotsOfProps)
 *
 * IDA signature:
 * void __cdecl Moho::CON_LotsOfProps(std::vector_string *a1);
 *
 * What it does:
 * `LotsOfProps [propBlueprint] [count]`. Scatters `count` (default 100) copies
 * of one lowercased prop blueprint path across uniformly random height-field
 * cells, sampling terrain elevation at each cell center and lifting the spawn to
 * the water plane where the map's water sits above the terrain.
 */
void moho::CON_LotsOfProps(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

  msvc8::string propBlueprintPath;
  if (args.Count() >= 2u) {
    propBlueprintPath.assign_owned(TokenDataOrEmpty(args.At(1u)));

    // The binary lowercases the freshly copied path in place through the same
    // transform helper rather than building a second buffer.
    char* const pathBegin = propBlueprintPath.raw_data_mut_unsafe();
    (void)CopyLowercasedRange(pathBegin, pathBegin, pathBegin + propBlueprintPath.size());
  } else {
    propBlueprintPath.assign_owned(kPlaceholderPropBlueprintPath);
  }

  int propCount = kLotsOfPropsDefaultCount;
  if (args.Count() >= 3u) {
    propCount = ParseIntToken(args.At(2u));
  }

  const STIMap* const terrainMap = ResolveSessionTerrainMap(session);
  const CHeightField* const heightField = terrainMap->mHeightField.get();

  for (int spawnIndex = 0; spawnIndex < propCount; ++spawnIndex) {
    // Both cell indices are truncated to 16 bits before they become world
    // coordinates, exactly as the binary's `movsx`/`fild` pair does.
    const auto cellX =
      static_cast<std::int16_t>(RandomIndexBelowExtent(static_cast<std::uint32_t>(heightField->width - 1)));
    const auto cellZ =
      static_cast<std::int16_t>(RandomIndexBelowExtent(static_cast<std::uint32_t>(heightField->height - 1)));

    const float worldX = static_cast<float>(cellX) + 0.5f;
    const float worldZ = static_cast<float>(cellZ) + 0.5f;

    float worldY = heightField->GetElevation(worldX, worldZ);
    if (terrainMap->mWaterEnabled != 0u && terrainMap->mWaterElevation > worldY) {
      worldY = terrainMap->mWaterElevation;
    }

    SIM_GetActiveDriver()->CreateProp(propBlueprintPath.c_str(), Wm3::Vec3f{worldX, worldY, worldZ});
  }
}

/**
 * Address: 0x00833C70 (FUN_00833C70, Moho::CON_CConFunc_KillSelectedUnits)
 *
 * What it does:
 * Issues one `UNITCOMMAND_KillSelf` against the active session's selection with
 * the queue-clear flag set, so the selected units die through their normal
 * death sequence. Prints localized "no session" feedback when no world session
 * is active.
 */
void moho::CON_KillSelectedUnits(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_KillSelf);
  ISSUE_Command(session->mSelection, commandIssueData, true);
}

/**
 * Address: 0x00833D60 (FUN_00833D60, Moho::CON_DestroySelectedUnits)
 *
 * What it does:
 * Issues one `UNITCOMMAND_DestroySelf` against the active session's selection
 * with the queue-clear flag set, removing the selected units outright rather
 * than killing them. Prints localized "no session" feedback when no world
 * session is active.
 */
void moho::CON_DestroySelectedUnits(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_DestroySelf);
  ISSUE_Command(session->mSelection, commandIssueData, true);
}

namespace
{
  /**
   * Resolves one `UserEntity*` from a selection weak-ref slot, matching the
   * `DecodeSelectedUserEntity` helper recovered in CWldSession.cpp. The
   * selection set stores `&UserEntity::mIUnitChainHead` (offset +0x08) in
   * `mOwnerLinkSlot`; subtracting that offset yields the owning entity.
   * Tombstoned slots (null pointer or sentinel `(void*)8`) decode to nullptr.
   */
  [[nodiscard]] moho::UserEntity* DecodeUserEntityFromSelectionSlot(
    const moho::SSelectionWeakRefUserEntity& weakRef) noexcept
  {
    void* const ownerLinkSlot = weakRef.mOwnerLinkSlot;
    if (ownerLinkSlot == nullptr || ownerLinkSlot == reinterpret_cast<void*>(static_cast<std::uintptr_t>(8u))) {
      return nullptr;
    }

    constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(ownerLinkSlot);
    if (raw < kSelectionOwnerLinkOffset) {
      return nullptr;
    }
    return reinterpret_cast<moho::UserEntity*>(raw - kSelectionOwnerLinkOffset);
  }

  /**
   * Returns the bitwise `commandCapsMask` flag (UnitAttributes +0x60) for one
   * recovered user-unit selection entry, or 0 when the entity is not a
   * user-unit. Walks the typed `IUnit` bridge subobject the binary stores at
   * `userUnit + 0x148`.
   */
  [[nodiscard]] std::uint32_t GetUserUnitCommandCapsMask(moho::UserUnit* const userUnit) noexcept
  {
    moho::IUnit* const iunit = ResolveIUnitBridge(userUnit);
    if (iunit == nullptr) {
      return 0u;
    }
    return iunit->GetAttributes().commandCapsMask;
  }

  /**
   * Walks the live entries of `selection` skipping tombstone nodes and stops
   * at the first live `UserEntity` whose typed `UserUnit` bridge advertises a
   * `commandCapsMask` that intersects `requiredCapsMask`. Returns `true` when
   * the selection has at least one such unit.
   */
  [[nodiscard]] bool SelectionHasUnitWithCommandCap(
    moho::SSelectionSetUserEntity& selection, const std::uint32_t requiredCapsMask
  )
  {
    moho::SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return false;
    }

    moho::SSelectionNodeUserEntity* node = head->mLeft;
    node = moho::SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != head) {
      moho::UserEntity* const entity = DecodeUserEntityFromSelectionSlot(node->mEnt);
      if (entity != nullptr) {
        if (moho::UserUnit* const userUnit = entity->IsUserUnit(); userUnit != nullptr) {
          if ((GetUserUnitCommandCapsMask(userUnit) & requiredCapsMask) != 0u) {
            return true;
          }
        }
      }

      moho::SSelectionSetUserEntity::Iterator_inc(&node);
      node = moho::SSelectionSetUserEntity::find(&selection, node, &node);
    }

    return false;
  }

  /**
   * The first live selection entry, or `nullptr` when the selection holds only
   * tombstones. The binary reaches it by starting at the tree's left-most node
   * and letting `find` prune dead weak-links forward; both `UI_TrackUnit` and
   * `RenameUnit` open with exactly that probe.
   */
  [[nodiscard]] moho::SSelectionNodeUserEntity* FirstLiveSelectionNode(moho::SSelectionSetUserEntity& selection)
  {
    moho::SSelectionNodeUserEntity* const head = selection.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    moho::SSelectionNodeUserEntity* cursor = nullptr;
    moho::SSelectionNodeUserEntity* const node = moho::SSelectionSetUserEntity::find(&selection, head->mLeft, &cursor);
    return node != head ? node : nullptr;
  }
} // namespace

/**
 * Address: 0x007B55D0 (FUN_007B55D0, Moho::CON_CopySelectedUnitsToClipboard)
 *
 * What it does:
 * Builds one `CreateUnitAtMouse(...)` Lua line per selected user-unit,
 * positioned/oriented relative to the selection centroid, and copies the
 * whole script to the Windows clipboard. Silently does nothing when there is
 * no active session or the selection is empty (no localized "no session"
 * feedback, unlike the other selection commands in this file).
 *
 * The binary reads the active session through the raw global `Moho::sWldSession`
 * rather than through `WLD_GetActiveSession()`; both name the same `.data`
 * slot (confirmed from `WLD_CreateSession`/`WLD_DestroySession`, which write
 * that exact address while assigning the already-recovered `gActiveWldSession`),
 * so this uses the established wrapper for consistency with every sibling
 * command in this file.
 */
void moho::CON_CopySelectedUnitsToClipboard(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  SSelectionSetUserEntity& selection = session->mSelection;
  SSelectionNodeUserEntity* const head = selection.mHead;
  if (head == nullptr || FirstLiveSelectionNode(selection) == nullptr) {
    return;
  }

  // First pass: sum ground-plane position (X/Z) across every live selected
  // entity to find the selection's centroid.
  float sumX = 0.0f;
  float sumZ = 0.0f;
  {
    SSelectionNodeUserEntity* node = head->mLeft;
    node = SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != head) {
      if (UserEntity* const entity = DecodeUserEntityFromSelectionSlot(node->mEnt); entity != nullptr) {
        sumX += entity->mVariableData.mCurTransform.pos_.x;
        sumZ += entity->mVariableData.mCurTransform.pos_.z;
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&selection, node, &node);
    }
  }

  const double inverseSelectionSize = 1.0 / static_cast<double>(static_cast<unsigned int>(selection.size()));
  const float centroidX = static_cast<float>(sumX * inverseSelectionSize);
  const float centroidZ = static_cast<float>(sumZ * inverseSelectionSize);

  // Second pass: for every selected user-unit, append one
  // `CreateUnitAtMouse` line encoding its position/yaw relative to the
  // centroid, its blueprint id, and its owning army index.
  msvc8::string commandScript;
  {
    SSelectionNodeUserEntity* node = head->mLeft;
    node = SSelectionSetUserEntity::find(&selection, node, &node);
    while (node != head) {
      if (UserEntity* const entity = DecodeUserEntityFromSelectionSlot(node->mEnt); entity != nullptr) {
        if (UserUnit* const unit = entity->IsUserUnit(); unit != nullptr) {
          const VTransform& transform = unit->mVariableData.mCurTransform;
          const float relX = transform.pos_.x - centroidX;
          const float relZ = transform.pos_.z - centroidZ;

          // Standard yaw-from-quaternion extraction (Y-up ground plane):
          // atan2(2*(w*y + x*z), 1 - 2*(x^2 + y^2)).
          const float sinYaw = 2.0f
            * (transform.orient_.w * transform.orient_.y + transform.orient_.z * transform.orient_.x);
          const float cosYaw = 1.0f
            - 2.0f * (transform.orient_.y * transform.orient_.y + transform.orient_.x * transform.orient_.x);
          const float yaw = std::atan2(sinYaw, cosYaw);

          const UserArmy* const army = unit->mArmy;
          const RUnitBlueprint* const blueprint = unit->GetBlueprint();

          const msvc8::string commandLine = gpg::STR_Printf(
            "   CreateUnitAtMouse('%s', %d, %7.2f, %7.2f, %8.5f)\n",
            blueprint->mBlueprintId.c_str(),
            army->mArmyIndex,
            relX,
            relZ,
            yaw
          );
          commandScript += commandLine;
        }
      }

      SSelectionSetUserEntity::Iterator_inc(&node);
      node = SSelectionSetUserEntity::find(&selection, node, &node);
    }
  }

  const std::wstring wideCommandScript = gpg::STR_Utf8ToWide(commandScript.c_str());
  (void)WIN_CopyToClipboard(wideCommandScript.c_str());
}

/**
 * Address: 0x0089E3C0 (FUN_0089E3C0, Moho::CON_AddSplat)
 *
 * IDA signature:
 * void __cdecl Moho::CON_AddSplat(std::vector_string *arg0);
 *
 * What it does:
 * `AddSplat [texture <path>]`. Drops one decal splat at the cursor's world
 * position through the active session's terrain decal manager, textured with
 * `/env/common/splats/tank_treads_albedo.dds` by default. Scanning arguments
 * 1..N-1 for a literal "texture" token overrides the texture path with the
 * following argument. The decal type passed to `NewSplatAt` is a raw `1` in
 * the binary (IDA's own "DECALTYPE_Tarmac" label is a mislabeled unrelated
 * enum - the value matches `WldTerrainDecalType_Albedo`, consistent with the
 * default texture's own "albedo" filename). Prints "No session." when there
 * is no active session; silently does nothing when the session has no
 * terrain resource or decal manager.
 */
void moho::CON_AddSplat(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    CON_Printf("No session.");
    return;
  }

  msvc8::string texturePath = "/env/common/splats/tank_treads_albedo.dds";

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const std::size_t tokenCount = args.Count();
  for (std::size_t i = 1u; i < tokenCount; ++i) {
    if (const msvc8::string* const token = args.At(i); token != nullptr && *token == "texture") {
      if (const msvc8::string* const path = args.At(i + 1u); path != nullptr) {
        texturePath = *path;
      }
    }
  }

  IWldTerrainRes* const terrainRes = session->mWldMap != nullptr ? session->mWldMap->mTerrainRes : nullptr;
  if (terrainRes == nullptr) {
    return;
  }

  // `GetDecalManager()` returns the `IDecalManager` interface pointer the
  // binary dispatches `NewSplatAt` through (vtable slot +0x44); `CDecalManager`
  // is this engine's sole concrete implementation, and `NewSplatAt` is not
  // yet one of the members `CDecalManager` has moved into its declared
  // "virtual dispatch table, in binary slot order" section (see that
  // section's own comment in CWldSplat.h), so this calls it directly on the
  // concrete type rather than through a not-yet-modelled virtual slot --
  // behaviorally identical while there is only one implementing class.
  if (IDecalManager* const decalManager = terrainRes->GetDecalManager(); decalManager != nullptr) {
    (void)static_cast<CDecalManager*>(decalManager)->NewSplatAt(
      session->CursorWorldPos, WldTerrainDecalType_Albedo, texturePath
    );
  }
}

/**
 * Address: 0x00834240 (FUN_00834240, Moho::CON_ProcessInfoPair)
 *
 * IDA signature:
 * void __cdecl Moho::CON_ProcessInfoPair(std::vector_string *arg0);
 *
 * What it does:
 * `ProcessInfoPair <key> <value>`. Publishes the pair through
 * `ISTIDriver::ProcessInfoPair` once per selected unit, but only for units
 * owned by the session's focus army - the same ownership gate the sim applies
 * before honouring an info pair. Prints localized "no session" feedback when no
 * world session is active, and silently ignores short argument vectors.
 */
void moho::CON_ProcessInfoPair(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 3u) {
    return;
  }

  const UserArmy* const focusArmy = session->GetFocusArmy();

  msvc8::vector<UserUnit*> selectedUnits;
  session->GetSelectionUnits(selectedUnits);

  const char* const infoKey = TokenDataOrEmpty(args.At(1u));
  const char* const infoValue = TokenDataOrEmpty(args.At(2u));

  for (UserUnit* const selectedUnit : selectedUnits) {
    UserEntity* const entityView = ResolveUserEntityView(selectedUnit);
    if (entityView == nullptr || entityView->mArmy != focusArmy) {
      continue;
    }

    SIM_GetActiveDriver()->ProcessInfoPair(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(entityView->mParams.mEntityId)),
      infoKey,
      infoValue
    );
  }
}

/**
 * Address: 0x00834460 (FUN_00834460, Moho::UI_TrackUnit)
 *
 * IDA signature:
 * void __cdecl Moho::CON_UI_TrackUnit(std::vector_string *a1);
 *
 * What it does:
 * `UI_TrackUnit <camera> [camera ...]`. For each named runtime camera this
 * toggles selection tracking: the camera drops its target when the selection is
 * empty or when its current target already is the first selected entity,
 * otherwise it starts tracking the whole selection at the camera's current
 * target zoom with a zero-second transition.
 */
void moho::UI_TrackUnit(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  const std::size_t tokenCount = args.Count();
  if (tokenCount <= 1u) {
    return;
  }

  SSelectionSetUserEntity& selection = session->mSelection;

  for (std::size_t tokenIndex = 1u; tokenIndex < tokenCount; ++tokenIndex) {
    CameraImpl* const camera = CAM_GetManager()->GetCamera(TokenDataOrEmpty(args.At(tokenIndex)));
    if (camera == nullptr) {
      continue;
    }

    SSelectionNodeUserEntity* const firstLiveNode = FirstLiveSelectionNode(selection);
    if (firstLiveNode == nullptr) {
      camera->TargetNothing();
      continue;
    }

    if (DecodeUserEntityFromSelectionSlot(firstLiveNode->mEnt) == camera->GetTargetEntity()) {
      camera->TargetNothing();
      continue;
    }

    camera->TargetEntities(selection, true, camera->CameraGetTargetZoom(), 0.0f);
  }
}

/**
 * Address: 0x008354B0 (FUN_008354B0, Moho::RenameUnit)
 *
 * IDA signature:
 * void __cdecl Moho::RenameUnit(std::vector_string *arg0);
 *
 * What it does:
 * `RenameUnit [name words ...]`. With no name tokens it prints the single
 * selected unit's custom name (or the localized "no custom name" line);
 * otherwise it joins every remaining token with single spaces, trims the
 * surrounding whitespace, and publishes the result as a `("CustomName", name)`
 * info pair through the sim driver. Requires exactly one selected user-unit and
 * prints the matching localized rejection otherwise.
 */
void moho::RenameUnit(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  SSelectionSetUserEntity& selection = session->mSelection;
  SSelectionNodeUserEntity* const firstLiveNode = FirstLiveSelectionNode(selection);
  if (firstLiveNode == nullptr) {
    PrintLocalizedConsoleLine(kRenameUnitSelectionRequiredLocToken);
    return;
  }

  if (selection.size() > 1) {
    PrintLocalizedConsoleLine(kRenameUnitSingleSelectionLocToken);
    return;
  }

  UserEntity* const selectedEntity = DecodeUserEntityFromSelectionSlot(firstLiveNode->mEnt);
  UserUnit* const selectedUnit = selectedEntity != nullptr ? selectedEntity->IsUserUnit() : nullptr;
  if (selectedUnit == nullptr) {
    PrintLocalizedConsoleLine(kRenameUnitSelectionRequiredLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() == 1u) {
    const msvc8::string& currentName = CustomNameStorage(selectedUnit);
    if (currentName.empty()) {
      PrintLocalizedConsoleLine(kRenameUnitNoCustomNameLocToken);
      return;
    }

    CON_Printf(kRenameUnitPrintFormat, currentName.c_str());
    return;
  }

  // The binary appends `token + " "` for every remaining token and then trims,
  // which leaves exactly the single-space join the shared helper produces.
  const msvc8::string joinedName = JoinConCommandTokens(args, 1u);
  const msvc8::string customName = gpg::STR_TrimWhitespace(joinedName.c_str());

  UserEntity* const entityView = ResolveUserEntityView(selectedUnit);
  SIM_GetActiveDriver()->ProcessInfoPair(
    reinterpret_cast<void*>(static_cast<std::uintptr_t>(entityView->mParams.mEntityId)),
    kRenameUnitInfoKey,
    customName.c_str()
  );
}

/**
 * Address: 0x008338A0 (FUN_008338A0, Moho::CON_StartCommandMode)
 * Mangled: ?CON_StartCommandMode@Moho@@YAXAAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z
 *
 * IDA signature:
 * void __cdecl Moho::CON_StartCommandMode(int commandArgs);
 *
 * What it does:
 * Console handler for the `StartCommandMode` command. When no world session
 * is active, prints the localized "<LOC _No_session>" feedback. With a
 * session and at least three argument tokens (program name, mode token, mode
 * payload tag), builds a `UICommandModeData{mode, {name=arg1}}`, compares the
 * requested mode against the currently active UI command mode, and:
 *   - if the mode matches both the active mode string and its `name` payload
 *     field, ends the current command mode through `UI_EndCommandMode`
 *     (toggle off);
 *   - otherwise resolves the mode token to an `ERuleBPUnitCommandCaps` bit
 *     through the reflection lexical setter, scans the active selection for
 *     a live user-unit that advertises that command capability, and dispatches
 *     `UI_StartCommandMode` with the new mode data when a matching unit is
 *     found.
 */
void moho::CON_StartCommandMode(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 3u) {
    return;
  }

  const msvc8::string* const modeToken = args.At(1u);
  if (modeToken == nullptr) {
    return;
  }

  // Build the requested command-mode data: mode = arg1, payload = { name = arg1 }.
  UICommandModeData requested;
  requested.mMode = modeToken->c_str();
  requested.mPayload.AssignNewTable(session->mState, 0, 0u);
  requested.mPayload.SetString("name", modeToken->c_str());

  // Read the active command mode through the UI Lua state.
  UICommandModeData active;
  UI_GetCommandMode(active);

  // When the requested mode matches both the active mode string and its
  // `name` payload field (case-insensitive), the command toggles the mode off.
  // The binary short-circuits on mode-string mismatch before touching the
  // payload table; mirror that to preserve allocation order.
  bool modesMatch = false;
  if (_stricmp(requested.mMode.c_str(), active.mMode.c_str()) == 0) {
    const char* const requestedName = requested.mPayload["name"].GetString();
    const char* const activeName = active.mPayload["name"].GetString();
    if (requestedName != nullptr && activeName != nullptr && _stricmp(requestedName, activeName) == 0) {
      modesMatch = true;
    }
  }

  if (modesMatch) {
    UI_EndCommandMode();
    return;
  }

  // Translate the requested mode name into an `ERuleBPUnitCommandCaps` bit
  // through the reflection lexical setter, then scan the selection for a live
  // user-unit that advertises that capability.
  ERuleBPUnitCommandCaps requestedCaps = static_cast<ERuleBPUnitCommandCaps>(0);
  gpg::RRef capsRef{};
  (void)gpg::RRef_ERuleBPUnitCommandCaps(&capsRef, &requestedCaps);
  (void)capsRef.mType->SetLexical(capsRef, requested.mPayload["name"].GetString());

  if (SelectionHasUnitWithCommandCap(session->mSelection, static_cast<std::uint32_t>(requestedCaps))) {
    UI_StartCommandMode(requested);
  }
}

/**
 * Address: 0x00847250 (FUN_00847250)
 *
 * What it does:
 * Invokes `CWldSession::GenerateBuildTemplates()` on the global active
 * session when it is present, then returns 0.
 */
[[maybe_unused]] int GenerateBuildTemplatesOnGlobalSessionIfPresent()
{
  if (moho::CWldSession* const activeSession = moho::WLD_GetActiveSession(); activeSession != nullptr) {
    activeSession->GenerateBuildTemplates();
  }
  return 0;
}

/**
 * Address: 0x00833E50 (FUN_00833E50, Moho::CON_DebugGenerateBuildTemplateFromSelection)
 *
 * What it does:
 * Generates build templates from current selection when a world session is
 * active; otherwise prints localized "no session" feedback.
 */
void moho::CON_DebugGenerateBuildTemplateFromSelection(void* const commandArgs)
{
  (void)commandArgs;

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    (void)session;
    (void)GenerateBuildTemplatesOnGlobalSessionIfPresent();
    return;
  }

  PrintLocalizedConsoleLine(kNoSessionLocToken);
}

/**
 * Address: 0x00833EF0 (FUN_00833EF0, Moho::CON_DebugClearBuildTemplates)
 *
 * What it does:
 * Clears build-template state when a world session is active; otherwise prints
 * localized "no session" feedback.
 */
void moho::CON_DebugClearBuildTemplates(void* const commandArgs)
{
  (void)commandArgs;

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    (void)session;
    gpg::Warnf("CON_DebugClearBuildTemplates: clear path is not recovered yet.");
    return;
  }

  PrintLocalizedConsoleLine(kNoSessionLocToken);
}

/**
 * Address: 0x00833F90 (FUN_00833F90, Moho::CON_TeleportSelectedUnits)
 *
 * What it does:
 * Teleports currently selected units owned by the focused army to cursor world
 * position, preserving orientation and applying spawn-elevation correction.
 */
void moho::CON_TeleportSelectedUnits(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    const msvc8::string noSessionText = Loc(USER_GetLuaState(), kNoSessionLocToken);
    CON_Printf(noSessionText.c_str());
    return;
  }

  UserArmy* focusArmy = nullptr;
  if (session->FocusArmy >= 0) {
    const std::size_t focusArmyIndex = static_cast<std::size_t>(session->FocusArmy);
    if (focusArmyIndex < session->userArmies.size()) {
      focusArmy = session->userArmies[focusArmyIndex];
    }
  }

  const STIMap* const terrainMap = ResolveSessionTerrainMap(session);
  ISTIDriver* const simDriver = SIM_GetActiveDriver();

  msvc8::vector<UserUnit*> selectedUnits;
  session->GetSelectionUnits(selectedUnits);

  for (UserUnit* const userUnit : selectedUnits) {
    UserEntity* const entityView = ResolveUserEntityView(userUnit);
    if (entityView->mArmy != focusArmy) {
      continue;
    }

    IUnit* const iunit = ResolveIUnitBridge(userUnit);
    VTransform destination = entityView->mVariableData.mCurTransform;
    destination.pos_ = session->CursorWorldPos;
    destination.pos_.y = IUnit::CalcSpawnElevation(
      terrainMap,
      static_cast<ELayer>(entityView->mVariableData.mLayerMask),
      destination,
      iunit->GetAttributes()
    );

    simDriver->WarpEntity(static_cast<EntId>(entityView->mParams.mEntityId), destination);
  }
}

/**
 * Address: 0x00897580 (FUN_00897580, sub_897580)
 *
 * void*
 *
 * What it does:
 * Toggles the world session's invalid-build-placement-preview flag, which
 * this command uses as a "skip UI command validation" switch. Prints
 * localized "no session" feedback when no session is active.
 *
 * The registrar (FUN_00BE77D0, `__xc_a` static-initializer lane) stores this
 * callback's address into the `CConFunc` at `stru_F5B7A4`/`dword_F5B7B0`; the
 * command's own name/description ("SkipUIChecks" / "Don't perform any
 * command validation in UI") are the struct's `.data` initializers, read
 * directly from the shipped PE.
 */
void moho::SkipUIChecks(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  session->mShowInvalidBuildPlacementPreview = !session->mShowInvalidBuildPlacementPreview;
}

/**
 * Address: 0x00897630 (FUN_00897630, sub_897630)
 *
 * void*
 *
 * What it does:
 * Restarts rendering of the current beat by zeroing the session's
 * time-since-last-tick accumulator. Prints localized "no session" feedback
 * when no session is active.
 *
 * Registrar: FUN_00BE7810 (`__xc_a` lane), name/description ("WLD_RestartBeat"
 * / "Restart rendering the current beat.") read from the PE `.data`
 * initializers of `stru_F5B7B4`/`dword_F5B7C0`.
 */
void moho::WLD_RestartBeat(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  session->mTimeSinceLastTick = 0.0f;
}

/**
 * Address: 0x008976D0 (FUN_008976D0, sub_8976D0)
 *
 * What it does:
 * Advances the sim one beat by forcing the session's time-since-last-tick
 * accumulator to a full beat interval. Prints localized "no session"
 * feedback when no session is active.
 *
 * Registrar: FUN_00BE7850 (`__xc_a` lane), name/description ("WLD_AdvanceBeat"
 * / "Advance the sim one beat.") read from the PE `.data` initializers of
 * `stru_F5B7C4`/`dword_F5B7D0`.
 */
void moho::WLD_AdvanceBeat(void* const commandArgs)
{
  (void)commandArgs;

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  session->mTimeSinceLastTick = 1.0f;
}

/**
 * Address: 0x0088E0B0 (FUN_0088E0B0, sub_88E0B0)
 *
 * What it does:
 * Single-steps the active sim driver one tick. Prints localized "no
 * session" feedback when no sim driver is active.
 *
 * The binary's raw `ISTIDriver::SingleStep` slot writes its command-cookie
 * result through an out-pointer to a scratch stack local this call site
 * never reads back; `CSimDriver::SingleStep()`'s already-recovered signature
 * (SimDriver.cpp) folds that into an ordinary return value instead, so this
 * call discards the result the same way the binary's caller effectively
 * does. Registrar: FUN_00BE7430 (`__xc_a` lane), name/description
 * ("WLD_SingleStep" / "Single-step the sim one tick.") read from the PE
 * `.data` initializers of `stru_F5B734`/`dword_F5B740`.
 */
void moho::WLD_SingleStep(void* const commandArgs)
{
  (void)commandArgs;

  ISTIDriver* const simDriver = SIM_GetActiveDriver();
  if (simDriver == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  (void)simDriver->SingleStep();
}

/**
 * Address: 0x0088E150 (FUN_0088E150, sub_88E150)
 *
 * What it does:
 * Parses one numeric argument and sets the active sim driver's requested
 * sim rate, clamped to [-10, 50]. Prints usage text for any other argument
 * count; silently no-ops when no sim driver is active. This is a wider,
 * console-only debug range than `WLD_SetGameSpeed`'s UI-facing [-10, 10]
 * clamp (CWldSession.cpp) - the two are distinct binary functions with
 * distinct bounds, not the same command recovered twice.
 *
 * Registrar: FUN_00BE7470 (`__xc_a` lane), name/description ("WLD_GameSpeed"
 * / "Set a new game speed") read from the PE `.data` initializers of
 * `stru_F5B744`/`dword_F5B750`.
 */
void moho::WLD_GameSpeed(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() != 2u) {
    CON_Printf("WLD_GameSpeed <int> - set current game speed");
    return;
  }

  ISTIDriver* const simDriver = SIM_GetActiveDriver();
  if (simDriver == nullptr) {
    return;
  }

  const msvc8::string* const rateToken = args.At(1u);
  int requestedSpeed = static_cast<int>(std::atof(TokenDataOrEmpty(rateToken)));
  if (requestedSpeed > 50) {
    requestedSpeed = 50;
  }
  if (requestedSpeed < -10) {
    requestedSpeed = -10;
  }

  simDriver->GetClientManager()->SetSimRate(requestedSpeed);
}

/**
 * Address: 0x008D3CC0 (FUN_008D3CC0, sub_8D3CC0)
 *
 * std::vector_string*
 *
 * What it does:
 * `FindUnit term...`. Lowercases every argument after the command name into
 * a scratch term list, then walks the active session's rules' unit
 * blueprint map (`RRuleGameRulesImpl::GetUnitBlueprints`, an ordinary
 * `msvc8::map<msvc8::string, void*>` - iterated in place, matching the
 * no-defensive-copy idiom `InitializeArmyUnitCategorySets` in
 * CArmyImpl.cpp already established for this exact container). A blueprint
 * matches when every lowercased term is a substring of its (also
 * lowercased) `Display.DisplayName`; each match prints `"id - displayName"`
 * and a trailing `"%d units matching"` line reports the count. Silently
 * does nothing with no active session or fewer than two arguments - the
 * binary has no localized "no session" feedback here, unlike most of this
 * file's other selection/session commands.
 *
 * Registrar: FUN_00BE95C0 (`__xc_a` lane), data-xref
 * `dword_F5BEAC = offset sub_8D3CC0` is the callsite evidence. Name is read
 * from the PE `.data` initializer of `stru_F5BEA0` ("FindUnit"); the
 * description string sits in the same struct.
 */
void moho::CON_FindUnit(void* const commandArgs)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() < 2u) {
    return;
  }

  msvc8::vector<msvc8::string> searchTermsLower;
  for (std::size_t index = 1u; index < args.Count(); ++index) {
    searchTermsLower.push_back(gpg::STR_ToLower(TokenDataOrEmpty(args.At(index))));
  }

  RRuleGameRulesImpl* const rules = session->mRules;
  int matchCount = 0;
  for (const auto& [blueprintId, blueprintPtr] : rules->GetUnitBlueprints()) {
    auto* const unitBlueprint = static_cast<RUnitBlueprint*>(blueprintPtr);
    if (unitBlueprint == nullptr) {
      continue;
    }

    const msvc8::string nameLower = gpg::STR_ToLower(unitBlueprint->Display.DisplayName.c_str());
    const bool allTermsMatch = std::all_of(
      searchTermsLower.begin(),
      searchTermsLower.end(),
      [&nameLower](const msvc8::string& term) { return std::strstr(nameLower.c_str(), term.c_str()) != nullptr; }
    );

    if (allTermsMatch) {
      CON_Printf("%s - %s", blueprintId.c_str(), unitBlueprint->Display.DisplayName.c_str());
      ++matchCount;
    }
  }

  CON_Printf("%d units matching", matchCount);

  // `msvc8::string` has no destructor by design (String.h); release each
  // term's owned heap buffer explicitly, matching the established
  // `.tidy(true, 0u)` cleanup idiom (REntityBlueprintTypeInfo.cpp,
  // LaunchInfoBase.cpp) rather than leaking non-SSO search terms.
  for (msvc8::string& term : searchTermsLower) {
    term.tidy(true, 0u);
  }
}

/**
 * Address: 0x008D4150 (FUN_008D4150, sub_8D4150)
 *
 * What it does:
 * Opens the script-debug window and binds the debug hook onto the user Lua
 * state, then onto the active world session's Lua state when a session is
 * active. `SCR_HookState` already reproduces the binary's own
 * `if (sSrcDebugWindow) lua_sethook(state, DebugLuaHook, 4, 0)` guard
 * internally (via `SCR_IsDebugWindowActive`), so this recovery does not
 * duplicate that check.
 *
 * Registrar: FUN_00BE9680 (`__xc_a` lane), data-xref
 * `dword_F5BEDC = offset sub_8D4150` is the callsite evidence. Name is read
 * from the PE `.data` initializer of `stru_F5BED0` ("SC_LuaDebugger").
 */
void moho::SC_LuaDebugger(void* const commandArgs)
{
  (void)commandArgs;

  LuaPlus::LuaState* const userLuaState = USER_GetLuaState();
  if (userLuaState == nullptr) {
    return;
  }

  SCR_CreateDebugWindow();
  SCR_HookState(userLuaState);

  CWldSession* const session = WLD_GetActiveSession();
  if (session != nullptr) {
    SCR_HookState(session->mState);
  }
}

/**
 * Address: 0x0088E440 (FUN_0088E440, sub_88E440)
 *
 * What it does:
 * See header. The binary's raw control flow (confirmed against the raw .asm,
 * 0x0088E466-0x0088E6AF - Hex-Rays' decompiled .c wrongly merges the
 * no-sim-driver branch into a fall-through of the main path):
 *   - fewer than 2 arguments: print the usage line, return;
 *   - no active sim driver: print localized "no session" feedback, return;
 *   - otherwise: walk the selection, dispatch, return (no further output).
 * The binary reads `Moho::sWldSession` unconditionally once `sSimDriver` is
 * confirmed (no separate null check), trusting the engine invariant that an
 * active driver implies an active session; this recovery adds a defensive
 * null check instead of reproducing that latent unchecked dereference,
 * falling back to an empty selection / zeroed world position and focus army
 * if the invariant is ever violated - undefined behavior avoidance per the
 * project's fidelity contract, not an observed-behavior change on any
 * reachable path.
 *
 * The dispatch's exact 4-argument mapping (command/worldPos/focusArmy/
 * entities) was reconstructed from an instruction-by-instruction
 * esp-relative trace of the call site cross-checked against the callee's
 * own prologue (`Moho::CSimDriver::ExecuteDebugCommand`, FUN_0073D1B0,
 * SimDriver.cpp): `command` is `CON_UnparseCommand`'s result c_str(),
 * `worldPos` is `session->CursorWorldPos`, `focusArmy` is
 * `session->FocusArmy`, and `entities` is a `BVSet<EntId, EntIdUniverse>`
 * built from the current selection's entity IDs. The raw call site also
 * passes a 5th, undocumented hidden out-pointer that the already-recovered
 * `ISTIDriver::ExecuteDebugCommand` wrapper folds into an ordinary `CmdId`
 * return value (unread here, matching the binary discarding it too).
 *
 * Registrar: FUN_00BE74D0 (`__xc_a` lane), data-xref
 * `dword_F5B760 = offset sub_88E440` is the callsite evidence. Name is read
 * from the PE `.data` initializer of `stru_F5B754` ("DoSimCommand").
 */
void moho::DoSimCommand(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() <= 1u) {
    CON_Printf("usage: DoSimCommand command args...");
    return;
  }

  ISTIDriver* const simDriver = SIM_GetActiveDriver();
  if (simDriver == nullptr) {
    PrintLocalizedConsoleLine(kNoSessionLocToken);
    return;
  }

  CWldSession* const session = WLD_GetActiveSession();

  BVSet<EntId, EntIdUniverse> entities{};
  msvc8::vector<msvc8::string> remainingArgs;
  Wm3::Vector3f worldPos{};
  std::uint32_t focusArmy = 0u;

  if (session != nullptr) {
    msvc8::vector<UserUnit*> selectedUnits;
    session->GetSelectionUnits(selectedUnits);
    for (UserUnit* const userUnit : selectedUnits) {
      UserEntity* const entityView = ResolveUserEntityView(userUnit);
      (void)entities.Bits().Add(entityView->mParams.mEntityId);
    }

    worldPos = session->CursorWorldPos;
    focusArmy = static_cast<std::uint32_t>(session->FocusArmy);
  }

  for (std::size_t index = 1u; index < args.Count(); ++index) {
    if (const msvc8::string* const token = args.At(index); token != nullptr) {
      remainingArgs.push_back(*token);
    }
  }

  const msvc8::string unparsedCommand = CON_UnparseCommand(remainingArgs);
  (void)simDriver->ExecuteDebugCommand(unparsedCommand.c_str(), worldPos, focusArmy, entities);
}

/**
 * Address: 0x008D3810 (FUN_008D3810, sub_8D3810)
 *
 * What it does:
 * Legacy startup callback lane for anti-aliasing command wiring: when exactly
 * two command tokens are present, forwards token `0` to
 * `d3d_AntiAliasingSamples`.
 */
[[maybe_unused]] void moho::CON_d3d_AntiAliasingSamplesSeedFromFirstToken(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() != 2u) {
    return;
  }

  const msvc8::string* const sampleToken = args.At(0u);
  if (sampleToken == nullptr) {
    return;
  }

  CON_Executef("d3d_AntiAliasingSamples %s", sampleToken->c_str());
}

/**
 * Address: 0x0043D360 (FUN_0043D360, Moho::CON_ren_MipSkipLevels)
 *
 * What it does:
 * Parses one `ren_MipSkipLevels` value argument and applies clamped
 * non-negative mip-skip state to active D3D device resources.
 */
void moho::CON_ren_MipSkipLevels(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() != 2u) {
    return;
  }

  CD3DDevice* const device = D3D_GetDevice();
  if (device == nullptr) {
    return;
  }

  ID3DDeviceResources* const resources = device->GetResources();
  if (resources == nullptr) {
    return;
  }

  const int requestedMipSkip = ParseIntToken(args.At(1));
  resources->SetSkipMipLevels(requestedMipSkip >= 0 ? requestedMipSkip : 0);
}

/**
 * Address: 0x0043D400 (FUN_0043D400, Moho::CON_DumpPreloadedTextures)
 *
 * What it does:
 * Opens `PreloadedTextures.txt`, asks active D3D resources to dump preloaded
 * texture state into it, then closes the stream.
 */
void moho::CON_DumpPreloadedTextures(void* const commandArgs)
{
  (void)commandArgs;

  CD3DDevice* const device = D3D_GetDevice();
  if (device == nullptr) {
    return;
  }

  ID3DDeviceResources* const resources = device->GetResources();
  if (resources == nullptr) {
    return;
  }

  gpg::FileStream stream("PreloadedTextures.txt", gpg::Stream::ModeSend, 0U, 4096);
  resources->DumpPreloadedTextures(&stream);
  stream.VirtClose(gpg::Stream::ModeBoth);
}

// `gpg::gal::sMeshAllowInstancing`/`sMeshAllowFloat16`
// (gpg/gal/backends/d3d9/D3D9Interfaces.cpp) - the binary's `mesh_Rebatch`
// body writes these two bytes directly, not through an accessor, so this TU
// needs the same direct access. No owning header exists for the D3D9 backend
// TU's globals yet, so they are declared `extern` here where they are
// written, matching the pattern already used elsewhere in this codebase for
// globals without a home header.
namespace gpg::gal
{
  extern std::uint8_t sMeshAllowFloat16;
  extern std::uint8_t sMeshAllowInstancing;
} // namespace gpg::gal

/**
 * Address: 0x007EC220 (FUN_007EC220, Moho::CON_mesh_Rebatch)
 *
 * What it does:
 * `mesh_Rebatch <allowInstancing> <allowFloat16>` console command - see the
 * declaration.
 */
void moho::CON_mesh_Rebatch(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() != 3u) {
    CON_Printf("usage: mesh_Rebatch [allowInstancing] [allowFloat16]");
    return;
  }

  gpg::gal::sMeshAllowInstancing = TokenEq(args.At(1), "true") ? 1U : 0U;
  gpg::gal::sMeshAllowFloat16 = TokenEq(args.At(2), "true") ? 1U : 0U;

  REN_ResetHardwareVertexFormatter();
  MeshRenderer::GetInstance()->Reset();
}

namespace
{
  /**
   * Address: 0x0066A2A0 (FUN_0066A2A0, sub_66A2A0)
   *
   * IDA signature:
   * void __usercall sub_66A2A0(moho::ManagedWindowSlot *slot@<eax>, moho::WWinManagedFrame *frame@<ecx>);
   *
   * What it does:
   * Rebinds one managed-window slot onto `frame`'s intrusive owner-chain head
   * (`WWinManagedFrame::mManagedSlotsHead`, +0x178 - the `lea edx, [ecx+178h]`
   * at 0x0066A2A4): returns immediately when the slot is already bound there,
   * otherwise splices the slot out of whatever chain currently holds it and
   * pushes it at the head of the new one. A null `frame` leaves the slot
   * bound to nothing.
   *
   * This is the per-translation-unit emission the linker kept for
   * `EFX_CreateEmitterWindow`'s scoped frame handle; the wx runtime carries
   * its own sibling emission for the `managedWindows`/`managedFrames`
   * registry vectors.
   */
  void RebindManagedWindowSlotToFrame(moho::ManagedWindowSlot& slot, moho::WWinManagedFrame* const frame) noexcept
  {
    moho::ManagedWindowSlot** const ownerHeadLink = frame != nullptr ? &frame->mManagedSlotsHead : nullptr;
    if (slot.ownerHeadLink == ownerHeadLink) {
      return;
    }

    if (slot.ownerHeadLink != nullptr) {
      // 0x0066A2B8..0x0066A2CD: the detach walk assumes the slot really is in
      // the chain its owner link names, exactly as the binary does.
      moho::ManagedWindowSlot** link = slot.ownerHeadLink;
      while (*link != &slot) {
        link = &(*link)->nextInOwnerChain;
      }
      *link = slot.nextInOwnerChain;
    }

    slot.ownerHeadLink = ownerHeadLink;
    if (ownerHeadLink == nullptr) {
      slot.nextInOwnerChain = nullptr;
      return;
    }

    slot.nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = &slot;
  }

  /**
   * Scoped managed-window handle on one `WWinManagedFrame`.
   *
   * `EFX_CreateEmitterWindow` keeps its freshly built editor frame alive
   * through a stack-local slot bound into the frame's own owner chain, and
   * unlinks it again on the way out - including on unwind, which is what the
   * function's SEH state-0 funclet at 0x00BAD130 does.
   */
  class ScopedManagedFrameHandle
  {
  public:
    explicit ScopedManagedFrameHandle(moho::WWinManagedFrame* const frame) noexcept
    {
      RebindManagedWindowSlotToFrame(mSlot, frame);
    }

    ScopedManagedFrameHandle(const ScopedManagedFrameHandle&) = delete;
    ScopedManagedFrameHandle& operator=(const ScopedManagedFrameHandle&) = delete;

    ~ScopedManagedFrameHandle() noexcept
    {
      mSlot.UnlinkFromOwner();
    }

    /** 0x0066A00C..0x0066A01E: `ownerHeadLink - 0x178`, or null when unbound. */
    [[nodiscard]] moho::WWinManagedFrame* Get() const noexcept
    {
      return moho::WWinManagedFrame::FromManagedSlotHeadLink(mSlot.ownerHeadLink);
    }

  private:
    moho::ManagedWindowSlot mSlot{};
  };

  /**
   * Resolves the first still-live `UserEntity` held by one session selection
   * set, or null when the selection has none left.
   *
   * 0x00669F14..0x00669F58 runs the tombstone-pruning `find` twice: once to
   * test the set against its head sentinel and once more to read the surviving
   * node's weak owner-link slot back into an entity pointer.
   */
  [[nodiscard]] moho::UserEntity* FirstLiveSelectedUserEntity(moho::SSelectionSetUserEntity& selection)
  {
    if (selection.IsEmptyFromHeadFind()) {
      return nullptr;
    }

    moho::SSelectionNodeUserEntity* liveNode = nullptr;
    (void)moho::SSelectionSetUserEntity::find(&selection, selection.mHead->mLeft, &liveNode);
    return liveNode != nullptr ? DecodeUserEntityFromSelectionSlot(liveNode->mEnt) : nullptr;
  }
} // namespace

/**
 * Address: 0x00669EB0 (FUN_00669EB0, Moho::EFX_CreateEmitterWindow)
 *
 * IDA signature:
 * void __cdecl Moho::EFX_CreateEmitterWindow(std::vector_string *commandArgs);
 *
 * What it does:
 * `EFX_CreateEmitterWindow [boneName]` console command - see the declaration.
 * The attach target is resolved before the arguments are even looked at
 * (0x00669EDF..0x00669F58) and the attached form is only taken when the
 * argument vector carries a bone-name token *and* that target survived; every
 * other combination opens the free-standing editor at the same cursor world
 * position.
 */
void moho::EFX_CreateEmitterWindow(void* const commandArgs)
{
  // 0x00669EDF: the binary loads the active-session global and dereferences it
  // straight away - this command is only reachable from an in-session console.
  CWldSession& session = *WLD_GetActiveSession();

  const Wm3::Vector3f spawnPosition = session.CursorWorldPos;
  UserEntity* const attachEntity = FirstLiveSelectedUserEntity(session.mSelection);

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

  WEmitterWx* const editor = (args.Count() > 1u && attachEntity != nullptr)
    ? new WEmitterWx(attachEntity, spawnPosition, args.At(1u)->c_str())
    : new WEmitterWx(nullptr, spawnPosition, nullptr);

  const ScopedManagedFrameHandle editorHandle(editor);
  (void)editorHandle.Get()->Show(true);
}

namespace
{
  int RunConTextMatchesLuaCallback(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kConTextMatchesHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject prefixStack(state, 1);
    const char* const prefix = lua_tostring(rawState, 1);
    if (prefix == nullptr) {
      prefixStack.TypeError("string");
    }

    msvc8::vector<msvc8::string> matches = CON_GetFindTextMatches(prefix);

    LuaPlus::LuaObject resultTable(state);
    resultTable.AssignNewTable(state, 0, static_cast<int>(matches.size()));
    int luaIndex = 1;
    for (const msvc8::string& match : matches) {
      resultTable.SetString(luaIndex, match.c_str());
      ++luaIndex;
    }

    resultTable.PushStack(state);
    return 1;
  }

  template <void (*TExecutor)(const char*)>
  int RunConExecuteLuaCallback(LuaPlus::LuaState* const state, const char* const helpText)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        helpText != nullptr ? helpText : "",
        1,
        argumentCount
      );
    }

    const char* const commandText = luaL_checkstring(rawState, 1);
    TExecutor(commandText);
    return 0;
  }
} // namespace

/**
 * Address: 0x0083DB10 (FUN_0083DB10, cfunc_ConTextMatchesL)
 *
 * What it does:
 * Returns a Lua table of console-command text matches for one input prefix.
 */
int moho::cfunc_ConTextMatchesL(LuaPlus::LuaState* const state)
{
  return RunConTextMatchesLuaCallback(state);
}

/**
 * Address: 0x0083DA90 (FUN_0083DA90, cfunc_ConTextMatches)
 *
 * What it does:
 * Lua callback thunk from `lua_State*` context to `LuaPlus::LuaState*`.
 */
int moho::cfunc_ConTextMatches(lua_State* const luaContext)
{
  return cfunc_ConTextMatchesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083DAB0 (FUN_0083DAB0, func_ConTextMatches_LuaFuncDef)
 *
 * What it does:
 * Creates/returns Lua binder for global `ConTextMatches`.
 */
moho::CScrLuaInitForm* moho::func_ConTextMatches_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ConTextMatches",
    &moho::cfunc_ConTextMatches,
    nullptr,
    "<global>",
    kConTextMatchesHelpText
  );
  return &binder;
}

/**
 * Address: 0x0041CBE0 (FUN_0041CBE0, cfunc_ConExecuteL)
 *
 * What it does:
 * Validates one string argument and executes it as a console command.
 */
int moho::cfunc_ConExecuteL(LuaPlus::LuaState* const state)
{
  return RunConExecuteLuaCallback<&moho::CON_Execute>(state, kConExecuteHelpText);
}

/**
 * Address: 0x0041CB60 (FUN_0041CB60, cfunc_ConExecute)
 *
 * What it does:
 * Lua callback thunk from `lua_State*` context to `LuaPlus::LuaState*`.
 */
int moho::cfunc_ConExecute(lua_State* const luaContext)
{
  return cfunc_ConExecuteL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0041D200 (FUN_0041D200, cfunc_ConExecuteSaveL)
 *
 * What it does:
 * Validates one string argument and executes it through save+execute path.
 */
int moho::cfunc_ConExecuteSaveL(LuaPlus::LuaState* const state)
{
  return RunConExecuteLuaCallback<&moho::CON_ExecuteSave>(state, kConExecuteSaveHelpText);
}

/**
 * Address: 0x0041D180 (FUN_0041D180, cfunc_ConExecuteSave)
 *
 * What it does:
 * Lua callback thunk from `lua_State*` context to `LuaPlus::LuaState*`.
 */
int moho::cfunc_ConExecuteSave(lua_State* const luaContext)
{
  return cfunc_ConExecuteSaveL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0041CB80 (FUN_0041CB80, func_ConExecute_LuaFuncDef)
 *
 * What it does:
 * Creates/returns Lua binder for global `ConExecute`.
 */
moho::CScrLuaInitForm* moho::func_ConExecute_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ConExecute",
    &moho::cfunc_ConExecute,
    nullptr,
    "<global>",
    kConExecuteHelpText
  );
  return &binder;
}

/**
 * Address: 0x0041D1A0 (FUN_0041D1A0, func_ConExecuteSave_LuaFuncDef)
 *
 * What it does:
 * Creates/returns Lua binder for global `ConExecuteSave`.
 */
moho::CScrLuaInitForm* moho::func_ConExecuteSave_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ConExecuteSave",
    &moho::cfunc_ConExecuteSave,
    nullptr,
    "<global>",
    kConExecuteSaveHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC38B0 (FUN_00BC38B0, register_ConExecute_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_ConExecute_LuaFuncDef()
{
  return func_ConExecute_LuaFuncDef();
}

/**
 * Address: 0x00BC38C0 (FUN_00BC38C0, register_ConExecuteSave_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_ConExecuteSave_LuaFuncDef()
{
  return func_ConExecuteSave_LuaFuncDef();
}

namespace
{
  /**
   * Address: 0x00BEEAF0 (FUN_00BEEAF0, sub_BEEAF0)
   *
   * What it does:
   * Destroys and releases saved-console-command string storage and resets
   * vector pointer lanes to null.
   */
  void cleanup_console_command_buffer()
  {
    // Per-element ~string(), free, null the three lanes: VC8 _Tidy().
    gSavedConsoleCommands = msvc8::vector<msvc8::string>{};
  }
} // namespace

/**
 * Address: 0x00BC3890 (FUN_00BC3890, register_console_command_buffer)
 *
 * What it does:
 * Registers process-exit cleanup for saved console-command history storage.
 */
void moho::register_console_command_buffer()
{
  (void)std::atexit(&cleanup_console_command_buffer);
}

/**
 * Address: 0x0041F9C0 (FUN_0041F9C0, sub_41F9C0)
 * Address: 0x1001ED50 (FUN_1001ED50)
 *
 * What it does:
 * Dispatches bool convar command parsing and mutation.
 */
template <>
void moho::TConVar<bool>::Handle(void* commandArgs)
{
  HandleBoolConVarCommand(GetConCommandArgsView(commandArgs), mName, ValuePtr());
}

/**
 * Address: 0x0041FA10 (FUN_0041FA10, sub_41FA10)
 * Address: 0x1001EDB0 (FUN_1001EDB0)
 *
 * What it does:
 * Handles int convar command; prints current value when no RHS command args are provided.
 */
template <>
void moho::TConVar<int>::Handle(void* commandArgs)
{
  int* const value = ValuePtr();
  if (value == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() >= 2) {
    HandleIntConVarCommand(args, value);
  } else {
    gpg::Logf("int %s == %d", mName ? mName : "", *value);
  }
}

/**
 * Address: 0x0041FAC0 (FUN_0041FAC0, sub_41FAC0)
 * Address: 0x1001EE50 (FUN_1001EE50)
 *
 * What it does:
 * Handles uint8 convar command; prints current value when no RHS command args are provided.
 */
template <>
void moho::TConVar<std::uint8_t>::Handle(void* commandArgs)
{
  std::uint8_t* const value = ValuePtr();
  if (value == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() >= 2) {
    HandleUInt8ConVarCommand(args, value);
  } else {
    gpg::Logf("uint8 %s == %d", mName ? mName : "", static_cast<int>(*value));
  }
}

/**
 * Address: 0x0041FB50 (FUN_0041FB50, sub_41FB50)
 * Address: 0x1001EEF0 (FUN_1001EEF0)
 *
 * What it does:
 * Handles float convar command; prints current value when no RHS command args are provided.
 */
template <>
void moho::TConVar<float>::Handle(void* commandArgs)
{
  float* const value = ValuePtr();
  if (value == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() >= 2) {
    HandleFloatConVarCommand(args, value);
  } else {
    gpg::Logf("float %s == %.4f", mName ? mName : "", *value);
  }
}

/**
 * Address: 0x007FDE00 (FUN_007FDE00, Moho::TConVar_uint::Process)
  * Alias of FUN_103C8880 (non-canonical helper lane).
 *
 * What it does:
 * Handles uint32 convar command; prints current value when no RHS command args are provided.
 */
template <>
void moho::TConVar<std::uint32_t>::Handle(void* commandArgs)
{
  std::uint32_t* const value = ValuePtr();
  if (value == nullptr) {
    return;
  }

  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() >= 2) {
    HandleUInt32ConVarCommand(args, value);
  } else {
    CON_Printf("uint32 %s == %u (%x)", mName ? mName : "", *value, *value);
  }
}

/**
 * Address: 0x0041FBE0 (FUN_0041FBE0, sub_41FBE0)
 * Address: 0x1001EF90 (FUN_1001EF90)
 *
 * What it does:
 * Handles string convar command assignment and value display.
 */
template <>
void moho::TConVar<msvc8::string>::Handle(void* commandArgs)
{
  HandleStringConVarCommand(GetConCommandArgsView(commandArgs), mName, ValuePtr());
}

namespace
{
  constexpr const char* kConsoleStartupTestVarDescription = "Test variable - not used.";
  constexpr const char* kConsoleStartupGraphicsFidelityDescription = "Graphics fidelity level.";
  constexpr const char* kConsoleStartupGraphicsFidelitySupportedDescription = "Supported graphics fidelity levels.";
  constexpr const char* kConsoleStartupShadowFidelityDescription = "Shadow fidelity level.";
  constexpr const char* kConsoleStartupShadowFidelitySupportedDescription = "Supported shadow fidelity levels.";
  constexpr const char* kConsoleStartupD3DUseRefRastDescription = "Force D3D reference rasterizer.";
  constexpr const char* kConsoleStartupD3DForceSoftwareVPDescription = "Force D3D software vertex processing.";
  constexpr const char* kConsoleStartupD3DNoPureDeviceDescription = "Disable D3D pure device usage.";
  constexpr const char* kConsoleStartupD3DForceDirect3DDebugDescription = "Enable D3D debug runtime usage.";
  constexpr const char* kConsoleStartupD3DWindowsCursorDescription = "Use the Windows cursor in D3D mode.";
  constexpr const char* kConsoleStartupSndExtraDoWorkCallsDescription = "Enable extra audio-engine do-work calls.";
  constexpr const char* kConsoleStartupConEchoDescription = "Echo command arguments to console output.";
  constexpr const char* kConsoleStartupConListCommandsDescription = "List all registered console commands.";
  constexpr const char* kConsoleStartupConLuaDocDescription = "Dump Lua API binder docs.";
  constexpr const char* kConsoleStartupConLuaDescription = "Execute one Lua command line in the user Lua state.";
  constexpr const char* kConsoleStartupConExecutePasteBufferDescription =
    "Execute UTF-8 clipboard text as a Lua chunk.";
  constexpr const char* kConsoleStartupConUiResetViewDescription = "Reset one or more named cameras.";
  constexpr const char* kConsoleStartupConInBindKeyDescription =
    "Specify a key combo and a console command, binds console command to key";
  constexpr const char* kConsoleStartupConGetVersionDescription = "Print current engine version text.";
  constexpr const char* kConsoleStartupConExecuteLastCommandDescription = "Execute the most recently saved command.";
  constexpr const char* kConsoleStartupConPrintStatsDescription = "Print the selected engine stats subtree.";
  constexpr const char* kConsoleStartupConClearStatsDescription = "Clear a selected engine stats subtree.";
  constexpr const char* kConsoleStartupConBeginLoggingStatsDescription = "Begin engine stats logging.";
  constexpr const char* kConsoleStartupConEndLoggingStatsDescription = "End engine stats logging.";
  constexpr const char* kConsoleStartupConD3DAntiAliasingSamplesDescription = "Set D3D anti-aliasing sample count.";
  constexpr const char* kConsoleStartupConRenMipSkipLevelsDescription = "Set D3D texture mip-skip levels.";
  constexpr const char* kConsoleStartupConDumpPreloadedTexturesDescription =
    "Dump preloaded D3D texture list to PreloadedTextures.txt.";
  constexpr const char* kConsoleStartupConLogDescription = "Emit one info-severity log line.";
  constexpr const char* kConsoleStartupConDebugWarnDescription = "Emit one warning-severity log line.";
  constexpr const char* kConsoleStartupConDebugErrorDescription = "Terminate engine with one debug error line.";
  constexpr const char* kConsoleStartupConDebugAssertDescription = "Invoke debug assert command callback.";
  constexpr const char* kConsoleStartupConDebugCrashDescription = "Force an intentional debug crash.";
  constexpr const char* kConsoleStartupConDebugThrowDescription = "Throw one debug exception.";
  constexpr const char* kConsoleStartupConStartCommandModeDescription =
    "Start/toggle a UI command mode (e.g. RULEUCC_Move) for the active selection.";
  constexpr const char* kConsoleStartupConDebugGenerateBuildTemplateDescription =
    "Generate build templates from current selection.";
  constexpr const char* kConsoleStartupConDebugClearBuildTemplatesDescription =
    "Clear all generated build templates.";
  constexpr const char* kConsoleStartupConCreatePropDescription = "Spawn one prop at cursor world position.";
  // Command name/description pairs below are the exact `.data` initializers the
  // binary stores in each `CConFunc` global (the registrar only writes the
  // vftable and callback words); read back from `ForgedAlliance.exe` at the
  // global's `+0x04`/`+0x08` lanes.
  constexpr const char* kConsoleStartupConCreateUnitDescription =
    "spawn a unit by id at the mouse cursor or specified location, case sensitive";
  constexpr const char* kConsoleStartupConLotsOfPropsDescription =
    "spawn 100 props all over the map 2nd Arg = name of prop";
  constexpr const char* kConsoleStartupConKillSelectedUnitsDescription = "kill selected units.";
  constexpr const char* kConsoleStartupConDestroySelectedUnitsDescription = "destroy selected units.";
  constexpr const char* kConsoleStartupConCopySelectedUnitsToClipboardDescription =
    "copy selected units as a CreateUnitAtMouse Lua script to the clipboard.";
  /// 0x00E4B6D8, the `.data` initializer of `Moho::CConFunc_AddSplat` (read
  /// directly from the shipped exe, matching this file's established
  /// `.data`-readback convention for these description constants).
  constexpr const char* kConsoleStartupConAddSplatDescription = "Add a splat to the world underneath the cursor";
  constexpr const char* kConsoleStartupConProcessInfoPairDescription =
    "set the assist mode flag for the selected units.";
  constexpr const char* kConsoleStartupConUITrackUnitDescription = "track selected units.";
  constexpr const char* kConsoleStartupConRenameUnitDescription =
    "Give selected unit a custom name, or with no parameters print name";
  constexpr const char* kConsoleStartupConIssueCommandDescription =
    "Issue a fixed unit command (Stop/Pause/Dive/SiloBuildTactical/SiloBuildNuke) to the current selection.";
  constexpr const char* kConsoleStartupConMeshRebatchDescription =
    "Toggle hardware mesh-batching capability flags (instancing, float16) and rebuild mesh render state.";
  /// 0x00F59EDC, the `.data` initializer of `Moho::CConFunc_EFX_CreateEmitterWindow`.
  constexpr const char* kConsoleStartupConEfxCreateEmitterWindowDescription = "Create emitter control window";
  constexpr const char* kConsoleStartupConP4EditDescription = "Perforce edit bridge command (unsupported in this build).";
  constexpr const char* kConsoleStartupConP4IsOpenedForEditDescription =
    "Perforce opened-for-edit query command (unsupported in this build).";
  constexpr const char* kConsoleStartupConExitDescription = "Exit the application.";
  constexpr const char* kConsoleStartupConWinToggleLogDialogDescription = "Toggle the log dialog.";
  constexpr const char* kConsoleStartupConWinShowLogDialogDescription = "Show the log dialog.";
  constexpr const char* kConsoleStartupConWxInputBoxDescription = "Open the wx input box.";
  constexpr const char* kConsoleStartupReconDebugDescription = "Army index for recon debug rendering output.";
  constexpr const char* kConsoleStartupRuleParanoidDescription =
    "Paranoid-mode flag controlling rule-driven defensive runtime checks.";
  constexpr const char* kConsoleStartupRuleBlueprintReloadDelayDescription =
    "Minimum delay in seconds between blueprint hot-reload probes.";
  /// 0x00E3C758, the `.data` initializer of `Moho::CConFunc_ANI_DumpSkeleton` (+0x08).
  constexpr const char* kConsoleStartupConAniDumpSkeletonDescription = "Dump the skeleton for the selected entity";

  CConFunc gCConFunc_CON_Echo{};
  CConFunc gCConFunc_CON_ListCommands{};
  CConFunc gCConFunc_PrintStats{};
  CConFunc gCConFunc_ClearStats{};
  CConFunc gCConFunc_BeginLoggingStats{};
  CConFunc gCConFunc_EndLoggingStats{};
  CConFunc gCConFunc_LUADOC{};
  CConFunc gCConFunc_LUA{};
  CConFunc gCConFunc_ExecutePasteBuffer{};
  CConFunc gCConFunc_UI_ResetView{};
  CConFunc gCConFunc_IN_BindKey{};
  CConFunc gCConFunc_GetVersion{};
  CConFunc gCConFunc_CON_ExecuteLastCommand{};
  CConFunc gCConFunc_ANI_DumpSkeleton{};
  CConFunc gCConFunc_d3d_AntiAliasingSamples{};
  CConFunc gCConFunc_ren_MipSkipLevels{};
  CConFunc gCConFunc_DumpPreloadedTextures{};
  CConFunc gCConFunc_Log{};
  CConFunc gCConFunc_Debug_Warn{};
  CConFunc gCConFunc_Debug_Error{};
  CConFunc gCConFunc_Debug_Assert{};
  CConFunc gCConFunc_Debug_Crash{};
  CConFunc gCConFunc_Debug_Throw{};
  CConFunc gCConFunc_StartCommandMode{};
  CConFunc gCConFunc_DebugGenerateBuildTemplateFromSelection{};
  CConFunc gCConFunc_DebugClearBuildTemplates{};
  CConFunc gCConFunc_CreateProp{};
  CConFunc gCConFunc_CreateUnit{};
  CConFunc gCConFunc_LotsOfProps{};
  CConFunc gCConFunc_KillSelectedUnits{};
  CConFunc gCConFunc_DestroySelectedUnits{};
  CConFunc gCConFunc_CopySelectedUnitsToClipboard{};
  CConFunc gCConFunc_AddSplat{};
  CConFunc gCConFunc_ProcessInfoPair{};
  CConFunc gCConFunc_UI_TrackUnit{};
  CConFunc gCConFunc_RenameUnit{};
  CConFunc gCConFunc_SkipUIChecks{};
  CConFunc gCConFunc_WLD_RestartBeat{};
  CConFunc gCConFunc_WLD_AdvanceBeat{};
  CConFunc gCConFunc_WLD_SingleStep{};
  CConFunc gCConFunc_WLD_GameSpeed{};
  CConFunc gCConFunc_FindUnit{};
  CConFunc gCConFunc_SC_LuaDebugger{};
  CConFunc gCConFunc_DoSimCommand{};
  CConFunc gCConFunc_IssueCommand{};
  CConFunc gCConFunc_mesh_Rebatch{};
  CConFunc gCConFunc_EFX_CreateEmitterWindow{};
  CConFunc gCConFunc_p4_Edit{};
  CConFunc gCConFunc_p4_IsOpenedForEdit{};
  CConFunc gCConFunc_exit{};
  CConFunc gCConFunc_WIN_ToggleLogDialog{};
  CConFunc gCConFunc_WIN_ShowLogDialog{};
  CConFunc gCConFunc_WxInputBox{};

  TConVar<bool> gTConVar_con_TestVarBool(
    "con_TestVarBool",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarBool
  );
  TConVar<int> gTConVar_con_TestVar("con_TestVar", kConsoleStartupTestVarDescription, &moho::con_TestVar);
  TConVar<float> gTConVar_con_TestVarFloat(
    "con_TestVarFloat",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarFloat
  );
  TConVar<msvc8::string> gTConVar_con_TestVarStr(
    "con_TestVarStr",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarStr
  );
  TConVar<int> gTConVar_recon_debug("recon_debug", kConsoleStartupReconDebugDescription, &moho::recon_debug);
  /**
   * Address: 0x00BF3950 (FUN_00BF3950, Moho::TConVar_rule_Paranoid::~TConVar_rule_Paranoid)
   *
   * The implicit `~TConVar<int>()` destructor runs at process exit on this
   * global, chaining through `~CConCommand` to reset the vftable and (when a
   * name lane is still set) reregister the slot via `CON_ReregisterCom`. The
   * binary records this teardown as a per-instance generated dtor.
   */
  TConVar<int> gTConVar_rule_Paranoid(
    "rule_Paranoid",
    kConsoleStartupRuleParanoidDescription,
    &moho::rule_Paranoid
  );

  /**
   * Address: 0x00BF3980 (FUN_00BF3980, Moho::TConVar_rule_BlueprintReloadDelay::~TConVar_rule_BlueprintReloadDelay)
   *
   * The implicit `~TConVar<float>()` destructor runs at process exit on this
   * global, mirroring the same `~CConCommand`-driven teardown shape as the
   * other recovered rule-bucket convars.
   */
  TConVar<float> gTConVar_rule_BlueprintReloadDelay(
    "rule_BlueprintReloadDelay",
    kConsoleStartupRuleBlueprintReloadDelayDescription,
    &moho::rule_BlueprintReloadDelay
  );
  TConVar<int> gTConVar_graphics_Fidelity(
    "graphics_Fidelity",
    kConsoleStartupGraphicsFidelityDescription,
    &moho::graphics_Fidelity
  );
  TConVar<int> gTConVar_graphics_FidelitySupported(
    "graphics_FidelitySupported",
    kConsoleStartupGraphicsFidelitySupportedDescription,
    &moho::graphics_FidelitySupported
  );
  TConVar<int> gTConVar_shadow_Fidelity(
    "shadow_Fidelity",
    kConsoleStartupShadowFidelityDescription,
    &moho::shadow_Fidelity
  );
  TConVar<int> gTConVar_shadow_FidelitySupported(
    "shadow_FidelitySupported",
    kConsoleStartupShadowFidelitySupportedDescription,
    &moho::shadow_FidelitySupported
  );
  TConVar<bool> gTConVar_d3d_UseRefRast(
    "d3d_UseRefRast",
    kConsoleStartupD3DUseRefRastDescription,
    &moho::d3d_UseRefRast
  );
  TConVar<bool> gTConVar_d3d_ForceSoftwareVP(
    "d3d_ForceSoftwareVP",
    kConsoleStartupD3DForceSoftwareVPDescription,
    &moho::d3d_ForceSoftwareVP
  );
  TConVar<bool> gTConVar_d3d_NoPureDevice(
    "d3d_NoPureDevice",
    kConsoleStartupD3DNoPureDeviceDescription,
    &moho::d3d_NoPureDevice
  );
  TConVar<bool> gTConVar_d3d_ForceDirect3DDebugEnabled(
    "d3d_ForceDirect3DDebugEnabled",
    kConsoleStartupD3DForceDirect3DDebugDescription,
    &moho::d3d_ForceDirect3DDebugEnabled
  );
  TConVar<bool> gTConVar_d3d_WindowsCursor(
    "d3d_WindowsCursor",
    kConsoleStartupD3DWindowsCursorDescription,
    &moho::d3d_WindowsCursor
  );
  TConVar<bool> gTConVar_snd_ExtraDoWorkCalls(
    "snd_ExtraDoWorkCalls",
    kConsoleStartupSndExtraDoWorkCallsDescription,
    &moho::snd_ExtraDoWorkCalls
  );

  // `CleanupStartupConCommand` / `RegisterStartupConVar` now live in
  // CConCommand.h so every subsystem's registration translation unit shares one
  // definition instead of re-emitting a private copy. The `register_*` /
  // `cleanup_*` bodies below sit in `namespace moho` and pick them up by
  // ordinary unqualified lookup.

  void RegisterStartupConFunc(
    CConFunc& conFunc,
    const char* const description,
    const char* const name,
    const CConFunc::Callback callback,
    void (*cleanupFn)()
  ) noexcept
  {
    conFunc.InitializeRecovered(description, name, callback);
    (void)std::atexit(cleanupFn);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF1C20 (FUN_00BF1C20, ??1CConFunc_p4_Edit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `p4_Edit`.
   */
  void cleanup_CConFunc_p4_Edit()
  {
    CleanupStartupConCommand(gCConFunc_p4_Edit);
  }

  /**
   * Address: 0x00C03F00 (FUN_00C03F00, ??1CConFunc_mesh_Rebatch@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `mesh_Rebatch`.
   */
  void cleanup_CConFunc_mesh_Rebatch()
  {
    CleanupStartupConCommand(gCConFunc_mesh_Rebatch);
  }

  /**
   * Address: 0x00BE0A20 (FUN_00BE0A20, register_CConFunc_mesh_Rebatch)
   *
   * What it does:
   * Registers startup console callback for `mesh_Rebatch`. The store
   * `Moho__CConFunc_mesh_Rebatch.mFunc = offset Moho__CON_mesh_Rebatch` is the
   * only reference to `Moho::CON_mesh_Rebatch` anywhere in the image.
   */
  void register_CConFunc_mesh_Rebatch()
  {
    RegisterStartupConFunc(
      gCConFunc_mesh_Rebatch,
      kConsoleStartupConMeshRebatchDescription,
      "mesh_Rebatch",
      &moho::CON_mesh_Rebatch,
      &cleanup_CConFunc_mesh_Rebatch
    );
  }

  /**
   * Address: 0x00BFBF50 (FUN_00BFBF50, ??1CConFunc_EFX_CreateEmitterWindow@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `EFX_CreateEmitterWindow`.
   */
  void cleanup_CConFunc_EFX_CreateEmitterWindow()
  {
    CleanupStartupConCommand(gCConFunc_EFX_CreateEmitterWindow);
  }

  /**
   * Address: 0x00BD44C0 (FUN_00BD44C0, register_CConFunc_EFX_CreateEmitterWindow)
   *
   * What it does:
   * Registers the startup console callback for `EFX_CreateEmitterWindow`. The
   * store `Moho__CConFunc_EFX_CreateEmitterWindow.mFunc = offset
   * Moho__EFX_CreateEmitterWindow` at 0x00BD44E0 is the only reference to
   * `Moho::EFX_CreateEmitterWindow` anywhere in the image. Name and
   * description are the `.data` initializers the global already carries at
   * `+0x04`/`+0x08` (0x00F59ED8 / 0x00F59EDC).
   */
  void register_CConFunc_EFX_CreateEmitterWindow()
  {
    RegisterStartupConFunc(
      gCConFunc_EFX_CreateEmitterWindow,
      kConsoleStartupConEfxCreateEmitterWindowDescription,
      "EFX_CreateEmitterWindow",
      &moho::EFX_CreateEmitterWindow,
      &cleanup_CConFunc_EFX_CreateEmitterWindow
    );
  }

  /**
   * Address: 0x00BC76F0 (FUN_00BC76F0, register_CConFunc_p4_Edit)
   *
   * What it does:
   * Registers startup console callback for `p4_Edit`.
   */
  void register_CConFunc_p4_Edit()
  {
    RegisterStartupConFunc(
      gCConFunc_p4_Edit,
      kConsoleStartupConP4EditDescription,
      "p4_Edit",
      &moho::CON_p4_Edit,
      &cleanup_CConFunc_p4_Edit
    );
  }

  /**
   * Address: 0x00BF1C50 (FUN_00BF1C50, ??1CConFunc_p4_IsOpenedForEdit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `p4_IsOpenedForEdit`.
   */
  void cleanup_CConFunc_p4_IsOpenedForEdit()
  {
    CleanupStartupConCommand(gCConFunc_p4_IsOpenedForEdit);
  }

  /**
   * Address: 0x00BC7730 (FUN_00BC7730, register_CConFunc_p4_IsOpenedForEdit)
   *
   * What it does:
   * Registers startup console callback for `p4_IsOpenedForEdit`.
   */
  void register_CConFunc_p4_IsOpenedForEdit()
  {
    RegisterStartupConFunc(
      gCConFunc_p4_IsOpenedForEdit,
      kConsoleStartupConP4IsOpenedForEditDescription,
      "p4_IsOpenedForEdit",
      &moho::CON_p4_IsOpenedForEdit,
      &cleanup_CConFunc_p4_IsOpenedForEdit
    );
  }

  /**
   * Address: 0x00C08250 (FUN_00C08250, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SkipUIChecks`.
   */
  void cleanup_CConFunc_SkipUIChecks()
  {
    CleanupStartupConCommand(gCConFunc_SkipUIChecks);
  }

  /**
   * Address: 0x00BE77D0 (FUN_00BE77D0, register_CConFunc_SkipUIChecks)
   *
   * What it does:
   * Registers startup console callback for `SkipUIChecks`. The store
   * `dword_F5B7B0 = offset sub_897580` at 0x00BE77DC is the only reference to
   * `Moho::SkipUIChecks` anywhere in the image.
   */
  void register_CConFunc_SkipUIChecks()
  {
    RegisterStartupConFunc(
      gCConFunc_SkipUIChecks,
      kConsoleStartupSkipUIChecksDescription,
      "SkipUIChecks",
      &moho::SkipUIChecks,
      &cleanup_CConFunc_SkipUIChecks
    );
  }

  /**
   * Address: 0x00C08280 (FUN_00C08280, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_RestartBeat`.
   */
  void cleanup_CConFunc_WLD_RestartBeat()
  {
    CleanupStartupConCommand(gCConFunc_WLD_RestartBeat);
  }

  /**
   * Address: 0x00BE7810 (FUN_00BE7810, register_CConFunc_WLD_RestartBeat)
   *
   * What it does:
   * Registers startup console callback for `WLD_RestartBeat`. The store
   * `dword_F5B7C0 = offset sub_897630` at 0x00BE781C is the only reference to
   * `Moho::WLD_RestartBeat` anywhere in the image.
   */
  void register_CConFunc_WLD_RestartBeat()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_RestartBeat,
      kConsoleStartupWLDRestartBeatDescription,
      "WLD_RestartBeat",
      &moho::WLD_RestartBeat,
      &cleanup_CConFunc_WLD_RestartBeat
    );
  }

  /**
   * Address: 0x00C082B0 (FUN_00C082B0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_AdvanceBeat`.
   */
  void cleanup_CConFunc_WLD_AdvanceBeat()
  {
    CleanupStartupConCommand(gCConFunc_WLD_AdvanceBeat);
  }

  /**
   * Address: 0x00BE7850 (FUN_00BE7850, register_CConFunc_WLD_AdvanceBeat)
   *
   * What it does:
   * Registers startup console callback for `WLD_AdvanceBeat`. The store
   * `dword_F5B7D0 = offset sub_8976D0` at 0x00BE785C is the only reference to
   * `Moho::WLD_AdvanceBeat` anywhere in the image.
   */
  void register_CConFunc_WLD_AdvanceBeat()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_AdvanceBeat,
      kConsoleStartupWLDAdvanceBeatDescription,
      "WLD_AdvanceBeat",
      &moho::WLD_AdvanceBeat,
      &cleanup_CConFunc_WLD_AdvanceBeat
    );
  }

  /**
   * Address: 0x00C07FF0 (FUN_00C07FF0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_SingleStep`.
   */
  void cleanup_CConFunc_WLD_SingleStep()
  {
    CleanupStartupConCommand(gCConFunc_WLD_SingleStep);
  }

  /**
   * Address: 0x00BE7430 (FUN_00BE7430, register_CConFunc_WLD_SingleStep)
   *
   * What it does:
   * Registers startup console callback for `WLD_SingleStep`. The store
   * `dword_F5B740 = offset sub_88E0B0` at 0x00BE743C is the only reference to
   * `Moho::WLD_SingleStep` anywhere in the image.
   */
  void register_CConFunc_WLD_SingleStep()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_SingleStep,
      kConsoleStartupWLDSingleStepDescription,
      "WLD_SingleStep",
      &moho::WLD_SingleStep,
      &cleanup_CConFunc_WLD_SingleStep
    );
  }

  /**
   * Address: 0x00C08020 (FUN_00C08020, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_GameSpeed`.
   */
  void cleanup_CConFunc_WLD_GameSpeed()
  {
    CleanupStartupConCommand(gCConFunc_WLD_GameSpeed);
  }

  /**
   * Address: 0x00BE7470 (FUN_00BE7470, register_CConFunc_WLD_GameSpeed)
   *
   * What it does:
   * Registers startup console callback for `WLD_GameSpeed`. The store
   * `dword_F5B750 = offset sub_88E150` at 0x00BE747C is the only reference to
   * `Moho::WLD_GameSpeed` anywhere in the image.
   */
  void register_CConFunc_WLD_GameSpeed()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_GameSpeed,
      kConsoleStartupWLDGameSpeedDescription,
      "WLD_GameSpeed",
      &moho::WLD_GameSpeed,
      &cleanup_CConFunc_WLD_GameSpeed
    );
  }

  /**
   * Address: 0x00C08E20 (FUN_00C08E20, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `FindUnit`.
   */
  void cleanup_CConFunc_FindUnit()
  {
    CleanupStartupConCommand(gCConFunc_FindUnit);
  }

  /**
   * Address: 0x00BE95C0 (FUN_00BE95C0, register_CConFunc_FindUnit)
   *
   * What it does:
   * Registers startup console callback for `FindUnit`. The store
   * `dword_F5BEAC = offset sub_8D3CC0` at 0x00BE95CC is the only reference to
   * `Moho::CON_FindUnit` anywhere in the image.
   */
  void register_CConFunc_FindUnit()
  {
    RegisterStartupConFunc(
      gCConFunc_FindUnit,
      kConsoleStartupConFindUnitDescription,
      "FindUnit",
      &moho::CON_FindUnit,
      &cleanup_CConFunc_FindUnit
    );
  }

  /**
   * Address: 0x00C08EB0 (FUN_00C08EB0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_LuaDebugger`.
   */
  void cleanup_CConFunc_SC_LuaDebugger()
  {
    CleanupStartupConCommand(gCConFunc_SC_LuaDebugger);
  }

  /**
   * Address: 0x00BE9680 (FUN_00BE9680, register_CConFunc_SC_LuaDebugger)
   *
   * What it does:
   * Registers startup console callback for `SC_LuaDebugger`. The store
   * `dword_F5BEDC = offset sub_8D4150` at 0x00BE968C is the only reference to
   * `Moho::SC_LuaDebugger` anywhere in the image.
   */
  void register_CConFunc_SC_LuaDebugger()
  {
    RegisterStartupConFunc(
      gCConFunc_SC_LuaDebugger,
      kConsoleStartupSCLuaDebuggerDescription,
      "SC_LuaDebugger",
      &moho::SC_LuaDebugger,
      &cleanup_CConFunc_SC_LuaDebugger
    );
  }

  /**
   * Address: 0x00C08050 (FUN_00C08050, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `DoSimCommand`.
   */
  void cleanup_CConFunc_DoSimCommand()
  {
    CleanupStartupConCommand(gCConFunc_DoSimCommand);
  }

  /**
   * Address: 0x00BE74D0 (FUN_00BE74D0, register_CConFunc_DoSimCommand)
   *
   * What it does:
   * Registers startup console callback for `DoSimCommand`. The store
   * `dword_F5B760 = offset sub_88E440` at 0x00BE74F0 is the only reference to
   * `Moho::DoSimCommand` anywhere in the image.
   */
  void register_CConFunc_DoSimCommand()
  {
    RegisterStartupConFunc(
      gCConFunc_DoSimCommand,
      kConsoleStartupDoSimCommandDescription,
      "DoSimCommand",
      &moho::DoSimCommand,
      &cleanup_CConFunc_DoSimCommand
    );
  }

  void cleanup_CConFunc_exit()
  {
    CleanupStartupConCommand(gCConFunc_exit);
  }

  void cleanup_CConFunc_WIN_ToggleLogDialog()
  {
    CleanupStartupConCommand(gCConFunc_WIN_ToggleLogDialog);
  }

  void cleanup_CConFunc_WIN_ShowLogDialog()
  {
    CleanupStartupConCommand(gCConFunc_WIN_ShowLogDialog);
  }

  void cleanup_CConFunc_WxInputBox()
  {
    CleanupStartupConCommand(gCConFunc_WxInputBox);
  }

  /**
   * Address: 0x00BC7270 (FUN_00BC7270, register_CConFunc_exit)
   *
   * What it does:
   * Registers the startup console command that exits the application.
   */
  void register_CConFunc_exit()
  {
    RegisterStartupConFunc(
      gCConFunc_exit,
      kConsoleStartupConExitDescription,
      "exit",
      reinterpret_cast<CConFunc::Callback>(&WIN_AppRequestExit),
      &cleanup_CConFunc_exit
    );
  }

  /**
   * Address: 0x00BC7360 (FUN_00BC7360, register_CConFunc_WIN_ToggleLogDialog)
   *
   * What it does:
   * Registers the startup console command that toggles the log dialog.
   */
  void register_CConFunc_WIN_ToggleLogDialog()
  {
    RegisterStartupConFunc(
      gCConFunc_WIN_ToggleLogDialog,
      kConsoleStartupConWinToggleLogDialogDescription,
      "WIN_ToggleLogDialog",
      reinterpret_cast<CConFunc::Callback>(&WIN_ToggleLogDialog),
      &cleanup_CConFunc_WIN_ToggleLogDialog
    );
  }

  /**
   * Address: 0x00BC73A0 (FUN_00BC73A0, register_CConFunc_WIN_ShowLogDialog)
   *
   * What it does:
   * Registers the startup console command that shows the log dialog.
   */
  void register_CConFunc_WIN_ShowLogDialog()
  {
    RegisterStartupConFunc(
      gCConFunc_WIN_ShowLogDialog,
      kConsoleStartupConWinShowLogDialogDescription,
      "WIN_ShowLogDialog",
      reinterpret_cast<CConFunc::Callback>(&WIN_ShowLogDialog),
      &cleanup_CConFunc_WIN_ShowLogDialog
    );
  }

  /**
   * Address: 0x00BC73F0 (FUN_00BC73F0, register_CConFunc_WxInputBox)
   *
   * What it does:
   * Registers the startup console command that opens the wx input box.
   */
  void register_CConFunc_WxInputBox()
  {
    RegisterStartupConFunc(
      gCConFunc_WxInputBox,
      kConsoleStartupConWxInputBoxDescription,
      "WxInputBox",
      reinterpret_cast<CConFunc::Callback>(&CON_WxInputBox),
      &cleanup_CConFunc_WxInputBox
    );
  }

  /**
   * Address: 0x00BEE7F0 (FUN_00BEE7F0, ??1CConFunc_PrintStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `PrintStats`.
   */
  void cleanup_CConFunc_PrintStats()
  {
    CleanupStartupConCommand(gCConFunc_PrintStats);
  }

  /**
   * Address: 0x00BC3440 (FUN_00BC3440, register_CConFunc_PrintStats)
   *
   * What it does:
   * Registers startup console callback for `PrintStats`.
   */
  void register_CConFunc_PrintStats()
  {
    RegisterStartupConFunc(
      gCConFunc_PrintStats,
      kConsoleStartupConPrintStatsDescription,
      "PrintStats",
      &moho::CON_PrintStats,
      &cleanup_CConFunc_PrintStats
    );
  }

  /**
   * Address: 0x00BEE820 (FUN_00BEE820, ??1CConFunc_ClearStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ClearStats`.
   */
  void cleanup_CConFunc_ClearStats()
  {
    CleanupStartupConCommand(gCConFunc_ClearStats);
  }

  /**
   * Address: 0x00BC3480 (FUN_00BC3480, register_CConFunc_ClearStats)
   *
   * What it does:
   * Registers startup console callback for `ClearStats`.
   */
  void register_CConFunc_ClearStats()
  {
    RegisterStartupConFunc(
      gCConFunc_ClearStats,
      kConsoleStartupConClearStatsDescription,
      "ClearStats",
      &moho::CON_ClearStats,
      &cleanup_CConFunc_ClearStats
    );
  }

  /**
   * Address: 0x00BEE850 (FUN_00BEE850, ??1CConFunc_BeginLoggingStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `BeginLoggingStats`.
   */
  void cleanup_CConFunc_BeginLoggingStats()
  {
    CleanupStartupConCommand(gCConFunc_BeginLoggingStats);
  }

  /**
   * Address: 0x00BC34C0 (FUN_00BC34C0, register_CConFunc_BeginLoggingStats)
   *
   * What it does:
   * Registers startup console callback for `BeginLoggingStats`.
   */
  void register_CConFunc_BeginLoggingStats()
  {
    RegisterStartupConFunc(
      gCConFunc_BeginLoggingStats,
      kConsoleStartupConBeginLoggingStatsDescription,
      "BeginLoggingStats",
      &moho::CON_BeginLoggingStats,
      &cleanup_CConFunc_BeginLoggingStats
    );
  }

  /**
   * Address: 0x00BEE880 (FUN_00BEE880, ??1CConFunc_EndLoggingStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `EndLoggingStats`.
   */
  void cleanup_CConFunc_EndLoggingStats()
  {
    CleanupStartupConCommand(gCConFunc_EndLoggingStats);
  }

  /**
   * Address: 0x00BC3500 (FUN_00BC3500, register_CConFunc_EndLoggingStats)
   *
   * What it does:
   * Registers startup console callback for `EndLoggingStats`.
   */
  void register_CConFunc_EndLoggingStats()
  {
    RegisterStartupConFunc(
      gCConFunc_EndLoggingStats,
      kConsoleStartupConEndLoggingStatsDescription,
      "EndLoggingStats",
      &moho::CON_EndLoggingStats,
      &cleanup_CConFunc_EndLoggingStats
    );
  }

  /**
   * Address: 0x00BEEC10 (FUN_00BEEC10, ??1CConFunc_CON_Echo@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CON_Echo`.
   */
  void cleanup_CConFunc_CON_Echo()
  {
    CleanupStartupConCommand(gCConFunc_CON_Echo);
  }

  /**
   * Address: 0x00BC3910 (FUN_00BC3910, register_CConFunc_CON_Echo)
   *
   * What it does:
   * Registers startup console callback for `CON_Echo`.
   */
  void register_CConFunc_CON_Echo()
  {
    RegisterStartupConFunc(
      gCConFunc_CON_Echo,
      kConsoleStartupConEchoDescription,
      "CON_Echo",
      &moho::CON_Echo,
      &cleanup_CConFunc_CON_Echo
    );
  }

  /**
   * Address: 0x00BEEC40 (FUN_00BEEC40, ??1CConFunc_CON_ListCommands@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CON_ListCommands`.
   */
  void cleanup_CConFunc_CON_ListCommands()
  {
    CleanupStartupConCommand(gCConFunc_CON_ListCommands);
  }

  /**
   * Address: 0x00BC3950 (FUN_00BC3950, register_CConFunc_CON_ListCommands)
   *
   * What it does:
   * Registers startup console callback for `CON_ListCommands`.
   */
  void register_CConFunc_CON_ListCommands()
  {
    RegisterStartupConFunc(
      gCConFunc_CON_ListCommands,
      kConsoleStartupConListCommandsDescription,
      "CON_ListCommands",
      &moho::CON_ListCommands,
      &cleanup_CConFunc_CON_ListCommands
    );
  }

  /**
   * Address: 0x00BF0C90 (FUN_00BF0C90, ??1CConFunc_LUADOC@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `LUADOC`.
   */
  void cleanup_CConFunc_LUADOC()
  {
    CleanupStartupConCommand(gCConFunc_LUADOC);
  }

  /**
   * Address: 0x00BC6450 (FUN_00BC6450, register_CConFunc_LUADOC)
   *
   * What it does:
   * Registers startup console callback for `LUADOC`.
   */
  void register_CConFunc_LUADOC()
  {
    RegisterStartupConFunc(
      gCConFunc_LUADOC,
      kConsoleStartupConLuaDocDescription,
      "LUADOC",
      &moho::CON_LUADOC,
      &cleanup_CConFunc_LUADOC
    );
  }

  /**
   * Address: 0x00C08820 (FUN_00C08820, ??1CConFunc_LUA@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `LUA`.
   */
  void cleanup_CConFunc_LUA()
  {
    CleanupStartupConCommand(gCConFunc_LUA);
  }

  /**
   * Address: 0x00BE8A20 (FUN_00BE8A20, register_CConFunc_LUA)
   *
   * What it does:
   * Registers startup console callback for `LUA`.
   */
  void register_CConFunc_LUA()
  {
    RegisterStartupConFunc(
      gCConFunc_LUA,
      kConsoleStartupConLuaDescription,
      "LUA",
      &moho::CON_LUA,
      &cleanup_CConFunc_LUA
    );
  }

  /**
   * Address: 0x00C03750 (FUN_00C03750, ??1CConFunc_ExecutePasteBuffer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ExecutePasteBuffer`.
   */
  void cleanup_CConFunc_ExecutePasteBuffer()
  {
    CleanupStartupConCommand(gCConFunc_ExecutePasteBuffer);
  }

  /**
   * Address: 0x00BDF9D0 (FUN_00BDF9D0, register_CConFunc_ExecutePasteBuffer)
   *
   * What it does:
   * Registers startup console callback for `ExecutePasteBuffer`.
   */
  void register_CConFunc_ExecutePasteBuffer()
  {
    RegisterStartupConFunc(
      gCConFunc_ExecutePasteBuffer,
      kConsoleStartupConExecutePasteBufferDescription,
      "ExecutePasteBuffer",
      reinterpret_cast<CConFunc::Callback>(&moho::CON_ExecutePasteBuffer),
      &cleanup_CConFunc_ExecutePasteBuffer
    );
  }

  /**
   * Address: 0x00C03620 (FUN_00C03620, ??1CConFunc_UI_ResetView@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_ResetView`.
   */
  void cleanup_CConFunc_UI_ResetView()
  {
    CleanupStartupConCommand(gCConFunc_UI_ResetView);
  }

  /**
   * Address: 0x00BDF780 (FUN_00BDF780, register_CConFunc_UI_ResetView)
   *
   * What it does:
   * Registers startup console callback for `UI_ResetView`.
   */
  void register_CConFunc_UI_ResetView()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_ResetView,
      kConsoleStartupConUiResetViewDescription,
      "UI_ResetView",
      &moho::UI_ResetView,
      &cleanup_CConFunc_UI_ResetView
    );
  }

  // Compiler-generated global cleanup lane for FUN_00C06760. The owning
  // source construct is the typed CConFunc object registered below; no
  // standalone engine behavior is attached to that artifact address.
  void cleanup_CConFunc_IN_BindKey()
  {
    CleanupStartupConCommand(gCConFunc_IN_BindKey);
  }

  /**
   * Address: 0x00BE4850 (FUN_00BE4850, register_CConFunc_IN_BindKey)
   *
   * What it does:
   * Registers the `IN_BindKey` console name and exact description, stores the
   * recovered callback at CConFunc +0x0C, and schedules its cleanup at exit.
   */
  void register_CConFunc_IN_BindKey()
  {
    RegisterStartupConFunc(
      gCConFunc_IN_BindKey,
      kConsoleStartupConInBindKeyDescription,
      "IN_BindKey",
      &moho::IN_BindKey,
      &cleanup_CConFunc_IN_BindKey
    );
  }

  /**
   * Address: 0x00BF0D10 (FUN_00BF0D10, ??1CConFunc_GetVersion@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `GetVersion`.
   */
  void cleanup_CConFunc_GetVersion()
  {
    CleanupStartupConCommand(gCConFunc_GetVersion);
  }

  /**
   * Address: 0x00BC6630 (FUN_00BC6630, register_CConFunc_GetVersion)
   *
   * What it does:
   * Registers startup console callback for `GetVersion`.
   */
  void register_CConFunc_GetVersion()
  {
    RegisterStartupConFunc(
      gCConFunc_GetVersion,
      kConsoleStartupConGetVersionDescription,
      "GetVersion",
      &moho::CON_GetVersion,
      &cleanup_CConFunc_GetVersion
    );
  }

  /**
   * Address: 0x00BEEC70 (FUN_00BEEC70, ??1CConFunc_CON_ExecuteLastCommand@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CON_ExecuteLastCommand`.
   */
  void cleanup_CConFunc_CON_ExecuteLastCommand()
  {
    CleanupStartupConCommand(gCConFunc_CON_ExecuteLastCommand);
  }

  /**
   * Address: 0x00BC3990 (FUN_00BC3990, register_CConFunc_CON_ExecuteLastCommand)
   *
   * What it does:
   * Registers startup console callback for `CON_ExecuteLastCommand`.
   */
  void register_CConFunc_CON_ExecuteLastCommand()
  {
    RegisterStartupConFunc(
      gCConFunc_CON_ExecuteLastCommand,
      kConsoleStartupConExecuteLastCommandDescription,
      "CON_ExecuteLastCommand",
      reinterpret_cast<CConFunc::Callback>(&moho::CON_ExecuteLastCommand),
      &cleanup_CConFunc_CON_ExecuteLastCommand
    );
  }

  /**
   * Address: 0x00C036D0 (FUN_00C036D0, ??1CConFunc_ANI_DumpSkeleton@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ANI_DumpSkeleton`.
   */
  void cleanup_CConFunc_ANI_DumpSkeleton()
  {
    CleanupStartupConCommand(gCConFunc_ANI_DumpSkeleton);
  }

  /**
   * Address: 0x00BDF8D0 (FUN_00BDF8D0, register_CConFunc_ANI_DumpSkeleton)
   *
   * What it does:
   * Registers startup console callback for `ANI_DumpSkeleton`. The store
   * `Moho__CConFunc_ANI_DumpSkeleton.mFunc = offset Moho__ANI_DumpSkeleton`
   * at 0x00BDF8F0 is the only reference to `Moho::ANI_DumpSkeleton` in the
   * image. `Moho::ANI_DumpSkeleton` takes no arguments, so it is cast to
   * `CConFunc::Callback` the same way the other zero-argument command in
   * this file (`CON_ExecuteLastCommand`, above) is.
   */
  void register_CConFunc_ANI_DumpSkeleton()
  {
    RegisterStartupConFunc(
      gCConFunc_ANI_DumpSkeleton,
      kConsoleStartupConAniDumpSkeletonDescription,
      "ANI_DumpSkeleton",
      reinterpret_cast<CConFunc::Callback>(&moho::ANI_DumpSkeleton),
      &cleanup_CConFunc_ANI_DumpSkeleton
    );
  }

  /**
   * Address: 0x00BEECA0 (FUN_00BEECA0, ??1TConVar_con_TestVarBool@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `con_TestVarBool`.
   */
  void cleanup_TConVar_con_TestVarBool()
  {
    CleanupStartupConCommand(gTConVar_con_TestVarBool);
  }

  /**
   * Address: 0x00BC39D0 (FUN_00BC39D0, register_TConVar_con_TestVarBool)
   *
   * What it does:
   * Registers startup convar for `con_TestVarBool`.
   */
  void register_TConVar_con_TestVarBool()
  {
    RegisterStartupConVar(gTConVar_con_TestVarBool, &cleanup_TConVar_con_TestVarBool);
  }

  /**
   * Address: 0x00BEECD0 (FUN_00BEECD0, ??1TConVar_con_TestVar@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `con_TestVar`.
   */
  void cleanup_TConVar_con_TestVar()
  {
    CleanupStartupConCommand(gTConVar_con_TestVar);
  }

  /**
   * Address: 0x00BC3A10 (FUN_00BC3A10, register_TConVar_con_TestVar)
   *
   * What it does:
   * Registers startup convar for `con_TestVar`.
   */
  void register_TConVar_con_TestVar()
  {
    RegisterStartupConVar(gTConVar_con_TestVar, &cleanup_TConVar_con_TestVar);
  }

  /**
   * Address: 0x00BEED00 (FUN_00BEED00, ??1ConVar_con_TestVarUByte@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `con_TestVarUByte`.
   */
  void cleanup_ConVar_con_TestVarUByte()
  {
    StartupConVar_con_TestVarUByte().~ConVar_con_TestVarUByte();
  }

  /**
   * Address: 0x00BC3A50 (FUN_00BC3A50, register_ConVar_con_TestVarUByte)
   *
   * What it does:
   * Constructs and registers startup convar storage for `con_TestVarUByte`.
   */
  void register_ConVar_con_TestVarUByte()
  {
    new (&StartupConVar_con_TestVarUByte()) ConVar_con_TestVarUByte();
    (void)std::atexit(&cleanup_ConVar_con_TestVarUByte);
  }

  /**
   * Address: 0x00BEED30 (FUN_00BEED30, ??1TConVar_con_TestVarFloat@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `con_TestVarFloat`.
   */
  void cleanup_TConVar_con_TestVarFloat()
  {
    CleanupStartupConCommand(gTConVar_con_TestVarFloat);
  }

  /**
   * Address: 0x00BC3A70 (FUN_00BC3A70, register_TConVar_con_TestVarFloat)
   *
   * What it does:
   * Registers startup convar for `con_TestVarFloat`.
   */
  void register_TConVar_con_TestVarFloat()
  {
    RegisterStartupConVar(gTConVar_con_TestVarFloat, &cleanup_TConVar_con_TestVarFloat);
  }

  /**
   * Address: 0x00BEED60 (FUN_00BEED60, sub_BEED60)
   *
   * What it does:
   * Clears startup string storage for `con_TestVarStr`.
   */
  void cleanup_con_TestVarStr()
  {
    con_TestVarStr.tidy(true, 0U);
  }

  /**
   * Address: 0x00BC3AB0 (FUN_00BC3AB0, register_con_TestVarStr)
   *
   * What it does:
   * Initializes startup string storage for `con_TestVarStr`.
   */
  void register_con_TestVarStr()
  {
    con_TestVarStr.assign_owned("string");
    (void)std::atexit(&cleanup_con_TestVarStr);
  }

  /**
   * Address: 0x00BEED90 (FUN_00BEED90, ??1TConVar_con_TestVarStr@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `con_TestVarStr`.
   */
  void cleanup_TConVar_con_TestVarStr()
  {
    CleanupStartupConCommand(gTConVar_con_TestVarStr);
  }

  /**
   * Address: 0x00BC3AD0 (FUN_00BC3AD0, register_TConVar_con_TestVarStr)
   *
   * What it does:
   * Registers startup convar for `con_TestVarStr`.
   */
  void register_TConVar_con_TestVarStr()
  {
    RegisterStartupConVar(gTConVar_con_TestVarStr, &cleanup_TConVar_con_TestVarStr);
  }

  /**
   * Address: 0x00BEEF30 (FUN_00BEEF30, ??1TConVar_graphics_Fidelity@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `graphics_Fidelity`.
   */
  void cleanup_TConVar_graphics_Fidelity()
  {
    CleanupStartupConCommand(gTConVar_graphics_Fidelity);
  }

  /**
   * Address: 0x00BC3D00 (FUN_00BC3D00, register_TConVar_graphics_Fidelity)
   *
   * What it does:
   * Registers startup convar for `graphics_Fidelity`.
   */
  void register_TConVar_graphics_Fidelity()
  {
    RegisterStartupConVar(gTConVar_graphics_Fidelity, &cleanup_TConVar_graphics_Fidelity);
  }

  /**
   * Address: 0x00BEEF60 (FUN_00BEEF60, ??1TConVar_graphics_FidelitySupported@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `graphics_FidelitySupported`.
   */
  void cleanup_TConVar_graphics_FidelitySupported()
  {
    CleanupStartupConCommand(gTConVar_graphics_FidelitySupported);
  }

  /**
   * Address: 0x00BC3D40 (FUN_00BC3D40, register_TConVar_graphics_FidelitySupported)
   *
   * What it does:
   * Registers startup convar for `graphics_FidelitySupported`.
   */
  void register_TConVar_graphics_FidelitySupported()
  {
    RegisterStartupConVar(gTConVar_graphics_FidelitySupported, &cleanup_TConVar_graphics_FidelitySupported);
  }

  /**
   * Address: 0x00BEEF90 (FUN_00BEEF90, ??1TConVar_shadow_Fidelity@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `shadow_Fidelity`.
   */
  void cleanup_TConVar_shadow_Fidelity()
  {
    CleanupStartupConCommand(gTConVar_shadow_Fidelity);
  }

  /**
   * Address: 0x00BC3D80 (FUN_00BC3D80, register_TConVar_shadow_Fidelity)
   *
   * What it does:
   * Registers startup convar for `shadow_Fidelity`.
   */
  void register_TConVar_shadow_Fidelity()
  {
    RegisterStartupConVar(gTConVar_shadow_Fidelity, &cleanup_TConVar_shadow_Fidelity);
  }

  /**
   * Address: 0x00BEEFC0 (FUN_00BEEFC0, ??1TConVar_shadow_FidelitySupported@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `shadow_FidelitySupported`.
   */
  void cleanup_TConVar_shadow_FidelitySupported()
  {
    CleanupStartupConCommand(gTConVar_shadow_FidelitySupported);
  }

  /**
   * Address: 0x00BC3DC0 (FUN_00BC3DC0, register_TConVar_shadow_FidelitySupported)
   *
   * What it does:
   * Registers startup convar for `shadow_FidelitySupported`.
   */
  void register_TConVar_shadow_FidelitySupported()
  {
    RegisterStartupConVar(gTConVar_shadow_FidelitySupported, &cleanup_TConVar_shadow_FidelitySupported);
  }

  /**
   * Address: 0x00BEEFF0 (FUN_00BEEFF0, ??1TConVar_d3d_UseRefRast@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `d3d_UseRefRast`.
   */
  void cleanup_TConVar_d3d_UseRefRast()
  {
    CleanupStartupConCommand(gTConVar_d3d_UseRefRast);
  }

  /**
   * Address: 0x00BC3E00 (FUN_00BC3E00, register_TConVar_d3d_UseRefRast)
   *
   * What it does:
   * Registers startup convar for `d3d_UseRefRast`.
   */
  void register_TConVar_d3d_UseRefRast()
  {
    RegisterStartupConVar(gTConVar_d3d_UseRefRast, &cleanup_TConVar_d3d_UseRefRast);
  }

  /**
   * Address: 0x00BEF020 (FUN_00BEF020, ??1TConVar_d3d_ForceSoftwareVP@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `d3d_ForceSoftwareVP`.
   */
  void cleanup_TConVar_d3d_ForceSoftwareVP()
  {
    CleanupStartupConCommand(gTConVar_d3d_ForceSoftwareVP);
  }

  /**
   * Address: 0x00BC3E40 (FUN_00BC3E40, register_TConVar_d3d_ForceSoftwareVP)
   *
   * What it does:
   * Registers startup convar for `d3d_ForceSoftwareVP`.
   */
  void register_TConVar_d3d_ForceSoftwareVP()
  {
    RegisterStartupConVar(gTConVar_d3d_ForceSoftwareVP, &cleanup_TConVar_d3d_ForceSoftwareVP);
  }

  /**
   * Address: 0x00BEF050 (FUN_00BEF050, ??1TConVar_d3d_NoPureDevice@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `d3d_NoPureDevice`.
   */
  void cleanup_TConVar_d3d_NoPureDevice()
  {
    CleanupStartupConCommand(gTConVar_d3d_NoPureDevice);
  }

  /**
   * Address: 0x00BC3E80 (FUN_00BC3E80, register_TConVar_d3d_NoPureDevice)
   *
   * What it does:
   * Registers startup convar for `d3d_NoPureDevice`.
   */
  void register_TConVar_d3d_NoPureDevice()
  {
    RegisterStartupConVar(gTConVar_d3d_NoPureDevice, &cleanup_TConVar_d3d_NoPureDevice);
  }

  /**
   * Address: 0x00BEF080 (FUN_00BEF080, ??1TConVar_d3d_ForceDirect3DDebugEnabled@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `d3d_ForceDirect3DDebugEnabled`.
   */
  void cleanup_TConVar_d3d_ForceDirect3DDebugEnabled()
  {
    CleanupStartupConCommand(gTConVar_d3d_ForceDirect3DDebugEnabled);
  }

  /**
   * Address: 0x00BC3EC0 (FUN_00BC3EC0, register_TConVar_d3d_ForceDirect3DDebugEnabled)
   *
   * What it does:
   * Registers startup convar for `d3d_ForceDirect3DDebugEnabled`.
   */
  void register_TConVar_d3d_ForceDirect3DDebugEnabled()
  {
    RegisterStartupConVar(gTConVar_d3d_ForceDirect3DDebugEnabled, &cleanup_TConVar_d3d_ForceDirect3DDebugEnabled);
  }

  /**
   * Address: 0x00BEF0B0 (FUN_00BEF0B0, ??1TConVar_d3d_WindowsCursor@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `d3d_WindowsCursor`.
   */
  void cleanup_TConVar_d3d_WindowsCursor()
  {
    CleanupStartupConCommand(gTConVar_d3d_WindowsCursor);
  }

  /**
   * Address: 0x00BC3F00 (FUN_00BC3F00, register_TConVar_d3d_WindowsCursor)
   *
   * What it does:
   * Registers startup convar for `d3d_WindowsCursor`.
   */
  void register_TConVar_d3d_WindowsCursor()
  {
    RegisterStartupConVar(gTConVar_d3d_WindowsCursor, &cleanup_TConVar_d3d_WindowsCursor);
  }

  /**
   * Address: 0x00BF0D80 (FUN_00BF0D80, ??1TConVar_snd_ExtraDoWorkCalls@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `snd_ExtraDoWorkCalls`.
   */
  void cleanup_TConVar_snd_ExtraDoWorkCalls()
  {
    CleanupStartupConCommand(gTConVar_snd_ExtraDoWorkCalls);
  }

  /**
   * Address: 0x00BC6780 (FUN_00BC6780, register_TConVar_snd_ExtraDoWorkCalls)
   *
   * What it does:
   * Registers startup convar for `snd_ExtraDoWorkCalls`.
   */
  void register_TConVar_snd_ExtraDoWorkCalls()
  {
    RegisterStartupConVar(gTConVar_snd_ExtraDoWorkCalls, &cleanup_TConVar_snd_ExtraDoWorkCalls);
  }

  /**
   * Address: 0x00BEF0E0 (FUN_00BEF0E0, ??1CConFunc_d3d_AntiAliasingSamples@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `d3d_AntiAliasingSamples`.
   */
  void cleanup_CConFunc_d3d_AntiAliasingSamples()
  {
    CleanupStartupConCommand(gCConFunc_d3d_AntiAliasingSamples);
  }

  /**
   * Address: 0x00BC3F40 (FUN_00BC3F40, register_CConFunc_d3d_AntiAliasingSamples)
   *
   * What it does:
   * Registers startup command callback for `d3d_AntiAliasingSamples`.
   */
  void register_CConFunc_d3d_AntiAliasingSamples()
  {
    RegisterStartupConFunc(
      gCConFunc_d3d_AntiAliasingSamples,
      kConsoleStartupConD3DAntiAliasingSamplesDescription,
      "d3d_AntiAliasingSamples",
      &CD3DEffect::CON_d3d_AntiAliasingSamples,
      &cleanup_CConFunc_d3d_AntiAliasingSamples
    );
  }

  /**
   * Address: 0x00BEF1F0 (FUN_00BEF1F0, ??1CConFunc_ren_MipSkipLevels@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ren_MipSkipLevels`.
   */
  void cleanup_CConFunc_ren_MipSkipLevels()
  {
    CleanupStartupConCommand(gCConFunc_ren_MipSkipLevels);
  }

  /**
   * Address: 0x00BC4150 (FUN_00BC4150, register_CConFunc_ren_MipSkipLevels)
   *
   * What it does:
   * Registers startup console callback for `ren_MipSkipLevels`.
   */
  void register_CConFunc_ren_MipSkipLevels()
  {
    RegisterStartupConFunc(
      gCConFunc_ren_MipSkipLevels,
      kConsoleStartupConRenMipSkipLevelsDescription,
      "ren_MipSkipLevels",
      &CON_ren_MipSkipLevels,
      &cleanup_CConFunc_ren_MipSkipLevels
    );
  }

  /**
   * Address: 0x00BEF220 (FUN_00BEF220, ??1CConFunc_DumpPreloadedTextures@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DumpPreloadedTextures`.
   */
  void cleanup_CConFunc_DumpPreloadedTextures()
  {
    CleanupStartupConCommand(gCConFunc_DumpPreloadedTextures);
  }

  /**
   * Address: 0x00BC4190 (FUN_00BC4190, register_CConFunc_DumpPreloadedTextures)
   *
   * What it does:
   * Registers startup console callback for `DumpPreloadedTextures`.
   */
  void register_CConFunc_DumpPreloadedTextures()
  {
    RegisterStartupConFunc(
      gCConFunc_DumpPreloadedTextures,
      kConsoleStartupConDumpPreloadedTexturesDescription,
      "DumpPreloadedTextures",
      &CON_DumpPreloadedTextures,
      &cleanup_CConFunc_DumpPreloadedTextures
    );
  }

  /**
   * Address: <synthetic teardown lane for gCConFunc_StartCommandMode>
   *
   * What it does:
   * Unregisters startup command storage for `StartCommandMode`.
   */
  void cleanup_CConFunc_StartCommandMode()
  {
    CleanupStartupConCommand(gCConFunc_StartCommandMode);
  }

  /**
   * Address: 0x00BE3FF0 (FUN_00BE3FF0, register_CConFunc_StartCommandMode)
   *
   * What it does:
   * Registers startup console callback for `StartCommandMode`. The binary
   * stores `&Moho::CON_StartCommandMode` into `gCConFunc_StartCommandMode`'s
   * function-pointer payload at CRT static-init time and schedules the
   * matching cleanup lane at process exit.
   */
  void register_CConFunc_StartCommandMode()
  {
    RegisterStartupConFunc(
      gCConFunc_StartCommandMode,
      kConsoleStartupConStartCommandModeDescription,
      "StartCommandMode",
      &CON_StartCommandMode,
      &cleanup_CConFunc_StartCommandMode
    );
  }

  /**
   * Address: 0x00C061F0 (FUN_00C061F0, ??1CConFunc_DebugGenerateBuildTemplateFromSelection@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DebugGenerateBuildTemplateFromSelection`.
   */
  void cleanup_CConFunc_DebugGenerateBuildTemplateFromSelection()
  {
    CleanupStartupConCommand(gCConFunc_DebugGenerateBuildTemplateFromSelection);
  }

  /**
   * Address: 0x00BE40B0 (FUN_00BE40B0, register_CConFunc_DebugGenerateBuildTemplateFromSelection)
   *
   * What it does:
   * Registers startup console callback for `DebugGenerateBuildTemplateFromSelection`.
   */
  void register_CConFunc_DebugGenerateBuildTemplateFromSelection()
  {
    RegisterStartupConFunc(
      gCConFunc_DebugGenerateBuildTemplateFromSelection,
      kConsoleStartupConDebugGenerateBuildTemplateDescription,
      "DebugGenerateBuildTemplateFromSelection",
      &CON_DebugGenerateBuildTemplateFromSelection,
      &cleanup_CConFunc_DebugGenerateBuildTemplateFromSelection
    );
  }

  /**
   * Address: 0x00C06220 (FUN_00C06220, ??1CConFunc_DebugClearBuildTemplates@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DebugClearBuildTemplates`.
   */
  void cleanup_CConFunc_DebugClearBuildTemplates()
  {
    CleanupStartupConCommand(gCConFunc_DebugClearBuildTemplates);
  }

  /**
   * Address: 0x00BE40F0 (FUN_00BE40F0, register_CConFunc_DebugClearBuildTemplates)
   *
   * What it does:
   * Registers startup console callback for `DebugClearBuildTemplates`.
   */
  void register_CConFunc_DebugClearBuildTemplates()
  {
    RegisterStartupConFunc(
      gCConFunc_DebugClearBuildTemplates,
      kConsoleStartupConDebugClearBuildTemplatesDescription,
      "DebugClearBuildTemplates",
      &CON_DebugClearBuildTemplates,
      &cleanup_CConFunc_DebugClearBuildTemplates
    );
  }

  /**
   * Address: 0x00C06100 (FUN_00C06100, ??1CConFunc_CreateProp@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CreateProp`.
   */
  void cleanup_CConFunc_CreateProp()
  {
    CleanupStartupConCommand(gCConFunc_CreateProp);
  }

  /**
   * Address: 0x00BE3F70 (FUN_00BE3F70, register_CConFunc_CreateProp)
   *
   * What it does:
   * Registers startup console callback for `CreateProp`.
   */
  void register_CConFunc_CreateProp()
  {
    RegisterStartupConFunc(
      gCConFunc_CreateProp,
      kConsoleStartupConCreatePropDescription,
      "CreateProp",
      &CON_CreateProp,
      &cleanup_CConFunc_CreateProp
    );
  }

  /**
   * Address: 0x00C060A0 (FUN_00C060A0, ??1CConFunc_CreateUnit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CreateUnit`.
   */
  void cleanup_CConFunc_CreateUnit()
  {
    CleanupStartupConCommand(gCConFunc_CreateUnit);
  }

  /**
   * Address: 0x00BE3EF0 (FUN_00BE3EF0, register_CConFunc_CreateUnit)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_00832C50.xrefs.txt` -> `code from=0x00BE3F10 owner=0x00BE3EF0 type= 1
   * from_name=register_CConFunc_CreateUnit owner_name=register_CConFunc_CreateUnit`
   * (`mov Moho__CConFunc_CreateUnit.mFunc, offset Moho__CON_CreateUnit`).
   *
   * What it does:
   * Registers startup console callback for `CreateUnit` and schedules the
   * matching cleanup lane at process exit.
   */
  void register_CConFunc_CreateUnit()
  {
    RegisterStartupConFunc(
      gCConFunc_CreateUnit,
      kConsoleStartupConCreateUnitDescription,
      "CreateUnit",
      &CON_CreateUnit,
      &cleanup_CConFunc_CreateUnit
    );
  }

  /**
   * Address: 0x00C060D0 (FUN_00C060D0, ??1CConFunc_LotsOfProps@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `LotsOfProps`.
   */
  void cleanup_CConFunc_LotsOfProps()
  {
    CleanupStartupConCommand(gCConFunc_LotsOfProps);
  }

  /**
   * Address: 0x00BE3F30 (FUN_00BE3F30, register_CConFunc_LotsOfProps)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_008330B0.xrefs.txt` -> `code from=0x00BE3F50 owner=0x00BE3F30 type= 1
   * from_name=register_CConFunc_LotsOfProps owner_name=register_CConFunc_LotsOfProps`
   * (`mov Moho__CConFunc_LotsOfProps.mFunc, offset Moho__CON_LotsOfProps`).
   *
   * What it does:
   * Registers startup console callback for `LotsOfProps`.
   */
  void register_CConFunc_LotsOfProps()
  {
    RegisterStartupConFunc(
      gCConFunc_LotsOfProps,
      kConsoleStartupConLotsOfPropsDescription,
      "LotsOfProps",
      &CON_LotsOfProps,
      &cleanup_CConFunc_LotsOfProps
    );
  }

  /**
   * Address: 0x00C06190 (FUN_00C06190, ??1CConFunc_KillSelectedUnits@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `KillSelectedUnits`.
   */
  void cleanup_CConFunc_KillSelectedUnits()
  {
    CleanupStartupConCommand(gCConFunc_KillSelectedUnits);
  }

  /**
   * Address: 0x00BE4030 (FUN_00BE4030, register_CConFunc_KillSelectedUnits)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_00833C70.xrefs.txt` -> `code from=0x00BE4050 owner=0x00BE4030 type= 1
   * from_name=register_CConFunc_KillSelectedUnits owner_name=register_CConFunc_KillSelectedUnits`
   * (`mov Moho__CConFunc_KillSelectedUnits.mFunc, offset Moho__CON_CConFunc_KillSelectedUnits`).
   *
   * What it does:
   * Registers startup console callback for `KillSelectedUnits`.
   */
  void register_CConFunc_KillSelectedUnits()
  {
    RegisterStartupConFunc(
      gCConFunc_KillSelectedUnits,
      kConsoleStartupConKillSelectedUnitsDescription,
      "KillSelectedUnits",
      &CON_KillSelectedUnits,
      &cleanup_CConFunc_KillSelectedUnits
    );
  }

  /**
   * Address: 0x00C061C0 (FUN_00C061C0, ??1CConFunc_DestroySelectedUnits@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DestroySelectedUnits`.
   */
  void cleanup_CConFunc_DestroySelectedUnits()
  {
    CleanupStartupConCommand(gCConFunc_DestroySelectedUnits);
  }

  /**
   * Address: 0x00BE4070 (FUN_00BE4070, register_CConFunc_DestroySelectedUnits)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_00833D60.xrefs.txt` -> `code from=0x00BE4090 owner=0x00BE4070 type= 1
   * from_name=register_CConFunc_DestroySelectedUnits owner_name=register_CConFunc_DestroySelectedUnits`
   * (`mov Moho__CConFunc_DestroySelectedUnits.mFunc, offset Moho__CON_DestroySelectedUnits`).
   *
   * What it does:
   * Registers startup console callback for `DestroySelectedUnits`.
   */
  void register_CConFunc_DestroySelectedUnits()
  {
    RegisterStartupConFunc(
      gCConFunc_DestroySelectedUnits,
      kConsoleStartupConDestroySelectedUnitsDescription,
      "DestroySelectedUnits",
      &CON_DestroySelectedUnits,
      &cleanup_CConFunc_DestroySelectedUnits
    );
  }

  /**
   * Address: 0x00C03720 (FUN_00C03720, ??1CConFunc_CopySelectedUnitsToClipboard@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `CopySelectedUnitsToClipboard`.
   */
  void cleanup_CConFunc_CopySelectedUnitsToClipboard()
  {
    CleanupStartupConCommand(gCConFunc_CopySelectedUnitsToClipboard);
  }

  /**
   * Address: 0x00BDF990 (FUN_00BDF990, register_CConFunc_CopySelectedUnitsToClipboard)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_007B55D0.xrefs.txt` -> `code from=0x00BDF9B0 owner=0x00BDF990 type= 1
   * from_name=register_CConFunc_CopySelectedUnitsToClipboard owner_name=register_CConFunc_CopySelectedUnitsToClipboard`
   * (`mov Moho__CConFunc_CopySelectedUnitsToClipboard.mFunc, offset Moho__CON_CopySelectedUnitsToClipboard`).
   *
   * What it does:
   * Registers startup console callback for `CopySelectedUnitsToClipboard`.
   */
  void register_CConFunc_CopySelectedUnitsToClipboard()
  {
    RegisterStartupConFunc(
      gCConFunc_CopySelectedUnitsToClipboard,
      kConsoleStartupConCopySelectedUnitsToClipboardDescription,
      "CopySelectedUnitsToClipboard",
      &CON_CopySelectedUnitsToClipboard,
      &cleanup_CConFunc_CopySelectedUnitsToClipboard
    );
  }

  /**
   * Address: 0x00C08480 (FUN_00C08480, ??1CConFunc_AddSplat@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `AddSplat`.
   */
  void cleanup_CConFunc_AddSplat()
  {
    CleanupStartupConCommand(gCConFunc_AddSplat);
  }

  /**
   * Address: 0x00BE7CE0 (FUN_00BE7CE0, register_CConFunc_AddSplat)
   *
   * Callsite evidence (class 2, data xref into a function-pointer table):
   * `FUN_0089E3C0.xrefs.txt` -> `code from=0x00BE7D00 owner=0x00BE7CE0 ...
   * mov Moho__CConFunc_AddSplat.mFunc, offset Moho__CON_AddSplat`.
   *
   * What it does:
   * Registers startup console callback for `AddSplat`.
   */
  void register_CConFunc_AddSplat()
  {
    RegisterStartupConFunc(
      gCConFunc_AddSplat,
      kConsoleStartupConAddSplatDescription,
      "AddSplat",
      &CON_AddSplat,
      &cleanup_CConFunc_AddSplat
    );
  }

  /**
   * Address: 0x00C06280 (FUN_00C06280, ??1CConFunc_ProcessInfoPair@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ProcessInfoPair`.
   */
  void cleanup_CConFunc_ProcessInfoPair()
  {
    CleanupStartupConCommand(gCConFunc_ProcessInfoPair);
  }

  /**
   * Address: 0x00BE4170 (FUN_00BE4170, register_CConFunc_ProcessInfoPair)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_00834240.xrefs.txt` -> `code from=0x00BE4190 owner=0x00BE4170 type= 1
   * from_name=register_CConFunc_ProcessInfoPair owner_name=register_CConFunc_ProcessInfoPair`
   * (`mov Moho__CConFunc_ProcessInfoPair.mFunc, offset Moho__CON_ProcessInfoPair`).
   *
   * What it does:
   * Registers startup console callback for `ProcessInfoPair`.
   */
  void register_CConFunc_ProcessInfoPair()
  {
    RegisterStartupConFunc(
      gCConFunc_ProcessInfoPair,
      kConsoleStartupConProcessInfoPairDescription,
      "ProcessInfoPair",
      &CON_ProcessInfoPair,
      &cleanup_CConFunc_ProcessInfoPair
    );
  }

  /**
   * Address: 0x00C062B0 (FUN_00C062B0, ??1CConFunc_UI_TrackUnit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_TrackUnit`.
   */
  void cleanup_CConFunc_UI_TrackUnit()
  {
    CleanupStartupConCommand(gCConFunc_UI_TrackUnit);
  }

  /**
   * Address: 0x00BE41B0 (FUN_00BE41B0, register_CConFunc_UI_TrackUnit)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_00834460.xrefs.txt` -> `code from=0x00BE41D0 owner=0x00BE41B0 type= 1
   * from_name=register_CConFunc_UI_TrackUnit owner_name=register_CConFunc_UI_TrackUnit`
   * (`mov Moho__CConFunc_UI_TrackUnit.mFunc, offset Moho__UI_TrackUnit`).
   *
   * What it does:
   * Registers startup console callback for `UI_TrackUnit`.
   */
  void register_CConFunc_UI_TrackUnit()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_TrackUnit,
      kConsoleStartupConUITrackUnitDescription,
      "UI_TrackUnit",
      &UI_TrackUnit,
      &cleanup_CConFunc_UI_TrackUnit
    );
  }

  /**
   * Address: 0x00C06520 (FUN_00C06520, ??1CConFunc_RenameUnit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `RenameUnit`.
   */
  void cleanup_CConFunc_RenameUnit()
  {
    CleanupStartupConCommand(gCConFunc_RenameUnit);
  }

  /**
   * Address: 0x00BE44F0 (FUN_00BE44F0, register_CConFunc_RenameUnit)
   *
   * Callsite evidence (class 1, code xref):
   * `FUN_008354B0.xrefs.txt` -> `code from=0x00BE4510 owner=0x00BE44F0 type= 1
   * from_name=register_CConFunc_RenameUnit owner_name=register_CConFunc_RenameUnit`
   * (`mov Moho__CConFunc_RenameUnit.mFunc, offset Moho__RenameUnit`).
   *
   * What it does:
   * Registers startup console callback for `RenameUnit`.
   */
  void register_CConFunc_RenameUnit()
  {
    RegisterStartupConFunc(
      gCConFunc_RenameUnit,
      kConsoleStartupConRenameUnitDescription,
      "RenameUnit",
      &RenameUnit,
      &cleanup_CConFunc_RenameUnit
    );
  }

  /**
   * Address: 0x00C06130 (FUN_00C06130, ??1CConFunc_IssueCommand@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `IssueCommand`.
   */
  void cleanup_CConFunc_IssueCommand()
  {
    CleanupStartupConCommand(gCConFunc_IssueCommand);
  }

  /**
   * Address: 0x00BE3FB0 (FUN_00BE3FB0, register_CConFunc_IssueCommand)
   *
   * What it does:
   * Registers startup console callback for `IssueCommand`.
   */
  void register_CConFunc_IssueCommand()
  {
    RegisterStartupConFunc(
      gCConFunc_IssueCommand,
      kConsoleStartupConIssueCommandDescription,
      "IssueCommand",
      &CON_IssueCommand,
      &cleanup_CConFunc_IssueCommand
    );
  }

  /**
   * Address: 0x00BEF8C0 (FUN_00BEF8C0, ??1CConFunc_Log@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Log`.
   */
  void cleanup_CConFunc_Log()
  {
    CleanupStartupConCommand(gCConFunc_Log);
  }

  /**
   * Address: 0x00BC4B70 (FUN_00BC4B70, register_CConFunc_Log)
   *
   * What it does:
   * Registers startup console callback for `Log`.
   */
  void register_CConFunc_Log()
  {
    RegisterStartupConFunc(gCConFunc_Log, kConsoleStartupConLogDescription, "Log", &CON_Log, &cleanup_CConFunc_Log);
  }

  /**
   * Address: 0x00BEF8F0 (FUN_00BEF8F0, ??1CConFunc_Debug_Warn@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Debug_Warn`.
   */
  void cleanup_CConFunc_Debug_Warn()
  {
    CleanupStartupConCommand(gCConFunc_Debug_Warn);
  }

  /**
   * Address: 0x00BC4BB0 (FUN_00BC4BB0, register_CConFunc_Debug_Warn)
   *
   * What it does:
   * Registers startup console callback for `Debug_Warn`.
   */
  void register_CConFunc_Debug_Warn()
  {
    RegisterStartupConFunc(
      gCConFunc_Debug_Warn,
      kConsoleStartupConDebugWarnDescription,
      "Debug_Warn",
      &CON_Debug_Warn,
      &cleanup_CConFunc_Debug_Warn
    );
  }

  /**
   * Address: 0x00BEF920 (FUN_00BEF920, ??1CConFunc_Debug_Error@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Debug_Error`.
   */
  void cleanup_CConFunc_Debug_Error()
  {
    CleanupStartupConCommand(gCConFunc_Debug_Error);
  }

  /**
   * Address: 0x00BC4BF0 (FUN_00BC4BF0, register_CConFunc_Debug_Error)
   *
   * What it does:
   * Registers startup console callback for `Debug_Error`.
   */
  void register_CConFunc_Debug_Error()
  {
    RegisterStartupConFunc(
      gCConFunc_Debug_Error,
      kConsoleStartupConDebugErrorDescription,
      "Debug_Error",
      &CON_Debug_Error,
      &cleanup_CConFunc_Debug_Error
    );
  }

  /**
   * Address: 0x00BEF950 (FUN_00BEF950, ??1CConFunc_Debug_Assert@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Debug_Assert`.
   */
  void cleanup_CConFunc_Debug_Assert()
  {
    CleanupStartupConCommand(gCConFunc_Debug_Assert);
  }

  /**
   * Address: 0x00BC4C30 (FUN_00BC4C30, register_CConFunc_Debug_Assert)
   *
   * What it does:
   * Registers startup console callback for `Debug_Assert`.
   */
  void register_CConFunc_Debug_Assert()
  {
    RegisterStartupConFunc(
      gCConFunc_Debug_Assert,
      kConsoleStartupConDebugAssertDescription,
      "Debug_Assert",
      &CON_Debug_Assert,
      &cleanup_CConFunc_Debug_Assert
    );
  }

  /**
   * Address: 0x00BEF980 (FUN_00BEF980, ??1CConFunc_Debug_Crash@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Debug_Crash`.
   */
  void cleanup_CConFunc_Debug_Crash()
  {
    CleanupStartupConCommand(gCConFunc_Debug_Crash);
  }

  /**
   * Address: 0x00BC4C70 (FUN_00BC4C70, register_CConFunc_Debug_Crash)
   *
   * What it does:
   * Registers startup console callback for `Debug_Crash`.
   */
  void register_CConFunc_Debug_Crash()
  {
    RegisterStartupConFunc(
      gCConFunc_Debug_Crash,
      kConsoleStartupConDebugCrashDescription,
      "Debug_Crash",
      &CON_Debug_Crash,
      &cleanup_CConFunc_Debug_Crash
    );
  }

  /**
   * Address: 0x00BEF9B0 (FUN_00BEF9B0, ??1CConFunc_Debug_Throw@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `Debug_Throw`.
   */
  void cleanup_CConFunc_Debug_Throw()
  {
    CleanupStartupConCommand(gCConFunc_Debug_Throw);
  }

  /**
   * Address: 0x00BC4CB0 (FUN_00BC4CB0, register_CConFunc_Debug_Throw)
   *
   * What it does:
   * Registers startup console callback for `Debug_Throw`.
   */
  void register_CConFunc_Debug_Throw()
  {
    RegisterStartupConFunc(
      gCConFunc_Debug_Throw,
      kConsoleStartupConDebugThrowDescription,
      "Debug_Throw",
      &CON_Debug_Throw,
      &cleanup_CConFunc_Debug_Throw
    );
  }

  /**
   * Address: 0x00BF77B0 (FUN_00BF77B0, ??1TConVar_recon_debug@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `recon_debug`.
   */
  void cleanup_TConVar_recon_debug()
  {
    CleanupStartupConCommand(gTConVar_recon_debug);
  }

  /**
   * Address: 0x00BCDB70 (FUN_00BCDB70, register_TConVar_recon_debug)
   *
   * What it does:
   * Registers startup convar for `recon_debug`.
   */
  void register_TConVar_recon_debug()
  {
    RegisterStartupConVar(gTConVar_recon_debug, &cleanup_TConVar_recon_debug);
  }

  /**
   * Address: 0x00BF3910 (FUN_00BF3910, ??1TConVar_rule_Paranoid@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `rule_Paranoid`.
   */
  void cleanup_TConVar_rule_Paranoid()
  {
    CleanupStartupConCommand(gTConVar_rule_Paranoid);
  }

  /**
   * Address: 0x00BC8DC0 (FUN_00BC8DC0, register_TConVar_rule_Paranoid)
   *
   * What it does:
   * Registers startup convar for `rule_Paranoid`, inserting the typed int
   * convar into the process-global console command map and scheduling the
   * cleanup lane at exit.
   */
  void register_TConVar_rule_Paranoid()
  {
    RegisterStartupConVar(gTConVar_rule_Paranoid, &cleanup_TConVar_rule_Paranoid);
  }

  /**
   * Address: 0x00BF3940 (FUN_00BF3940, ??1TConVar_rule_BlueprintReloadDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `rule_BlueprintReloadDelay`.
   */
  void cleanup_TConVar_rule_BlueprintReloadDelay()
  {
    CleanupStartupConCommand(gTConVar_rule_BlueprintReloadDelay);
  }

  /**
   * Address: 0x00BC8E00 (FUN_00BC8E00, register_TConVar_rule_BlueprintReloadDelay)
   *
   * What it does:
   * Registers startup convar for `rule_BlueprintReloadDelay`, inserting the
   * typed float convar into the process-global console command map and
   * scheduling the cleanup lane at exit.
   */
  void register_TConVar_rule_BlueprintReloadDelay()
  {
    RegisterStartupConVar(gTConVar_rule_BlueprintReloadDelay, &cleanup_TConVar_rule_BlueprintReloadDelay);
  }
} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsRender
  {
    ConsoleStartupRegistrationsRender()
    {
      moho::register_CConFunc_CON_Echo();
      moho::register_CConFunc_CON_ListCommands();
      moho::register_CConFunc_GetVersion();
      moho::register_CConFunc_CON_ExecuteLastCommand();
      moho::register_CConFunc_ANI_DumpSkeleton();
      moho::register_CConFunc_IN_BindKey();
      moho::register_console_command_buffer();
      moho::register_sConsoleOutputHandlers();
      moho::register_TConVar_con_TestVarBool();
      moho::register_TConVar_con_TestVar();
      moho::register_ConVar_con_TestVarUByte();
      moho::register_TConVar_con_TestVarFloat();
      moho::register_con_TestVarStr();
      moho::register_TConVar_con_TestVarStr();
      moho::register_TConVar_graphics_Fidelity();
      moho::register_TConVar_graphics_FidelitySupported();
      moho::register_TConVar_shadow_Fidelity();
      moho::register_TConVar_shadow_FidelitySupported();
      moho::register_TConVar_d3d_UseRefRast();
      moho::register_TConVar_d3d_ForceSoftwareVP();
      moho::register_TConVar_d3d_NoPureDevice();
      moho::register_TConVar_d3d_ForceDirect3DDebugEnabled();
      moho::register_TConVar_d3d_WindowsCursor();
      moho::register_TConVar_snd_ExtraDoWorkCalls();
      moho::register_CConFunc_d3d_AntiAliasingSamples();
      moho::register_CConFunc_ren_MipSkipLevels();
      moho::register_CConFunc_DumpPreloadedTextures();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsRender gConsoleStartupRegistrationsRender;

  struct ConsoleStartupRegistrationsDebug
  {
    ConsoleStartupRegistrationsDebug()
    {
      moho::register_CConFunc_LUADOC();
      moho::register_CConFunc_LUA();
      moho::register_CConFunc_ExecutePasteBuffer();
      moho::register_CConFunc_UI_ResetView();
      moho::register_CConFunc_PrintStats();
      moho::register_CConFunc_ClearStats();
      moho::register_CConFunc_BeginLoggingStats();
      moho::register_CConFunc_EndLoggingStats();
      moho::register_CConFunc_mesh_Rebatch();
      moho::register_CConFunc_EFX_CreateEmitterWindow();
      moho::register_CConFunc_p4_Edit();
      moho::register_CConFunc_p4_IsOpenedForEdit();
      moho::register_CConFunc_Log();
      moho::register_CConFunc_CreateProp();
      moho::register_CConFunc_CreateUnit();
      moho::register_CConFunc_LotsOfProps();
      moho::register_CConFunc_KillSelectedUnits();
      moho::register_CConFunc_DestroySelectedUnits();
      moho::register_CConFunc_CopySelectedUnitsToClipboard();
      moho::register_CConFunc_AddSplat();
      moho::register_CConFunc_ProcessInfoPair();
      moho::register_CConFunc_UI_TrackUnit();
      moho::register_CConFunc_RenameUnit();
      moho::register_CConFunc_IssueCommand();
      moho::register_CConFunc_SkipUIChecks();
      moho::register_CConFunc_WLD_RestartBeat();
      moho::register_CConFunc_WLD_AdvanceBeat();
      moho::register_CConFunc_WLD_SingleStep();
      moho::register_CConFunc_WLD_GameSpeed();
      moho::register_CConFunc_FindUnit();
      moho::register_CConFunc_SC_LuaDebugger();
      moho::register_CConFunc_DoSimCommand();
      moho::register_CConFunc_StartCommandMode();
      moho::register_CConFunc_DebugGenerateBuildTemplateFromSelection();
      moho::register_CConFunc_DebugClearBuildTemplates();
      moho::register_CConFunc_Debug_Warn();
      moho::register_CConFunc_Debug_Error();
      moho::register_CConFunc_Debug_Assert();
      moho::register_CConFunc_Debug_Crash();
      moho::register_CConFunc_Debug_Throw();
      moho::register_TConVar_recon_debug();
      moho::register_TConVar_rule_Paranoid();
      moho::register_TConVar_rule_BlueprintReloadDelay();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsDebug gConsoleStartupRegistrationsDebug;

  struct ConsoleStartupRegistrationsWindow
  {
    ConsoleStartupRegistrationsWindow()
    {
      moho::register_CConFunc_exit();
      moho::register_CConFunc_WIN_ToggleLogDialog();
      moho::register_CConFunc_WIN_ShowLogDialog();
      moho::register_CConFunc_WxInputBox();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsWindow gConsoleStartupRegistrationsWindow;
} // namespace

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct CConCommandLuaBinderBootstrap
  {
    CConCommandLuaBinderBootstrap()
    {
      (void)::moho::register_ConExecute_LuaFuncDef();
      (void)::moho::register_ConExecuteSave_LuaFuncDef();
    }
  };

  const CConCommandLuaBinderBootstrap gCConCommandLuaBinderBootstrap{};
} // namespace

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct CConCommandLuaFuncDefBootstrap
  {
    CConCommandLuaFuncDefBootstrap()
    {
      (void)::moho::func_ConTextMatches_LuaFuncDef();
    }
  };

  const CConCommandLuaFuncDefBootstrap gCConCommandLuaFuncDefBootstrap{};
} // namespace
