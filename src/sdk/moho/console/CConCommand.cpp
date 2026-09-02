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
#include "moho/audio/CUserSoundManager.h"
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
#include "moho/render/MapImager.h"
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
#include "moho/sim/Sim.h"
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

// Defined at global scope in SimRecoveryRuntime.cpp (that file declares no
// header of its own).
extern void SimDriverDebugClientManagerRuntime();

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
    return userUnit;  // UserEntity is a base of UserUnit; let the compiler adjust
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
void moho::CON_d3d_AntiAliasingSamplesSeedFromFirstToken(void* const commandArgs)
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
  constexpr const char* kConsoleStartupConInSetKeyNameDescription = "Set a key name to map to a key code";
  constexpr const char* kConsoleStartupConInDumpKeyNamesDescription = "Shows all the key names.";
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
  CConFunc gCConFunc_IN_SetKeyName{};
  CConFunc gCConFunc_IN_DumpKeyNames{};
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

  /**
   * Address: 0x00BF1880 (FUN_00BF1880, ??1CConFunc_exit@Moho@@QAE@XZ)
   *
   * What it does:
   * Unregisters startup command storage for `exit`.
   */
  void cleanup_CConFunc_exit()
  {
    CleanupStartupConCommand(gCConFunc_exit);
  }

  /**
   * Address: 0x00BF18E0 (FUN_00BF18E0, ??1CConFunc_WIN_ToggleLogDialog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `WIN_ToggleLogDialog`.
   */
  void cleanup_CConFunc_WIN_ToggleLogDialog()
  {
    CleanupStartupConCommand(gCConFunc_WIN_ToggleLogDialog);
  }

  /**
   * Address: 0x00BF1910 (FUN_00BF1910, ??1CConFunc_WIN_ShowLogDialog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `WIN_ShowLogDialog`.
   */
  void cleanup_CConFunc_WIN_ShowLogDialog()
  {
    CleanupStartupConCommand(gCConFunc_WIN_ShowLogDialog);
  }

  /**
   * Address: 0x00BF1960 (FUN_00BF1960, ??1CConFunc_WxInputBox@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `WxInputBox`.
   */
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

  /**
   * Address: 0x00C06760 (FUN_00C06760, ??1CConFunc_IN_BindKey@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `IN_BindKey`.
   */
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
   * Address: 0x00C067C0 (FUN_00C067C0, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `IN_SetKeyName`.
   */
  void cleanup_CConFunc_IN_SetKeyName()
  {
    CleanupStartupConCommand(gCConFunc_IN_SetKeyName);
  }

  /**
   * Address: 0x00BE48D0 (FUN_00BE48D0, register_CConFunc_IN_SetKeyName)
   *
   * What it does:
   * Registers the `IN_SetKeyName` startup console callback with its exact
   * command metadata (name and description confirmed from the registrar's
   * stru_F5B1AC in the PE .data image) and schedules the generated
   * command-object cleanup lane.
   */
  void register_CConFunc_IN_SetKeyName()
  {
    RegisterStartupConFunc(
      gCConFunc_IN_SetKeyName,
      kConsoleStartupConInSetKeyNameDescription,
      "IN_SetKeyName",
      &moho::IN_SetKeyName,
      &cleanup_CConFunc_IN_SetKeyName
    );
  }

  // Compiler-generated global cleanup lane for FUN_00BE4910's atexit callee.
  // The owning source construct is the typed CConFunc object registered
  // below; no standalone engine behavior is attached to that artifact
  // address.
  void cleanup_CConFunc_IN_DumpKeyNames()
  {
    CleanupStartupConCommand(gCConFunc_IN_DumpKeyNames);
  }

  /**
   * Address: 0x00BE4910 (FUN_00BE4910, register_CConFunc_IN_DumpKeyNames)
   *
   * What it does:
   * Registers the `IN_DumpKeyNames` startup console callback with its exact
   * command metadata (name and description confirmed from the registrar's
   * stru_F5B1BC in the PE .data image) and schedules the generated
   * command-object cleanup lane.
   */
  void register_CConFunc_IN_DumpKeyNames()
  {
    RegisterStartupConFunc(
      gCConFunc_IN_DumpKeyNames,
      kConsoleStartupConInDumpKeyNamesDescription,
      "IN_DumpKeyNames",
      &moho::IN_DumpKeyNames,
      &cleanup_CConFunc_IN_DumpKeyNames
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
   * Address: 0x00C06160 (FUN_00C06160, ??1CConFunc_StartCommandMode@Moho@@QAE@@Z)
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
      moho::register_CConFunc_IN_SetKeyName();
      moho::register_CConFunc_IN_DumpKeyNames();
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

namespace
{
  constexpr const char* kConsoleStartupAiInitialEnergyCurrencyDescription = "Initial currency of energy economy.";
  constexpr const char* kConsoleStartupAiInitialEnergyCurrencyMaxDescription = "Initial currency of energy economy.";
} // namespace

namespace moho
{
  TConVar<float> gTConVar_ai_InitialEnergyCurrency(
    "ai_InitialEnergyCurrency",
    kConsoleStartupAiInitialEnergyCurrencyDescription,
    &moho::ai_InitialEnergyCurrency
  );
  TConVar<float> gTConVar_ai_InitialEnergyCurrencyMax(
    "ai_InitialEnergyCurrencyMax",
    kConsoleStartupAiInitialEnergyCurrencyMaxDescription,
    &moho::ai_InitialEnergyCurrencyMax
  );

  /**
   * Address: 0x00C02130 (FUN_00C02130, ??1TConVar_ai_InitialEnergyCurrency@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ai_InitialEnergyCurrency`.
   */
  void cleanup_TConVar_ai_InitialEnergyCurrency()
  {
    CleanupStartupConCommand(gTConVar_ai_InitialEnergyCurrency);
  }

  /**
   * Address: 0x00BDCFB0 (FUN_00BDCFB0, register_TConVar_ai_InitialEnergyCurrency)
   *
   * What it does:
   * Registers startup convar for `ai_InitialEnergyCurrency`.
   */
  void register_TConVar_ai_InitialEnergyCurrency()
  {
    RegisterStartupConVar(gTConVar_ai_InitialEnergyCurrency, &cleanup_TConVar_ai_InitialEnergyCurrency);
  }

  /**
   * Address: 0x00C02190 (FUN_00C02190, ??1TConVar_ai_InitialEnergyCurrencyMax@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ai_InitialEnergyCurrencyMax`.
   */
  void cleanup_TConVar_ai_InitialEnergyCurrencyMax()
  {
    CleanupStartupConCommand(gTConVar_ai_InitialEnergyCurrencyMax);
  }

  /**
   * Address: 0x00BDD030 (FUN_00BDD030, register_TConVar_ai_InitialEnergyCurrencyMax)
   *
   * What it does:
   * Registers startup convar for `ai_InitialEnergyCurrencyMax`.
   */
  void register_TConVar_ai_InitialEnergyCurrencyMax()
  {
    RegisterStartupConVar(gTConVar_ai_InitialEnergyCurrencyMax, &cleanup_TConVar_ai_InitialEnergyCurrencyMax);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsAi
  {
    ConsoleStartupRegistrationsAi()
    {
      moho::register_TConVar_ai_InitialEnergyCurrency();
      moho::register_TConVar_ai_InitialEnergyCurrencyMax();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsAi gConsoleStartupRegistrationsAi;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupNetAckDelayDescription = "Number of milliseconds to delay before sending ACKs";
  constexpr const char* kConsoleStartupNetCompressionMethodDescription = "Compression method, 0=none, 1=deflate.  Only takes effect when connections are first established.";
  constexpr const char* kConsoleStartupNetDebugLevelDescription = "Amount of network debug spew";
  constexpr const char* kConsoleStartupNetLagDescription = "Lag, in milliseconds.";
  constexpr const char* kConsoleStartupNetLogPacketsDescription = "Log all incomming/outgoing packets.";
  constexpr const char* kConsoleStartupNetMaxBacklogDescription = "Maximum number of bytes to backlog to any one client.";
  constexpr const char* kConsoleStartupNetMaxResendDelayDescription = "Maximum number of milliseconds to delay before resending a packet.";
  constexpr const char* kConsoleStartupNetMaxSendRateDescription = "Maximum number of bytes to send per second to any one client.";
  constexpr const char* kConsoleStartupNetMinResendDelayDescription = "Minimum number of milliseconds to delay before resending a packet.";
  constexpr const char* kConsoleStartupNetResendPingMultiplierDescription = "The resend delay is ping*new_ResendPingMultiplier+net_ResendDelayBias.";
  constexpr const char* kConsoleStartupNetSendDelayDescription = "Number of milliseconds to delay before sending Data";
} // namespace

namespace moho
{
  extern int net_AckDelay;
  extern int net_CompressionMethod;
  extern int net_DebugLevel;
  extern bool net_LogPackets;
  extern int net_MaxBacklog;
  extern int net_MaxResendDelay;
  extern int net_MaxSendRate;
  extern int net_MinResendDelay;
  extern float net_ResendPingMultiplier;
  extern int net_SendDelay;

  TConVar<int> gTConVar_net_AckDelay(
    "net_AckDelay",
    kConsoleStartupNetAckDelayDescription,
    &moho::net_AckDelay
  );
  TConVar<int> gTConVar_net_CompressionMethod(
    "net_CompressionMethod",
    kConsoleStartupNetCompressionMethodDescription,
    &moho::net_CompressionMethod
  );
  TConVar<int> gTConVar_net_DebugLevel(
    "net_DebugLevel",
    kConsoleStartupNetDebugLevelDescription,
    &moho::net_DebugLevel
  );
  TConVar<float> gTConVar_net_Lag(
    "net_Lag",
    kConsoleStartupNetLagDescription,
    &moho::net_Lag
  );
  TConVar<bool> gTConVar_net_LogPackets(
    "net_LogPackets",
    kConsoleStartupNetLogPacketsDescription,
    &moho::net_LogPackets
  );
  TConVar<int> gTConVar_net_MaxBacklog(
    "net_MaxBacklog",
    kConsoleStartupNetMaxBacklogDescription,
    &moho::net_MaxBacklog
  );
  TConVar<int> gTConVar_net_MaxResendDelay(
    "net_MaxResendDelay",
    kConsoleStartupNetMaxResendDelayDescription,
    &moho::net_MaxResendDelay
  );
  TConVar<int> gTConVar_net_MaxSendRate(
    "net_MaxSendRate",
    kConsoleStartupNetMaxSendRateDescription,
    &moho::net_MaxSendRate
  );
  TConVar<int> gTConVar_net_MinResendDelay(
    "net_MinResendDelay",
    kConsoleStartupNetMinResendDelayDescription,
    &moho::net_MinResendDelay
  );
  TConVar<float> gTConVar_net_ResendPingMultiplier(
    "net_ResendPingMultiplier",
    kConsoleStartupNetResendPingMultiplierDescription,
    &moho::net_ResendPingMultiplier
  );
  TConVar<int> gTConVar_net_SendDelay(
    "net_SendDelay",
    kConsoleStartupNetSendDelayDescription,
    &moho::net_SendDelay
  );

  /**
   * Address: 0x00BEFB50 (FUN_00BEFB50, ??1TConVar_net_AckDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_AckDelay`.
   */
  void cleanup_TConVar_net_AckDelay()
  {
    CleanupStartupConCommand(gTConVar_net_AckDelay);
  }

  /**
   * Address: 0x00BC4EF0 (FUN_00BC4EF0, register_TConVar_net_AckDelay)
   *
   * What it does:
   * Registers startup convar for `net_AckDelay`.
   */
  void register_TConVar_net_AckDelay()
  {
    RegisterStartupConVar(gTConVar_net_AckDelay, &cleanup_TConVar_net_AckDelay);
  }

  /**
   * Address: 0x00BEFCA0 (FUN_00BEFCA0, ??1TConVar_net_CompressionMethod@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_CompressionMethod`.
   */
  void cleanup_TConVar_net_CompressionMethod()
  {
    CleanupStartupConCommand(gTConVar_net_CompressionMethod);
  }

  /**
   * Address: 0x00BC50B0 (FUN_00BC50B0, register_TConVar_net_CompressionMethod)
   *
   * What it does:
   * Registers startup convar for `net_CompressionMethod`.
   */
  void register_TConVar_net_CompressionMethod()
  {
    RegisterStartupConVar(gTConVar_net_CompressionMethod, &cleanup_TConVar_net_CompressionMethod);
  }

  /**
   * Address: 0x00BEFB20 (FUN_00BEFB20, ??1TConVar_net_DebugLevel@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_DebugLevel`.
   */
  void cleanup_TConVar_net_DebugLevel()
  {
    CleanupStartupConCommand(gTConVar_net_DebugLevel);
  }

  /**
   * Address: 0x00BC4EB0 (FUN_00BC4EB0, register_TConVar_net_DebugLevel)
   *
   * What it does:
   * Registers startup convar for `net_DebugLevel`.
   */
  void register_TConVar_net_DebugLevel()
  {
    RegisterStartupConVar(gTConVar_net_DebugLevel, &cleanup_TConVar_net_DebugLevel);
  }

  /**
   * Address: 0x00C00C00 (FUN_00C00C00, ??1TConVar_net_Lag@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_Lag`.
   */
  void cleanup_TConVar_net_Lag()
  {
    CleanupStartupConCommand(gTConVar_net_Lag);
  }

  /**
   * Address: 0x00BDB8E0 (FUN_00BDB8E0, register_TConVar_net_Lag)
   *
   * What it does:
   * Registers startup convar for `net_Lag`.
   */
  void register_TConVar_net_Lag()
  {
    RegisterStartupConVar(gTConVar_net_Lag, &cleanup_TConVar_net_Lag);
  }

  /**
   * Address: 0x00BEFBB0 (FUN_00BEFBB0, ??1TConVar_net_LogPackets@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_LogPackets`.
   */
  void cleanup_TConVar_net_LogPackets()
  {
    CleanupStartupConCommand(gTConVar_net_LogPackets);
  }

  /**
   * Address: 0x00BC4F70 (FUN_00BC4F70, register_TConVar_net_LogPackets)
   *
   * What it does:
   * Registers startup convar for `net_LogPackets`.
   */
  void register_TConVar_net_LogPackets()
  {
    RegisterStartupConVar(gTConVar_net_LogPackets, &cleanup_TConVar_net_LogPackets);
  }

  /**
   * Address: 0x00BEFC70 (FUN_00BEFC70, ??1TConVar_net_MaxBacklog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_MaxBacklog`.
   */
  void cleanup_TConVar_net_MaxBacklog()
  {
    CleanupStartupConCommand(gTConVar_net_MaxBacklog);
  }

  /**
   * Address: 0x00BC5070 (FUN_00BC5070, register_TConVar_net_MaxBacklog)
   *
   * What it does:
   * Registers startup convar for `net_MaxBacklog`.
   */
  void register_TConVar_net_MaxBacklog()
  {
    RegisterStartupConVar(gTConVar_net_MaxBacklog, &cleanup_TConVar_net_MaxBacklog);
  }

  /**
   * Address: 0x00BEFC10 (FUN_00BEFC10, ??1TConVar_net_MaxResendDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_MaxResendDelay`.
   */
  void cleanup_TConVar_net_MaxResendDelay()
  {
    CleanupStartupConCommand(gTConVar_net_MaxResendDelay);
  }

  /**
   * Address: 0x00BC4FF0 (FUN_00BC4FF0, register_TConVar_net_MaxResendDelay)
   *
   * What it does:
   * Registers startup convar for `net_MaxResendDelay`.
   */
  void register_TConVar_net_MaxResendDelay()
  {
    RegisterStartupConVar(gTConVar_net_MaxResendDelay, &cleanup_TConVar_net_MaxResendDelay);
  }

  /**
   * Address: 0x00BEFC40 (FUN_00BEFC40, ??1TConVar_net_MaxSendRate@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_MaxSendRate`.
   */
  void cleanup_TConVar_net_MaxSendRate()
  {
    CleanupStartupConCommand(gTConVar_net_MaxSendRate);
  }

  /**
   * Address: 0x00BC5030 (FUN_00BC5030, register_TConVar_net_MaxSendRate)
   *
   * What it does:
   * Registers startup convar for `net_MaxSendRate`.
   */
  void register_TConVar_net_MaxSendRate()
  {
    RegisterStartupConVar(gTConVar_net_MaxSendRate, &cleanup_TConVar_net_MaxSendRate);
  }

  /**
   * Address: 0x00BEFBE0 (FUN_00BEFBE0, ??1TConVar_net_MinResendDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_MinResendDelay`.
   */
  void cleanup_TConVar_net_MinResendDelay()
  {
    CleanupStartupConCommand(gTConVar_net_MinResendDelay);
  }

  /**
   * Address: 0x00BC4FB0 (FUN_00BC4FB0, register_TConVar_net_MinResendDelay)
   *
   * What it does:
   * Registers startup convar for `net_MinResendDelay`.
   */
  void register_TConVar_net_MinResendDelay()
  {
    RegisterStartupConVar(gTConVar_net_MinResendDelay, &cleanup_TConVar_net_MinResendDelay);
  }

  /**
   * Address: 0x00BEFCD0 (FUN_00BEFCD0, ??1TConVar_net_ResendPingMultiplier@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_ResendPingMultiplier`.
   */
  void cleanup_TConVar_net_ResendPingMultiplier()
  {
    CleanupStartupConCommand(gTConVar_net_ResendPingMultiplier);
  }

  /**
   * Address: 0x00BC50F0 (FUN_00BC50F0, register_TConVar_net_ResendPingMultiplier)
   *
   * What it does:
   * Registers startup convar for `net_ResendPingMultiplier`.
   */
  void register_TConVar_net_ResendPingMultiplier()
  {
    RegisterStartupConVar(gTConVar_net_ResendPingMultiplier, &cleanup_TConVar_net_ResendPingMultiplier);
  }

  /**
   * Address: 0x00BEFB80 (FUN_00BEFB80, ??1TConVar_net_SendDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `net_SendDelay`.
   */
  void cleanup_TConVar_net_SendDelay()
  {
    CleanupStartupConCommand(gTConVar_net_SendDelay);
  }

  /**
   * Address: 0x00BC4F30 (FUN_00BC4F30, register_TConVar_net_SendDelay)
   *
   * What it does:
   * Registers startup convar for `net_SendDelay`.
   */
  void register_TConVar_net_SendDelay()
  {
    RegisterStartupConVar(gTConVar_net_SendDelay, &cleanup_TConVar_net_SendDelay);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsNet
  {
    ConsoleStartupRegistrationsNet()
    {
      moho::register_TConVar_net_AckDelay();
      moho::register_TConVar_net_CompressionMethod();
      moho::register_TConVar_net_DebugLevel();
      moho::register_TConVar_net_Lag();
      moho::register_TConVar_net_LogPackets();
      moho::register_TConVar_net_MaxBacklog();
      moho::register_TConVar_net_MaxResendDelay();
      moho::register_TConVar_net_MaxSendRate();
      moho::register_TConVar_net_MinResendDelay();
      moho::register_TConVar_net_ResendPingMultiplier();
      moho::register_TConVar_net_SendDelay();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsNet gConsoleStartupRegistrationsNet;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupSimDebugCheatsDescription = "Log a backtrace when we detect a cheat.";
  constexpr const char* kConsoleStartupSimDebugDelayDescription = "Milliseconds to delay each sim tick to simulate a slow sim.";
  constexpr const char* kConsoleStartupSimInterlockedDescription = "If true, force the sim and UI threads to run interlocked.";
  constexpr const char* kConsoleStartupSimIssueThreadDebugLevelDescription = "How much debug spam to spew from the issue thread.";
  constexpr const char* kConsoleStartupSimKeepAllLogFilesDescription = "If true, keep all long files instead of just the ones for beats that appear out-of-sync.";
  constexpr const char* kConsoleStartupSimLogSizeDescription = "How many ticks to log before flushing files.";
  constexpr const char* kConsoleStartupSimReportCheatsDescription = "Report cheating when cheats are enabled.";
  constexpr const char* kConsoleStartupSimShowDamageDescription = "Show debug damage info";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
bool moho::sim_DebugCheats = false;
int moho::sim_DebugDelay = 0;
bool moho::sim_Interlocked = true;
int moho::sim_LogSize = 10;
bool moho::sim_ReportCheats = false;

namespace moho
{
  extern bool sim_KeepAllLogFiles;
  extern bool sim_ShowDamage;

  TConVar<bool> gTConVar_sim_DebugCheats(
    "sim_DebugCheats",
    kConsoleStartupSimDebugCheatsDescription,
    &moho::sim_DebugCheats
  );
  TConVar<int> gTConVar_sim_DebugDelay(
    "sim_DebugDelay",
    kConsoleStartupSimDebugDelayDescription,
    &moho::sim_DebugDelay
  );
  TConVar<bool> gTConVar_sim_Interlocked(
    "sim_Interlocked",
    kConsoleStartupSimInterlockedDescription,
    &moho::sim_Interlocked
  );
  TConVar<int> gTConVar_sim_IssueThreadDebugLevel(
    "sim_IssueThreadDebugLevel",
    kConsoleStartupSimIssueThreadDebugLevelDescription,
    &moho::sim_IssueThreadDebugLevel
  );
  TConVar<bool> gTConVar_sim_KeepAllLogFiles(
    "sim_KeepAllLogFiles",
    kConsoleStartupSimKeepAllLogFilesDescription,
    &moho::sim_KeepAllLogFiles
  );
  TConVar<int> gTConVar_sim_LogSize(
    "sim_LogSize",
    kConsoleStartupSimLogSizeDescription,
    &moho::sim_LogSize
  );
  TConVar<bool> gTConVar_sim_ReportCheats(
    "sim_ReportCheats",
    kConsoleStartupSimReportCheatsDescription,
    &moho::sim_ReportCheats
  );
  TConVar<bool> gTConVar_sim_ShowDamage(
    "sim_ShowDamage",
    kConsoleStartupSimShowDamageDescription,
    &moho::sim_ShowDamage
  );

  /**
   * Address: 0x00C00CE0 (FUN_00C00CE0, ??1TConVar_sim_DebugCheats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_DebugCheats`.
   */
  void cleanup_TConVar_sim_DebugCheats()
  {
    CleanupStartupConCommand(gTConVar_sim_DebugCheats);
  }

  /**
   * Address: 0x00BDBA50 (FUN_00BDBA50, register_TConVar_sim_DebugCheats)
   *
   * What it does:
   * Registers startup convar for `sim_DebugCheats`.
   */
  void register_TConVar_sim_DebugCheats()
  {
    RegisterStartupConVar(gTConVar_sim_DebugCheats, &cleanup_TConVar_sim_DebugCheats);
  }

  /**
   * Address: 0x00C00C30 (FUN_00C00C30, ??1TConVar_sim_DebugDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_DebugDelay`.
   */
  void cleanup_TConVar_sim_DebugDelay()
  {
    CleanupStartupConCommand(gTConVar_sim_DebugDelay);
  }

  /**
   * Address: 0x00BDB920 (FUN_00BDB920, register_TConVar_sim_DebugDelay)
   *
   * What it does:
   * Registers startup convar for `sim_DebugDelay`.
   */
  void register_TConVar_sim_DebugDelay()
  {
    RegisterStartupConVar(gTConVar_sim_DebugDelay, &cleanup_TConVar_sim_DebugDelay);
  }

  /**
   * Address: 0x00C00BA0 (FUN_00C00BA0, ??1TConVar_sim_Interlocked@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_Interlocked`.
   */
  void cleanup_TConVar_sim_Interlocked()
  {
    CleanupStartupConCommand(gTConVar_sim_Interlocked);
  }

  /**
   * Address: 0x00BDB860 (FUN_00BDB860, register_TConVar_sim_Interlocked)
   *
   * What it does:
   * Registers startup convar for `sim_Interlocked`.
   */
  void register_TConVar_sim_Interlocked()
  {
    RegisterStartupConVar(gTConVar_sim_Interlocked, &cleanup_TConVar_sim_Interlocked);
  }

  /**
   * Address: 0x00C00BD0 (FUN_00C00BD0, ??1TConVar_sim_IssueThreadDebugLevel@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_IssueThreadDebugLevel`.
   */
  void cleanup_TConVar_sim_IssueThreadDebugLevel()
  {
    CleanupStartupConCommand(gTConVar_sim_IssueThreadDebugLevel);
  }

  /**
   * Address: 0x00BDB8A0 (FUN_00BDB8A0, register_TConVar_sim_IssueThreadDebugLevel)
   *
   * What it does:
   * Registers startup convar for `sim_IssueThreadDebugLevel`.
   */
  void register_TConVar_sim_IssueThreadDebugLevel()
  {
    RegisterStartupConVar(gTConVar_sim_IssueThreadDebugLevel, &cleanup_TConVar_sim_IssueThreadDebugLevel);
  }

  /**
   * Address: 0x00C00CB0 (FUN_00C00CB0, ??1TConVar_sim_KeepAllLogFiles@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_KeepAllLogFiles`.
   */
  void cleanup_TConVar_sim_KeepAllLogFiles()
  {
    CleanupStartupConCommand(gTConVar_sim_KeepAllLogFiles);
  }

  /**
   * Address: 0x00BDBA10 (FUN_00BDBA10, register_TConVar_sim_KeepAllLogFiles)
   *
   * What it does:
   * Registers startup convar for `sim_KeepAllLogFiles`.
   */
  void register_TConVar_sim_KeepAllLogFiles()
  {
    RegisterStartupConVar(gTConVar_sim_KeepAllLogFiles, &cleanup_TConVar_sim_KeepAllLogFiles);
  }

  /**
   * Address: 0x00C00C80 (FUN_00C00C80, ??1TConVar_sim_LogSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_LogSize`.
   */
  void cleanup_TConVar_sim_LogSize()
  {
    CleanupStartupConCommand(gTConVar_sim_LogSize);
  }

  /**
   * Address: 0x00BDB9D0 (FUN_00BDB9D0, register_TConVar_sim_LogSize)
   *
   * What it does:
   * Registers startup convar for `sim_LogSize`.
   */
  void register_TConVar_sim_LogSize()
  {
    RegisterStartupConVar(gTConVar_sim_LogSize, &cleanup_TConVar_sim_LogSize);
  }

  /**
   * Address: 0x00C00D10 (FUN_00C00D10, ??1TConVar_sim_ReportCheats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_ReportCheats`.
   */
  void cleanup_TConVar_sim_ReportCheats()
  {
    CleanupStartupConCommand(gTConVar_sim_ReportCheats);
  }

  /**
   * Address: 0x00BDBA90 (FUN_00BDBA90, register_TConVar_sim_ReportCheats)
   *
   * What it does:
   * Registers startup convar for `sim_ReportCheats`.
   */
  void register_TConVar_sim_ReportCheats()
  {
    RegisterStartupConVar(gTConVar_sim_ReportCheats, &cleanup_TConVar_sim_ReportCheats);
  }

  /**
   * Address: 0x00C00AE0 (FUN_00C00AE0, ??1TConVar_sim_ShowDamage@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `sim_ShowDamage`.
   */
  void cleanup_TConVar_sim_ShowDamage()
  {
    CleanupStartupConCommand(gTConVar_sim_ShowDamage);
  }

  /**
   * Address: 0x00BDB6B0 (FUN_00BDB6B0, register_TConVar_sim_ShowDamage)
   *
   * What it does:
   * Registers startup convar for `sim_ShowDamage`.
   */
  void register_TConVar_sim_ShowDamage()
  {
    RegisterStartupConVar(gTConVar_sim_ShowDamage, &cleanup_TConVar_sim_ShowDamage);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsSim2
  {
    ConsoleStartupRegistrationsSim2()
    {
      moho::register_TConVar_sim_DebugCheats();
      moho::register_TConVar_sim_DebugDelay();
      moho::register_TConVar_sim_Interlocked();
      moho::register_TConVar_sim_IssueThreadDebugLevel();
      moho::register_TConVar_sim_KeepAllLogFiles();
      moho::register_TConVar_sim_LogSize();
      moho::register_TConVar_sim_ReportCheats();
      moho::register_TConVar_sim_ShowDamage();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsSim2 gConsoleStartupRegistrationsSim2;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupCamDefaultMiniLODDescription = "Default LOD for mini-map";
  constexpr const char* kConsoleStartupCamEntityBoxExpandDescription = "How much to expand the entity box when targetting entity";
  constexpr const char* kConsoleStartupCamFarFOVDescription = "FOV to use for perspective camera at farthest zoom, in degrees";
  constexpr const char* kConsoleStartupCamFarPitchDescription = "Pitch of camera at farthest zoom, in degrees";
  constexpr const char* kConsoleStartupCamFreeDescription = "Allow the camera to remain rotated";
  constexpr const char* kConsoleStartupCamMinSpinPitchDescription = "The min pitch resulting from a spin";
  constexpr const char* kConsoleStartupCamNearFOVDescription = "FOV to use for perspective camera at nearest zoom, in degrees";
  constexpr const char* kConsoleStartupCamNearPitchDescription = "Pitch of camera at nearest zoom, in degrees";
  constexpr const char* kConsoleStartupCamNearZoomDescription = "Closest mouse can zoom in to terrain";
  constexpr const char* kConsoleStartupCamPanSpeedDescription = "How fast the camera pans.";
  constexpr const char* kConsoleStartupCamShakeMultDescription = "How much camera shake to allow.";
  constexpr const char* kConsoleStartupCamSpinSpeedDescription = "How fast mouse spins camera, in degrees across screen size";
  constexpr const char* kConsoleStartupCamTrackProjectileTimeoutDescription = "Delay after tracking a projectile.";
  constexpr const char* kConsoleStartupCamZoomAmountDescription = "How far to zoom in response to the mouse wheel.";
  constexpr const char* kConsoleStartupCamZoomSpeedLargeDescription = "How fast the camera actually moves in response to a large zoom.";
  constexpr const char* kConsoleStartupCamZoomSpeedSmallDescription = "How fast the camera actually moves in response to a small zoom.";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
float moho::cam_TrackProjectileTimeout = 6.0f;

namespace moho
{
  extern float cam_DefaultMiniLOD;
  extern float cam_EntityBoxExpand;
  extern float cam_FarFOV;
  extern float cam_FarPitch;
  extern bool cam_Free;
  extern float cam_MinSpinPitch;
  extern float cam_NearFOV;
  extern float cam_NearPitch;
  extern float cam_NearZoom;
  extern float cam_PanSpeed;
  extern float cam_ShakeMult;
  extern float cam_SpinSpeed;
  extern float cam_ZoomAmount;
  extern float cam_ZoomSpeedLarge;
  extern float cam_ZoomSpeedSmall;

  TConVar<float> gTConVar_cam_DefaultMiniLOD(
    "cam_DefaultMiniLOD",
    kConsoleStartupCamDefaultMiniLODDescription,
    &moho::cam_DefaultMiniLOD
  );
  TConVar<float> gTConVar_cam_EntityBoxExpand(
    "cam_EntityBoxExpand",
    kConsoleStartupCamEntityBoxExpandDescription,
    &moho::cam_EntityBoxExpand
  );
  TConVar<float> gTConVar_cam_FarFOV(
    "cam_FarFOV",
    kConsoleStartupCamFarFOVDescription,
    &moho::cam_FarFOV
  );
  TConVar<float> gTConVar_cam_FarPitch(
    "cam_FarPitch",
    kConsoleStartupCamFarPitchDescription,
    &moho::cam_FarPitch
  );
  TConVar<bool> gTConVar_cam_Free(
    "cam_Free",
    kConsoleStartupCamFreeDescription,
    &moho::cam_Free
  );
  TConVar<float> gTConVar_cam_MinSpinPitch(
    "cam_MinSpinPitch",
    kConsoleStartupCamMinSpinPitchDescription,
    &moho::cam_MinSpinPitch
  );
  TConVar<float> gTConVar_cam_NearFOV(
    "cam_NearFOV",
    kConsoleStartupCamNearFOVDescription,
    &moho::cam_NearFOV
  );
  TConVar<float> gTConVar_cam_NearPitch(
    "cam_NearPitch",
    kConsoleStartupCamNearPitchDescription,
    &moho::cam_NearPitch
  );
  TConVar<float> gTConVar_cam_NearZoom(
    "cam_NearZoom",
    kConsoleStartupCamNearZoomDescription,
    &moho::cam_NearZoom
  );
  TConVar<float> gTConVar_cam_PanSpeed(
    "cam_PanSpeed",
    kConsoleStartupCamPanSpeedDescription,
    &moho::cam_PanSpeed
  );
  TConVar<float> gTConVar_cam_ShakeMult(
    "cam_ShakeMult",
    kConsoleStartupCamShakeMultDescription,
    &moho::cam_ShakeMult
  );
  TConVar<float> gTConVar_cam_SpinSpeed(
    "cam_SpinSpeed",
    kConsoleStartupCamSpinSpeedDescription,
    &moho::cam_SpinSpeed
  );
  TConVar<float> gTConVar_cam_TrackProjectileTimeout(
    "cam_TrackProjectileTimeout",
    kConsoleStartupCamTrackProjectileTimeoutDescription,
    &moho::cam_TrackProjectileTimeout
  );
  TConVar<float> gTConVar_cam_ZoomAmount(
    "cam_ZoomAmount",
    kConsoleStartupCamZoomAmountDescription,
    &moho::cam_ZoomAmount
  );
  TConVar<float> gTConVar_cam_ZoomSpeedLarge(
    "cam_ZoomSpeedLarge",
    kConsoleStartupCamZoomSpeedLargeDescription,
    &moho::cam_ZoomSpeedLarge
  );
  TConVar<float> gTConVar_cam_ZoomSpeedSmall(
    "cam_ZoomSpeedSmall",
    kConsoleStartupCamZoomSpeedSmallDescription,
    &moho::cam_ZoomSpeedSmall
  );

  /**
   * Address: 0x00C077E0 (FUN_00C077E0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_DefaultMiniLOD`.
   */
  void cleanup_TConVar_cam_DefaultMiniLOD()
  {
    CleanupStartupConCommand(gTConVar_cam_DefaultMiniLOD);
  }

  /**
   * Address: 0x00BE66E0 (FUN_00BE66E0, register_TConVar_cam_DefaultMiniLOD)
   *
   * What it does:
   * Registers startup convar for `cam_DefaultMiniLOD`.
   */
  void register_TConVar_cam_DefaultMiniLOD()
  {
    RegisterStartupConVar(gTConVar_cam_DefaultMiniLOD, &cleanup_TConVar_cam_DefaultMiniLOD);
  }

  /**
   * Address: 0x00C03550 (FUN_00C03550, ??1TConVar_cam_EntityBoxExpand@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_EntityBoxExpand`.
   */
  void cleanup_TConVar_cam_EntityBoxExpand()
  {
    CleanupStartupConCommand(gTConVar_cam_EntityBoxExpand);
  }

  /**
   * Address: 0x00BDF540 (FUN_00BDF540, register_TConVar_cam_EntityBoxExpand)
   *
   * What it does:
   * Registers startup convar for `cam_EntityBoxExpand`.
   */
  void register_TConVar_cam_EntityBoxExpand()
  {
    RegisterStartupConVar(gTConVar_cam_EntityBoxExpand, &cleanup_TConVar_cam_EntityBoxExpand);
  }

  /**
   * Address: 0x00C03370 (FUN_00C03370, ??1TConVar_cam_FarFOV@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_FarFOV`.
   */
  void cleanup_TConVar_cam_FarFOV()
  {
    CleanupStartupConCommand(gTConVar_cam_FarFOV);
  }

  /**
   * Address: 0x00BDF2C0 (FUN_00BDF2C0, register_TConVar_cam_FarFOV)
   *
   * What it does:
   * Registers startup convar for `cam_FarFOV`.
   */
  void register_TConVar_cam_FarFOV()
  {
    RegisterStartupConVar(gTConVar_cam_FarFOV, &cleanup_TConVar_cam_FarFOV);
  }

  /**
   * Address: 0x00C033D0 (FUN_00C033D0, ??1TConVar_cam_FarPitch@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_FarPitch`.
   */
  void cleanup_TConVar_cam_FarPitch()
  {
    CleanupStartupConCommand(gTConVar_cam_FarPitch);
  }

  /**
   * Address: 0x00BDF340 (FUN_00BDF340, register_TConVar_cam_FarPitch)
   *
   * What it does:
   * Registers startup convar for `cam_FarPitch`.
   */
  void register_TConVar_cam_FarPitch()
  {
    RegisterStartupConVar(gTConVar_cam_FarPitch, &cleanup_TConVar_cam_FarPitch);
  }

  /**
   * Address: 0x00C077B0 (FUN_00C077B0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_Free`.
   */
  void cleanup_TConVar_cam_Free()
  {
    CleanupStartupConCommand(gTConVar_cam_Free);
  }

  /**
   * Address: 0x00BE66A0 (FUN_00BE66A0, register_TConVar_cam_Free)
   *
   * What it does:
   * Registers startup convar for `cam_Free`.
   */
  void register_TConVar_cam_Free()
  {
    RegisterStartupConVar(gTConVar_cam_Free, &cleanup_TConVar_cam_Free);
  }

  /**
   * Address: 0x00C03580 (FUN_00C03580, ??1TConVar_cam_MinSpinPitch@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_MinSpinPitch`.
   */
  void cleanup_TConVar_cam_MinSpinPitch()
  {
    CleanupStartupConCommand(gTConVar_cam_MinSpinPitch);
  }

  /**
   * Address: 0x00BDF580 (FUN_00BDF580, register_TConVar_cam_MinSpinPitch)
   *
   * What it does:
   * Registers startup convar for `cam_MinSpinPitch`.
   */
  void register_TConVar_cam_MinSpinPitch()
  {
    RegisterStartupConVar(gTConVar_cam_MinSpinPitch, &cleanup_TConVar_cam_MinSpinPitch);
  }

  /**
   * Address: 0x00C03340 (FUN_00C03340, ??1TConVar_cam_NearFOV@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_NearFOV`.
   */
  void cleanup_TConVar_cam_NearFOV()
  {
    CleanupStartupConCommand(gTConVar_cam_NearFOV);
  }

  /**
   * Address: 0x00BDF280 (FUN_00BDF280, register_TConVar_cam_NearFOV)
   *
   * What it does:
   * Registers startup convar for `cam_NearFOV`.
   */
  void register_TConVar_cam_NearFOV()
  {
    RegisterStartupConVar(gTConVar_cam_NearFOV, &cleanup_TConVar_cam_NearFOV);
  }

  /**
   * Address: 0x00C033A0 (FUN_00C033A0, ??1TConVar_cam_NearPitch@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_NearPitch`.
   */
  void cleanup_TConVar_cam_NearPitch()
  {
    CleanupStartupConCommand(gTConVar_cam_NearPitch);
  }

  /**
   * Address: 0x00BDF300 (FUN_00BDF300, register_TConVar_cam_NearPitch)
   *
   * What it does:
   * Registers startup convar for `cam_NearPitch`.
   */
  void register_TConVar_cam_NearPitch()
  {
    RegisterStartupConVar(gTConVar_cam_NearPitch, &cleanup_TConVar_cam_NearPitch);
  }

  /**
   * Address: 0x00C03310 (FUN_00C03310, ??1TConVar_cam_NearZoom@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_NearZoom`.
   */
  void cleanup_TConVar_cam_NearZoom()
  {
    CleanupStartupConCommand(gTConVar_cam_NearZoom);
  }

  /**
   * Address: 0x00BDF240 (FUN_00BDF240, register_TConVar_cam_NearZoom)
   *
   * What it does:
   * Registers startup convar for `cam_NearZoom`.
   */
  void register_TConVar_cam_NearZoom()
  {
    RegisterStartupConVar(gTConVar_cam_NearZoom, &cleanup_TConVar_cam_NearZoom);
  }

  /**
   * Address: 0x00C034F0 (FUN_00C034F0, ??1TConVar_cam_PanSpeed@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_PanSpeed`.
   */
  void cleanup_TConVar_cam_PanSpeed()
  {
    CleanupStartupConCommand(gTConVar_cam_PanSpeed);
  }

  /**
   * Address: 0x00BDF4C0 (FUN_00BDF4C0, register_TConVar_cam_PanSpeed)
   *
   * What it does:
   * Registers startup convar for `cam_PanSpeed`.
   */
  void register_TConVar_cam_PanSpeed()
  {
    RegisterStartupConVar(gTConVar_cam_PanSpeed, &cleanup_TConVar_cam_PanSpeed);
  }

  /**
   * Address: 0x00C03520 (FUN_00C03520, ??1TConVar_cam_ShakeMult@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_ShakeMult`.
   */
  void cleanup_TConVar_cam_ShakeMult()
  {
    CleanupStartupConCommand(gTConVar_cam_ShakeMult);
  }

  /**
   * Address: 0x00BDF500 (FUN_00BDF500, register_TConVar_cam_ShakeMult)
   *
   * What it does:
   * Registers startup convar for `cam_ShakeMult`.
   */
  void register_TConVar_cam_ShakeMult()
  {
    RegisterStartupConVar(gTConVar_cam_ShakeMult, &cleanup_TConVar_cam_ShakeMult);
  }

  /**
   * Address: 0x00C034C0 (FUN_00C034C0, ??1TConVar_cam_SpinSpeed@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_SpinSpeed`.
   */
  void cleanup_TConVar_cam_SpinSpeed()
  {
    CleanupStartupConCommand(gTConVar_cam_SpinSpeed);
  }

  /**
   * Address: 0x00BDF480 (FUN_00BDF480, register_TConVar_cam_SpinSpeed)
   *
   * What it does:
   * Registers startup convar for `cam_SpinSpeed`.
   */
  void register_TConVar_cam_SpinSpeed()
  {
    RegisterStartupConVar(gTConVar_cam_SpinSpeed, &cleanup_TConVar_cam_SpinSpeed);
  }

  /**
   * Address: 0x00C03490 (FUN_00C03490, ??1TConVar_cam_TrackProjectileTimeout@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_TrackProjectileTimeout`.
   */
  void cleanup_TConVar_cam_TrackProjectileTimeout()
  {
    CleanupStartupConCommand(gTConVar_cam_TrackProjectileTimeout);
  }

  /**
   * Address: 0x00BDF440 (FUN_00BDF440, register_TConVar_cam_TrackProjectileTimeout)
   *
   * What it does:
   * Registers startup convar for `cam_TrackProjectileTimeout`.
   */
  void register_TConVar_cam_TrackProjectileTimeout()
  {
    RegisterStartupConVar(gTConVar_cam_TrackProjectileTimeout, &cleanup_TConVar_cam_TrackProjectileTimeout);
  }

  /**
   * Address: 0x00C03400 (FUN_00C03400, ??1TConVar_cam_ZoomAmount@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_ZoomAmount`.
   */
  void cleanup_TConVar_cam_ZoomAmount()
  {
    CleanupStartupConCommand(gTConVar_cam_ZoomAmount);
  }

  /**
   * Address: 0x00BDF380 (FUN_00BDF380, register_TConVar_cam_ZoomAmount)
   *
   * What it does:
   * Registers startup convar for `cam_ZoomAmount`.
   */
  void register_TConVar_cam_ZoomAmount()
  {
    RegisterStartupConVar(gTConVar_cam_ZoomAmount, &cleanup_TConVar_cam_ZoomAmount);
  }

  /**
   * Address: 0x00C03460 (FUN_00C03460, ??1TConVar_cam_ZoomSpeedLarge@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_ZoomSpeedLarge`.
   */
  void cleanup_TConVar_cam_ZoomSpeedLarge()
  {
    CleanupStartupConCommand(gTConVar_cam_ZoomSpeedLarge);
  }

  /**
   * Address: 0x00BDF400 (FUN_00BDF400, register_TConVar_cam_ZoomSpeedLarge)
   *
   * What it does:
   * Registers startup convar for `cam_ZoomSpeedLarge`.
   */
  void register_TConVar_cam_ZoomSpeedLarge()
  {
    RegisterStartupConVar(gTConVar_cam_ZoomSpeedLarge, &cleanup_TConVar_cam_ZoomSpeedLarge);
  }

  /**
   * Address: 0x00C03430 (FUN_00C03430, ??1TConVar_cam_ZoomSpeedSmall@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `cam_ZoomSpeedSmall`.
   */
  void cleanup_TConVar_cam_ZoomSpeedSmall()
  {
    CleanupStartupConCommand(gTConVar_cam_ZoomSpeedSmall);
  }

  /**
   * Address: 0x00BDF3C0 (FUN_00BDF3C0, register_TConVar_cam_ZoomSpeedSmall)
   *
   * What it does:
   * Registers startup convar for `cam_ZoomSpeedSmall`.
   */
  void register_TConVar_cam_ZoomSpeedSmall()
  {
    RegisterStartupConVar(gTConVar_cam_ZoomSpeedSmall, &cleanup_TConVar_cam_ZoomSpeedSmall);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsCam
  {
    ConsoleStartupRegistrationsCam()
    {
      moho::register_TConVar_cam_DefaultMiniLOD();
      moho::register_TConVar_cam_EntityBoxExpand();
      moho::register_TConVar_cam_FarFOV();
      moho::register_TConVar_cam_FarPitch();
      moho::register_TConVar_cam_Free();
      moho::register_TConVar_cam_MinSpinPitch();
      moho::register_TConVar_cam_NearFOV();
      moho::register_TConVar_cam_NearPitch();
      moho::register_TConVar_cam_NearZoom();
      moho::register_TConVar_cam_PanSpeed();
      moho::register_TConVar_cam_ShakeMult();
      moho::register_TConVar_cam_SpinSpeed();
      moho::register_TConVar_cam_TrackProjectileTimeout();
      moho::register_TConVar_cam_ZoomAmount();
      moho::register_TConVar_cam_ZoomSpeedLarge();
      moho::register_TConVar_cam_ZoomSpeedSmall();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsCam gConsoleStartupRegistrationsCam;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupDbgMetronomeDescription = "Tick a metronome every tick.";
  constexpr const char* kConsoleStartupDbgMonitorAddressSpaceDescription = "If true, monitor address space usage.";
  constexpr const char* kConsoleStartupDebugMovieDescription = "debug movie output";
  constexpr const char* kConsoleStartupDumpRateDescription = "Frame rate to use for movie dumps";
  constexpr const char* kConsoleStartupDumpOutputFrameNumberDescription = "Starting frame to dump on";
  constexpr const char* kConsoleStartupEdEnableHookDescription = "ed_EnableHook tuning value.";
  constexpr const char* kConsoleStartupEfxWaveCutoffDescription = "Shoreline LOD cutoff";
  constexpr const char* kConsoleStartupFogDistanceFogDescription = "Distance fog enabled?";
  constexpr const char* kConsoleStartupFogOffsetMultiplierDescription = "amount to fudge offset by to make fog go away as we zoom out";
  constexpr const char* kConsoleStartupScFrameTimeClampDescription = "Minimum time between frames, in milliseconds";
  constexpr const char* kConsoleStartupScSkipIntroDescription = "Skip intro movies";
  constexpr const char* kConsoleStartupSndCheckDistanceDescription = "Do distance checks for sound culling.";
  constexpr const char* kConsoleStartupSndCheckLOSDescription = "Do LOS checks for sound culling.";
  constexpr const char* kConsoleStartupSndSpewSoundDescription = "Spew debug sound info";
  constexpr const char* kConsoleStartupWldRunWithTheWindDescription = "If true, run beats as fast as we can.";
  constexpr const char* kConsoleStartupWldSkewRateAdjustBaseDescription = "How much to adjust the sim rate based on one beat of skew.";
  constexpr const char* kConsoleStartupWldSkewRateAdjustMaxDescription = "Max amount to adjust the sim rate due to skew.";
  constexpr const char* kConsoleStartupWndDefaultCreateHeightDescription = "Minimum initial window height";
  constexpr const char* kConsoleStartupWndDefaultCreateWidthDescription = "Minimum initial window width";
  constexpr const char* kConsoleStartupWndMinCmdLineHeightDescription = "Minimum command line height";
  constexpr const char* kConsoleStartupWndMinCmdLineWidthDescription = "Minimum command line width";
  constexpr const char* kConsoleStartupWndMinDragHeightDescription = "Minimum drag-resize height";
  constexpr const char* kConsoleStartupWndMinDragWidthDescription = "Minimum drag-resize width";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
bool moho::dbg_MonitorAddressSpace = false;
float moho::dump_Rate = 30.0f;
float moho::efx_WaveCutoff = 400.0f;
float moho::sc_FrameTimeClamp = 10.0f;
bool moho::sc_SkipIntro = false;

namespace moho
{
  extern bool dbg_Metronome;
  extern bool debug_movie;
  extern int dump_outputFrameNumber;
  extern bool ed_EnableHook;
  extern bool fog_DistanceFog;
  extern float fog_OffsetMultiplier;
  extern bool snd_CheckDistance;
  extern bool snd_CheckLOS;
  extern bool snd_SpewSound;
  extern bool wld_RunWithTheWind;
  extern float wld_SkewRateAdjustBase;
  extern float wld_SkewRateAdjustMax;
  extern int wnd_DefaultCreateHeight;
  extern int wnd_DefaultCreateWidth;
  extern int wnd_MinCmdLineHeight;
  extern int wnd_MinCmdLineWidth;
  extern int wnd_MinDragHeight;
  extern int wnd_MinDragWidth;

  TConVar<bool> gTConVar_dbg_Metronome(
    "dbg_Metronome",
    kConsoleStartupDbgMetronomeDescription,
    &moho::dbg_Metronome
  );
  TConVar<bool> gTConVar_dbg_MonitorAddressSpace(
    "dbg_MonitorAddressSpace",
    kConsoleStartupDbgMonitorAddressSpaceDescription,
    &moho::dbg_MonitorAddressSpace
  );
  TConVar<bool> gTConVar_debug_movie(
    "debug_movie",
    kConsoleStartupDebugMovieDescription,
    &moho::debug_movie
  );
  TConVar<float> gTConVar_dump_Rate(
    "dump_Rate",
    kConsoleStartupDumpRateDescription,
    &moho::dump_Rate
  );
  TConVar<int> gTConVar_dump_outputFrameNumber(
    "dump_outputFrameNumber",
    kConsoleStartupDumpOutputFrameNumberDescription,
    &moho::dump_outputFrameNumber
  );
  TConVar<bool> gTConVar_ed_EnableHook(
    "ed_EnableHook",
    kConsoleStartupEdEnableHookDescription,
    &moho::ed_EnableHook
  );
  TConVar<float> gTConVar_efx_WaveCutoff(
    "efx_WaveCutoff",
    kConsoleStartupEfxWaveCutoffDescription,
    &moho::efx_WaveCutoff
  );
  TConVar<bool> gTConVar_fog_DistanceFog(
    "fog_DistanceFog",
    kConsoleStartupFogDistanceFogDescription,
    &moho::fog_DistanceFog
  );
  TConVar<float> gTConVar_fog_OffsetMultiplier(
    "fog_OffsetMultiplier",
    kConsoleStartupFogOffsetMultiplierDescription,
    &moho::fog_OffsetMultiplier
  );
  TConVar<float> gTConVar_sc_FrameTimeClamp(
    "sc_FrameTimeClamp",
    kConsoleStartupScFrameTimeClampDescription,
    &moho::sc_FrameTimeClamp
  );
  TConVar<bool> gTConVar_sc_SkipIntro(
    "sc_SkipIntro",
    kConsoleStartupScSkipIntroDescription,
    &moho::sc_SkipIntro
  );
  TConVar<bool> gTConVar_snd_CheckDistance(
    "snd_CheckDistance",
    kConsoleStartupSndCheckDistanceDescription,
    &moho::snd_CheckDistance
  );
  TConVar<bool> gTConVar_snd_CheckLOS(
    "snd_CheckLOS",
    kConsoleStartupSndCheckLOSDescription,
    &moho::snd_CheckLOS
  );
  TConVar<bool> gTConVar_snd_SpewSound(
    "snd_SpewSound",
    kConsoleStartupSndSpewSoundDescription,
    &moho::snd_SpewSound
  );
  TConVar<bool> gTConVar_wld_RunWithTheWind(
    "wld_RunWithTheWind",
    kConsoleStartupWldRunWithTheWindDescription,
    &moho::wld_RunWithTheWind
  );
  TConVar<float> gTConVar_wld_SkewRateAdjustBase(
    "wld_SkewRateAdjustBase",
    kConsoleStartupWldSkewRateAdjustBaseDescription,
    &moho::wld_SkewRateAdjustBase
  );
  TConVar<float> gTConVar_wld_SkewRateAdjustMax(
    "wld_SkewRateAdjustMax",
    kConsoleStartupWldSkewRateAdjustMaxDescription,
    &moho::wld_SkewRateAdjustMax
  );
  TConVar<int> gTConVar_wnd_DefaultCreateHeight(
    "wnd_DefaultCreateHeight",
    kConsoleStartupWndDefaultCreateHeightDescription,
    &moho::wnd_DefaultCreateHeight
  );
  TConVar<int> gTConVar_wnd_DefaultCreateWidth(
    "wnd_DefaultCreateWidth",
    kConsoleStartupWndDefaultCreateWidthDescription,
    &moho::wnd_DefaultCreateWidth
  );
  TConVar<int> gTConVar_wnd_MinCmdLineHeight(
    "wnd_MinCmdLineHeight",
    kConsoleStartupWndMinCmdLineHeightDescription,
    &moho::wnd_MinCmdLineHeight
  );
  TConVar<int> gTConVar_wnd_MinCmdLineWidth(
    "wnd_MinCmdLineWidth",
    kConsoleStartupWndMinCmdLineWidthDescription,
    &moho::wnd_MinCmdLineWidth
  );
  TConVar<int> gTConVar_wnd_MinDragHeight(
    "wnd_MinDragHeight",
    kConsoleStartupWndMinDragHeightDescription,
    &moho::wnd_MinDragHeight
  );
  TConVar<int> gTConVar_wnd_MinDragWidth(
    "wnd_MinDragWidth",
    kConsoleStartupWndMinDragWidthDescription,
    &moho::wnd_MinDragWidth
  );

  /**
   * Address: 0x00C08160 (FUN_00C08160, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `dbg_Metronome`.
   */
  void cleanup_TConVar_dbg_Metronome()
  {
    CleanupStartupConCommand(gTConVar_dbg_Metronome);
  }

  /**
   * Address: 0x00BE76F0 (FUN_00BE76F0, register_TConVar_dbg_Metronome)
   *
   * What it does:
   * Registers startup convar for `dbg_Metronome`.
   */
  void register_TConVar_dbg_Metronome()
  {
    RegisterStartupConVar(gTConVar_dbg_Metronome, &cleanup_TConVar_dbg_Metronome);
  }

  /**
   * Address: 0x00C08C10 (FUN_00C08C10, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `dbg_MonitorAddressSpace`.
   */
  void cleanup_TConVar_dbg_MonitorAddressSpace()
  {
    CleanupStartupConCommand(gTConVar_dbg_MonitorAddressSpace);
  }

  /**
   * Address: 0x00BE8F60 (FUN_00BE8F60, register_TConVar_dbg_MonitorAddressSpace)
   *
   * What it does:
   * Registers startup convar for `dbg_MonitorAddressSpace`.
   */
  void register_TConVar_dbg_MonitorAddressSpace()
  {
    RegisterStartupConVar(gTConVar_dbg_MonitorAddressSpace, &cleanup_TConVar_dbg_MonitorAddressSpace);
  }

  /**
   * Address: 0x00C07B10 (FUN_00C07B10, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `debug_movie`.
   */
  void cleanup_TConVar_debug_movie()
  {
    CleanupStartupConCommand(gTConVar_debug_movie);
  }

  /**
   * Address: 0x00BE6C40 (FUN_00BE6C40, register_TConVar_debug_movie)
   *
   * What it does:
   * Registers startup convar for `debug_movie`.
   */
  void register_TConVar_debug_movie()
  {
    RegisterStartupConVar(gTConVar_debug_movie, &cleanup_TConVar_debug_movie);
  }

  /**
   * Address: 0x00C04210 (FUN_00C04210, ??1TConVar_dump_Rate@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `dump_Rate`.
   */
  void cleanup_TConVar_dump_Rate()
  {
    CleanupStartupConCommand(gTConVar_dump_Rate);
  }

  /**
   * Address: 0x00BE0F10 (FUN_00BE0F10, register_TConVar_dump_Rate)
   *
   * What it does:
   * Registers startup convar for `dump_Rate`.
   */
  void register_TConVar_dump_Rate()
  {
    RegisterStartupConVar(gTConVar_dump_Rate, &cleanup_TConVar_dump_Rate);
  }

  /**
   * Address: 0x00C041E0 (FUN_00C041E0, ??1TConVar_dump_outputFrameNumber@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `dump_outputFrameNumber`.
   */
  void cleanup_TConVar_dump_outputFrameNumber()
  {
    CleanupStartupConCommand(gTConVar_dump_outputFrameNumber);
  }

  /**
   * Address: 0x00BE0ED0 (FUN_00BE0ED0, register_TConVar_dump_outputFrameNumber)
   *
   * What it does:
   * Registers startup convar for `dump_outputFrameNumber`.
   */
  void register_TConVar_dump_outputFrameNumber()
  {
    RegisterStartupConVar(gTConVar_dump_outputFrameNumber, &cleanup_TConVar_dump_outputFrameNumber);
  }

  /**
   * Address: 0x00C04990 (FUN_00C04990, ??1TConVar_ed_EnableHook@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ed_EnableHook`.
   */
  void cleanup_TConVar_ed_EnableHook()
  {
    CleanupStartupConCommand(gTConVar_ed_EnableHook);
  }

  /**
   * Address: 0x00BE1A10 (FUN_00BE1A10, register_TConVar_ed_EnableHook)
   *
   * What it does:
   * Registers startup convar for `ed_EnableHook`.
   */
  void register_TConVar_ed_EnableHook()
  {
    RegisterStartupConVar(gTConVar_ed_EnableHook, &cleanup_TConVar_ed_EnableHook);
  }

  /**
   * Address: 0x00C07E60 (FUN_00C07E60, ??1TConVar_efx_WaveCutoff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `efx_WaveCutoff`.
   */
  void cleanup_TConVar_efx_WaveCutoff()
  {
    CleanupStartupConCommand(gTConVar_efx_WaveCutoff);
  }

  /**
   * Address: 0x00BE71B0 (FUN_00BE71B0, register_TConVar_efx_WaveCutoff)
   *
   * What it does:
   * Registers startup convar for `efx_WaveCutoff`.
   */
  void register_TConVar_efx_WaveCutoff()
  {
    RegisterStartupConVar(gTConVar_efx_WaveCutoff, &cleanup_TConVar_efx_WaveCutoff);
  }

  /**
   * Address: 0x00C04720 (FUN_00C04720, ??1TConVar_fog_DistanceFog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `fog_DistanceFog`.
   */
  void cleanup_TConVar_fog_DistanceFog()
  {
    CleanupStartupConCommand(gTConVar_fog_DistanceFog);
  }

  /**
   * Address: 0x00BE16D0 (FUN_00BE16D0, register_TConVar_fog_DistanceFog)
   *
   * What it does:
   * Registers startup convar for `fog_DistanceFog`.
   */
  void register_TConVar_fog_DistanceFog()
  {
    RegisterStartupConVar(gTConVar_fog_DistanceFog, &cleanup_TConVar_fog_DistanceFog);
  }

  /**
   * Address: 0x00C04B10 (FUN_00C04B10, ??1TConVar_fog_OffsetMultiplier@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `fog_OffsetMultiplier`.
   */
  void cleanup_TConVar_fog_OffsetMultiplier()
  {
    CleanupStartupConCommand(gTConVar_fog_OffsetMultiplier);
  }

  /**
   * Address: 0x00BE1C10 (FUN_00BE1C10, register_TConVar_fog_OffsetMultiplier)
   *
   * What it does:
   * Registers startup convar for `fog_OffsetMultiplier`.
   */
  void register_TConVar_fog_OffsetMultiplier()
  {
    RegisterStartupConVar(gTConVar_fog_OffsetMultiplier, &cleanup_TConVar_fog_OffsetMultiplier);
  }

  /**
   * Address: 0x00C08AC0 (FUN_00C08AC0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `sc_FrameTimeClamp`.
   */
  void cleanup_TConVar_sc_FrameTimeClamp()
  {
    CleanupStartupConCommand(gTConVar_sc_FrameTimeClamp);
  }

  /**
   * Address: 0x00BE8DA0 (FUN_00BE8DA0, register_TConVar_sc_FrameTimeClamp)
   *
   * What it does:
   * Registers startup convar for `sc_FrameTimeClamp`.
   */
  void register_TConVar_sc_FrameTimeClamp()
  {
    RegisterStartupConVar(gTConVar_sc_FrameTimeClamp, &cleanup_TConVar_sc_FrameTimeClamp);
  }

  /**
   * Address: 0x00C08A90 (FUN_00C08A90, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `sc_SkipIntro`.
   */
  void cleanup_TConVar_sc_SkipIntro()
  {
    CleanupStartupConCommand(gTConVar_sc_SkipIntro);
  }

  /**
   * Address: 0x00BE8D60 (FUN_00BE8D60, register_TConVar_sc_SkipIntro)
   *
   * What it does:
   * Registers startup convar for `sc_SkipIntro`.
   */
  void register_TConVar_sc_SkipIntro()
  {
    RegisterStartupConVar(gTConVar_sc_SkipIntro, &cleanup_TConVar_sc_SkipIntro);
  }

  /**
   * Address: 0x00C08520 (FUN_00C08520, ??1TConVar_snd_CheckDistance@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `snd_CheckDistance`.
   */
  void cleanup_TConVar_snd_CheckDistance()
  {
    CleanupStartupConCommand(gTConVar_snd_CheckDistance);
  }

  /**
   * Address: 0x00BE7E40 (FUN_00BE7E40, register_TConVar_snd_CheckDistance)
   *
   * What it does:
   * Registers startup convar for `snd_CheckDistance`.
   */
  void register_TConVar_snd_CheckDistance()
  {
    RegisterStartupConVar(gTConVar_snd_CheckDistance, &cleanup_TConVar_snd_CheckDistance);
  }

  /**
   * Address: 0x00C08550 (FUN_00C08550, ??1TConVar_snd_CheckLOS@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `snd_CheckLOS`.
   */
  void cleanup_TConVar_snd_CheckLOS()
  {
    CleanupStartupConCommand(gTConVar_snd_CheckLOS);
  }

  /**
   * Address: 0x00BE7E80 (FUN_00BE7E80, register_TConVar_snd_CheckLOS)
   *
   * What it does:
   * Registers startup convar for `snd_CheckLOS`.
   */
  void register_TConVar_snd_CheckLOS()
  {
    RegisterStartupConVar(gTConVar_snd_CheckLOS, &cleanup_TConVar_snd_CheckLOS);
  }

  /**
   * Address: 0x00C08580 (FUN_00C08580, ??1TConVar_snd_SpewSound@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `snd_SpewSound`.
   */
  void cleanup_TConVar_snd_SpewSound()
  {
    CleanupStartupConCommand(gTConVar_snd_SpewSound);
  }

  /**
   * Address: 0x00BE7EC0 (FUN_00BE7EC0, register_TConVar_snd_SpewSound)
   *
   * What it does:
   * Registers startup convar for `snd_SpewSound`.
   */
  void register_TConVar_snd_SpewSound()
  {
    RegisterStartupConVar(gTConVar_snd_SpewSound, &cleanup_TConVar_snd_SpewSound);
  }

  /**
   * Address: 0x00C08190 (FUN_00C08190, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wld_RunWithTheWind`.
   */
  void cleanup_TConVar_wld_RunWithTheWind()
  {
    CleanupStartupConCommand(gTConVar_wld_RunWithTheWind);
  }

  /**
   * Address: 0x00BE7730 (FUN_00BE7730, register_TConVar_wld_RunWithTheWind)
   *
   * What it does:
   * Registers startup convar for `wld_RunWithTheWind`.
   */
  void register_TConVar_wld_RunWithTheWind()
  {
    RegisterStartupConVar(gTConVar_wld_RunWithTheWind, &cleanup_TConVar_wld_RunWithTheWind);
  }

  /**
   * Address: 0x00C07F00 (FUN_00C07F00, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wld_SkewRateAdjustBase`.
   */
  void cleanup_TConVar_wld_SkewRateAdjustBase()
  {
    CleanupStartupConCommand(gTConVar_wld_SkewRateAdjustBase);
  }

  /**
   * Address: 0x00BE7290 (FUN_00BE7290, register_TConVar_wld_SkewRateAdjustBase)
   *
   * What it does:
   * Registers startup convar for `wld_SkewRateAdjustBase`.
   */
  void register_TConVar_wld_SkewRateAdjustBase()
  {
    RegisterStartupConVar(gTConVar_wld_SkewRateAdjustBase, &cleanup_TConVar_wld_SkewRateAdjustBase);
  }

  /**
   * Address: 0x00C07F30 (FUN_00C07F30, ??1TConVar_wld_SkewRateAdjustMax@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `wld_SkewRateAdjustMax`.
   */
  void cleanup_TConVar_wld_SkewRateAdjustMax()
  {
    CleanupStartupConCommand(gTConVar_wld_SkewRateAdjustMax);
  }

  /**
   * Address: 0x00BE72D0 (FUN_00BE72D0, register_TConVar_wld_SkewRateAdjustMax)
   *
   * What it does:
   * Registers startup convar for `wld_SkewRateAdjustMax`.
   */
  void register_TConVar_wld_SkewRateAdjustMax()
  {
    RegisterStartupConVar(gTConVar_wld_SkewRateAdjustMax, &cleanup_TConVar_wld_SkewRateAdjustMax);
  }

  /**
   * Address: 0x00C08BE0 (FUN_00C08BE0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_DefaultCreateHeight`.
   */
  void cleanup_TConVar_wnd_DefaultCreateHeight()
  {
    CleanupStartupConCommand(gTConVar_wnd_DefaultCreateHeight);
  }

  /**
   * Address: 0x00BE8F20 (FUN_00BE8F20, register_TConVar_wnd_DefaultCreateHeight)
   *
   * What it does:
   * Registers startup convar for `wnd_DefaultCreateHeight`.
   */
  void register_TConVar_wnd_DefaultCreateHeight()
  {
    RegisterStartupConVar(gTConVar_wnd_DefaultCreateHeight, &cleanup_TConVar_wnd_DefaultCreateHeight);
  }

  /**
   * Address: 0x00C08BB0 (FUN_00C08BB0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_DefaultCreateWidth`.
   */
  void cleanup_TConVar_wnd_DefaultCreateWidth()
  {
    CleanupStartupConCommand(gTConVar_wnd_DefaultCreateWidth);
  }

  /**
   * Address: 0x00BE8EE0 (FUN_00BE8EE0, register_TConVar_wnd_DefaultCreateWidth)
   *
   * What it does:
   * Registers startup convar for `wnd_DefaultCreateWidth`.
   */
  void register_TConVar_wnd_DefaultCreateWidth()
  {
    RegisterStartupConVar(gTConVar_wnd_DefaultCreateWidth, &cleanup_TConVar_wnd_DefaultCreateWidth);
  }

  /**
   * Address: 0x00C08B20 (FUN_00C08B20, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_MinCmdLineHeight`.
   */
  void cleanup_TConVar_wnd_MinCmdLineHeight()
  {
    CleanupStartupConCommand(gTConVar_wnd_MinCmdLineHeight);
  }

  /**
   * Address: 0x00BE8E20 (FUN_00BE8E20, register_TConVar_wnd_MinCmdLineHeight)
   *
   * What it does:
   * Registers startup convar for `wnd_MinCmdLineHeight`.
   */
  void register_TConVar_wnd_MinCmdLineHeight()
  {
    RegisterStartupConVar(gTConVar_wnd_MinCmdLineHeight, &cleanup_TConVar_wnd_MinCmdLineHeight);
  }

  /**
   * Address: 0x00C08AF0 (FUN_00C08AF0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_MinCmdLineWidth`.
   */
  void cleanup_TConVar_wnd_MinCmdLineWidth()
  {
    CleanupStartupConCommand(gTConVar_wnd_MinCmdLineWidth);
  }

  /**
   * Address: 0x00BE8DE0 (FUN_00BE8DE0, register_TConVar_wnd_MinCmdLineWidth)
   *
   * What it does:
   * Registers startup convar for `wnd_MinCmdLineWidth`.
   */
  void register_TConVar_wnd_MinCmdLineWidth()
  {
    RegisterStartupConVar(gTConVar_wnd_MinCmdLineWidth, &cleanup_TConVar_wnd_MinCmdLineWidth);
  }

  /**
   * Address: 0x00C08B80 (FUN_00C08B80, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_MinDragHeight`.
   */
  void cleanup_TConVar_wnd_MinDragHeight()
  {
    CleanupStartupConCommand(gTConVar_wnd_MinDragHeight);
  }

  /**
   * Address: 0x00BE8EA0 (FUN_00BE8EA0, register_TConVar_wnd_MinDragHeight)
   *
   * What it does:
   * Registers startup convar for `wnd_MinDragHeight`.
   */
  void register_TConVar_wnd_MinDragHeight()
  {
    RegisterStartupConVar(gTConVar_wnd_MinDragHeight, &cleanup_TConVar_wnd_MinDragHeight);
  }

  /**
   * Address: 0x00C08B50 (FUN_00C08B50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `wnd_MinDragWidth`.
   */
  void cleanup_TConVar_wnd_MinDragWidth()
  {
    CleanupStartupConCommand(gTConVar_wnd_MinDragWidth);
  }

  /**
   * Address: 0x00BE8E60 (FUN_00BE8E60, register_TConVar_wnd_MinDragWidth)
   *
   * What it does:
   * Registers startup convar for `wnd_MinDragWidth`.
   */
  void register_TConVar_wnd_MinDragWidth()
  {
    RegisterStartupConVar(gTConVar_wnd_MinDragWidth, &cleanup_TConVar_wnd_MinDragWidth);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsMisc
  {
    ConsoleStartupRegistrationsMisc()
    {
      moho::register_TConVar_dbg_Metronome();
      moho::register_TConVar_dbg_MonitorAddressSpace();
      moho::register_TConVar_debug_movie();
      moho::register_TConVar_dump_Rate();
      moho::register_TConVar_dump_outputFrameNumber();
      moho::register_TConVar_ed_EnableHook();
      moho::register_TConVar_efx_WaveCutoff();
      moho::register_TConVar_fog_DistanceFog();
      moho::register_TConVar_fog_OffsetMultiplier();
      moho::register_TConVar_sc_FrameTimeClamp();
      moho::register_TConVar_sc_SkipIntro();
      moho::register_TConVar_snd_CheckDistance();
      moho::register_TConVar_snd_CheckLOS();
      moho::register_TConVar_snd_SpewSound();
      moho::register_TConVar_wld_RunWithTheWind();
      moho::register_TConVar_wld_SkewRateAdjustBase();
      moho::register_TConVar_wld_SkewRateAdjustMax();
      moho::register_TConVar_wnd_DefaultCreateHeight();
      moho::register_TConVar_wnd_DefaultCreateWidth();
      moho::register_TConVar_wnd_MinCmdLineHeight();
      moho::register_TConVar_wnd_MinCmdLineWidth();
      moho::register_TConVar_wnd_MinDragHeight();
      moho::register_TConVar_wnd_MinDragWidth();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsMisc gConsoleStartupRegistrationsMisc;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupUIRenProectileTrailWidthDescription = "The half width, in pixels, of the projectile trail";
  // Unlike every other description string in this block, the two raw string
  // pointers this convar's registrar (0x00BE5BF0) carries in its own .data
  // image resolve into an unbacked/zero-filled region of .rdata rather than
  // real string literals -- confirmed via direct PE byte reads that the same
  // technique resolves correctly for every neighboring convar (e.g.
  // UI_RenProjectileGlow at 0x00BE5E20). The identifier "UI_RenProjectileArcs"
  // itself is certain (matches the CConCommand::mHandlerOrValue target
  // symbol and every sibling convar's name==identifier precedent); this
  // description text is inferred from the toggle's documented behavior
  // ("Gates the whole arc pass", ProjectileArcRenderer.h) and this file's own
  // "toggle X on/off" phrasing convention, not byte-verified.
  constexpr const char* kConsoleStartupUIRenProjectileArcsDescription = "toggle projectile trail arcs on/off";
  constexpr const char* kConsoleStartupUIRenProjectileArcsSampleIntervalDescription = "How often the position is updated for the projectile trail";
  constexpr const char* kConsoleStartupUIRenProjectileGlowDescription = "Toggle projectile icon glow";
  constexpr const char* kConsoleStartupUIRenProjectileGlowMaxDescription = "Maximum glow alpha on projecile icon";
  constexpr const char* kConsoleStartupUIRenProjectileGlowMinDescription = "Minimum glow alpha on projectile icon";
  constexpr const char* kConsoleStartupUIRenProjectileGlowPeriodDescription = "The period in which the projectile icon glow will pulse from min to max to min";
  constexpr const char* kConsoleStartupUIRenProjectileIconsDescription = "toggle projectile icons on/off";
  constexpr const char* kConsoleStartupUIRenProjectileTrailColorDescription = "ARGB value of the projectile trail";
  constexpr const char* kConsoleStartupUIRenResourcesDescription = "toggle resource icons on/off";
  constexpr const char* kConsoleStartupUIResourceLODCutoffDescription = "When to draw icons instead of resource deposit textures";
  constexpr const char* kConsoleStartupUISelectAnythingDescription = "Debug to allow UI to select anything";
  constexpr const char* kConsoleStartupUIShowControlUnderMouseDescription = "Highlights the control currently under the mouse";
  constexpr const char* kConsoleStartupUIStrategicProjectileLODDescription = "At what LODMetric do we draw projectile pixels on strategic view";
  constexpr const char* kConsoleStartupUIForceWeaponsToYellowDescription = "Force all minimap weapon fire to yellow";
  constexpr const char* kConsoleStartupUiAlwaysRenderStrategicIconsDescription = "When true, strategic icons always render, even when zoomed in";
  constexpr const char* kConsoleStartupUiArrowKeysScrollViewDescription = "Toggle if the arrow keys scroll the main view";
  constexpr const char* kConsoleStartupUiBuildPlaceTarmacAlphaDescription = "Tarmac alpha for buildings that are about to be placed";
  constexpr const char* kConsoleStartupUiCommandClickScaleDescription = "Scale applied to the click distance size of command waypoints";
  constexpr const char* kConsoleStartupUiCommandGraphMaxNodeUnitsDescription = "Limits the size of the waypoints";
  constexpr const char* kConsoleStartupUiCurveSegmentsDescription = "How many segments to subdivide curves into";
  constexpr const char* kConsoleStartupUiCurveSmoothnessDescription = "How big to make curves when drawing command previews";
  constexpr const char* kConsoleStartupUiCustomNameColorDescription = "Color of the custom name display";
  constexpr const char* kConsoleStartupUiCustomNameFontDescription = "Font family name of the custom name display";
  constexpr const char* kConsoleStartupUiCustomNameFontSizeDescription = "Point size of the custom name display";
  constexpr const char* kConsoleStartupUiDebugAltClickDescription = "Enable ALT+Click debug command to switch armies";
  constexpr const char* kConsoleStartupUiDisableCursorFixingDescription = "Allows you to toggle the cursor fixing functionality that is used for the mouse-controlled camera spinning/scrolling";
  constexpr const char* kConsoleStartupUiDragSelect2DDescription = "Use a 2D (screen-space) drag-selection box";
  constexpr const char* kConsoleStartupUiDrawPathPreviewDescription = "Turns on/off the arrow line";
  constexpr const char* kConsoleStartupUiExtractSnapToleranceDescription = "Sets the extraction unit 'snap-to' tolerance (in meters) for building.  Increase this to make it easier to auto-snap to extraction sites.";
  constexpr const char* kConsoleStartupUiFootprintMinThicknessDescription = "Mimimum render size for the footprint outline.";
  constexpr const char* kConsoleStartupUiForceLifbarsOnEnemyDescription = "force lifebars on for enemy units";
  constexpr const char* kConsoleStartupUiFuelBarColorDescription = "The color of the secondary Fuel bar";
  constexpr const char* kConsoleStartupUiFuelEmptyBlinkRateDescription = "Blink timer scale for empty fuel";
  constexpr const char* kConsoleStartupUiFuelWarningColorDescription = "The color of the feul warning flash";
  constexpr const char* kConsoleStartupUiKeyboardPanAccelerateMultiplierDescription = "How much faster the camera pans when accelerated";
  constexpr const char* kConsoleStartupUiKeyboardPanSpeedDescription = "How fast arrow keys pans camera";
  constexpr const char* kConsoleStartupUiKeyboardRotateAccelerateMultiplierDescription = "How much faster the camera rotates when accelerated";
  constexpr const char* kConsoleStartupUiKeyboardRotateSpeedDescription = "How fast ins/del rotate camera";
  constexpr const char* kConsoleStartupUiLifeBarBadColorDescription = "The color of the lifebar when there is poor health";
  constexpr const char* kConsoleStartupUiLifeBarBadCutoffDescription = "The percent of health where the life bar changes from bad to medium";
  constexpr const char* kConsoleStartupUiLifeBarGoodColorDescription = "The color of the lifebar when there is good health";
  constexpr const char* kConsoleStartupUiLifeBarGoodCutoffDescription = "The percent of health where the life bar changes from medium to good";
  constexpr const char* kConsoleStartupUiLifeBarMedColorDescription = "The color of the lifebar when there is medium health";
  constexpr const char* kConsoleStartupUiLifebarLODDescription = "LOD Cutoff for health bars";
  constexpr const char* kConsoleStartupUiLifebarOffsetDescription = "Y Offset in ogrids of all lifebars";
  constexpr const char* kConsoleStartupUiLifebarWidthDescription = "width of health/fuel bar in ogrids";
  constexpr const char* kConsoleStartupUiMaxExtractSnapPixelsDescription = "Allows us to put a pixel cap on the snap tolerance (in case we are zoomed in close.";
  constexpr const char* kConsoleStartupUiMaxTextLODDescription = "LOD level that timer text dissapears";
  constexpr const char* kConsoleStartupUiMaxWaypointSizeDescription = "Set the maximum pixel size of a waypoint";
  constexpr const char* kConsoleStartupUiMinExtractSnapPixelsDescription = "Allows us to put a pixel cap on the snap tolerance (in case we are zoomed out relatively far.";
  constexpr const char* kConsoleStartupUiMinWaypointSizeDescription = "Set the minimum pixel size of a waypoint";
  constexpr const char* kConsoleStartupUiNisRenderIconsDescription = "nis toggle for strat icons, also removes pause and diabled icons";
  constexpr const char* kConsoleStartupUiPathPreviewDescription = "Turns on/off the pathfinding preview line";
  constexpr const char* kConsoleStartupUiPathSmoothnessDescription = "How big to make curves when drawing path preview";
  constexpr const char* kConsoleStartupUiProgressBarColorDescription = "The color of the secondary Construction Progress bar";
  constexpr const char* kConsoleStartupUiRenderCustomNamesDescription = "toggle custom name display";
  constexpr const char* kConsoleStartupUiRenderIconsDescription = "toggle strategic icons on/off";
  constexpr const char* kConsoleStartupUiRenderSelectionSetNamesDescription = "toggle selection set names on/off";
  constexpr const char* kConsoleStartupUiRenderUnitBarsDescription = "render unit life/fuel bars?";
  constexpr const char* kConsoleStartupUiScreenEdgeScrollViewDescription = "Toggle if the mouse on the sides of the main window will scroll the view (fullscreen only)";
  constexpr const char* kConsoleStartupUiSelectToleranceDescription = "Sets the unit click tolerance (in pixels) for selection.  Increase this to make units have a larger selection box.";
  constexpr const char* kConsoleStartupUiSelectionSetNamesColorDescription = "Color of the selection set names";
  constexpr const char* kConsoleStartupUiShieldBarColorDescription = "The color of the secondary Shield bar";
  constexpr const char* kConsoleStartupUiStrategicIconBlinkDurationDescription = "How long to blink icon when unit is damage";
  constexpr const char* kConsoleStartupUiStrategicIconBlinkRateDescription = "Blink timer scale for strategic icons on damage";
  constexpr const char* kConsoleStartupUiWaypointLineScaleDescription = "Scale applied to the calculated waypoint line size";
  constexpr const char* kConsoleStartupUiWindowedAlwaysShowsCursorDescription = "Always show cursor in windowed mode, regardless of show/hide";
  constexpr const char* kConsoleStartupUiFuelbarHeightDescription = "size of the fuel bar as a fraction of the bar height";
  constexpr const char* kConsoleStartupUiLifebarHeightDescription = "height of health/fuel bar in ogrids";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
float moho::ui_BuildPlaceTarmacAlpha = 0.5f;
float moho::ui_CommandClickScale = 1.0f;
float moho::ui_fuelbarHeight = 0.25f;

namespace moho
{
  extern float UI_RenProectileTrailWidth;
  extern bool UI_RenProjectileArcs;
  extern int UI_RenProjectileArcsSampleInterval;
  extern bool UI_RenProjectileGlow;
  extern float UI_RenProjectileGlowMax;
  extern float UI_RenProjectileGlowMin;
  extern float UI_RenProjectileGlowPeriod;
  extern bool UI_RenProjectileIcons;
  extern int UI_RenProjectileTrailColor;
  extern bool UI_RenResources;
  extern float UI_ResourceLODCutoff;
  extern bool UI_SelectAnything;
  extern bool UI_ShowControlUnderMouse;
  extern float UI_StrategicProjectileLOD;
  extern bool UI_forceWeaponsToYellow;
  extern bool ui_AlwaysRenderStrategicIcons;
  extern bool ui_ArrowKeysScrollView;
  extern int ui_CommandGraphMaxNodeUnits;
  extern int ui_CurveSegments;
  extern float ui_CurveSmoothness;
  extern unsigned int ui_CustomNameColor;
  extern msvc8::string ui_CustomNameFont;
  extern int ui_CustomNameFontSize;
  extern bool ui_DebugAltClick;
  extern bool ui_DisableCursorFixing;
  extern bool ui_DragSelect2D;
  extern bool ui_DrawPathPreview;
  extern float ui_ExtractSnapTolerance;
  extern float ui_FootprintMinThickness;
  extern bool ui_ForceLifbarsOnEnemy;
  extern unsigned int ui_FuelBarColor;
  extern float ui_FuelEmptyBlinkRate;
  extern unsigned int ui_FuelWarningColor;
  extern float ui_KeyboardPanAccelerateMultiplier;
  extern float ui_KeyboardPanSpeed;
  extern float ui_KeyboardRotateAccelerateMultiplier;
  extern float ui_KeyboardRotateSpeed;
  extern unsigned int ui_LifeBarBadColor;
  extern float ui_LifeBarBadCutoff;
  extern unsigned int ui_LifeBarGoodColor;
  extern float ui_LifeBarGoodCutoff;
  extern unsigned int ui_LifeBarMedColor;
  extern float ui_LifebarLOD;
  extern float ui_LifebarOffset;
  extern float ui_LifebarWidth;
  extern float ui_MaxExtractSnapPixels;
  extern float ui_MaxTextLOD;
  extern float ui_MaxWaypointSize;
  extern float ui_MinExtractSnapPixels;
  extern float ui_MinWaypointSize;
  extern bool ui_NisRenderIcons;
  extern bool ui_PathPreview;
  extern float ui_PathSmoothness;
  extern unsigned int ui_ProgressBarColor;
  extern bool ui_RenderCustomNames;
  extern bool ui_RenderIcons;
  extern bool ui_RenderSelectionSetNames;
  extern bool ui_RenderUnitBars;
  extern bool ui_ScreenEdgeScrollView;
  extern float ui_SelectTolerance;
  extern unsigned int ui_SelectionSetNamesColor;
  extern unsigned int ui_ShieldBarColor;
  extern float ui_StrategicIconBlinkDuration;
  extern float ui_StrategicIconBlinkRate;
  extern float ui_WaypointLineScale;
  extern bool ui_WindowedAlwaysShowsCursor;
  extern float ui_lifebarHeight;

  TConVar<float> gTConVar_UI_RenProectileTrailWidth(
    "UI_RenProectileTrailWidth",
    kConsoleStartupUIRenProectileTrailWidthDescription,
    &moho::UI_RenProectileTrailWidth
  );
  TConVar<bool> gTConVar_UI_RenProjectileArcs(
    "UI_RenProjectileArcs",
    kConsoleStartupUIRenProjectileArcsDescription,
    &moho::UI_RenProjectileArcs
  );
  TConVar<int> gTConVar_UI_RenProjectileArcsSampleInterval(
    "UI_RenProjectileArcsSampleInterval",
    kConsoleStartupUIRenProjectileArcsSampleIntervalDescription,
    &moho::UI_RenProjectileArcsSampleInterval
  );
  TConVar<bool> gTConVar_UI_RenProjectileGlow(
    "UI_RenProjectileGlow",
    kConsoleStartupUIRenProjectileGlowDescription,
    &moho::UI_RenProjectileGlow
  );
  TConVar<float> gTConVar_UI_RenProjectileGlowMax(
    "UI_RenProjectileGlowMax",
    kConsoleStartupUIRenProjectileGlowMaxDescription,
    &moho::UI_RenProjectileGlowMax
  );
  TConVar<float> gTConVar_UI_RenProjectileGlowMin(
    "UI_RenProjectileGlowMin",
    kConsoleStartupUIRenProjectileGlowMinDescription,
    &moho::UI_RenProjectileGlowMin
  );
  TConVar<float> gTConVar_UI_RenProjectileGlowPeriod(
    "UI_RenProjectileGlowPeriod",
    kConsoleStartupUIRenProjectileGlowPeriodDescription,
    &moho::UI_RenProjectileGlowPeriod
  );
  TConVar<bool> gTConVar_UI_RenProjectileIcons(
    "UI_RenProjectileIcons",
    kConsoleStartupUIRenProjectileIconsDescription,
    &moho::UI_RenProjectileIcons
  );
  TConVar<int> gTConVar_UI_RenProjectileTrailColor(
    "UI_RenProjectileTrailColor",
    kConsoleStartupUIRenProjectileTrailColorDescription,
    &moho::UI_RenProjectileTrailColor
  );
  TConVar<bool> gTConVar_UI_RenResources(
    "UI_RenResources",
    kConsoleStartupUIRenResourcesDescription,
    &moho::UI_RenResources
  );
  TConVar<float> gTConVar_UI_ResourceLODCutoff(
    "UI_ResourceLODCutoff",
    kConsoleStartupUIResourceLODCutoffDescription,
    &moho::UI_ResourceLODCutoff
  );
  TConVar<bool> gTConVar_UI_SelectAnything(
    "UI_SelectAnything",
    kConsoleStartupUISelectAnythingDescription,
    &moho::UI_SelectAnything
  );
  TConVar<bool> gTConVar_UI_ShowControlUnderMouse(
    "UI_ShowControlUnderMouse",
    kConsoleStartupUIShowControlUnderMouseDescription,
    &moho::UI_ShowControlUnderMouse
  );
  TConVar<float> gTConVar_UI_StrategicProjectileLOD(
    "UI_StrategicProjectileLOD",
    kConsoleStartupUIStrategicProjectileLODDescription,
    &moho::UI_StrategicProjectileLOD
  );
  TConVar<bool> gTConVar_UI_forceWeaponsToYellow(
    "UI_forceWeaponsToYellow",
    kConsoleStartupUIForceWeaponsToYellowDescription,
    &moho::UI_forceWeaponsToYellow
  );
  TConVar<bool> gTConVar_ui_AlwaysRenderStrategicIcons(
    "ui_AlwaysRenderStrategicIcons",
    kConsoleStartupUiAlwaysRenderStrategicIconsDescription,
    &moho::ui_AlwaysRenderStrategicIcons
  );
  TConVar<bool> gTConVar_ui_ArrowKeysScrollView(
    "ui_ArrowKeysScrollView",
    kConsoleStartupUiArrowKeysScrollViewDescription,
    &moho::ui_ArrowKeysScrollView
  );
  TConVar<float> gTConVar_ui_BuildPlaceTarmacAlpha(
    "ui_BuildPlaceTarmacAlpha",
    kConsoleStartupUiBuildPlaceTarmacAlphaDescription,
    &moho::ui_BuildPlaceTarmacAlpha
  );
  TConVar<float> gTConVar_ui_CommandClickScale(
    "ui_CommandClickScale",
    kConsoleStartupUiCommandClickScaleDescription,
    &moho::ui_CommandClickScale
  );
  TConVar<int> gTConVar_ui_CommandGraphMaxNodeUnits(
    "ui_CommandGraphMaxNodeUnits",
    kConsoleStartupUiCommandGraphMaxNodeUnitsDescription,
    &moho::ui_CommandGraphMaxNodeUnits
  );
  TConVar<int> gTConVar_ui_CurveSegments(
    "ui_CurveSegments",
    kConsoleStartupUiCurveSegmentsDescription,
    &moho::ui_CurveSegments
  );
  TConVar<float> gTConVar_ui_CurveSmoothness(
    "ui_CurveSmoothness",
    kConsoleStartupUiCurveSmoothnessDescription,
    &moho::ui_CurveSmoothness
  );
  TConVar<unsigned int> gTConVar_ui_CustomNameColor(
    "ui_CustomNameColor",
    kConsoleStartupUiCustomNameColorDescription,
    &moho::ui_CustomNameColor
  );
  TConVar<msvc8::string> gTConVar_ui_CustomNameFont(
    "ui_CutsomNameFont",
    kConsoleStartupUiCustomNameFontDescription,
    &moho::ui_CustomNameFont
  );
  TConVar<int> gTConVar_ui_CustomNameFontSize(
    "ui_CustomNameFontSize",
    kConsoleStartupUiCustomNameFontSizeDescription,
    &moho::ui_CustomNameFontSize
  );
  TConVar<bool> gTConVar_ui_DebugAltClick(
    "ui_DebugAltClick",
    kConsoleStartupUiDebugAltClickDescription,
    &moho::ui_DebugAltClick
  );
  TConVar<bool> gTConVar_ui_DisableCursorFixing(
    "ui_DisableCursorFixing",
    kConsoleStartupUiDisableCursorFixingDescription,
    &moho::ui_DisableCursorFixing
  );
  TConVar<bool> gTConVar_ui_DragSelect2D(
    "ui_DragSelect2D",
    kConsoleStartupUiDragSelect2DDescription,
    &moho::ui_DragSelect2D
  );
  TConVar<bool> gTConVar_ui_DrawPathPreview(
    "ui_DrawPathPreview",
    kConsoleStartupUiDrawPathPreviewDescription,
    &moho::ui_DrawPathPreview
  );
  TConVar<float> gTConVar_ui_ExtractSnapTolerance(
    "ui_ExtractSnapTolerance",
    kConsoleStartupUiExtractSnapToleranceDescription,
    &moho::ui_ExtractSnapTolerance
  );
  TConVar<float> gTConVar_ui_FootprintMinThickness(
    "ui_FootprintMinThickness",
    kConsoleStartupUiFootprintMinThicknessDescription,
    &moho::ui_FootprintMinThickness
  );
  TConVar<bool> gTConVar_ui_ForceLifbarsOnEnemy(
    "ui_ForceLifbarsOnEnemy",
    kConsoleStartupUiForceLifbarsOnEnemyDescription,
    &moho::ui_ForceLifbarsOnEnemy
  );
  TConVar<unsigned int> gTConVar_ui_FuelBarColor(
    "ui_FuelBarColor",
    kConsoleStartupUiFuelBarColorDescription,
    &moho::ui_FuelBarColor
  );
  TConVar<float> gTConVar_ui_FuelEmptyBlinkRate(
    "ui_FuelEmptyBlinkRate",
    kConsoleStartupUiFuelEmptyBlinkRateDescription,
    &moho::ui_FuelEmptyBlinkRate
  );
  TConVar<unsigned int> gTConVar_ui_FuelWarningColor(
    "ui_FuelWarningColor",
    kConsoleStartupUiFuelWarningColorDescription,
    &moho::ui_FuelWarningColor
  );
  TConVar<float> gTConVar_ui_KeyboardPanAccelerateMultiplier(
    "ui_KeyboardPanAccelerateMultiplier",
    kConsoleStartupUiKeyboardPanAccelerateMultiplierDescription,
    &moho::ui_KeyboardPanAccelerateMultiplier
  );
  TConVar<float> gTConVar_ui_KeyboardPanSpeed(
    "ui_KeyboardPanSpeed",
    kConsoleStartupUiKeyboardPanSpeedDescription,
    &moho::ui_KeyboardPanSpeed
  );
  TConVar<float> gTConVar_ui_KeyboardRotateAccelerateMultiplier(
    "ui_KeyboardRotateAccelerateMultiplier",
    kConsoleStartupUiKeyboardRotateAccelerateMultiplierDescription,
    &moho::ui_KeyboardRotateAccelerateMultiplier
  );
  TConVar<float> gTConVar_ui_KeyboardRotateSpeed(
    "ui_KeyboardRotateSpeed",
    kConsoleStartupUiKeyboardRotateSpeedDescription,
    &moho::ui_KeyboardRotateSpeed
  );
  TConVar<unsigned int> gTConVar_ui_LifeBarBadColor(
    "ui_LifeBarBadColor",
    kConsoleStartupUiLifeBarBadColorDescription,
    &moho::ui_LifeBarBadColor
  );
  TConVar<float> gTConVar_ui_LifeBarBadCutoff(
    "ui_LifeBarBadCutoff",
    kConsoleStartupUiLifeBarBadCutoffDescription,
    &moho::ui_LifeBarBadCutoff
  );
  TConVar<unsigned int> gTConVar_ui_LifeBarGoodColor(
    "ui_LifeBarGoodColor",
    kConsoleStartupUiLifeBarGoodColorDescription,
    &moho::ui_LifeBarGoodColor
  );
  TConVar<float> gTConVar_ui_LifeBarGoodCutoff(
    "ui_LifeBarGoodCutoff",
    kConsoleStartupUiLifeBarGoodCutoffDescription,
    &moho::ui_LifeBarGoodCutoff
  );
  TConVar<unsigned int> gTConVar_ui_LifeBarMedColor(
    "ui_LifeBarMedColor",
    kConsoleStartupUiLifeBarMedColorDescription,
    &moho::ui_LifeBarMedColor
  );
  TConVar<float> gTConVar_ui_LifebarLOD(
    "ui_LifebarLOD",
    kConsoleStartupUiLifebarLODDescription,
    &moho::ui_LifebarLOD
  );
  TConVar<float> gTConVar_ui_LifebarOffset(
    "ui_LifebarOffset",
    kConsoleStartupUiLifebarOffsetDescription,
    &moho::ui_LifebarOffset
  );
  TConVar<float> gTConVar_ui_LifebarWidth(
    "ui_LifebarWidth",
    kConsoleStartupUiLifebarWidthDescription,
    &moho::ui_LifebarWidth
  );
  TConVar<float> gTConVar_ui_MaxExtractSnapPixels(
    "ui_MaxExtractSnapPixels",
    kConsoleStartupUiMaxExtractSnapPixelsDescription,
    &moho::ui_MaxExtractSnapPixels
  );
  TConVar<float> gTConVar_ui_MaxTextLOD(
    "ui_MaxTextLOD",
    kConsoleStartupUiMaxTextLODDescription,
    &moho::ui_MaxTextLOD
  );
  TConVar<float> gTConVar_ui_MaxWaypointSize(
    "ui_MaxWaypointSize",
    kConsoleStartupUiMaxWaypointSizeDescription,
    &moho::ui_MaxWaypointSize
  );
  TConVar<float> gTConVar_ui_MinExtractSnapPixels(
    "ui_MinExtractSnapPixels",
    kConsoleStartupUiMinExtractSnapPixelsDescription,
    &moho::ui_MinExtractSnapPixels
  );
  TConVar<float> gTConVar_ui_MinWaypointSize(
    "ui_MinWaypointSize",
    kConsoleStartupUiMinWaypointSizeDescription,
    &moho::ui_MinWaypointSize
  );
  TConVar<bool> gTConVar_ui_NisRenderIcons(
    "ui_NisRenderIcons",
    kConsoleStartupUiNisRenderIconsDescription,
    &moho::ui_NisRenderIcons
  );
  TConVar<bool> gTConVar_ui_PathPreview(
    "ui_PathPreview",
    kConsoleStartupUiPathPreviewDescription,
    &moho::ui_PathPreview
  );
  TConVar<float> gTConVar_ui_PathSmoothness(
    "ui_PathSmoothness",
    kConsoleStartupUiPathSmoothnessDescription,
    &moho::ui_PathSmoothness
  );
  TConVar<unsigned int> gTConVar_ui_ProgressBarColor(
    "ui_ProgressBarColor",
    kConsoleStartupUiProgressBarColorDescription,
    &moho::ui_ProgressBarColor
  );
  TConVar<bool> gTConVar_ui_RenderCustomNames(
    "ui_RenderCustomNames",
    kConsoleStartupUiRenderCustomNamesDescription,
    &moho::ui_RenderCustomNames
  );
  TConVar<bool> gTConVar_ui_RenderIcons(
    "ui_RenderIcons",
    kConsoleStartupUiRenderIconsDescription,
    &moho::ui_RenderIcons
  );
  TConVar<bool> gTConVar_ui_RenderSelectionSetNames(
    "ui_RenderSelectionSetNames",
    kConsoleStartupUiRenderSelectionSetNamesDescription,
    &moho::ui_RenderSelectionSetNames
  );
  TConVar<bool> gTConVar_ui_RenderUnitBars(
    "ui_RenderUnitBars",
    kConsoleStartupUiRenderUnitBarsDescription,
    &moho::ui_RenderUnitBars
  );
  TConVar<bool> gTConVar_ui_ScreenEdgeScrollView(
    "ui_ScreenEdgeScrollView",
    kConsoleStartupUiScreenEdgeScrollViewDescription,
    &moho::ui_ScreenEdgeScrollView
  );
  TConVar<float> gTConVar_ui_SelectTolerance(
    "ui_SelectTolerance",
    kConsoleStartupUiSelectToleranceDescription,
    &moho::ui_SelectTolerance
  );
  TConVar<unsigned int> gTConVar_ui_SelectionSetNamesColor(
    "ui_SelectionSetNamesColor",
    kConsoleStartupUiSelectionSetNamesColorDescription,
    &moho::ui_SelectionSetNamesColor
  );
  TConVar<unsigned int> gTConVar_ui_ShieldBarColor(
    "ui_ShieldBarColor",
    kConsoleStartupUiShieldBarColorDescription,
    &moho::ui_ShieldBarColor
  );
  TConVar<float> gTConVar_ui_StrategicIconBlinkDuration(
    "ui_StrategicIconBlinkDuration",
    kConsoleStartupUiStrategicIconBlinkDurationDescription,
    &moho::ui_StrategicIconBlinkDuration
  );
  TConVar<float> gTConVar_ui_StrategicIconBlinkRate(
    "ui_StrategicIconBlinkRate",
    kConsoleStartupUiStrategicIconBlinkRateDescription,
    &moho::ui_StrategicIconBlinkRate
  );
  TConVar<float> gTConVar_ui_WaypointLineScale(
    "ui_WaypointLineScale",
    kConsoleStartupUiWaypointLineScaleDescription,
    &moho::ui_WaypointLineScale
  );
  TConVar<bool> gTConVar_ui_WindowedAlwaysShowsCursor(
    "ui_WindowedAlwaysShowsCursor",
    kConsoleStartupUiWindowedAlwaysShowsCursorDescription,
    &moho::ui_WindowedAlwaysShowsCursor
  );
  TConVar<float> gTConVar_ui_fuelbarHeight(
    "ui_fuelbarHeight",
    kConsoleStartupUiFuelbarHeightDescription,
    &moho::ui_fuelbarHeight
  );
  TConVar<float> gTConVar_ui_lifebarHeight(
    "ui_lifebarHeight",
    kConsoleStartupUiLifebarHeightDescription,
    &moho::ui_lifebarHeight
  );

  /**
   * Address: 0x00C071F0 (FUN_00C071F0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProectileTrailWidth`.
   */
  void cleanup_TConVar_UI_RenProectileTrailWidth()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProectileTrailWidth);
  }

  /**
   * Address: 0x00BE5C70 (FUN_00BE5C70, register_TConVar_UI_RenProectileTrailWidth)
   *
   * What it does:
   * Registers startup convar for `UI_RenProectileTrailWidth`.
   */
  void register_TConVar_UI_RenProectileTrailWidth()
  {
    RegisterStartupConVar(gTConVar_UI_RenProectileTrailWidth, &cleanup_TConVar_UI_RenProectileTrailWidth);
  }

  /**
   * Address: 0x00C07190 (FUN_00C07190, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileArcs`.
   */
  void cleanup_TConVar_UI_RenProjectileArcs()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileArcs);
  }

  /**
   * Address: 0x00BE5BF0 (FUN_00BE5BF0, register_SimConVar_UI_RenProjectileArcs)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileArcs`, gating
   * `CRenderWorldView::Render`'s whole projectile-arc pass. The registrar
   * constructs a `TConVar<bool>` (vtable `??_7?$TConVar@_N@Moho@@6B@`) over
   * this storage -- the pre-existing `moho::UI_RenProjectileArcs` global was
   * mistyped `std::int32_t` (fixed alongside this recovery to `bool`, per
   * `ProjectileArcRenderer.h`/`.cpp`).
   */
  void register_TConVar_UI_RenProjectileArcs()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileArcs, &cleanup_TConVar_UI_RenProjectileArcs);
  }

  /**
   * Address: 0x00C07220 (FUN_00C07220, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileArcsSampleInterval`.
   */
  void cleanup_TConVar_UI_RenProjectileArcsSampleInterval()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileArcsSampleInterval);
  }

  /**
   * Address: 0x00BE5CB0 (FUN_00BE5CB0, register_TConVar_UI_RenProjectileArcsSampleInterval)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileArcsSampleInterval`.
   */
  void register_TConVar_UI_RenProjectileArcsSampleInterval()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileArcsSampleInterval, &cleanup_TConVar_UI_RenProjectileArcsSampleInterval);
  }

  /**
   * Address: 0x00C07310 (FUN_00C07310, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileGlow`.
   */
  void cleanup_TConVar_UI_RenProjectileGlow()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileGlow);
  }

  /**
   * Address: 0x00BE5E20 (FUN_00BE5E20, register_TConVar_UI_RenProjectileGlow)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileGlow`.
   */
  void register_TConVar_UI_RenProjectileGlow()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileGlow, &cleanup_TConVar_UI_RenProjectileGlow);
  }

  /**
   * Address: 0x00C07370 (FUN_00C07370, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileGlowMax`.
   */
  void cleanup_TConVar_UI_RenProjectileGlowMax()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileGlowMax);
  }

  /**
   * Address: 0x00BE5EA0 (FUN_00BE5EA0, register_TConVar_UI_RenProjectileGlowMax)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileGlowMax`.
   */
  void register_TConVar_UI_RenProjectileGlowMax()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileGlowMax, &cleanup_TConVar_UI_RenProjectileGlowMax);
  }

  /**
   * Address: 0x00C07340 (FUN_00C07340, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileGlowMin`.
   */
  void cleanup_TConVar_UI_RenProjectileGlowMin()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileGlowMin);
  }

  /**
   * Address: 0x00BE5E60 (FUN_00BE5E60, register_TConVar_UI_RenProjectileGlowMin)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileGlowMin`.
   */
  void register_TConVar_UI_RenProjectileGlowMin()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileGlowMin, &cleanup_TConVar_UI_RenProjectileGlowMin);
  }

  /**
   * Address: 0x00C073A0 (FUN_00C073A0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileGlowPeriod`.
   */
  void cleanup_TConVar_UI_RenProjectileGlowPeriod()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileGlowPeriod);
  }

  /**
   * Address: 0x00BE5EE0 (FUN_00BE5EE0, register_TConVar_UI_RenProjectileGlowPeriod)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileGlowPeriod`.
   */
  void register_TConVar_UI_RenProjectileGlowPeriod()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileGlowPeriod, &cleanup_TConVar_UI_RenProjectileGlowPeriod);
  }

  /**
   * Address: 0x00C072B0 (FUN_00C072B0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileIcons`.
   */
  void cleanup_TConVar_UI_RenProjectileIcons()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileIcons);
  }

  /**
   * Address: 0x00BE5DA0 (FUN_00BE5DA0, register_TConVar_UI_RenProjectileIcons)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileIcons`.
   */
  void register_TConVar_UI_RenProjectileIcons()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileIcons, &cleanup_TConVar_UI_RenProjectileIcons);
  }

  /**
   * Address: 0x00C071C0 (FUN_00C071C0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenProjectileTrailColor`.
   */
  void cleanup_TConVar_UI_RenProjectileTrailColor()
  {
    CleanupStartupConCommand(gTConVar_UI_RenProjectileTrailColor);
  }

  /**
   * Address: 0x00BE5C30 (FUN_00BE5C30, register_TConVar_UI_RenProjectileTrailColor)
   *
   * What it does:
   * Registers startup convar for `UI_RenProjectileTrailColor`.
   */
  void register_TConVar_UI_RenProjectileTrailColor()
  {
    RegisterStartupConVar(gTConVar_UI_RenProjectileTrailColor, &cleanup_TConVar_UI_RenProjectileTrailColor);
  }

  /**
   * Address: 0x00C07420 (FUN_00C07420, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_RenResources`.
   */
  void cleanup_TConVar_UI_RenResources()
  {
    CleanupStartupConCommand(gTConVar_UI_RenResources);
  }

  /**
   * Address: 0x00BE5FD0 (FUN_00BE5FD0, register_TConVar_UI_RenResources)
   *
   * What it does:
   * Registers startup convar for `UI_RenResources`.
   */
  void register_TConVar_UI_RenResources()
  {
    RegisterStartupConVar(gTConVar_UI_RenResources, &cleanup_TConVar_UI_RenResources);
  }

  /**
   * Address: 0x00C07450 (FUN_00C07450, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_ResourceLODCutoff`.
   */
  void cleanup_TConVar_UI_ResourceLODCutoff()
  {
    CleanupStartupConCommand(gTConVar_UI_ResourceLODCutoff);
  }

  /**
   * Address: 0x00BE6010 (FUN_00BE6010, register_TConVar_UI_ResourceLODCutoff)
   *
   * What it does:
   * Registers startup convar for `UI_ResourceLODCutoff`.
   */
  void register_TConVar_UI_ResourceLODCutoff()
  {
    RegisterStartupConVar(gTConVar_UI_ResourceLODCutoff, &cleanup_TConVar_UI_ResourceLODCutoff);
  }

  /**
   * Address: 0x00C07520 (FUN_00C07520, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_SelectAnything`.
   */
  void cleanup_TConVar_UI_SelectAnything()
  {
    CleanupStartupConCommand(gTConVar_UI_SelectAnything);
  }

  /**
   * Address: 0x00BE6180 (FUN_00BE6180, register_TConVar_UI_SelectAnything)
   *
   * What it does:
   * Registers startup convar for `UI_SelectAnything`.
   */
  void register_TConVar_UI_SelectAnything()
  {
    RegisterStartupConVar(gTConVar_UI_SelectAnything, &cleanup_TConVar_UI_SelectAnything);
  }

  /**
   * Address: 0x00C04960 (FUN_00C04960, ??1TConVar_UI_ShowControlUnderMouse@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_ShowControlUnderMouse`.
   */
  void cleanup_TConVar_UI_ShowControlUnderMouse()
  {
    CleanupStartupConCommand(gTConVar_UI_ShowControlUnderMouse);
  }

  /**
   * Address: 0x00BE19D0 (FUN_00BE19D0, register_TConVar_UI_ShowControlUnderMouse)
   *
   * What it does:
   * Registers startup convar for `UI_ShowControlUnderMouse`.
   */
  void register_TConVar_UI_ShowControlUnderMouse()
  {
    RegisterStartupConVar(gTConVar_UI_ShowControlUnderMouse, &cleanup_TConVar_UI_ShowControlUnderMouse);
  }

  /**
   * Address: 0x00C072E0 (FUN_00C072E0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_StrategicProjectileLOD`.
   */
  void cleanup_TConVar_UI_StrategicProjectileLOD()
  {
    CleanupStartupConCommand(gTConVar_UI_StrategicProjectileLOD);
  }

  /**
   * Address: 0x00BE5DE0 (FUN_00BE5DE0, register_TConVar_UI_StrategicProjectileLOD)
   *
   * What it does:
   * Registers startup convar for `UI_StrategicProjectileLOD`.
   */
  void register_TConVar_UI_StrategicProjectileLOD()
  {
    RegisterStartupConVar(gTConVar_UI_StrategicProjectileLOD, &cleanup_TConVar_UI_StrategicProjectileLOD);
  }

  /**
   * Address: 0x00C073D0 (FUN_00C073D0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `UI_forceWeaponsToYellow`.
   */
  void cleanup_TConVar_UI_forceWeaponsToYellow()
  {
    CleanupStartupConCommand(gTConVar_UI_forceWeaponsToYellow);
  }

  /**
   * Address: 0x00BE5F20 (FUN_00BE5F20, register_TConVar_UI_forceWeaponsToYellow)
   *
   * What it does:
   * Registers startup convar for `UI_forceWeaponsToYellow`.
   */
  void register_TConVar_UI_forceWeaponsToYellow()
  {
    RegisterStartupConVar(gTConVar_UI_forceWeaponsToYellow, &cleanup_TConVar_UI_forceWeaponsToYellow);
  }

  /**
   * Address: 0x00C070E0 (FUN_00C070E0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_AlwaysRenderStrategicIcons`.
   */
  void cleanup_TConVar_ui_AlwaysRenderStrategicIcons()
  {
    CleanupStartupConCommand(gTConVar_ui_AlwaysRenderStrategicIcons);
  }

  /**
   * Address: 0x00BE5B00 (FUN_00BE5B00, register_TConVar_ui_AlwaysRenderStrategicIcons)
   *
   * What it does:
   * Registers startup convar for `ui_AlwaysRenderStrategicIcons`.
   */
  void register_TConVar_ui_AlwaysRenderStrategicIcons()
  {
    RegisterStartupConVar(gTConVar_ui_AlwaysRenderStrategicIcons, &cleanup_TConVar_ui_AlwaysRenderStrategicIcons);
  }

  /**
   * Address: 0x00C07810 (FUN_00C07810, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ArrowKeysScrollView`.
   */
  void cleanup_TConVar_ui_ArrowKeysScrollView()
  {
    CleanupStartupConCommand(gTConVar_ui_ArrowKeysScrollView);
  }

  /**
   * Address: 0x00BE6720 (FUN_00BE6720, register_TConVar_ui_ArrowKeysScrollView)
   *
   * What it does:
   * Registers startup convar for `ui_ArrowKeysScrollView`.
   */
  void register_TConVar_ui_ArrowKeysScrollView()
  {
    RegisterStartupConVar(gTConVar_ui_ArrowKeysScrollView, &cleanup_TConVar_ui_ArrowKeysScrollView);
  }

  /**
   * Address: 0x00C06950 (FUN_00C06950, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_BuildPlaceTarmacAlpha`.
   */
  void cleanup_TConVar_ui_BuildPlaceTarmacAlpha()
  {
    CleanupStartupConCommand(gTConVar_ui_BuildPlaceTarmacAlpha);
  }

  /**
   * Address: 0x00BE50E0 (FUN_00BE50E0, register_TConVar_ui_BuildPlaceTarmacAlpha)
   *
   * What it does:
   * Registers startup convar for `ui_BuildPlaceTarmacAlpha`.
   */
  void register_TConVar_ui_BuildPlaceTarmacAlpha()
  {
    RegisterStartupConVar(gTConVar_ui_BuildPlaceTarmacAlpha, &cleanup_TConVar_ui_BuildPlaceTarmacAlpha);
  }

  /**
   * Address: 0x00C06050 (FUN_00C06050, ??1TConVar_ui_CommandClickScale@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CommandClickScale`.
   */
  void cleanup_TConVar_ui_CommandClickScale()
  {
    CleanupStartupConCommand(gTConVar_ui_CommandClickScale);
  }

  /**
   * Address: 0x00BE3E40 (FUN_00BE3E40, register_TConVar_ui_CommandClickScale)
   *
   * What it does:
   * Registers startup convar for `ui_CommandClickScale`.
   */
  void register_TConVar_ui_CommandClickScale()
  {
    RegisterStartupConVar(gTConVar_ui_CommandClickScale, &cleanup_TConVar_ui_CommandClickScale);
  }

  /**
   * Address: 0x00C05F30 (FUN_00C05F30, ??1TConVar_ui_CommandGraphMaxNodeUnits@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CommandGraphMaxNodeUnits`.
   */
  void cleanup_TConVar_ui_CommandGraphMaxNodeUnits()
  {
    CleanupStartupConCommand(gTConVar_ui_CommandGraphMaxNodeUnits);
  }

  /**
   * Address: 0x00BE3CC0 (FUN_00BE3CC0, register_TConVar_ui_CommandGraphMaxNodeUnits)
   *
   * What it does:
   * Registers startup convar for `ui_CommandGraphMaxNodeUnits`.
   */
  void register_TConVar_ui_CommandGraphMaxNodeUnits()
  {
    RegisterStartupConVar(gTConVar_ui_CommandGraphMaxNodeUnits, &cleanup_TConVar_ui_CommandGraphMaxNodeUnits);
  }

  /**
   * Address: 0x00C05E70 (FUN_00C05E70, ??1TConVar_ui_CurveSegments@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CurveSegments`.
   */
  void cleanup_TConVar_ui_CurveSegments()
  {
    CleanupStartupConCommand(gTConVar_ui_CurveSegments);
  }

  /**
   * Address: 0x00BE3BC0 (FUN_00BE3BC0, register_TConVar_ui_CurveSegments)
   *
   * What it does:
   * Registers startup convar for `ui_CurveSegments`.
   */
  void register_TConVar_ui_CurveSegments()
  {
    RegisterStartupConVar(gTConVar_ui_CurveSegments, &cleanup_TConVar_ui_CurveSegments);
  }

  /**
   * Address: 0x00C05EA0 (FUN_00C05EA0, ??1TConVar_ui_CurveSmoothness@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CurveSmoothness`.
   */
  void cleanup_TConVar_ui_CurveSmoothness()
  {
    CleanupStartupConCommand(gTConVar_ui_CurveSmoothness);
  }

  /**
   * Address: 0x00BE3C00 (FUN_00BE3C00, register_TConVar_ui_CurveSmoothness)
   *
   * What it does:
   * Registers startup convar for `ui_CurveSmoothness`.
   */
  void register_TConVar_ui_CurveSmoothness()
  {
    RegisterStartupConVar(gTConVar_ui_CurveSmoothness, &cleanup_TConVar_ui_CurveSmoothness);
  }

  /**
   * Address: 0x00C06D80 (FUN_00C06D80, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CustomNameColor`.
   */
  void cleanup_TConVar_ui_CustomNameColor()
  {
    CleanupStartupConCommand(gTConVar_ui_CustomNameColor);
  }

  /**
   * Address: 0x00BE56A0 (FUN_00BE56A0, register_TConVar_ui_CustomNameColor)
   *
   * What it does:
   * Registers startup convar for `ui_CustomNameColor`.
   */
  void register_TConVar_ui_CustomNameColor()
  {
    RegisterStartupConVar(gTConVar_ui_CustomNameColor, &cleanup_TConVar_ui_CustomNameColor);
  }

  /**
   * Address: 0x00C06E10 (FUN_00C06E10, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CustomNameFont`.
   */
  void cleanup_TConVar_ui_CustomNameFont()
  {
    CleanupStartupConCommand(gTConVar_ui_CustomNameFont);
  }

  /**
   * Address: 0x00BE5740 (FUN_00BE5740, register_ui_CutsomNameFont_ConVarDef)
   *
   * What it does:
   * Registers startup convar for `ui_CustomNameFont`. The registered console
   * name is byte-verified from the binary's own `.rdata` as
   * `"ui_CutsomNameFont"` -- the transposition typo is genuinely shipped in
   * the binary, not a transcription error here, so it is preserved exactly
   * (matching the underlying `ui_CutsomNameFont_ConVarDef` IDA export name).
   */
  void register_TConVar_ui_CustomNameFont()
  {
    RegisterStartupConVar(gTConVar_ui_CustomNameFont, &cleanup_TConVar_ui_CustomNameFont);
  }

  /**
   * Address: 0x00C06DB0 (FUN_00C06DB0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_CustomNameFontSize`.
   */
  void cleanup_TConVar_ui_CustomNameFontSize()
  {
    CleanupStartupConCommand(gTConVar_ui_CustomNameFontSize);
  }

  /**
   * Address: 0x00BE56E0 (FUN_00BE56E0, register_TConVar_ui_CustomNameFontSize)
   *
   * What it does:
   * Registers startup convar for `ui_CustomNameFontSize`.
   */
  void register_TConVar_ui_CustomNameFontSize()
  {
    RegisterStartupConVar(gTConVar_ui_CustomNameFontSize, &cleanup_TConVar_ui_CustomNameFontSize);
  }

  /**
   * Address: 0x00C074B0 (FUN_00C074B0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_DebugAltClick`.
   */
  void cleanup_TConVar_ui_DebugAltClick()
  {
    CleanupStartupConCommand(gTConVar_ui_DebugAltClick);
  }

  /**
   * Address: 0x00BE60E0 (FUN_00BE60E0, register_TConVar_ui_DebugAltClick)
   *
   * What it does:
   * Registers startup convar for `ui_DebugAltClick`.
   */
  void register_TConVar_ui_DebugAltClick()
  {
    RegisterStartupConVar(gTConVar_ui_DebugAltClick, &cleanup_TConVar_ui_DebugAltClick);
  }

  /**
   * Address: 0x00C078A0 (FUN_00C078A0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_DisableCursorFixing`.
   */
  void cleanup_TConVar_ui_DisableCursorFixing()
  {
    CleanupStartupConCommand(gTConVar_ui_DisableCursorFixing);
  }

  /**
   * Address: 0x00BE67E0 (FUN_00BE67E0, register_TConVar_ui_DisableCursorFixing)
   *
   * What it does:
   * Registers startup convar for `ui_DisableCursorFixing`.
   */
  void register_TConVar_ui_DisableCursorFixing()
  {
    RegisterStartupConVar(gTConVar_ui_DisableCursorFixing, &cleanup_TConVar_ui_DisableCursorFixing);
  }

  /**
   * Address: 0x00C074E0 (FUN_00C074E0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_DragSelect2D`.
   */
  void cleanup_TConVar_ui_DragSelect2D()
  {
    CleanupStartupConCommand(gTConVar_ui_DragSelect2D);
  }

  /**
   * Address: 0x00BE6120 (FUN_00BE6120, register_TConVar_ui_DragSelect2D)
   *
   * What it does:
   * Registers startup convar for `ui_DragSelect2D`.
   */
  void register_TConVar_ui_DragSelect2D()
  {
    RegisterStartupConVar(gTConVar_ui_DragSelect2D, &cleanup_TConVar_ui_DragSelect2D);
  }

  /**
   * Address: 0x00C05FC0 (FUN_00C05FC0, ??1TConVar_ui_DrawPathPreview@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_DrawPathPreview`.
   */
  void cleanup_TConVar_ui_DrawPathPreview()
  {
    CleanupStartupConCommand(gTConVar_ui_DrawPathPreview);
  }

  /**
   * Address: 0x00BE3D80 (FUN_00BE3D80, register_TConVar_ui_DrawPathPreview)
   *
   * What it does:
   * Registers startup convar for `ui_DrawPathPreview`.
   */
  void register_TConVar_ui_DrawPathPreview()
  {
    RegisterStartupConVar(gTConVar_ui_DrawPathPreview, &cleanup_TConVar_ui_DrawPathPreview);
  }

  /**
   * Address: 0x00C078D0 (FUN_00C078D0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ExtractSnapTolerance`.
   */
  void cleanup_TConVar_ui_ExtractSnapTolerance()
  {
    CleanupStartupConCommand(gTConVar_ui_ExtractSnapTolerance);
  }

  /**
   * Address: 0x00BE6820 (FUN_00BE6820, register_TConVar_ui_ExtractSnapTolerance)
   *
   * What it does:
   * Registers startup convar for `ui_ExtractSnapTolerance`.
   */
  void register_TConVar_ui_ExtractSnapTolerance()
  {
    RegisterStartupConVar(gTConVar_ui_ExtractSnapTolerance, &cleanup_TConVar_ui_ExtractSnapTolerance);
  }

  /**
   * Address: 0x00C06B50 (FUN_00C06B50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_FootprintMinThickness`.
   */
  void cleanup_TConVar_ui_FootprintMinThickness()
  {
    CleanupStartupConCommand(gTConVar_ui_FootprintMinThickness);
  }

  /**
   * Address: 0x00BE5370 (FUN_00BE5370, register_TConVar_ui_FootprintMinThickness)
   *
   * What it does:
   * Registers startup convar for `ui_FootprintMinThickness`.
   */
  void register_TConVar_ui_FootprintMinThickness()
  {
    RegisterStartupConVar(gTConVar_ui_FootprintMinThickness, &cleanup_TConVar_ui_FootprintMinThickness);
  }

  /**
   * Address: 0x00C06CC0 (FUN_00C06CC0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ForceLifbarsOnEnemy`.
   */
  void cleanup_TConVar_ui_ForceLifbarsOnEnemy()
  {
    CleanupStartupConCommand(gTConVar_ui_ForceLifbarsOnEnemy);
  }

  /**
   * Address: 0x00BE55A0 (FUN_00BE55A0, register_TConVar_ui_ForceLifbarsOnEnemy)
   *
   * What it does:
   * Registers startup convar for `ui_ForceLifbarsOnEnemy`.
   */
  void register_TConVar_ui_ForceLifbarsOnEnemy()
  {
    RegisterStartupConVar(gTConVar_ui_ForceLifbarsOnEnemy, &cleanup_TConVar_ui_ForceLifbarsOnEnemy);
  }

  /**
   * Address: 0x00C07020 (FUN_00C07020, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_FuelBarColor`.
   */
  void cleanup_TConVar_ui_FuelBarColor()
  {
    CleanupStartupConCommand(gTConVar_ui_FuelBarColor);
  }

  /**
   * Address: 0x00BE5A00 (FUN_00BE5A00, register_TConVar_ui_FuelBarColor)
   *
   * What it does:
   * Registers startup convar for `ui_FuelBarColor`.
   */
  void register_TConVar_ui_FuelBarColor()
  {
    RegisterStartupConVar(gTConVar_ui_FuelBarColor, &cleanup_TConVar_ui_FuelBarColor);
  }

  /**
   * Address: 0x00C06ED0 (FUN_00C06ED0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_FuelEmptyBlinkRate`.
   */
  void cleanup_TConVar_ui_FuelEmptyBlinkRate()
  {
    CleanupStartupConCommand(gTConVar_ui_FuelEmptyBlinkRate);
  }

  /**
   * Address: 0x00BE5840 (FUN_00BE5840, register_TConVar_ui_FuelEmptyBlinkRate)
   *
   * What it does:
   * Registers startup convar for `ui_FuelEmptyBlinkRate`.
   */
  void register_TConVar_ui_FuelEmptyBlinkRate()
  {
    RegisterStartupConVar(gTConVar_ui_FuelEmptyBlinkRate, &cleanup_TConVar_ui_FuelEmptyBlinkRate);
  }

  /**
   * Address: 0x00C07050 (FUN_00C07050, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_FuelWarningColor`.
   */
  void cleanup_TConVar_ui_FuelWarningColor()
  {
    CleanupStartupConCommand(gTConVar_ui_FuelWarningColor);
  }

  /**
   * Address: 0x00BE5A40 (FUN_00BE5A40, register_TConVar_ui_FuelWarningColor)
   *
   * What it does:
   * Registers startup convar for `ui_FuelWarningColor`.
   */
  void register_TConVar_ui_FuelWarningColor()
  {
    RegisterStartupConVar(gTConVar_ui_FuelWarningColor, &cleanup_TConVar_ui_FuelWarningColor);
  }

  /**
   * Address: 0x00C07A20 (FUN_00C07A20, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_KeyboardPanAccelerateMultiplier`.
   */
  void cleanup_TConVar_ui_KeyboardPanAccelerateMultiplier()
  {
    CleanupStartupConCommand(gTConVar_ui_KeyboardPanAccelerateMultiplier);
  }

  /**
   * Address: 0x00BE6980 (FUN_00BE6980, register_TConVar_ui_KeyboardPanAccelerateMultiplier)
   *
   * What it does:
   * Registers startup convar for `ui_KeyboardPanAccelerateMultiplier`.
   */
  void register_TConVar_ui_KeyboardPanAccelerateMultiplier()
  {
    RegisterStartupConVar(gTConVar_ui_KeyboardPanAccelerateMultiplier, &cleanup_TConVar_ui_KeyboardPanAccelerateMultiplier);
  }

  /**
   * Address: 0x00C079F0 (FUN_00C079F0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_KeyboardPanSpeed`.
   */
  void cleanup_TConVar_ui_KeyboardPanSpeed()
  {
    CleanupStartupConCommand(gTConVar_ui_KeyboardPanSpeed);
  }

  /**
   * Address: 0x00BE6940 (FUN_00BE6940, register_TConVar_ui_KeyboardPanSpeed)
   *
   * What it does:
   * Registers startup convar for `ui_KeyboardPanSpeed`.
   */
  void register_TConVar_ui_KeyboardPanSpeed()
  {
    RegisterStartupConVar(gTConVar_ui_KeyboardPanSpeed, &cleanup_TConVar_ui_KeyboardPanSpeed);
  }

  /**
   * Address: 0x00C07A80 (FUN_00C07A80, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_KeyboardRotateAccelerateMultiplier`.
   */
  void cleanup_TConVar_ui_KeyboardRotateAccelerateMultiplier()
  {
    CleanupStartupConCommand(gTConVar_ui_KeyboardRotateAccelerateMultiplier);
  }

  /**
   * Address: 0x00BE6A00 (FUN_00BE6A00, register_TConVar_ui_KeyboardRotateAccelerateMultiplier)
   *
   * What it does:
   * Registers startup convar for `ui_KeyboardRotateAccelerateMultiplier`.
   */
  void register_TConVar_ui_KeyboardRotateAccelerateMultiplier()
  {
    RegisterStartupConVar(gTConVar_ui_KeyboardRotateAccelerateMultiplier, &cleanup_TConVar_ui_KeyboardRotateAccelerateMultiplier);
  }

  /**
   * Address: 0x00C07A50 (FUN_00C07A50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_KeyboardRotateSpeed`.
   */
  void cleanup_TConVar_ui_KeyboardRotateSpeed()
  {
    CleanupStartupConCommand(gTConVar_ui_KeyboardRotateSpeed);
  }

  /**
   * Address: 0x00BE69C0 (FUN_00BE69C0, register_TConVar_ui_KeyboardRotateSpeed)
   *
   * What it does:
   * Registers startup convar for `ui_KeyboardRotateSpeed`.
   */
  void register_TConVar_ui_KeyboardRotateSpeed()
  {
    RegisterStartupConVar(gTConVar_ui_KeyboardRotateSpeed, &cleanup_TConVar_ui_KeyboardRotateSpeed);
  }

  /**
   * Address: 0x00C06F90 (FUN_00C06F90, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifeBarBadColor`.
   */
  void cleanup_TConVar_ui_LifeBarBadColor()
  {
    CleanupStartupConCommand(gTConVar_ui_LifeBarBadColor);
  }

  /**
   * Address: 0x00BE5940 (FUN_00BE5940, register_TConVar_ui_LifeBarBadColor)
   *
   * What it does:
   * Registers startup convar for `ui_LifeBarBadColor`.
   */
  void register_TConVar_ui_LifeBarBadColor()
  {
    RegisterStartupConVar(gTConVar_ui_LifeBarBadColor, &cleanup_TConVar_ui_LifeBarBadColor);
  }

  /**
   * Address: 0x00C06FF0 (FUN_00C06FF0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifeBarBadCutoff`.
   */
  void cleanup_TConVar_ui_LifeBarBadCutoff()
  {
    CleanupStartupConCommand(gTConVar_ui_LifeBarBadCutoff);
  }

  /**
   * Address: 0x00BE59C0 (FUN_00BE59C0, register_TConVar_ui_LifeBarBadCutoff)
   *
   * What it does:
   * Registers startup convar for `ui_LifeBarBadCutoff`.
   */
  void register_TConVar_ui_LifeBarBadCutoff()
  {
    RegisterStartupConVar(gTConVar_ui_LifeBarBadCutoff, &cleanup_TConVar_ui_LifeBarBadCutoff);
  }

  /**
   * Address: 0x00C06F30 (FUN_00C06F30, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifeBarGoodColor`.
   */
  void cleanup_TConVar_ui_LifeBarGoodColor()
  {
    CleanupStartupConCommand(gTConVar_ui_LifeBarGoodColor);
  }

  /**
   * Address: 0x00BE58C0 (FUN_00BE58C0, register_TConVar_ui_LifeBarGoodColor)
   *
   * What it does:
   * Registers startup convar for `ui_LifeBarGoodColor`.
   */
  void register_TConVar_ui_LifeBarGoodColor()
  {
    RegisterStartupConVar(gTConVar_ui_LifeBarGoodColor, &cleanup_TConVar_ui_LifeBarGoodColor);
  }

  /**
   * Address: 0x00C06FC0 (FUN_00C06FC0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifeBarGoodCutoff`.
   */
  void cleanup_TConVar_ui_LifeBarGoodCutoff()
  {
    CleanupStartupConCommand(gTConVar_ui_LifeBarGoodCutoff);
  }

  /**
   * Address: 0x00BE5980 (FUN_00BE5980, register_TConVar_ui_LifeBarGoodCutoff)
   *
   * What it does:
   * Registers startup convar for `ui_LifeBarGoodCutoff`.
   */
  void register_TConVar_ui_LifeBarGoodCutoff()
  {
    RegisterStartupConVar(gTConVar_ui_LifeBarGoodCutoff, &cleanup_TConVar_ui_LifeBarGoodCutoff);
  }

  /**
   * Address: 0x00C06F60 (FUN_00C06F60, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifeBarMedColor`.
   */
  void cleanup_TConVar_ui_LifeBarMedColor()
  {
    CleanupStartupConCommand(gTConVar_ui_LifeBarMedColor);
  }

  /**
   * Address: 0x00BE5900 (FUN_00BE5900, register_TConVar_ui_LifeBarMedColor)
   *
   * What it does:
   * Registers startup convar for `ui_LifeBarMedColor`.
   */
  void register_TConVar_ui_LifeBarMedColor()
  {
    RegisterStartupConVar(gTConVar_ui_LifeBarMedColor, &cleanup_TConVar_ui_LifeBarMedColor);
  }

  /**
   * Address: 0x00C06C30 (FUN_00C06C30, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifebarLOD`.
   */
  void cleanup_TConVar_ui_LifebarLOD()
  {
    CleanupStartupConCommand(gTConVar_ui_LifebarLOD);
  }

  /**
   * Address: 0x00BE54E0 (FUN_00BE54E0, register_TConVar_ui_LifebarLOD)
   *
   * What it does:
   * Registers startup convar for `ui_LifebarLOD`.
   */
  void register_TConVar_ui_LifebarLOD()
  {
    RegisterStartupConVar(gTConVar_ui_LifebarLOD, &cleanup_TConVar_ui_LifebarLOD);
  }

  /**
   * Address: 0x00C06C60 (FUN_00C06C60, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifebarOffset`.
   */
  void cleanup_TConVar_ui_LifebarOffset()
  {
    CleanupStartupConCommand(gTConVar_ui_LifebarOffset);
  }

  /**
   * Address: 0x00BE5520 (FUN_00BE5520, register_TConVar_ui_LifebarOffset)
   *
   * What it does:
   * Registers startup convar for `ui_LifebarOffset`.
   */
  void register_TConVar_ui_LifebarOffset()
  {
    RegisterStartupConVar(gTConVar_ui_LifebarOffset, &cleanup_TConVar_ui_LifebarOffset);
  }

  /**
   * Address: 0x00C06C00 (FUN_00C06C00, ??0TConVar_ui_LifebarWidth@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_LifebarWidth`.
   */
  void cleanup_TConVar_ui_LifebarWidth()
  {
    CleanupStartupConCommand(gTConVar_ui_LifebarWidth);
  }

  /**
   * Address: 0x00BE54A0 (FUN_00BE54A0, register_TConVar_ui_LifebarWidth)
   *
   * What it does:
   * Registers startup convar for `ui_LifebarWidth`.
   */
  void register_TConVar_ui_LifebarWidth()
  {
    RegisterStartupConVar(gTConVar_ui_LifebarWidth, &cleanup_TConVar_ui_LifebarWidth);
  }

  /**
   * Address: 0x00C07930 (FUN_00C07930, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_MaxExtractSnapPixels`.
   */
  void cleanup_TConVar_ui_MaxExtractSnapPixels()
  {
    CleanupStartupConCommand(gTConVar_ui_MaxExtractSnapPixels);
  }

  /**
   * Address: 0x00BE68A0 (FUN_00BE68A0, register_TConVar_ui_MaxExtractSnapPixels)
   *
   * What it does:
   * Registers startup convar for `ui_MaxExtractSnapPixels`.
   */
  void register_TConVar_ui_MaxExtractSnapPixels()
  {
    RegisterStartupConVar(gTConVar_ui_MaxExtractSnapPixels, &cleanup_TConVar_ui_MaxExtractSnapPixels);
  }

  /**
   * Address: 0x00C05F00 (FUN_00C05F00, ??1TConVar_ui_MaxTextLOD@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_MaxTextLOD`.
   */
  void cleanup_TConVar_ui_MaxTextLOD()
  {
    CleanupStartupConCommand(gTConVar_ui_MaxTextLOD);
  }

  /**
   * Address: 0x00BE3C80 (FUN_00BE3C80, register_TConVar_ui_MaxTextLOD)
   *
   * What it does:
   * Registers startup convar for `ui_MaxTextLOD`.
   */
  void register_TConVar_ui_MaxTextLOD()
  {
    RegisterStartupConVar(gTConVar_ui_MaxTextLOD, &cleanup_TConVar_ui_MaxTextLOD);
  }

  /**
   * Address: 0x00C05F90 (FUN_00C05F90, ??1TConVar_ui_MaxWaypointSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_MaxWaypointSize`.
   */
  void cleanup_TConVar_ui_MaxWaypointSize()
  {
    CleanupStartupConCommand(gTConVar_ui_MaxWaypointSize);
  }

  /**
   * Address: 0x00BE3D40 (FUN_00BE3D40, register_TConVar_ui_MaxWaypointSize)
   *
   * What it does:
   * Registers startup convar for `ui_MaxWaypointSize`.
   */
  void register_TConVar_ui_MaxWaypointSize()
  {
    RegisterStartupConVar(gTConVar_ui_MaxWaypointSize, &cleanup_TConVar_ui_MaxWaypointSize);
  }

  /**
   * Address: 0x00C07900 (FUN_00C07900, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_MinExtractSnapPixels`.
   */
  void cleanup_TConVar_ui_MinExtractSnapPixels()
  {
    CleanupStartupConCommand(gTConVar_ui_MinExtractSnapPixels);
  }

  /**
   * Address: 0x00BE6860 (FUN_00BE6860, register_TConVar_ui_MinExtractSnapPixels)
   *
   * What it does:
   * Registers startup convar for `ui_MinExtractSnapPixels`.
   */
  void register_TConVar_ui_MinExtractSnapPixels()
  {
    RegisterStartupConVar(gTConVar_ui_MinExtractSnapPixels, &cleanup_TConVar_ui_MinExtractSnapPixels);
  }

  /**
   * Address: 0x00C05F60 (FUN_00C05F60, ??1TConVar_ui_MinWaypointSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_MinWaypointSize`.
   */
  void cleanup_TConVar_ui_MinWaypointSize()
  {
    CleanupStartupConCommand(gTConVar_ui_MinWaypointSize);
  }

  /**
   * Address: 0x00BE3D00 (FUN_00BE3D00, register_TConVar_ui_MinWaypointSize)
   *
   * What it does:
   * Registers startup convar for `ui_MinWaypointSize`.
   */
  void register_TConVar_ui_MinWaypointSize()
  {
    RegisterStartupConVar(gTConVar_ui_MinWaypointSize, &cleanup_TConVar_ui_MinWaypointSize);
  }

  /**
   * Address: 0x00C06D20 (FUN_00C06D20, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_NisRenderIcons`.
   */
  void cleanup_TConVar_ui_NisRenderIcons()
  {
    CleanupStartupConCommand(gTConVar_ui_NisRenderIcons);
  }

  /**
   * Address: 0x00BE5620 (FUN_00BE5620, register_TConVar_ui_NisRenderIcons)
   *
   * What it does:
   * Registers startup convar for `ui_NisRenderIcons`.
   */
  void register_TConVar_ui_NisRenderIcons()
  {
    RegisterStartupConVar(gTConVar_ui_NisRenderIcons, &cleanup_TConVar_ui_NisRenderIcons);
  }

  /**
   * Address: 0x00C05FF0 (FUN_00C05FF0, ??1TConVar_ui_PathPreview@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_PathPreview`.
   */
  void cleanup_TConVar_ui_PathPreview()
  {
    CleanupStartupConCommand(gTConVar_ui_PathPreview);
  }

  /**
   * Address: 0x00BE3DC0 (FUN_00BE3DC0, register_TConVar_ui_PathPreview)
   *
   * What it does:
   * Registers startup convar for `ui_PathPreview`.
   */
  void register_TConVar_ui_PathPreview()
  {
    RegisterStartupConVar(gTConVar_ui_PathPreview, &cleanup_TConVar_ui_PathPreview);
  }

  /**
   * Address: 0x00C05ED0 (FUN_00C05ED0, ??1TConVar_ui_PathSmoothness@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_PathSmoothness`.
   */
  void cleanup_TConVar_ui_PathSmoothness()
  {
    CleanupStartupConCommand(gTConVar_ui_PathSmoothness);
  }

  /**
   * Address: 0x00BE3C40 (FUN_00BE3C40, register_TConVar_ui_PathSmoothness)
   *
   * What it does:
   * Registers startup convar for `ui_PathSmoothness`.
   */
  void register_TConVar_ui_PathSmoothness()
  {
    RegisterStartupConVar(gTConVar_ui_PathSmoothness, &cleanup_TConVar_ui_PathSmoothness);
  }

  /**
   * Address: 0x00C070B0 (FUN_00C070B0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ProgressBarColor`.
   */
  void cleanup_TConVar_ui_ProgressBarColor()
  {
    CleanupStartupConCommand(gTConVar_ui_ProgressBarColor);
  }

  /**
   * Address: 0x00BE5AC0 (FUN_00BE5AC0, register_TConVar_ui_ProgressBarColor)
   *
   * What it does:
   * Registers startup convar for `ui_ProgressBarColor`.
   */
  void register_TConVar_ui_ProgressBarColor()
  {
    RegisterStartupConVar(gTConVar_ui_ProgressBarColor, &cleanup_TConVar_ui_ProgressBarColor);
  }

  /**
   * Address: 0x00C06D50 (FUN_00C06D50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_RenderCustomNames`.
   */
  void cleanup_TConVar_ui_RenderCustomNames()
  {
    CleanupStartupConCommand(gTConVar_ui_RenderCustomNames);
  }

  /**
   * Address: 0x00BE5660 (FUN_00BE5660, register_TConVar_ui_RenderCustomNames)
   *
   * What it does:
   * Registers startup convar for `ui_RenderCustomNames`.
   */
  void register_TConVar_ui_RenderCustomNames()
  {
    RegisterStartupConVar(gTConVar_ui_RenderCustomNames, &cleanup_TConVar_ui_RenderCustomNames);
  }

  /**
   * Address: 0x00C06CF0 (FUN_00C06CF0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_RenderIcons`.
   */
  void cleanup_TConVar_ui_RenderIcons()
  {
    CleanupStartupConCommand(gTConVar_ui_RenderIcons);
  }

  /**
   * Address: 0x00BE55E0 (FUN_00BE55E0, register_TConVar_ui_RenderIcons)
   *
   * What it does:
   * Registers startup convar for `ui_RenderIcons`.
   */
  void register_TConVar_ui_RenderIcons()
  {
    RegisterStartupConVar(gTConVar_ui_RenderIcons, &cleanup_TConVar_ui_RenderIcons);
  }

  /**
   * Address: 0x00C06E40 (FUN_00C06E40, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_RenderSelectionSetNames`.
   */
  void cleanup_TConVar_ui_RenderSelectionSetNames()
  {
    CleanupStartupConCommand(gTConVar_ui_RenderSelectionSetNames);
  }

  /**
   * Address: 0x00BE5780 (FUN_00BE5780, register_TConVar_ui_RenderSelectionSetNames)
   *
   * What it does:
   * Registers startup convar for `ui_RenderSelectionSetNames`.
   */
  void register_TConVar_ui_RenderSelectionSetNames()
  {
    RegisterStartupConVar(gTConVar_ui_RenderSelectionSetNames, &cleanup_TConVar_ui_RenderSelectionSetNames);
  }

  /**
   * Address: 0x00C06C90 (FUN_00C06C90, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_RenderUnitBars`.
   */
  void cleanup_TConVar_ui_RenderUnitBars()
  {
    CleanupStartupConCommand(gTConVar_ui_RenderUnitBars);
  }

  /**
   * Address: 0x00BE5560 (FUN_00BE5560, register_TConVar_ui_RenderUnitBars)
   *
   * What it does:
   * Registers startup convar for `ui_RenderUnitBars`.
   */
  void register_TConVar_ui_RenderUnitBars()
  {
    RegisterStartupConVar(gTConVar_ui_RenderUnitBars, &cleanup_TConVar_ui_RenderUnitBars);
  }

  /**
   * Address: 0x00C07840 (FUN_00C07840, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ScreenEdgeScrollView`.
   */
  void cleanup_TConVar_ui_ScreenEdgeScrollView()
  {
    CleanupStartupConCommand(gTConVar_ui_ScreenEdgeScrollView);
  }

  /**
   * Address: 0x00BE6760 (FUN_00BE6760, register_TConVar_ui_ScreenEdgeScrollView)
   *
   * What it does:
   * Registers startup convar for `ui_ScreenEdgeScrollView`.
   */
  void register_TConVar_ui_ScreenEdgeScrollView()
  {
    RegisterStartupConVar(gTConVar_ui_ScreenEdgeScrollView, &cleanup_TConVar_ui_ScreenEdgeScrollView);
  }

  /**
   * Address: 0x00C07870 (FUN_00C07870, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_SelectTolerance`.
   */
  void cleanup_TConVar_ui_SelectTolerance()
  {
    CleanupStartupConCommand(gTConVar_ui_SelectTolerance);
  }

  /**
   * Address: 0x00BE67A0 (FUN_00BE67A0, register_TConVar_ui_SelectTolerance)
   *
   * What it does:
   * Registers startup convar for `ui_SelectTolerance`.
   */
  void register_TConVar_ui_SelectTolerance()
  {
    RegisterStartupConVar(gTConVar_ui_SelectTolerance, &cleanup_TConVar_ui_SelectTolerance);
  }

  /**
   * Address: 0x00C06E70 (FUN_00C06E70, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_SelectionSetNamesColor`.
   */
  void cleanup_TConVar_ui_SelectionSetNamesColor()
  {
    CleanupStartupConCommand(gTConVar_ui_SelectionSetNamesColor);
  }

  /**
   * Address: 0x00BE57C0 (FUN_00BE57C0, register_TConVar_ui_SelectionSetNamesColor)
   *
   * What it does:
   * Registers startup convar for `ui_SelectionSetNamesColor`.
   */
  void register_TConVar_ui_SelectionSetNamesColor()
  {
    RegisterStartupConVar(gTConVar_ui_SelectionSetNamesColor, &cleanup_TConVar_ui_SelectionSetNamesColor);
  }

  /**
   * Address: 0x00C07080 (FUN_00C07080, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_ShieldBarColor`.
   */
  void cleanup_TConVar_ui_ShieldBarColor()
  {
    CleanupStartupConCommand(gTConVar_ui_ShieldBarColor);
  }

  /**
   * Address: 0x00BE5A80 (FUN_00BE5A80, register_TConVar_ui_ShieldBarColor)
   *
   * What it does:
   * Registers startup convar for `ui_ShieldBarColor`.
   */
  void register_TConVar_ui_ShieldBarColor()
  {
    RegisterStartupConVar(gTConVar_ui_ShieldBarColor, &cleanup_TConVar_ui_ShieldBarColor);
  }

  /**
   * Address: 0x00C06F00 (FUN_00C06F00, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_StrategicIconBlinkDuration`.
   */
  void cleanup_TConVar_ui_StrategicIconBlinkDuration()
  {
    CleanupStartupConCommand(gTConVar_ui_StrategicIconBlinkDuration);
  }

  /**
   * Address: 0x00BE5880 (FUN_00BE5880, register_TConVar_ui_StrategicIconBlinkDuration)
   *
   * What it does:
   * Registers startup convar for `ui_StrategicIconBlinkDuration`.
   */
  void register_TConVar_ui_StrategicIconBlinkDuration()
  {
    RegisterStartupConVar(gTConVar_ui_StrategicIconBlinkDuration, &cleanup_TConVar_ui_StrategicIconBlinkDuration);
  }

  /**
   * Address: 0x00C06EA0 (FUN_00C06EA0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_StrategicIconBlinkRate`.
   */
  void cleanup_TConVar_ui_StrategicIconBlinkRate()
  {
    CleanupStartupConCommand(gTConVar_ui_StrategicIconBlinkRate);
  }

  /**
   * Address: 0x00BE5800 (FUN_00BE5800, register_TConVar_ui_StrategicIconBlinkRate)
   *
   * What it does:
   * Registers startup convar for `ui_StrategicIconBlinkRate`.
   */
  void register_TConVar_ui_StrategicIconBlinkRate()
  {
    RegisterStartupConVar(gTConVar_ui_StrategicIconBlinkRate, &cleanup_TConVar_ui_StrategicIconBlinkRate);
  }

  /**
   * Address: 0x00C06020 (FUN_00C06020, ??1TConVar_ui_WaypointLineScale@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_WaypointLineScale`.
   */
  void cleanup_TConVar_ui_WaypointLineScale()
  {
    CleanupStartupConCommand(gTConVar_ui_WaypointLineScale);
  }

  /**
   * Address: 0x00BE3E00 (FUN_00BE3E00, register_TConVar_ui_WaypointLineScale)
   *
   * What it does:
   * Registers startup convar for `ui_WaypointLineScale`.
   */
  void register_TConVar_ui_WaypointLineScale()
  {
    RegisterStartupConVar(gTConVar_ui_WaypointLineScale, &cleanup_TConVar_ui_WaypointLineScale);
  }

  /**
   * Address: 0x00C02C40 (FUN_00C02C40, ??1TConVar_ui_WindowedAlwaysShowsCursor@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_WindowedAlwaysShowsCursor`.
   */
  void cleanup_TConVar_ui_WindowedAlwaysShowsCursor()
  {
    CleanupStartupConCommand(gTConVar_ui_WindowedAlwaysShowsCursor);
  }

  /**
   * Address: 0x00BDDFB0 (FUN_00BDDFB0, register_TConVar_ui_WindowedAlwaysShowsCursor)
   *
   * What it does:
   * Registers startup convar for `ui_WindowedAlwaysShowsCursor`.
   */
  void register_TConVar_ui_WindowedAlwaysShowsCursor()
  {
    RegisterStartupConVar(gTConVar_ui_WindowedAlwaysShowsCursor, &cleanup_TConVar_ui_WindowedAlwaysShowsCursor);
  }

  /**
   * Address: 0x00C06BA0 (FUN_00C06BA0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_fuelbarHeight`.
   */
  void cleanup_TConVar_ui_fuelbarHeight()
  {
    CleanupStartupConCommand(gTConVar_ui_fuelbarHeight);
  }

  /**
   * Address: 0x00BE5420 (FUN_00BE5420, register_TConVar_ui_fuelbarHeight)
   *
   * What it does:
   * Registers startup convar for `ui_fuelbarHeight`.
   */
  void register_TConVar_ui_fuelbarHeight()
  {
    RegisterStartupConVar(gTConVar_ui_fuelbarHeight, &cleanup_TConVar_ui_fuelbarHeight);
  }

  /**
   * Address: 0x00C06BD0 (FUN_00C06BD0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ui_lifebarHeight`.
   */
  void cleanup_TConVar_ui_lifebarHeight()
  {
    CleanupStartupConCommand(gTConVar_ui_lifebarHeight);
  }

  /**
   * Address: 0x00BE5460 (FUN_00BE5460, register_TConVar_ui_lifebarHeight)
   *
   * What it does:
   * Registers startup convar for `ui_lifebarHeight`.
   */
  void register_TConVar_ui_lifebarHeight()
  {
    RegisterStartupConVar(gTConVar_ui_lifebarHeight, &cleanup_TConVar_ui_lifebarHeight);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsUiTuning
  {
    ConsoleStartupRegistrationsUiTuning()
    {
      moho::register_TConVar_UI_RenProectileTrailWidth();
      moho::register_TConVar_UI_RenProjectileArcs();
      moho::register_TConVar_UI_RenProjectileArcsSampleInterval();
      moho::register_TConVar_UI_RenProjectileGlow();
      moho::register_TConVar_UI_RenProjectileGlowMax();
      moho::register_TConVar_UI_RenProjectileGlowMin();
      moho::register_TConVar_UI_RenProjectileGlowPeriod();
      moho::register_TConVar_UI_RenProjectileIcons();
      moho::register_TConVar_UI_RenProjectileTrailColor();
      moho::register_TConVar_UI_RenResources();
      moho::register_TConVar_UI_ResourceLODCutoff();
      moho::register_TConVar_UI_SelectAnything();
      moho::register_TConVar_UI_ShowControlUnderMouse();
      moho::register_TConVar_UI_StrategicProjectileLOD();
      moho::register_TConVar_UI_forceWeaponsToYellow();
      moho::register_TConVar_ui_AlwaysRenderStrategicIcons();
      moho::register_TConVar_ui_ArrowKeysScrollView();
      moho::register_TConVar_ui_BuildPlaceTarmacAlpha();
      moho::register_TConVar_ui_CommandClickScale();
      moho::register_TConVar_ui_CommandGraphMaxNodeUnits();
      moho::register_TConVar_ui_CurveSegments();
      moho::register_TConVar_ui_CurveSmoothness();
      moho::register_TConVar_ui_CustomNameColor();
      moho::register_TConVar_ui_CustomNameFont();
      moho::register_TConVar_ui_CustomNameFontSize();
      moho::register_TConVar_ui_DebugAltClick();
      moho::register_TConVar_ui_DisableCursorFixing();
      moho::register_TConVar_ui_DragSelect2D();
      moho::register_TConVar_ui_DrawPathPreview();
      moho::register_TConVar_ui_ExtractSnapTolerance();
      moho::register_TConVar_ui_FootprintMinThickness();
      moho::register_TConVar_ui_ForceLifbarsOnEnemy();
      moho::register_TConVar_ui_FuelBarColor();
      moho::register_TConVar_ui_FuelEmptyBlinkRate();
      moho::register_TConVar_ui_FuelWarningColor();
      moho::register_TConVar_ui_KeyboardPanAccelerateMultiplier();
      moho::register_TConVar_ui_KeyboardPanSpeed();
      moho::register_TConVar_ui_KeyboardRotateAccelerateMultiplier();
      moho::register_TConVar_ui_KeyboardRotateSpeed();
      moho::register_TConVar_ui_LifeBarBadColor();
      moho::register_TConVar_ui_LifeBarBadCutoff();
      moho::register_TConVar_ui_LifeBarGoodColor();
      moho::register_TConVar_ui_LifeBarGoodCutoff();
      moho::register_TConVar_ui_LifeBarMedColor();
      moho::register_TConVar_ui_LifebarLOD();
      moho::register_TConVar_ui_LifebarOffset();
      moho::register_TConVar_ui_LifebarWidth();
      moho::register_TConVar_ui_MaxExtractSnapPixels();
      moho::register_TConVar_ui_MaxTextLOD();
      moho::register_TConVar_ui_MaxWaypointSize();
      moho::register_TConVar_ui_MinExtractSnapPixels();
      moho::register_TConVar_ui_MinWaypointSize();
      moho::register_TConVar_ui_NisRenderIcons();
      moho::register_TConVar_ui_PathPreview();
      moho::register_TConVar_ui_PathSmoothness();
      moho::register_TConVar_ui_ProgressBarColor();
      moho::register_TConVar_ui_RenderCustomNames();
      moho::register_TConVar_ui_RenderIcons();
      moho::register_TConVar_ui_RenderSelectionSetNames();
      moho::register_TConVar_ui_RenderUnitBars();
      moho::register_TConVar_ui_ScreenEdgeScrollView();
      moho::register_TConVar_ui_SelectTolerance();
      moho::register_TConVar_ui_SelectionSetNamesColor();
      moho::register_TConVar_ui_ShieldBarColor();
      moho::register_TConVar_ui_StrategicIconBlinkDuration();
      moho::register_TConVar_ui_StrategicIconBlinkRate();
      moho::register_TConVar_ui_WaypointLineScale();
      moho::register_TConVar_ui_WindowedAlwaysShowsCursor();
      moho::register_TConVar_ui_fuelbarHeight();
      moho::register_TConVar_ui_lifebarHeight();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsUiTuning gConsoleStartupRegistrationsUiTuning;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupRenBandwidthDisplayKernelDescription = "Width of bandwidth filter (in seconds).";
  constexpr const char* kConsoleStartupRenBandwidthDisplaySecondsDescription = "Number of seconds of bandwidth data to display.";
  constexpr const char* kConsoleStartupRenBgLowerBoundDescription = "ren_BgLowerBound tuning value.";
  constexpr const char* kConsoleStartupRenBloomDescription = "Render Blooms?";
  constexpr const char* kConsoleStartupRenBloomBlurCountDescription = "Bloom Blur Count";
  constexpr const char* kConsoleStartupRenBloomBlurKernelScaleDescription = "Amount to scale blurred amount by.";
  constexpr const char* kConsoleStartupRenBloomGlowCopyScaleDescription = "Scale when copying glowing stuff to glow buffer before blur";
  constexpr const char* kConsoleStartupRenBorderSizeDescription = "Size of edge border";
  constexpr const char* kConsoleStartupRenClipDecalLevelDescription = "Level at which we clip decals for super quick reject";
  constexpr const char* kConsoleStartupRenClipDecalsDescription = "Clip Decals vertex count";
  constexpr const char* kConsoleStartupRenClutterDescription = "Render clutter";
  constexpr const char* kConsoleStartupRenClutterRadiusDescription = "ren_ClutterRadius tuning value.";
  constexpr const char* kConsoleStartupRenDecalAlbedoLodCutoffDescription = "Fudge factor for decal cutoff on zoom out for albedos";
  constexpr const char* kConsoleStartupRenDecalFadeFractionDescription = "fraction (0..1) of their range that decals start to fade";
  constexpr const char* kConsoleStartupRenDecalFidelityDescription = "ren_DecalFidelity tuning value.";
  constexpr const char* kConsoleStartupRenDecalFlatTolDescription = "flatness tolerance";
  constexpr const char* kConsoleStartupRenDecalNormalLodCutoffDescription = "Fudge factor for decal cutoff on zoom out for normals";
  constexpr const char* kConsoleStartupRenDecalOverDrawDescription = "Render overdraw display for decals";
  constexpr const char* kConsoleStartupRenDecalsDescription = "Render Terrain Decals.";
  constexpr const char* kConsoleStartupRenErrorCacheDescription = "use error threshold cache?";
  constexpr const char* kConsoleStartupRenFogIntensityDescription = "intensity of gray fog";
  constexpr const char* kConsoleStartupRenFogOfWarDescription = "Draw terrain with fog-of-war.";
  constexpr const char* kConsoleStartupRenForceUpdateMinimapTerrainDescription = "Update the terrain tesselation/decals if it's a minimap";
  constexpr const char* kConsoleStartupRenFrameTimeSecondsDescription = "Number of seconds to display.";
  constexpr const char* kConsoleStartupRenFxDescription = "Render FX?";
  constexpr const char* kConsoleStartupRenGenerateMeshDescription = "Generate a new mesh or use the old one?";
  constexpr const char* kConsoleStartupRenHideSecondaryDescription = "Hide secondary views";
  constexpr const char* kConsoleStartupRenIgnoreDecalLODDescription = "Force decals to render regardless of LOD";
  constexpr const char* kConsoleStartupRenMeshDissolveDescription = "Fade mesh alpha from 1.0 to 0.0";
  constexpr const char* kConsoleStartupRenMeshDissolveCutoffDescription = "ren_MeshDissolveCutoff tuning value.";
  constexpr const char* kConsoleStartupRenMeshSkinnedDescription = "toggle rendering of meshes which have and use skeletons";
  constexpr const char* kConsoleStartupRenMeshStaticDescription = "toggle rendering of meshes which do not have or ignore skeletons";
  constexpr const char* kConsoleStartupRenNewFogUpdateDescription = "Use new fog update code";
  constexpr const char* kConsoleStartupRenNewPipelineDescription = "ren_NewPipeline tuning value.";
  constexpr const char* kConsoleStartupRenNormalDecalsDescription = "Render Normal Decals";
  constexpr const char* kConsoleStartupRenOblivionDescription = "ren_Oblivion tuning value.";
  constexpr const char* kConsoleStartupRenOnlyFirstViewDescription = "Render only the first view in the list";
  constexpr const char* kConsoleStartupRenPlayableBoundaryDescription = "ren_PlayableBoundary tuning value.";
  constexpr const char* kConsoleStartupRenReflectionDescription = "Render reflection?";
  constexpr const char* kConsoleStartupRenRefractionDescription = "Render refraction?";
  constexpr const char* kConsoleStartupRenRegenShoreDescription = "Regenerate shoreline (editor only)";
  constexpr const char* kConsoleStartupRenRenderNothingDescription = "Render nothing?";
  constexpr const char* kConsoleStartupRenSelectDescription = "Render select meshes?";
  constexpr const char* kConsoleStartupRenSelectBoxesDescription = "Toggle selection box rendering";
  constexpr const char* kConsoleStartupRenSelectBracketMinPixelSizeDescription = "Minimum selection bracket thickness in pixels.";
  constexpr const char* kConsoleStartupRenSelectBracketSizeDescription = "Default selection bracket thickness";
  constexpr const char* kConsoleStartupRenSelectColorDescription = "What color do we want the selection box?";
  constexpr const char* kConsoleStartupRenSelectionHeightFudgeDescription = "How far off the ground selection boxes are fudged";
  constexpr const char* kConsoleStartupRenSelectionSizeFudgeDescription = "How much selection box extents are fudged (multiplier)";
  constexpr const char* kConsoleStartupRenShadowBlurDescription = "Toggle shadow blurring";
  constexpr const char* kConsoleStartupRenShadowCoeffDescription = "ren_ShadowCoeff tuning value.";
  constexpr const char* kConsoleStartupRenShadowLODDescription = "At what LODMetric do we stop rendering shadows";
  constexpr const char* kConsoleStartupRenShadowSizeDescription = "Sizeof shadow texture";
  constexpr const char* kConsoleStartupRenShadowsDescription = "Render Shadows?";
  constexpr const char* kConsoleStartupRenShoreErrorCoeffDescription = "ren_ShoreErrorCoeff tuning value.";
  constexpr const char* kConsoleStartupRenShorelineDescription = "Render shoreline";
  constexpr const char* kConsoleStartupRenShorelineCutoffDescription = "Shoreline LOD cutoff";
  constexpr const char* kConsoleStartupRenShowBandwidthUsageDescription = "Show the amount of network bandwidth we are using.";
  constexpr const char* kConsoleStartupRenShowBoneNamesDescription = "Show bone names";
  constexpr const char* kConsoleStartupRenShowDirtyTerrainDescription = "Show or hide the dirty terrain bits.";
  constexpr const char* kConsoleStartupRenShowFrameTimesDescription = "Graphically show the frame times.";
  constexpr const char* kConsoleStartupRenShowNetworkStatsDescription = "Show various network stats.";
  constexpr const char* kConsoleStartupRenShowNormalsDescription = "Variable to track show/hide normals rendering.";
  constexpr const char* kConsoleStartupRenShowWireframeDescription = "Variable to track show/hide wireframe rendering.";
  constexpr const char* kConsoleStartupRenSkirtDescription = "Use new fog update code";
  constexpr const char* kConsoleStartupRenSkyDomeDescription = "Render sky";
  constexpr const char* kConsoleStartupRenSplatsDescription = "Render Terrain splats.";
  constexpr const char* kConsoleStartupRenSyncTerrainLODDescription = "Distance at which to start display terrain sync changes";
  constexpr const char* kConsoleStartupRenTTerrainGlowDescription = "Render the terrain using TTerrainGlow";
  constexpr const char* kConsoleStartupRenTeamColorLookupCountDescription = "Number of 'channels' in team color lookup texture.";
  constexpr const char* kConsoleStartupRenTerrainDescription = "Show or hide the terrain.";
  constexpr const char* kConsoleStartupRenTreesDescription = "Show or hide the trees.";
  constexpr const char* kConsoleStartupRenUiDescription = "Render UI?";
  constexpr const char* kConsoleStartupRenUnitSelectionScaleDescription = "How much unit selection box extents are scaled (multiplier)";
  constexpr const char* kConsoleStartupRenUnitSilhouetteDescription = "ren_UnitSilhouette tuning value.";
  constexpr const char* kConsoleStartupRenViewErrorDescription = "ren_ViewError tuning value.";
  constexpr const char* kConsoleStartupRenWaterDescription = "Show or hide the water.";
  constexpr const char* kConsoleStartupRenWorldBorderDescription = "Render UI world border frame?";
  constexpr const char* kConsoleStartupRenBicubicnormalsDescription = "Sample normal map basis using bicubic filter";
  constexpr const char* kConsoleStartupRenFogDescription = "Do we render fog of war, rendering only no effect on database.";
  constexpr const char* kConsoleStartupRenGlowingDecalsDescription = "Render glowing decals";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
bool moho::ren_Clutter = false;
int moho::ren_FogIntensity = 100;
bool moho::ren_HideSecondary = false;
bool moho::ren_NewFogUpdate = true;
bool moho::ren_NewPipeline = true;
bool moho::ren_Refraction = true;
bool moho::ren_RegenShore = false;
bool moho::ren_ShowBoneNames = false;
bool moho::ren_TTerrainGlow = false;
int moho::ren_TeamColorLookupCount = 32;
bool moho::ren_Trees = false;
float moho::ren_ViewError = 0.003000000026077032f;

namespace moho
{
  extern float ren_BandwidthDisplayKernel;
  extern float ren_BandwidthDisplaySeconds;
  extern float ren_BgLowerBound;
  extern bool ren_Bloom;
  extern int ren_BloomBlurCount;
  extern float ren_BloomBlurKernelScale;
  extern float ren_BloomGlowCopyScale;
  extern float ren_BorderSize;
  extern int ren_ClipDecalLevel;
  extern bool ren_ClipDecals;
  extern float ren_ClutterRadius;
  extern float ren_DecalAlbedoLodCutoff;
  extern float ren_DecalFadeFraction;
  extern int ren_DecalFidelity;
  extern float ren_DecalFlatTol;
  extern float ren_DecalNormalLodCutoff;
  extern bool ren_DecalOverDraw;
  extern bool ren_Decals;
  extern bool ren_ErrorCache;
  extern bool ren_FogOfWar;
  extern bool ren_ForceUpdateMinimapTerrain;
  extern float ren_FrameTimeSeconds;
  extern bool ren_Fx;
  extern bool ren_GenerateMesh;
  extern bool ren_IgnoreDecalLOD;
  extern float ren_MeshDissolve;
  extern float ren_MeshDissolveCutoff;
  extern bool ren_MeshSkinned;
  extern bool ren_MeshStatic;
  extern bool ren_NormalDecals;
  extern bool ren_Oblivion;
  extern bool ren_OnlyFirstView;
  extern bool ren_PlayableBoundary;
  extern bool ren_Reflection;
  extern bool ren_RenderNothing;
  extern bool ren_Select;
  extern bool ren_SelectBoxes;
  extern float ren_SelectBracketMinPixelSize;
  extern float ren_SelectBracketSize;
  extern unsigned int ren_SelectColor;
  extern float ren_SelectionHeightFudge;
  extern float ren_SelectionSizeFudge;
  extern bool ren_ShadowBlur;
  extern float ren_ShadowCoeff;
  extern float ren_ShadowLOD;
  extern int ren_ShadowSize;
  extern bool ren_Shadows;
  extern float ren_ShoreErrorCoeff;
  extern bool ren_Shoreline;
  extern float ren_ShorelineCutoff;
  extern bool ren_ShowBandwidthUsage;
  extern bool ren_ShowDirtyTerrain;
  extern bool ren_ShowFrameTimes;
  extern bool ren_ShowNetworkStats;
  extern bool ren_ShowNormals;
  extern bool ren_ShowWireframe;
  extern bool ren_Skirt;
  extern bool ren_SkyDome;
  extern bool ren_Splats;
  extern float ren_SyncTerrainLOD;
  extern bool ren_Terrain;
  extern bool ren_Ui;
  extern float ren_UnitSelectionScale;
  extern bool ren_UnitSilhouette;
  extern bool ren_Water;
  extern bool ren_WorldBorder;
  extern bool ren_bicubicnormals;
  extern bool ren_fog;
  extern bool ren_glowingDecals;

  TConVar<float> gTConVar_ren_BandwidthDisplayKernel(
    "ren_BandwidthDisplayKernel",
    kConsoleStartupRenBandwidthDisplayKernelDescription,
    &moho::ren_BandwidthDisplayKernel
  );
  TConVar<float> gTConVar_ren_BandwidthDisplaySeconds(
    "ren_BandwidthDisplaySeconds",
    kConsoleStartupRenBandwidthDisplaySecondsDescription,
    &moho::ren_BandwidthDisplaySeconds
  );
  TConVar<float> gTConVar_ren_BgLowerBound(
    "ren_BgLowerBound",
    kConsoleStartupRenBgLowerBoundDescription,
    &moho::ren_BgLowerBound
  );
  TConVar<bool> gTConVar_ren_Bloom(
    "ren_Bloom",
    kConsoleStartupRenBloomDescription,
    &moho::ren_Bloom
  );
  TConVar<int> gTConVar_ren_BloomBlurCount(
    "ren_BloomBlurCount",
    kConsoleStartupRenBloomBlurCountDescription,
    &moho::ren_BloomBlurCount
  );
  TConVar<float> gTConVar_ren_BloomBlurKernelScale(
    "ren_BloomBlurKernelScale",
    kConsoleStartupRenBloomBlurKernelScaleDescription,
    &moho::ren_BloomBlurKernelScale
  );
  TConVar<float> gTConVar_ren_BloomGlowCopyScale(
    "ren_BloomGlowCopyScale",
    kConsoleStartupRenBloomGlowCopyScaleDescription,
    &moho::ren_BloomGlowCopyScale
  );
  TConVar<float> gTConVar_ren_BorderSize(
    "ren_BorderSize",
    kConsoleStartupRenBorderSizeDescription,
    &moho::ren_BorderSize
  );
  TConVar<int> gTConVar_ren_ClipDecalLevel(
    "ren_ClipDecalLevel",
    kConsoleStartupRenClipDecalLevelDescription,
    &moho::ren_ClipDecalLevel
  );
  TConVar<bool> gTConVar_ren_ClipDecals(
    "ren_ClipDecals",
    kConsoleStartupRenClipDecalsDescription,
    &moho::ren_ClipDecals
  );
  TConVar<bool> gTConVar_ren_Clutter(
    "ren_Clutter",
    kConsoleStartupRenClutterDescription,
    &moho::ren_Clutter
  );
  TConVar<float> gTConVar_ren_ClutterRadius(
    "ren_ClutterRadius",
    kConsoleStartupRenClutterRadiusDescription,
    &moho::ren_ClutterRadius
  );
  TConVar<float> gTConVar_ren_DecalAlbedoLodCutoff(
    "ren_DecalAlbedoLodCutoff",
    kConsoleStartupRenDecalAlbedoLodCutoffDescription,
    &moho::ren_DecalAlbedoLodCutoff
  );
  TConVar<float> gTConVar_ren_DecalFadeFraction(
    "ren_DecalFadeFraction",
    kConsoleStartupRenDecalFadeFractionDescription,
    &moho::ren_DecalFadeFraction
  );
  TConVar<int> gTConVar_ren_DecalFidelity(
    "ren_DecalFidelity",
    kConsoleStartupRenDecalFidelityDescription,
    &moho::ren_DecalFidelity
  );
  TConVar<float> gTConVar_ren_DecalFlatTol(
    "ren_DecalFlatTol",
    kConsoleStartupRenDecalFlatTolDescription,
    &moho::ren_DecalFlatTol
  );
  TConVar<float> gTConVar_ren_DecalNormalLodCutoff(
    "ren_DecalNormalLodCutoff",
    kConsoleStartupRenDecalNormalLodCutoffDescription,
    &moho::ren_DecalNormalLodCutoff
  );
  TConVar<bool> gTConVar_ren_DecalOverDraw(
    "ren_DecalOverDraw",
    kConsoleStartupRenDecalOverDrawDescription,
    &moho::ren_DecalOverDraw
  );
  TConVar<bool> gTConVar_ren_Decals(
    "ren_Decals",
    kConsoleStartupRenDecalsDescription,
    &moho::ren_Decals
  );
  TConVar<bool> gTConVar_ren_ErrorCache(
    "ren_ErrorCache",
    kConsoleStartupRenErrorCacheDescription,
    &moho::ren_ErrorCache
  );
  TConVar<int> gTConVar_ren_FogIntensity(
    "ren_FogIntensity",
    kConsoleStartupRenFogIntensityDescription,
    &moho::ren_FogIntensity
  );
  TConVar<bool> gTConVar_ren_FogOfWar(
    "ren_FogOfWar",
    kConsoleStartupRenFogOfWarDescription,
    &moho::ren_FogOfWar
  );
  TConVar<bool> gTConVar_ren_ForceUpdateMinimapTerrain(
    "ren_ForceUpdateMinimapTerrain",
    kConsoleStartupRenForceUpdateMinimapTerrainDescription,
    &moho::ren_ForceUpdateMinimapTerrain
  );
  TConVar<float> gTConVar_ren_FrameTimeSeconds(
    "ren_FrameTimeSeconds",
    kConsoleStartupRenFrameTimeSecondsDescription,
    &moho::ren_FrameTimeSeconds
  );
  TConVar<bool> gTConVar_ren_Fx(
    "ren_Fx",
    kConsoleStartupRenFxDescription,
    &moho::ren_Fx
  );
  TConVar<bool> gTConVar_ren_GenerateMesh(
    "ren_GenerateMesh",
    kConsoleStartupRenGenerateMeshDescription,
    &moho::ren_GenerateMesh
  );
  TConVar<bool> gTConVar_ren_HideSecondary(
    "ren_HideSecondary",
    kConsoleStartupRenHideSecondaryDescription,
    &moho::ren_HideSecondary
  );
  TConVar<bool> gTConVar_ren_IgnoreDecalLOD(
    "ren_IgnoreDecalLOD",
    kConsoleStartupRenIgnoreDecalLODDescription,
    &moho::ren_IgnoreDecalLOD
  );
  TConVar<float> gTConVar_ren_MeshDissolve(
    "ren_MeshDissolve",
    kConsoleStartupRenMeshDissolveDescription,
    &moho::ren_MeshDissolve
  );
  TConVar<float> gTConVar_ren_MeshDissolveCutoff(
    "ren_MeshDissolveCutoff",
    kConsoleStartupRenMeshDissolveCutoffDescription,
    &moho::ren_MeshDissolveCutoff
  );
  TConVar<bool> gTConVar_ren_MeshSkinned(
    "ren_MeshSkinned",
    kConsoleStartupRenMeshSkinnedDescription,
    &moho::ren_MeshSkinned
  );
  TConVar<bool> gTConVar_ren_MeshStatic(
    "ren_MeshStatic",
    kConsoleStartupRenMeshStaticDescription,
    &moho::ren_MeshStatic
  );
  TConVar<bool> gTConVar_ren_NewFogUpdate(
    "ren_NewFogUpdate",
    kConsoleStartupRenNewFogUpdateDescription,
    &moho::ren_NewFogUpdate
  );
  TConVar<bool> gTConVar_ren_NewPipeline(
    "ren_NewPipeline",
    kConsoleStartupRenNewPipelineDescription,
    &moho::ren_NewPipeline
  );
  TConVar<bool> gTConVar_ren_NormalDecals(
    "ren_NormalDecals",
    kConsoleStartupRenNormalDecalsDescription,
    &moho::ren_NormalDecals
  );
  TConVar<bool> gTConVar_ren_Oblivion(
    "ren_Oblivion",
    kConsoleStartupRenOblivionDescription,
    &moho::ren_Oblivion
  );
  TConVar<bool> gTConVar_ren_OnlyFirstView(
    "ren_OnlyFirstView",
    kConsoleStartupRenOnlyFirstViewDescription,
    &moho::ren_OnlyFirstView
  );
  TConVar<bool> gTConVar_ren_PlayableBoundary(
    "ren_PlayableBoundary",
    kConsoleStartupRenPlayableBoundaryDescription,
    &moho::ren_PlayableBoundary
  );
  TConVar<bool> gTConVar_ren_Reflection(
    "ren_Reflection",
    kConsoleStartupRenReflectionDescription,
    &moho::ren_Reflection
  );
  TConVar<bool> gTConVar_ren_Refraction(
    "ren_Refraction",
    kConsoleStartupRenRefractionDescription,
    &moho::ren_Refraction
  );
  TConVar<bool> gTConVar_ren_RegenShore(
    "ren_RegenShore",
    kConsoleStartupRenRegenShoreDescription,
    &moho::ren_RegenShore
  );
  TConVar<bool> gTConVar_ren_RenderNothing(
    "ren_RenderNothing",
    kConsoleStartupRenRenderNothingDescription,
    &moho::ren_RenderNothing
  );
  TConVar<bool> gTConVar_ren_Select(
    "ren_Select",
    kConsoleStartupRenSelectDescription,
    &moho::ren_Select
  );
  TConVar<bool> gTConVar_ren_SelectBoxes(
    "ren_SelectBoxes",
    kConsoleStartupRenSelectBoxesDescription,
    &moho::ren_SelectBoxes
  );
  TConVar<float> gTConVar_ren_SelectBracketMinPixelSize(
    "ren_SelectBracketMinPixelSize",
    kConsoleStartupRenSelectBracketMinPixelSizeDescription,
    &moho::ren_SelectBracketMinPixelSize
  );
  TConVar<float> gTConVar_ren_SelectBracketSize(
    "ren_SelectBracketSize",
    kConsoleStartupRenSelectBracketSizeDescription,
    &moho::ren_SelectBracketSize
  );
  TConVar<unsigned int> gTConVar_ren_SelectColor(
    "ren_SelectColor",
    kConsoleStartupRenSelectColorDescription,
    &moho::ren_SelectColor
  );
  TConVar<float> gTConVar_ren_SelectionHeightFudge(
    "ren_SelectionHeightFudge",
    kConsoleStartupRenSelectionHeightFudgeDescription,
    &moho::ren_SelectionHeightFudge
  );
  TConVar<float> gTConVar_ren_SelectionSizeFudge(
    "ren_SelectionSizeFudge",
    kConsoleStartupRenSelectionSizeFudgeDescription,
    &moho::ren_SelectionSizeFudge
  );
  TConVar<bool> gTConVar_ren_ShadowBlur(
    "ren_ShadowBlur",
    kConsoleStartupRenShadowBlurDescription,
    &moho::ren_ShadowBlur
  );
  TConVar<float> gTConVar_ren_ShadowCoeff(
    "ren_ShadowCoeff",
    kConsoleStartupRenShadowCoeffDescription,
    &moho::ren_ShadowCoeff
  );
  TConVar<float> gTConVar_ren_ShadowLOD(
    "ren_ShadowLOD",
    kConsoleStartupRenShadowLODDescription,
    &moho::ren_ShadowLOD
  );
  TConVar<int> gTConVar_ren_ShadowSize(
    "ren_ShadowSize",
    kConsoleStartupRenShadowSizeDescription,
    &moho::ren_ShadowSize
  );
  TConVar<bool> gTConVar_ren_Shadows(
    "ren_Shadows",
    kConsoleStartupRenShadowsDescription,
    &moho::ren_Shadows
  );
  TConVar<float> gTConVar_ren_ShoreErrorCoeff(
    "ren_ShoreErrorCoeff",
    kConsoleStartupRenShoreErrorCoeffDescription,
    &moho::ren_ShoreErrorCoeff
  );
  TConVar<bool> gTConVar_ren_Shoreline(
    "ren_Shoreline",
    kConsoleStartupRenShorelineDescription,
    &moho::ren_Shoreline
  );
  TConVar<float> gTConVar_ren_ShorelineCutoff(
    "ren_ShorelineCutoff",
    kConsoleStartupRenShorelineCutoffDescription,
    &moho::ren_ShorelineCutoff
  );
  TConVar<bool> gTConVar_ren_ShowBandwidthUsage(
    "ren_ShowBandwidthUsage",
    kConsoleStartupRenShowBandwidthUsageDescription,
    &moho::ren_ShowBandwidthUsage
  );
  TConVar<bool> gTConVar_ren_ShowBoneNames(
    "ren_ShowBoneNames",
    kConsoleStartupRenShowBoneNamesDescription,
    &moho::ren_ShowBoneNames
  );
  TConVar<bool> gTConVar_ren_ShowDirtyTerrain(
    "ren_ShowDirtyTerrain",
    kConsoleStartupRenShowDirtyTerrainDescription,
    &moho::ren_ShowDirtyTerrain
  );
  TConVar<bool> gTConVar_ren_ShowFrameTimes(
    "ren_ShowFrameTimes",
    kConsoleStartupRenShowFrameTimesDescription,
    &moho::ren_ShowFrameTimes
  );
  TConVar<bool> gTConVar_ren_ShowNetworkStats(
    "ren_ShowNetworkStats",
    kConsoleStartupRenShowNetworkStatsDescription,
    &moho::ren_ShowNetworkStats
  );
  TConVar<bool> gTConVar_ren_ShowNormals(
    "ren_ShowNormals",
    kConsoleStartupRenShowNormalsDescription,
    &moho::ren_ShowNormals
  );
  TConVar<bool> gTConVar_ren_ShowWireframe(
    "ren_ShowWireframe",
    kConsoleStartupRenShowWireframeDescription,
    &moho::ren_ShowWireframe
  );
  TConVar<bool> gTConVar_ren_Skirt(
    "ren_Skirt",
    kConsoleStartupRenSkirtDescription,
    &moho::ren_Skirt
  );
  TConVar<bool> gTConVar_ren_SkyDome(
    "ren_SkyDome",
    kConsoleStartupRenSkyDomeDescription,
    &moho::ren_SkyDome
  );
  TConVar<bool> gTConVar_ren_Splats(
    "ren_Splats",
    kConsoleStartupRenSplatsDescription,
    &moho::ren_Splats
  );
  TConVar<float> gTConVar_ren_SyncTerrainLOD(
    "ren_SyncTerrainLOD",
    kConsoleStartupRenSyncTerrainLODDescription,
    &moho::ren_SyncTerrainLOD
  );
  TConVar<bool> gTConVar_ren_TTerrainGlow(
    "ren_TTerrainGlow",
    kConsoleStartupRenTTerrainGlowDescription,
    &moho::ren_TTerrainGlow
  );
  TConVar<int> gTConVar_ren_TeamColorLookupCount(
    "ren_TeamColorLookupCount",
    kConsoleStartupRenTeamColorLookupCountDescription,
    &moho::ren_TeamColorLookupCount
  );
  TConVar<bool> gTConVar_ren_Terrain(
    "ren_Terrain",
    kConsoleStartupRenTerrainDescription,
    &moho::ren_Terrain
  );
  TConVar<bool> gTConVar_ren_Trees(
    "ren_Trees",
    kConsoleStartupRenTreesDescription,
    &moho::ren_Trees
  );
  TConVar<bool> gTConVar_ren_Ui(
    "ren_Ui",
    kConsoleStartupRenUiDescription,
    &moho::ren_Ui
  );
  TConVar<float> gTConVar_ren_UnitSelectionScale(
    "ren_UnitSelectionScale",
    kConsoleStartupRenUnitSelectionScaleDescription,
    &moho::ren_UnitSelectionScale
  );
  TConVar<bool> gTConVar_ren_UnitSilhouette(
    "ren_UnitSilhouette",
    kConsoleStartupRenUnitSilhouetteDescription,
    &moho::ren_UnitSilhouette
  );
  TConVar<float> gTConVar_ren_ViewError(
    "ren_ViewError",
    kConsoleStartupRenViewErrorDescription,
    &moho::ren_ViewError
  );
  TConVar<bool> gTConVar_ren_Water(
    "ren_Water",
    kConsoleStartupRenWaterDescription,
    &moho::ren_Water
  );
  TConVar<bool> gTConVar_ren_WorldBorder(
    "ren_WorldBorder",
    kConsoleStartupRenWorldBorderDescription,
    &moho::ren_WorldBorder
  );
  TConVar<bool> gTConVar_ren_bicubicnormals(
    "ren_bicubicnormals",
    kConsoleStartupRenBicubicnormalsDescription,
    &moho::ren_bicubicnormals
  );
  TConVar<bool> gTConVar_ren_fog(
    "ren_fog",
    kConsoleStartupRenFogDescription,
    &moho::ren_fog
  );
  TConVar<bool> gTConVar_ren_glowingDecals(
    "ren_glowingDecals",
    kConsoleStartupRenGlowingDecalsDescription,
    &moho::ren_glowingDecals
  );

  /**
   * Address: 0x00C040E0 (FUN_00C040E0, ??1TConVar_ren_BandwidthDisplayKernel@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BandwidthDisplayKernel`.
   */
  void cleanup_TConVar_ren_BandwidthDisplayKernel()
  {
    CleanupStartupConCommand(gTConVar_ren_BandwidthDisplayKernel);
  }

  /**
   * Address: 0x00BE0D40 (FUN_00BE0D40, register_TConVar_ren_BandwidthDisplayKernel)
   *
   * What it does:
   * Registers startup convar for `ren_BandwidthDisplayKernel`.
   */
  void register_TConVar_ren_BandwidthDisplayKernel()
  {
    RegisterStartupConVar(gTConVar_ren_BandwidthDisplayKernel, &cleanup_TConVar_ren_BandwidthDisplayKernel);
  }

  /**
   * Address: 0x00C040B0 (FUN_00C040B0, ??1TConVar_ren_BandwidthDisplaySeconds@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BandwidthDisplaySeconds`.
   */
  void cleanup_TConVar_ren_BandwidthDisplaySeconds()
  {
    CleanupStartupConCommand(gTConVar_ren_BandwidthDisplaySeconds);
  }

  /**
   * Address: 0x00BE0D00 (FUN_00BE0D00, register_TConVar_ren_BandwidthDisplaySeconds)
   *
   * What it does:
   * Registers startup convar for `ren_BandwidthDisplaySeconds`.
   */
  void register_TConVar_ren_BandwidthDisplaySeconds()
  {
    RegisterStartupConVar(gTConVar_ren_BandwidthDisplaySeconds, &cleanup_TConVar_ren_BandwidthDisplaySeconds);
  }

  /**
   * Address: 0x00C07960 (FUN_00C07960, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BgLowerBound`.
   */
  void cleanup_TConVar_ren_BgLowerBound()
  {
    CleanupStartupConCommand(gTConVar_ren_BgLowerBound);
  }

  /**
   * Address: 0x00BE68E0 (FUN_00BE68E0, register_TConVar_ren_BgLowerBound)
   *
   * What it does:
   * Registers startup convar for `ren_BgLowerBound`.
   */
  void register_TConVar_ren_BgLowerBound()
  {
    RegisterStartupConVar(gTConVar_ren_BgLowerBound, &cleanup_TConVar_ren_BgLowerBound);
  }

  /**
   * Address: 0x00C04750 (FUN_00C04750, ??1TConVar_ren_Bloom@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Bloom`.
   */
  void cleanup_TConVar_ren_Bloom()
  {
    CleanupStartupConCommand(gTConVar_ren_Bloom);
  }

  /**
   * Address: 0x00BE1710 (FUN_00BE1710, register_TConVar_ren_Bloom)
   *
   * What it does:
   * Registers startup convar for `ren_Bloom`.
   */
  void register_TConVar_ren_Bloom()
  {
    RegisterStartupConVar(gTConVar_ren_Bloom, &cleanup_TConVar_ren_Bloom);
  }

  /**
   * Address: 0x00C04130 (FUN_00C04130, ??1TConVar_ren_BloomBlurCount@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BloomBlurCount`.
   */
  void cleanup_TConVar_ren_BloomBlurCount()
  {
    CleanupStartupConCommand(gTConVar_ren_BloomBlurCount);
  }

  /**
   * Address: 0x00BE0E00 (FUN_00BE0E00, register_TConVar_ren_BloomBlurCount)
   *
   * What it does:
   * Registers startup convar for `ren_BloomBlurCount`.
   */
  void register_TConVar_ren_BloomBlurCount()
  {
    RegisterStartupConVar(gTConVar_ren_BloomBlurCount, &cleanup_TConVar_ren_BloomBlurCount);
  }

  /**
   * Address: 0x00C04300 (FUN_00C04300, ??1TConVar_ren_BloomBlurKernelScale@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BloomBlurKernelScale`.
   */
  void cleanup_TConVar_ren_BloomBlurKernelScale()
  {
    CleanupStartupConCommand(gTConVar_ren_BloomBlurKernelScale);
  }

  /**
   * Address: 0x00BE1040 (FUN_00BE1040, register_TConVar_ren_BloomBlurKernelScale)
   *
   * What it does:
   * Registers startup convar for `ren_BloomBlurKernelScale`.
   */
  void register_TConVar_ren_BloomBlurKernelScale()
  {
    RegisterStartupConVar(gTConVar_ren_BloomBlurKernelScale, &cleanup_TConVar_ren_BloomBlurKernelScale);
  }

  /**
   * Address: 0x00C04330 (FUN_00C04330, ??1TConVar_ren_BloomGlowCopyScale@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BloomGlowCopyScale`.
   */
  void cleanup_TConVar_ren_BloomGlowCopyScale()
  {
    CleanupStartupConCommand(gTConVar_ren_BloomGlowCopyScale);
  }

  /**
   * Address: 0x00BE1080 (FUN_00BE1080, register_TConVar_ren_BloomGlowCopyScale)
   *
   * What it does:
   * Registers startup convar for `ren_BloomGlowCopyScale`.
   */
  void register_TConVar_ren_BloomGlowCopyScale()
  {
    RegisterStartupConVar(gTConVar_ren_BloomGlowCopyScale, &cleanup_TConVar_ren_BloomGlowCopyScale);
  }

  /**
   * Address: 0x00C05A00 (FUN_00C05A00, ??1TConVar_ren_BorderSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_BorderSize`.
   */
  void cleanup_TConVar_ren_BorderSize()
  {
    CleanupStartupConCommand(gTConVar_ren_BorderSize);
  }

  /**
   * Address: 0x00BE31D0 (FUN_00BE31D0, register_TConVar_ren_BorderSize)
   *
   * What it does:
   * Registers startup convar for `ren_BorderSize`.
   */
  void register_TConVar_ren_BorderSize()
  {
    RegisterStartupConVar(gTConVar_ren_BorderSize, &cleanup_TConVar_ren_BorderSize);
  }

  /**
   * Address: 0x00C059D0 (FUN_00C059D0, ??1TConVar_ren_ClipDecalLevel@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ClipDecalLevel`.
   */
  void cleanup_TConVar_ren_ClipDecalLevel()
  {
    CleanupStartupConCommand(gTConVar_ren_ClipDecalLevel);
  }

  /**
   * Address: 0x00BE3190 (FUN_00BE3190, register_TConVar_ren_ClipDecalLevel)
   *
   * What it does:
   * Registers startup convar for `ren_ClipDecalLevel`.
   */
  void register_TConVar_ren_ClipDecalLevel()
  {
    RegisterStartupConVar(gTConVar_ren_ClipDecalLevel, &cleanup_TConVar_ren_ClipDecalLevel);
  }

  /**
   * Address: 0x00C059A0 (FUN_00C059A0, ??1TConVar_ren_ClipDecals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ClipDecals`.
   */
  void cleanup_TConVar_ren_ClipDecals()
  {
    CleanupStartupConCommand(gTConVar_ren_ClipDecals);
  }

  /**
   * Address: 0x00BE3150 (FUN_00BE3150, register_TConVar_ren_ClipDecals)
   *
   * What it does:
   * Registers startup convar for `ren_ClipDecals`.
   */
  void register_TConVar_ren_ClipDecals()
  {
    RegisterStartupConVar(gTConVar_ren_ClipDecals, &cleanup_TConVar_ren_ClipDecals);
  }

  /**
   * Address: 0x00C04810 (FUN_00C04810, ??1TConVar_ren_Clutter@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Clutter`.
   */
  void cleanup_TConVar_ren_Clutter()
  {
    CleanupStartupConCommand(gTConVar_ren_Clutter);
  }

  /**
   * Address: 0x00BE1810 (FUN_00BE1810, register_TConVar_ren_Clutter)
   *
   * What it does:
   * Registers startup convar for `ren_Clutter`.
   */
  void register_TConVar_ren_Clutter()
  {
    RegisterStartupConVar(gTConVar_ren_Clutter, &cleanup_TConVar_ren_Clutter);
  }

  /**
   * Address: 0x00C03AC0 (FUN_00C03AC0, ??1TConVar_ren_ClutterRadius@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ClutterRadius`.
   */
  void cleanup_TConVar_ren_ClutterRadius()
  {
    CleanupStartupConCommand(gTConVar_ren_ClutterRadius);
  }

  /**
   * Address: 0x00BE0200 (FUN_00BE0200, register_TConVar_ren_ClutterRadius)
   *
   * What it does:
   * Registers startup convar for `ren_ClutterRadius`.
   */
  void register_TConVar_ren_ClutterRadius()
  {
    RegisterStartupConVar(gTConVar_ren_ClutterRadius, &cleanup_TConVar_ren_ClutterRadius);
  }

  /**
   * Address: 0x00C083C0 (FUN_00C083C0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalAlbedoLodCutoff`.
   */
  void cleanup_TConVar_ren_DecalAlbedoLodCutoff()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalAlbedoLodCutoff);
  }

  /**
   * Address: 0x00BE7A40 (FUN_00BE7A40, register_TConVar_ren_DecalAlbedoLodCutoff)
   *
   * What it does:
   * Registers startup convar for `ren_DecalAlbedoLodCutoff`.
   */
  void register_TConVar_ren_DecalAlbedoLodCutoff()
  {
    RegisterStartupConVar(gTConVar_ren_DecalAlbedoLodCutoff, &cleanup_TConVar_ren_DecalAlbedoLodCutoff);
  }

  /**
   * Address: 0x00C083F0 (FUN_00C083F0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalFadeFraction`.
   */
  void cleanup_TConVar_ren_DecalFadeFraction()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalFadeFraction);
  }

  /**
   * Address: 0x00BE7A80 (FUN_00BE7A80, register_TConVar_ren_DecalFadeFraction)
   *
   * What it does:
   * Registers startup convar for `ren_DecalFadeFraction`.
   */
  void register_TConVar_ren_DecalFadeFraction()
  {
    RegisterStartupConVar(gTConVar_ren_DecalFadeFraction, &cleanup_TConVar_ren_DecalFadeFraction);
  }

  /**
   * Address: 0x00C05180 (FUN_00C05180, ??1TConVar_ren_DecalFidelity@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalFidelity`.
   */
  void cleanup_TConVar_ren_DecalFidelity()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalFidelity);
  }

  /**
   * Address: 0x00BE2550 (FUN_00BE2550, register_TConVar_ren_DecalFidelity)
   *
   * What it does:
   * Registers startup convar for `ren_DecalFidelity`.
   */
  void register_TConVar_ren_DecalFidelity()
  {
    RegisterStartupConVar(gTConVar_ren_DecalFidelity, &cleanup_TConVar_ren_DecalFidelity);
  }

  /**
   * Address: 0x00C08420 (FUN_00C08420, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalFlatTol`.
   */
  void cleanup_TConVar_ren_DecalFlatTol()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalFlatTol);
  }

  /**
   * Address: 0x00BE7AC0 (FUN_00BE7AC0, register_TConVar_ren_DecalFlatTol)
   *
   * What it does:
   * Registers startup convar for `ren_DecalFlatTol`.
   */
  void register_TConVar_ren_DecalFlatTol()
  {
    RegisterStartupConVar(gTConVar_ren_DecalFlatTol, &cleanup_TConVar_ren_DecalFlatTol);
  }

  /**
   * Address: 0x00C08390 (FUN_00C08390, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalNormalLodCutoff`.
   */
  void cleanup_TConVar_ren_DecalNormalLodCutoff()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalNormalLodCutoff);
  }

  /**
   * Address: 0x00BE7A00 (FUN_00BE7A00, register_TConVar_ren_DecalNormalLodCutoff)
   *
   * What it does:
   * Registers startup convar for `ren_DecalNormalLodCutoff`.
   */
  void register_TConVar_ren_DecalNormalLodCutoff()
  {
    RegisterStartupConVar(gTConVar_ren_DecalNormalLodCutoff, &cleanup_TConVar_ren_DecalNormalLodCutoff);
  }

  /**
   * Address: 0x00C05090 (FUN_00C05090, ??1TConVar_ren_DecalOverDraw@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_DecalOverDraw`.
   */
  void cleanup_TConVar_ren_DecalOverDraw()
  {
    CleanupStartupConCommand(gTConVar_ren_DecalOverDraw);
  }

  /**
   * Address: 0x00BE2410 (FUN_00BE2410, register_TConVar_ren_DecalOverDraw)
   *
   * What it does:
   * Registers startup convar for `ren_DecalOverDraw`.
   */
  void register_TConVar_ren_DecalOverDraw()
  {
    RegisterStartupConVar(gTConVar_ren_DecalOverDraw, &cleanup_TConVar_ren_DecalOverDraw);
  }

  /**
   * Address: 0x00C04F70 (FUN_00C04F70, ??1TConVar_ren_Decals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Decals`.
   */
  void cleanup_TConVar_ren_Decals()
  {
    CleanupStartupConCommand(gTConVar_ren_Decals);
  }

  /**
   * Address: 0x00BE2290 (FUN_00BE2290, register_TConVar_ren_Decals)
   *
   * What it does:
   * Registers startup convar for `ren_Decals`.
   */
  void register_TConVar_ren_Decals()
  {
    RegisterStartupConVar(gTConVar_ren_Decals, &cleanup_TConVar_ren_Decals);
  }

  /**
   * Address: 0x00C05A60 (FUN_00C05A60, ??1TConVar_ren_ErrorCache@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ErrorCache`.
   */
  void cleanup_TConVar_ren_ErrorCache()
  {
    CleanupStartupConCommand(gTConVar_ren_ErrorCache);
  }

  /**
   * Address: 0x00BE3250 (FUN_00BE3250, register_TConVar_ren_ErrorCache)
   *
   * What it does:
   * Registers startup convar for `ren_ErrorCache`.
   */
  void register_TConVar_ren_ErrorCache()
  {
    RegisterStartupConVar(gTConVar_ren_ErrorCache, &cleanup_TConVar_ren_ErrorCache);
  }

  /**
   * Address: 0x00C08640 (FUN_00C08640, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_FogIntensity`.
   */
  void cleanup_TConVar_ren_FogIntensity()
  {
    CleanupStartupConCommand(gTConVar_ren_FogIntensity);
  }

  /**
   * Address: 0x00BE8120 (FUN_00BE8120, register_TConVar_ren_FogIntensity)
   *
   * What it does:
   * Registers startup convar for `ren_FogIntensity`.
   */
  void register_TConVar_ren_FogIntensity()
  {
    RegisterStartupConVar(gTConVar_ren_FogIntensity, &cleanup_TConVar_ren_FogIntensity);
  }

  /**
   * Address: 0x00C04F10 (FUN_00C04F10, ??1TConVar_ren_FogOfWar@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_FogOfWar`.
   */
  void cleanup_TConVar_ren_FogOfWar()
  {
    CleanupStartupConCommand(gTConVar_ren_FogOfWar);
  }

  /**
   * Address: 0x00BE2210 (FUN_00BE2210, register_TConVar_ren_FogOfWar)
   *
   * What it does:
   * Registers startup convar for `ren_FogOfWar`.
   */
  void register_TConVar_ren_FogOfWar()
  {
    RegisterStartupConVar(gTConVar_ren_FogOfWar, &cleanup_TConVar_ren_FogOfWar);
  }

  /**
   * Address: 0x00C050C0 (FUN_00C050C0, ??1TConVar_ren_ForceUpdateMinimapTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ForceUpdateMinimapTerrain`.
   */
  void cleanup_TConVar_ren_ForceUpdateMinimapTerrain()
  {
    CleanupStartupConCommand(gTConVar_ren_ForceUpdateMinimapTerrain);
  }

  /**
   * Address: 0x00BE2450 (FUN_00BE2450, register_TConVar_ren_ForceUpdateMinimapTerrain)
   *
   * What it does:
   * Registers startup convar for `ren_ForceUpdateMinimapTerrain`.
   */
  void register_TConVar_ren_ForceUpdateMinimapTerrain()
  {
    RegisterStartupConVar(gTConVar_ren_ForceUpdateMinimapTerrain, &cleanup_TConVar_ren_ForceUpdateMinimapTerrain);
  }

  /**
   * Address: 0x00C049F0 (FUN_00C049F0, ??1TConVar_ren_FrameTimeSeconds@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_FrameTimeSeconds`.
   */
  void cleanup_TConVar_ren_FrameTimeSeconds()
  {
    CleanupStartupConCommand(gTConVar_ren_FrameTimeSeconds);
  }

  /**
   * Address: 0x00BE1A90 (FUN_00BE1A90, register_TConVar_ren_FrameTimeSeconds)
   *
   * What it does:
   * Registers startup convar for `ren_FrameTimeSeconds`.
   */
  void register_TConVar_ren_FrameTimeSeconds()
  {
    RegisterStartupConVar(gTConVar_ren_FrameTimeSeconds, &cleanup_TConVar_ren_FrameTimeSeconds);
  }

  /**
   * Address: 0x00C045A0 (FUN_00C045A0, ??1TConVar_ren_Fx@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Fx`.
   */
  void cleanup_TConVar_ren_Fx()
  {
    CleanupStartupConCommand(gTConVar_ren_Fx);
  }

  /**
   * Address: 0x00BE14D0 (FUN_00BE14D0, register_TConVar_ren_Fx)
   *
   * What it does:
   * Registers startup convar for `ren_Fx`.
   */
  void register_TConVar_ren_Fx()
  {
    RegisterStartupConVar(gTConVar_ren_Fx, &cleanup_TConVar_ren_Fx);
  }

  /**
   * Address: 0x00C05000 (FUN_00C05000, ??1TConVar_ren_GenerateMesh@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_GenerateMesh`.
   */
  void cleanup_TConVar_ren_GenerateMesh()
  {
    CleanupStartupConCommand(gTConVar_ren_GenerateMesh);
  }

  /**
   * Address: 0x00BE2350 (FUN_00BE2350, register_TConVar_ren_GenerateMesh)
   *
   * What it does:
   * Registers startup convar for `ren_GenerateMesh`.
   */
  void register_TConVar_ren_GenerateMesh()
  {
    RegisterStartupConVar(gTConVar_ren_GenerateMesh, &cleanup_TConVar_ren_GenerateMesh);
  }

  /**
   * Address: 0x00C04900 (FUN_00C04900, ??1TConVar_ren_HideSecondary@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_HideSecondary`.
   */
  void cleanup_TConVar_ren_HideSecondary()
  {
    CleanupStartupConCommand(gTConVar_ren_HideSecondary);
  }

  /**
   * Address: 0x00BE1950 (FUN_00BE1950, register_TConVar_ren_HideSecondary)
   *
   * What it does:
   * Registers startup convar for `ren_HideSecondary`.
   */
  void register_TConVar_ren_HideSecondary()
  {
    RegisterStartupConVar(gTConVar_ren_HideSecondary, &cleanup_TConVar_ren_HideSecondary);
  }

  /**
   * Address: 0x00C05030 (FUN_00C05030, ??1TConVar_ren_IgnoreDecalLOD@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_IgnoreDecalLOD`.
   */
  void cleanup_TConVar_ren_IgnoreDecalLOD()
  {
    CleanupStartupConCommand(gTConVar_ren_IgnoreDecalLOD);
  }

  /**
   * Address: 0x00BE2390 (FUN_00BE2390, register_TConVar_ren_IgnoreDecalLOD)
   *
   * What it does:
   * Registers startup convar for `ren_IgnoreDecalLOD`.
   */
  void register_TConVar_ren_IgnoreDecalLOD()
  {
    RegisterStartupConVar(gTConVar_ren_IgnoreDecalLOD, &cleanup_TConVar_ren_IgnoreDecalLOD);
  }

  /**
   * Address: 0x00C03B90 (FUN_00C03B90, ??1TConVar_ren_MeshDissolve@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_MeshDissolve`.
   */
  void cleanup_TConVar_ren_MeshDissolve()
  {
    CleanupStartupConCommand(gTConVar_ren_MeshDissolve);
  }

  /**
   * Address: 0x00BE03A0 (FUN_00BE03A0, register_TConVar_ren_MeshDissolve)
   *
   * What it does:
   * Registers startup convar for `ren_MeshDissolve`.
   */
  void register_TConVar_ren_MeshDissolve()
  {
    RegisterStartupConVar(gTConVar_ren_MeshDissolve, &cleanup_TConVar_ren_MeshDissolve);
  }

  /**
   * Address: 0x00C03BC0 (FUN_00C03BC0, ??1TConVar_ren_MeshDissolveCutoff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_MeshDissolveCutoff`.
   */
  void cleanup_TConVar_ren_MeshDissolveCutoff()
  {
    CleanupStartupConCommand(gTConVar_ren_MeshDissolveCutoff);
  }

  /**
   * Address: 0x00BE03E0 (FUN_00BE03E0, register_TConVar_ren_MeshDissolveCutoff)
   *
   * What it does:
   * Registers startup convar for `ren_MeshDissolveCutoff`.
   */
  void register_TConVar_ren_MeshDissolveCutoff()
  {
    RegisterStartupConVar(gTConVar_ren_MeshDissolveCutoff, &cleanup_TConVar_ren_MeshDissolveCutoff);
  }

  /**
   * Address: 0x00C03B30 (FUN_00C03B30, ??1TConVar_ren_MeshSkinned@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_MeshSkinned`.
   */
  void cleanup_TConVar_ren_MeshSkinned()
  {
    CleanupStartupConCommand(gTConVar_ren_MeshSkinned);
  }

  /**
   * Address: 0x00BE0320 (FUN_00BE0320, register_TConVar_ren_MeshSkinned)
   *
   * What it does:
   * Registers startup convar for `ren_MeshSkinned`.
   */
  void register_TConVar_ren_MeshSkinned()
  {
    RegisterStartupConVar(gTConVar_ren_MeshSkinned, &cleanup_TConVar_ren_MeshSkinned);
  }

  /**
   * Address: 0x00C03B60 (FUN_00C03B60, ??1TConVar_ren_MeshStatic@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_MeshStatic`.
   */
  void cleanup_TConVar_ren_MeshStatic()
  {
    CleanupStartupConCommand(gTConVar_ren_MeshStatic);
  }

  /**
   * Address: 0x00BE0360 (FUN_00BE0360, register_TConVar_ren_MeshStatic)
   *
   * What it does:
   * Registers startup convar for `ren_MeshStatic`.
   */
  void register_TConVar_ren_MeshStatic()
  {
    RegisterStartupConVar(gTConVar_ren_MeshStatic, &cleanup_TConVar_ren_MeshStatic);
  }

  /**
   * Address: 0x00C05120 (FUN_00C05120, ??1TConVar_ren_NewFogUpdate@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_NewFogUpdate`.
   */
  void cleanup_TConVar_ren_NewFogUpdate()
  {
    CleanupStartupConCommand(gTConVar_ren_NewFogUpdate);
  }

  /**
   * Address: 0x00BE24D0 (FUN_00BE24D0, register_TConVar_ren_NewFogUpdate)
   *
   * What it does:
   * Registers startup convar for `ren_NewFogUpdate`.
   */
  void register_TConVar_ren_NewFogUpdate()
  {
    RegisterStartupConVar(gTConVar_ren_NewFogUpdate, &cleanup_TConVar_ren_NewFogUpdate);
  }

  /**
   * Address: 0x00C044B0 (FUN_00C044B0, ??1TConVar_ren_NewPipeline@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_NewPipeline`.
   */
  void cleanup_TConVar_ren_NewPipeline()
  {
    CleanupStartupConCommand(gTConVar_ren_NewPipeline);
  }

  /**
   * Address: 0x00BE1390 (FUN_00BE1390, register_TConVar_ren_NewPipeline)
   *
   * What it does:
   * Registers startup convar for `ren_NewPipeline`.
   */
  void register_TConVar_ren_NewPipeline()
  {
    RegisterStartupConVar(gTConVar_ren_NewPipeline, &cleanup_TConVar_ren_NewPipeline);
  }

  /**
   * Address: 0x00C04FA0 (FUN_00C04FA0, ??1TConVar_ren_NormalDecals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_NormalDecals`.
   */
  void cleanup_TConVar_ren_NormalDecals()
  {
    CleanupStartupConCommand(gTConVar_ren_NormalDecals);
  }

  /**
   * Address: 0x00BE22D0 (FUN_00BE22D0, register_TConVar_ren_NormalDecals)
   *
   * What it does:
   * Registers startup convar for `ren_NormalDecals`.
   */
  void register_TConVar_ren_NormalDecals()
  {
    RegisterStartupConVar(gTConVar_ren_NormalDecals, &cleanup_TConVar_ren_NormalDecals);
  }

  /**
   * Address: 0x00C04510 (FUN_00C04510, ??1TConVar_ren_Oblivion@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Oblivion`.
   */
  void cleanup_TConVar_ren_Oblivion()
  {
    CleanupStartupConCommand(gTConVar_ren_Oblivion);
  }

  /**
   * Address: 0x00BE1410 (FUN_00BE1410, register_TConVar_ren_Oblivion)
   *
   * What it does:
   * Registers startup convar for `ren_Oblivion`.
   */
  void register_TConVar_ren_Oblivion()
  {
    RegisterStartupConVar(gTConVar_ren_Oblivion, &cleanup_TConVar_ren_Oblivion);
  }

  /**
   * Address: 0x00C04780 (FUN_00C04780, ??1TConVar_ren_OnlyFirstView@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_OnlyFirstView`.
   */
  void cleanup_TConVar_ren_OnlyFirstView()
  {
    CleanupStartupConCommand(gTConVar_ren_OnlyFirstView);
  }

  /**
   * Address: 0x00BE1750 (FUN_00BE1750, register_TConVar_ren_OnlyFirstView)
   *
   * What it does:
   * Registers startup convar for `ren_OnlyFirstView`.
   */
  void register_TConVar_ren_OnlyFirstView()
  {
    RegisterStartupConVar(gTConVar_ren_OnlyFirstView, &cleanup_TConVar_ren_OnlyFirstView);
  }

  /**
   * Address: 0x00C046C0 (FUN_00C046C0, ??1TConVar_ren_PlayableBoundary@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_PlayableBoundary`.
   */
  void cleanup_TConVar_ren_PlayableBoundary()
  {
    CleanupStartupConCommand(gTConVar_ren_PlayableBoundary);
  }

  /**
   * Address: 0x00BE1650 (FUN_00BE1650, register_TConVar_ren_PlayableBoundary)
   *
   * What it does:
   * Registers startup convar for `ren_PlayableBoundary`.
   */
  void register_TConVar_ren_PlayableBoundary()
  {
    RegisterStartupConVar(gTConVar_ren_PlayableBoundary, &cleanup_TConVar_ren_PlayableBoundary);
  }

  /**
   * Address: 0x00C045D0 (FUN_00C045D0, ??1TConVar_ren_Reflection@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Reflection`.
   */
  void cleanup_TConVar_ren_Reflection()
  {
    CleanupStartupConCommand(gTConVar_ren_Reflection);
  }

  /**
   * Address: 0x00BE1510 (FUN_00BE1510, register_TConVar_ren_Reflection)
   *
   * What it does:
   * Registers startup convar for `ren_Reflection`.
   */
  void register_TConVar_ren_Reflection()
  {
    RegisterStartupConVar(gTConVar_ren_Reflection, &cleanup_TConVar_ren_Reflection);
  }

  /**
   * Address: 0x00C04600 (FUN_00C04600, ??1TConVar_ren_Refraction@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Refraction`.
   */
  void cleanup_TConVar_ren_Refraction()
  {
    CleanupStartupConCommand(gTConVar_ren_Refraction);
  }

  /**
   * Address: 0x00BE1550 (FUN_00BE1550, register_TConVar_ren_Refraction)
   *
   * What it does:
   * Registers startup convar for `ren_Refraction`.
   */
  void register_TConVar_ren_Refraction()
  {
    RegisterStartupConVar(gTConVar_ren_Refraction, &cleanup_TConVar_ren_Refraction);
  }

  /**
   * Address: 0x00C048A0 (FUN_00C048A0, ??1TConVar_ren_RegenShore@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_RegenShore`.
   */
  void cleanup_TConVar_ren_RegenShore()
  {
    CleanupStartupConCommand(gTConVar_ren_RegenShore);
  }

  /**
   * Address: 0x00BE18D0 (FUN_00BE18D0, register_TConVar_ren_RegenShore)
   *
   * What it does:
   * Registers startup convar for `ren_RegenShore`.
   */
  void register_TConVar_ren_RegenShore()
  {
    RegisterStartupConVar(gTConVar_ren_RegenShore, &cleanup_TConVar_ren_RegenShore);
  }

  /**
   * Address: 0x00C044E0 (FUN_00C044E0, ??1TConVar_ren_RenderNothing@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_RenderNothing`.
   */
  void cleanup_TConVar_ren_RenderNothing()
  {
    CleanupStartupConCommand(gTConVar_ren_RenderNothing);
  }

  /**
   * Address: 0x00BE13D0 (FUN_00BE13D0, register_TConVar_ren_RenderNothing)
   *
   * What it does:
   * Registers startup convar for `ren_RenderNothing`.
   */
  void register_TConVar_ren_RenderNothing()
  {
    RegisterStartupConVar(gTConVar_ren_RenderNothing, &cleanup_TConVar_ren_RenderNothing);
  }

  /**
   * Address: 0x00C04630 (FUN_00C04630, ??1TConVar_ren_Select@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Select`.
   */
  void cleanup_TConVar_ren_Select()
  {
    CleanupStartupConCommand(gTConVar_ren_Select);
  }

  /**
   * Address: 0x00BE1590 (FUN_00BE1590, register_TConVar_ren_Select)
   *
   * What it does:
   * Registers startup convar for `ren_Select`.
   */
  void register_TConVar_ren_Select()
  {
    RegisterStartupConVar(gTConVar_ren_Select, &cleanup_TConVar_ren_Select);
  }

  /**
   * Address: 0x00C04C80 (FUN_00C04C80, ??1TConVar_ren_SelectBoxes@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectBoxes`.
   */
  void cleanup_TConVar_ren_SelectBoxes()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectBoxes);
  }

  /**
   * Address: 0x00BE1E40 (FUN_00BE1E40, register_TConVar_ren_SelectBoxes)
   *
   * What it does:
   * Registers startup convar for `ren_SelectBoxes`.
   */
  void register_TConVar_ren_SelectBoxes()
  {
    RegisterStartupConVar(gTConVar_ren_SelectBoxes, &cleanup_TConVar_ren_SelectBoxes);
  }

  /**
   * Address: 0x00C04BF0 (FUN_00C04BF0, ??1TConVar_ren_SelectBracketMinPixelSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectBracketMinPixelSize`.
   */
  void cleanup_TConVar_ren_SelectBracketMinPixelSize()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectBracketMinPixelSize);
  }

  /**
   * Address: 0x00BE1D80 (FUN_00BE1D80, register_TConVar_ren_SelectBracketMinPixelSize)
   *
   * What it does:
   * Registers startup convar for `ren_SelectBracketMinPixelSize`.
   */
  void register_TConVar_ren_SelectBracketMinPixelSize()
  {
    RegisterStartupConVar(gTConVar_ren_SelectBracketMinPixelSize, &cleanup_TConVar_ren_SelectBracketMinPixelSize);
  }

  /**
   * Address: 0x00C04C20 (FUN_00C04C20, ??1TConVar_ren_SelectBracketSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectBracketSize`.
   */
  void cleanup_TConVar_ren_SelectBracketSize()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectBracketSize);
  }

  /**
   * Address: 0x00BE1DC0 (FUN_00BE1DC0, register_TConVar_ren_SelectBracketSize)
   *
   * What it does:
   * Registers startup convar for `ren_SelectBracketSize`.
   */
  void register_TConVar_ren_SelectBracketSize()
  {
    RegisterStartupConVar(gTConVar_ren_SelectBracketSize, &cleanup_TConVar_ren_SelectBracketSize);
  }

  /**
   * Address: 0x00C04C50 (FUN_00C04C50, ??1TConVar_ren_SelectColor@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectColor`.
   */
  void cleanup_TConVar_ren_SelectColor()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectColor);
  }

  /**
   * Address: 0x00BE1E00 (FUN_00BE1E00, register_TConVar_ren_SelectColor)
   *
   * What it does:
   * Registers startup convar for `ren_SelectColor`.
   */
  void register_TConVar_ren_SelectColor()
  {
    RegisterStartupConVar(gTConVar_ren_SelectColor, &cleanup_TConVar_ren_SelectColor);
  }

  /**
   * Address: 0x00C04B90 (FUN_00C04B90, ??1TConVar_ren_SelectionHeightFudge@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectionHeightFudge`.
   */
  void cleanup_TConVar_ren_SelectionHeightFudge()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectionHeightFudge);
  }

  /**
   * Address: 0x00BE1D00 (FUN_00BE1D00, register_TConVar_ren_SelectionHeightFudge)
   *
   * What it does:
   * Registers startup convar for `ren_SelectionHeightFudge`.
   */
  void register_TConVar_ren_SelectionHeightFudge()
  {
    RegisterStartupConVar(gTConVar_ren_SelectionHeightFudge, &cleanup_TConVar_ren_SelectionHeightFudge);
  }

  /**
   * Address: 0x00C04B60 (FUN_00C04B60, ??1TConVar_ren_SelectionSizeFudge@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SelectionSizeFudge`.
   */
  void cleanup_TConVar_ren_SelectionSizeFudge()
  {
    CleanupStartupConCommand(gTConVar_ren_SelectionSizeFudge);
  }

  /**
   * Address: 0x00BE1CC0 (FUN_00BE1CC0, register_TConVar_ren_SelectionSizeFudge)
   *
   * What it does:
   * Registers startup convar for `ren_SelectionSizeFudge`.
   */
  void register_TConVar_ren_SelectionSizeFudge()
  {
    RegisterStartupConVar(gTConVar_ren_SelectionSizeFudge, &cleanup_TConVar_ren_SelectionSizeFudge);
  }

  /**
   * Address: 0x00C04840 (FUN_00C04840, ??1TConVar_ren_ShadowBlur@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShadowBlur`.
   */
  void cleanup_TConVar_ren_ShadowBlur()
  {
    CleanupStartupConCommand(gTConVar_ren_ShadowBlur);
  }

  /**
   * Address: 0x00BE1850 (FUN_00BE1850, register_TConVar_ren_ShadowBlur)
   *
   * What it does:
   * Registers startup convar for `ren_ShadowBlur`.
   */
  void register_TConVar_ren_ShadowBlur()
  {
    RegisterStartupConVar(gTConVar_ren_ShadowBlur, &cleanup_TConVar_ren_ShadowBlur);
  }

  /**
   * Address: 0x00C04D80 (FUN_00C04D80, ??1TConVar_ren_ShadowCoeff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShadowCoeff`.
   */
  void cleanup_TConVar_ren_ShadowCoeff()
  {
    CleanupStartupConCommand(gTConVar_ren_ShadowCoeff);
  }

  /**
   * Address: 0x00BE1FA0 (FUN_00BE1FA0, register_TConVar_ren_ShadowCoeff)
   *
   * What it does:
   * Registers startup convar for `ren_ShadowCoeff`.
   */
  void register_TConVar_ren_ShadowCoeff()
  {
    RegisterStartupConVar(gTConVar_ren_ShadowCoeff, &cleanup_TConVar_ren_ShadowCoeff);
  }

  /**
   * Address: 0x00C04DB0 (FUN_00C04DB0, ??1TConVar_ren_ShadowLOD@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShadowLOD`.
   */
  void cleanup_TConVar_ren_ShadowLOD()
  {
    CleanupStartupConCommand(gTConVar_ren_ShadowLOD);
  }

  /**
   * Address: 0x00BE1FE0 (FUN_00BE1FE0, register_TConVar_ren_ShadowLOD)
   *
   * What it does:
   * Registers startup convar for `ren_ShadowLOD`.
   */
  void register_TConVar_ren_ShadowLOD()
  {
    RegisterStartupConVar(gTConVar_ren_ShadowLOD, &cleanup_TConVar_ren_ShadowLOD);
  }

  /**
   * Address: 0x00C04870 (FUN_00C04870, ??1TConVar_ren_ShadowSize@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShadowSize`.
   */
  void cleanup_TConVar_ren_ShadowSize()
  {
    CleanupStartupConCommand(gTConVar_ren_ShadowSize);
  }

  /**
   * Address: 0x00BE1890 (FUN_00BE1890, register_TConVar_ren_ShadowSize)
   *
   * What it does:
   * Registers startup convar for `ren_ShadowSize`.
   */
  void register_TConVar_ren_ShadowSize()
  {
    RegisterStartupConVar(gTConVar_ren_ShadowSize, &cleanup_TConVar_ren_ShadowSize);
  }

  /**
   * Address: 0x00C047E0 (FUN_00C047E0, ??1TConVar_ren_Shadows@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Shadows`.
   */
  void cleanup_TConVar_ren_Shadows()
  {
    CleanupStartupConCommand(gTConVar_ren_Shadows);
  }

  /**
   * Address: 0x00BE17D0 (FUN_00BE17D0, register_TConVar_ren_Shadows)
   *
   * What it does:
   * Registers startup convar for `ren_Shadows`.
   */
  void register_TConVar_ren_Shadows()
  {
    RegisterStartupConVar(gTConVar_ren_Shadows, &cleanup_TConVar_ren_Shadows);
  }

  /**
   * Address: 0x00C05A30 (FUN_00C05A30, ??1TConVar_ren_ShoreErrorCoeff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShoreErrorCoeff`.
   */
  void cleanup_TConVar_ren_ShoreErrorCoeff()
  {
    CleanupStartupConCommand(gTConVar_ren_ShoreErrorCoeff);
  }

  /**
   * Address: 0x00BE3210 (FUN_00BE3210, register_TConVar_ren_ShoreErrorCoeff)
   *
   * What it does:
   * Registers startup convar for `ren_ShoreErrorCoeff`.
   */
  void register_TConVar_ren_ShoreErrorCoeff()
  {
    RegisterStartupConVar(gTConVar_ren_ShoreErrorCoeff, &cleanup_TConVar_ren_ShoreErrorCoeff);
  }

  /**
   * Address: 0x00C05CF0 (FUN_00C05CF0, ??1TConVar_ren_Shoreline@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Shoreline`.
   */
  void cleanup_TConVar_ren_Shoreline()
  {
    CleanupStartupConCommand(gTConVar_ren_Shoreline);
  }

  /**
   * Address: 0x00BE37B0 (FUN_00BE37B0, register_TConVar_ren_Shoreline)
   *
   * What it does:
   * Registers startup convar for `ren_Shoreline`.
   */
  void register_TConVar_ren_Shoreline()
  {
    RegisterStartupConVar(gTConVar_ren_Shoreline, &cleanup_TConVar_ren_Shoreline);
  }

  /**
   * Address: 0x00C05D20 (FUN_00C05D20, ??1TConVar_ren_ShorelineCutoff@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShorelineCutoff`.
   */
  void cleanup_TConVar_ren_ShorelineCutoff()
  {
    CleanupStartupConCommand(gTConVar_ren_ShorelineCutoff);
  }

  /**
   * Address: 0x00BE37F0 (FUN_00BE37F0, register_TConVar_ren_ShorelineCutoff)
   *
   * What it does:
   * Registers startup convar for `ren_ShorelineCutoff`.
   */
  void register_TConVar_ren_ShorelineCutoff()
  {
    RegisterStartupConVar(gTConVar_ren_ShorelineCutoff, &cleanup_TConVar_ren_ShorelineCutoff);
  }

  /**
   * Address: 0x00C04A50 (FUN_00C04A50, ??1TConVar_ren_ShowBandwidthUsage@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowBandwidthUsage`.
   */
  void cleanup_TConVar_ren_ShowBandwidthUsage()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowBandwidthUsage);
  }

  /**
   * Address: 0x00BE1B10 (FUN_00BE1B10, register_TConVar_ren_ShowBandwidthUsage)
   *
   * What it does:
   * Registers startup convar for `ren_ShowBandwidthUsage`.
   */
  void register_TConVar_ren_ShowBandwidthUsage()
  {
    RegisterStartupConVar(gTConVar_ren_ShowBandwidthUsage, &cleanup_TConVar_ren_ShowBandwidthUsage);
  }

  /**
   * Address: 0x00C048D0 (FUN_00C048D0, ??1TConVar_ren_ShowBoneNames@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowBoneNames`.
   */
  void cleanup_TConVar_ren_ShowBoneNames()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowBoneNames);
  }

  /**
   * Address: 0x00BE1910 (FUN_00BE1910, register_TConVar_ren_ShowBoneNames)
   *
   * What it does:
   * Registers startup convar for `ren_ShowBoneNames`.
   */
  void register_TConVar_ren_ShowBoneNames()
  {
    RegisterStartupConVar(gTConVar_ren_ShowBoneNames, &cleanup_TConVar_ren_ShowBoneNames);
  }

  /**
   * Address: 0x00C04EB0 (FUN_00C04EB0, ??1TConVar_ren_ShowDirtyTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowDirtyTerrain`.
   */
  void cleanup_TConVar_ren_ShowDirtyTerrain()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowDirtyTerrain);
  }

  /**
   * Address: 0x00BE2190 (FUN_00BE2190, register_TConVar_ren_ShowDirtyTerrain)
   *
   * What it does:
   * Registers startup convar for `ren_ShowDirtyTerrain`.
   */
  void register_TConVar_ren_ShowDirtyTerrain()
  {
    RegisterStartupConVar(gTConVar_ren_ShowDirtyTerrain, &cleanup_TConVar_ren_ShowDirtyTerrain);
  }

  /**
   * Address: 0x00C049C0 (FUN_00C049C0, ??1TConVar_ren_ShowFrameTimes@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowFrameTimes`.
   */
  void cleanup_TConVar_ren_ShowFrameTimes()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowFrameTimes);
  }

  /**
   * Address: 0x00BE1A50 (FUN_00BE1A50, register_TConVar_ren_ShowFrameTimes)
   *
   * What it does:
   * Registers startup convar for `ren_ShowFrameTimes`.
   */
  void register_TConVar_ren_ShowFrameTimes()
  {
    RegisterStartupConVar(gTConVar_ren_ShowFrameTimes, &cleanup_TConVar_ren_ShowFrameTimes);
  }

  /**
   * Address: 0x00C04A20 (FUN_00C04A20, ??1TConVar_ren_ShowNetworkStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowNetworkStats`.
   */
  void cleanup_TConVar_ren_ShowNetworkStats()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowNetworkStats);
  }

  /**
   * Address: 0x00BE1AD0 (FUN_00BE1AD0, register_TConVar_ren_ShowNetworkStats)
   *
   * What it does:
   * Registers startup convar for `ren_ShowNetworkStats`.
   */
  void register_TConVar_ren_ShowNetworkStats()
  {
    RegisterStartupConVar(gTConVar_ren_ShowNetworkStats, &cleanup_TConVar_ren_ShowNetworkStats);
  }

  /**
   * Address: 0x00C04E50 (FUN_00C04E50, ??1TConVar_ren_ShowNormals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowNormals`.
   */
  void cleanup_TConVar_ren_ShowNormals()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowNormals);
  }

  /**
   * Address: 0x00BE2110 (FUN_00BE2110, register_TConVar_ren_ShowNormals)
   *
   * What it does:
   * Registers startup convar for `ren_ShowNormals`.
   */
  void register_TConVar_ren_ShowNormals()
  {
    RegisterStartupConVar(gTConVar_ren_ShowNormals, &cleanup_TConVar_ren_ShowNormals);
  }

  /**
   * Address: 0x00C04660 (FUN_00C04660, ??1TConVar_ren_ShowWireframe@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShowWireframe`.
   */
  void cleanup_TConVar_ren_ShowWireframe()
  {
    CleanupStartupConCommand(gTConVar_ren_ShowWireframe);
  }

  /**
   * Address: 0x00BE15D0 (FUN_00BE15D0, register_TConVar_ren_ShowWireframe)
   *
   * What it does:
   * Registers startup convar for `ren_ShowWireframe`.
   */
  void register_TConVar_ren_ShowWireframe()
  {
    RegisterStartupConVar(gTConVar_ren_ShowWireframe, &cleanup_TConVar_ren_ShowWireframe);
  }

  /**
   * Address: 0x00C05150 (FUN_00C05150, ??1TConVar_ren_Skirt@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Skirt`.
   */
  void cleanup_TConVar_ren_Skirt()
  {
    CleanupStartupConCommand(gTConVar_ren_Skirt);
  }

  /**
   * Address: 0x00BE2510 (FUN_00BE2510, register_TConVar_ren_Skirt)
   *
   * What it does:
   * Registers startup convar for `ren_Skirt`.
   */
  void register_TConVar_ren_Skirt()
  {
    RegisterStartupConVar(gTConVar_ren_Skirt, &cleanup_TConVar_ren_Skirt);
  }

  /**
   * Address: 0x00C047B0 (FUN_00C047B0, ??1TConVar_ren_SkyDome@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SkyDome`.
   */
  void cleanup_TConVar_ren_SkyDome()
  {
    CleanupStartupConCommand(gTConVar_ren_SkyDome);
  }

  /**
   * Address: 0x00BE1790 (FUN_00BE1790, register_TConVar_ren_SkyDome)
   *
   * What it does:
   * Registers startup convar for `ren_SkyDome`.
   */
  void register_TConVar_ren_SkyDome()
  {
    RegisterStartupConVar(gTConVar_ren_SkyDome, &cleanup_TConVar_ren_SkyDome);
  }

  /**
   * Address: 0x00C04FD0 (FUN_00C04FD0, ??1TConVar_ren_Splats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Splats`.
   */
  void cleanup_TConVar_ren_Splats()
  {
    CleanupStartupConCommand(gTConVar_ren_Splats);
  }

  /**
   * Address: 0x00BE2310 (FUN_00BE2310, register_TConVar_ren_Splats)
   *
   * What it does:
   * Registers startup convar for `ren_Splats`.
   */
  void register_TConVar_ren_Splats()
  {
    RegisterStartupConVar(gTConVar_ren_Splats, &cleanup_TConVar_ren_Splats);
  }

  /**
   * Address: 0x00C084D0 (FUN_00C084D0, ??1TConVar_ren_SyncTerrainLOD@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_SyncTerrainLOD`.
   */
  void cleanup_TConVar_ren_SyncTerrainLOD()
  {
    CleanupStartupConCommand(gTConVar_ren_SyncTerrainLOD);
  }

  /**
   * Address: 0x00BE7D90 (FUN_00BE7D90, register_TConVar_ren_SyncTerrainLOD)
   *
   * What it does:
   * Registers startup convar for `ren_SyncTerrainLOD`.
   */
  void register_TConVar_ren_SyncTerrainLOD()
  {
    RegisterStartupConVar(gTConVar_ren_SyncTerrainLOD, &cleanup_TConVar_ren_SyncTerrainLOD);
  }

  /**
   * Address: 0x00C050F0 (FUN_00C050F0, ??1TConVar_ren_TTerrainGlow@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_TTerrainGlow`.
   */
  void cleanup_TConVar_ren_TTerrainGlow()
  {
    CleanupStartupConCommand(gTConVar_ren_TTerrainGlow);
  }

  /**
   * Address: 0x00BE2490 (FUN_00BE2490, register_TConVar_ren_TTerrainGlow)
   *
   * What it does:
   * Registers startup convar for `ren_TTerrainGlow`.
   */
  void register_TConVar_ren_TTerrainGlow()
  {
    RegisterStartupConVar(gTConVar_ren_TTerrainGlow, &cleanup_TConVar_ren_TTerrainGlow);
  }

  /**
   * Address: 0x00C08750 (FUN_00C08750, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_TeamColorLookupCount`.
   */
  void cleanup_TConVar_ren_TeamColorLookupCount()
  {
    CleanupStartupConCommand(gTConVar_ren_TeamColorLookupCount);
  }

  /**
   * Address: 0x00BE86E0 (FUN_00BE86E0, register_TConVar_ren_TeamColorLookupCount)
   *
   * What it does:
   * Registers startup convar for `ren_TeamColorLookupCount`.
   */
  void register_TConVar_ren_TeamColorLookupCount()
  {
    RegisterStartupConVar(gTConVar_ren_TeamColorLookupCount, &cleanup_TConVar_ren_TeamColorLookupCount);
  }

  /**
   * Address: 0x00C04E80 (FUN_00C04E80, ??1TConVar_ren_Terrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Terrain`.
   */
  void cleanup_TConVar_ren_Terrain()
  {
    CleanupStartupConCommand(gTConVar_ren_Terrain);
  }

  /**
   * Address: 0x00BE2150 (FUN_00BE2150, register_TConVar_ren_Terrain)
   *
   * What it does:
   * Registers startup convar for `ren_Terrain`.
   */
  void register_TConVar_ren_Terrain()
  {
    RegisterStartupConVar(gTConVar_ren_Terrain, &cleanup_TConVar_ren_Terrain);
  }

  /**
   * Address: 0x00C04EE0 (FUN_00C04EE0, ??1TConVar_ren_Trees@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Trees`.
   */
  void cleanup_TConVar_ren_Trees()
  {
    CleanupStartupConCommand(gTConVar_ren_Trees);
  }

  /**
   * Address: 0x00BE21D0 (FUN_00BE21D0, register_TConVar_ren_Trees)
   *
   * What it does:
   * Registers startup convar for `ren_Trees`.
   */
  void register_TConVar_ren_Trees()
  {
    RegisterStartupConVar(gTConVar_ren_Trees, &cleanup_TConVar_ren_Trees);
  }

  /**
   * Address: 0x00C04540 (FUN_00C04540, ??1TConVar_ren_Ui@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Ui`.
   */
  void cleanup_TConVar_ren_Ui()
  {
    CleanupStartupConCommand(gTConVar_ren_Ui);
  }

  /**
   * Address: 0x00BE1450 (FUN_00BE1450, register_TConVar_ren_Ui)
   *
   * What it does:
   * Registers startup convar for `ren_Ui`.
   */
  void register_TConVar_ren_Ui()
  {
    RegisterStartupConVar(gTConVar_ren_Ui, &cleanup_TConVar_ren_Ui);
  }

  /**
   * Address: 0x00C04BC0 (FUN_00C04BC0, ??1TConVar_ren_UnitSelectionScale@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_UnitSelectionScale`.
   */
  void cleanup_TConVar_ren_UnitSelectionScale()
  {
    CleanupStartupConCommand(gTConVar_ren_UnitSelectionScale);
  }

  /**
   * Address: 0x00BE1D40 (FUN_00BE1D40, register_TConVar_ren_UnitSelectionScale)
   *
   * What it does:
   * Registers startup convar for `ren_UnitSelectionScale`.
   */
  void register_TConVar_ren_UnitSelectionScale()
  {
    RegisterStartupConVar(gTConVar_ren_UnitSelectionScale, &cleanup_TConVar_ren_UnitSelectionScale);
  }

  /**
   * Address: 0x00C04930 (FUN_00C04930, ??1TConVar_ren_UnitSilhouette@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_UnitSilhouette`.
   */
  void cleanup_TConVar_ren_UnitSilhouette()
  {
    CleanupStartupConCommand(gTConVar_ren_UnitSilhouette);
  }

  /**
   * Address: 0x00BE1990 (FUN_00BE1990, register_TConVar_ren_UnitSilhouette)
   *
   * What it does:
   * Registers startup convar for `ren_UnitSilhouette`.
   */
  void register_TConVar_ren_UnitSilhouette()
  {
    RegisterStartupConVar(gTConVar_ren_UnitSilhouette, &cleanup_TConVar_ren_UnitSilhouette);
  }

  /**
   * Address: 0x00C05970 (FUN_00C05970, ??1TConVar_ren_maxViewError@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ViewError`.
   */
  void cleanup_TConVar_ren_ViewError()
  {
    CleanupStartupConCommand(gTConVar_ren_ViewError);
  }

  /**
   * Address: 0x00BE3110 (FUN_00BE3110, register_TConVar_ren_ViewError)
   *
   * What it does:
   * Registers startup convar for `ren_ViewError`.
   */
  void register_TConVar_ren_ViewError()
  {
    RegisterStartupConVar(gTConVar_ren_ViewError, &cleanup_TConVar_ren_ViewError);
  }

  /**
   * Address: 0x00C04F40 (FUN_00C04F40, ??1TConVar_ren_Water@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_Water`.
   */
  void cleanup_TConVar_ren_Water()
  {
    CleanupStartupConCommand(gTConVar_ren_Water);
  }

  /**
   * Address: 0x00BE2250 (FUN_00BE2250, register_TConVar_ren_Water)
   *
   * What it does:
   * Registers startup convar for `ren_Water`.
   */
  void register_TConVar_ren_Water()
  {
    RegisterStartupConVar(gTConVar_ren_Water, &cleanup_TConVar_ren_Water);
  }

  /**
   * Address: 0x00C04570 (FUN_00C04570, ??1TConVar_ren_WorldBorder@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_WorldBorder`.
   */
  void cleanup_TConVar_ren_WorldBorder()
  {
    CleanupStartupConCommand(gTConVar_ren_WorldBorder);
  }

  /**
   * Address: 0x00BE1490 (FUN_00BE1490, register_TConVar_ren_WorldBorder)
   *
   * What it does:
   * Registers startup convar for `ren_WorldBorder`.
   */
  void register_TConVar_ren_WorldBorder()
  {
    RegisterStartupConVar(gTConVar_ren_WorldBorder, &cleanup_TConVar_ren_WorldBorder);
  }

  /**
   * Address: 0x00C04E20 (FUN_00C04E20, ??1TConVar_ren_bicubicnormals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_bicubicnormals`.
   */
  void cleanup_TConVar_ren_bicubicnormals()
  {
    CleanupStartupConCommand(gTConVar_ren_bicubicnormals);
  }

  /**
   * Address: 0x00BE20D0 (FUN_00BE20D0, register_TConVar_ren_bicubicnormals)
   *
   * What it does:
   * Registers startup convar for `ren_bicubicnormals`.
   */
  void register_TConVar_ren_bicubicnormals()
  {
    RegisterStartupConVar(gTConVar_ren_bicubicnormals, &cleanup_TConVar_ren_bicubicnormals);
  }

  /**
   * Address: 0x00C04690 (FUN_00C04690, ??1TConVar_ren_fog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_fog`.
   */
  void cleanup_TConVar_ren_fog()
  {
    CleanupStartupConCommand(gTConVar_ren_fog);
  }

  /**
   * Address: 0x00BE1610 (FUN_00BE1610, register_TConVar_ren_fog)
   *
   * What it does:
   * Registers startup convar for `ren_fog`.
   */
  void register_TConVar_ren_fog()
  {
    RegisterStartupConVar(gTConVar_ren_fog, &cleanup_TConVar_ren_fog);
  }

  /**
   * Address: 0x00C05060 (FUN_00C05060, ??1TConVar_ren_glowingDecals@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_glowingDecals`.
   */
  void cleanup_TConVar_ren_glowingDecals()
  {
    CleanupStartupConCommand(gTConVar_ren_glowingDecals);
  }

  /**
   * Address: 0x00BE23D0 (FUN_00BE23D0, register_TConVar_ren_glowingDecals)
   *
   * What it does:
   * Registers startup convar for `ren_glowingDecals`.
   */
  void register_TConVar_ren_glowingDecals()
  {
    RegisterStartupConVar(gTConVar_ren_glowingDecals, &cleanup_TConVar_ren_glowingDecals);
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsRenTuning
  {
    ConsoleStartupRegistrationsRenTuning()
    {
      moho::register_TConVar_ren_BandwidthDisplayKernel();
      moho::register_TConVar_ren_BandwidthDisplaySeconds();
      moho::register_TConVar_ren_BgLowerBound();
      moho::register_TConVar_ren_Bloom();
      moho::register_TConVar_ren_BloomBlurCount();
      moho::register_TConVar_ren_BloomBlurKernelScale();
      moho::register_TConVar_ren_BloomGlowCopyScale();
      moho::register_TConVar_ren_BorderSize();
      moho::register_TConVar_ren_ClipDecalLevel();
      moho::register_TConVar_ren_ClipDecals();
      moho::register_TConVar_ren_Clutter();
      moho::register_TConVar_ren_ClutterRadius();
      moho::register_TConVar_ren_DecalAlbedoLodCutoff();
      moho::register_TConVar_ren_DecalFadeFraction();
      moho::register_TConVar_ren_DecalFidelity();
      moho::register_TConVar_ren_DecalFlatTol();
      moho::register_TConVar_ren_DecalNormalLodCutoff();
      moho::register_TConVar_ren_DecalOverDraw();
      moho::register_TConVar_ren_Decals();
      moho::register_TConVar_ren_ErrorCache();
      moho::register_TConVar_ren_FogIntensity();
      moho::register_TConVar_ren_FogOfWar();
      moho::register_TConVar_ren_ForceUpdateMinimapTerrain();
      moho::register_TConVar_ren_FrameTimeSeconds();
      moho::register_TConVar_ren_Fx();
      moho::register_TConVar_ren_GenerateMesh();
      moho::register_TConVar_ren_HideSecondary();
      moho::register_TConVar_ren_IgnoreDecalLOD();
      moho::register_TConVar_ren_MeshDissolve();
      moho::register_TConVar_ren_MeshDissolveCutoff();
      moho::register_TConVar_ren_MeshSkinned();
      moho::register_TConVar_ren_MeshStatic();
      moho::register_TConVar_ren_NewFogUpdate();
      moho::register_TConVar_ren_NewPipeline();
      moho::register_TConVar_ren_NormalDecals();
      moho::register_TConVar_ren_Oblivion();
      moho::register_TConVar_ren_OnlyFirstView();
      moho::register_TConVar_ren_PlayableBoundary();
      moho::register_TConVar_ren_Reflection();
      moho::register_TConVar_ren_Refraction();
      moho::register_TConVar_ren_RegenShore();
      moho::register_TConVar_ren_RenderNothing();
      moho::register_TConVar_ren_Select();
      moho::register_TConVar_ren_SelectBoxes();
      moho::register_TConVar_ren_SelectBracketMinPixelSize();
      moho::register_TConVar_ren_SelectBracketSize();
      moho::register_TConVar_ren_SelectColor();
      moho::register_TConVar_ren_SelectionHeightFudge();
      moho::register_TConVar_ren_SelectionSizeFudge();
      moho::register_TConVar_ren_ShadowBlur();
      moho::register_TConVar_ren_ShadowCoeff();
      moho::register_TConVar_ren_ShadowLOD();
      moho::register_TConVar_ren_ShadowSize();
      moho::register_TConVar_ren_Shadows();
      moho::register_TConVar_ren_ShoreErrorCoeff();
      moho::register_TConVar_ren_Shoreline();
      moho::register_TConVar_ren_ShorelineCutoff();
      moho::register_TConVar_ren_ShowBandwidthUsage();
      moho::register_TConVar_ren_ShowBoneNames();
      moho::register_TConVar_ren_ShowDirtyTerrain();
      moho::register_TConVar_ren_ShowFrameTimes();
      moho::register_TConVar_ren_ShowNetworkStats();
      moho::register_TConVar_ren_ShowNormals();
      moho::register_TConVar_ren_ShowWireframe();
      moho::register_TConVar_ren_Skirt();
      moho::register_TConVar_ren_SkyDome();
      moho::register_TConVar_ren_Splats();
      moho::register_TConVar_ren_SyncTerrainLOD();
      moho::register_TConVar_ren_TTerrainGlow();
      moho::register_TConVar_ren_TeamColorLookupCount();
      moho::register_TConVar_ren_Terrain();
      moho::register_TConVar_ren_Trees();
      moho::register_TConVar_ren_Ui();
      moho::register_TConVar_ren_UnitSelectionScale();
      moho::register_TConVar_ren_UnitSilhouette();
      moho::register_TConVar_ren_ViewError();
      moho::register_TConVar_ren_Water();
      moho::register_TConVar_ren_WorldBorder();
      moho::register_TConVar_ren_bicubicnormals();
      moho::register_TConVar_ren_fog();
      moho::register_TConVar_ren_glowingDecals();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsRenTuning gConsoleStartupRegistrationsRenTuning;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupCamSetLODDescription = "Set the lod scale factor for a camera";
  constexpr const char* kConsoleStartupDumpCameraDescription = "Dump out camera position data for the editor";
  constexpr const char* kConsoleStartupPopupCreateUnitMenuDescription = "Popup the create unit menu.";
  constexpr const char* kConsoleStartupPathDebugDescription = "Debug the path finder";
  constexpr const char* kConsoleStartupTeleportSelectedUnitsDescription = "teleport selected units.";
  constexpr const char* kConsoleStartupSetFocusArmyDescription = "Pass in army index or -1";
  constexpr const char* kConsoleStartupUISetSkinDescription = "Sets a new skin";
  constexpr const char* kConsoleStartupUIRotateSkinDescription = "Cycles through all available skins";
  constexpr const char* kConsoleStartupUIRotateLayoutDescription = "Cycles through all available layouts";
  constexpr const char* kConsoleStartupUIToggleGamePanelsDescription = "Hide/show the UI panels in game, and expands the world view to fill the screen when panels are hidden.";
  constexpr const char* kConsoleStartupUIQuitDescription = "Drives quit behavior of the game depending on the state of the UI";
  constexpr const char* kConsoleStartupUIMakeSelectionSetDescription = "Takes a name, and makes a named selection set from the current selection";
  constexpr const char* kConsoleStartupUIApplySelectionSetDescription = "Takes a selection set name and applies the selection";
  constexpr const char* kConsoleStartupUICreateHead1MapDescription = "Destroys anything on head 1 and shows a full screen map in its place";
  constexpr const char* kConsoleStartupUILuaDescription = "Run lua code in the appropriate UI lua state.";
  constexpr const char* kConsoleStartupUIShowRenameDialogDescription = "Display the rename unit dialog during a game";
  constexpr const char* kConsoleStartupUIDumpControlsDescription = "Dumps information about all controls to current log target.";
  constexpr const char* kConsoleStartupUIDumpControlsUnderCursorDescription = "Dumps all controls under the cursor to the debug log";
} // namespace

namespace moho
{
  CConFunc gCConFunc_cam_SetLOD{};
  CConFunc gCConFunc_DumpCamera{};
  CConFunc gCConFunc_PopupCreateUnitMenu{};
  CConFunc gCConFunc_PathDebug{};
  CConFunc gCConFunc_TeleportSelectedUnits{};
  CConFunc gCConFunc_SetFocusArmy{};
  CConFunc gCConFunc_UI_SetSkin{};
  CConFunc gCConFunc_UI_RotateSkin{};
  CConFunc gCConFunc_UI_RotateLayout{};
  CConFunc gCConFunc_UI_ToggleGamePanels{};
  CConFunc gCConFunc_UI_Quit{};
  CConFunc gCConFunc_UI_MakeSelectionSet{};
  CConFunc gCConFunc_UI_ApplySelectionSet{};
  CConFunc gCConFunc_UI_CreateHead1Map{};
  CConFunc gCConFunc_UI_Lua{};
  CConFunc gCConFunc_UI_ShowRenameDialog{};
  CConFunc gCConFunc_UI_DumpControls{};
  CConFunc gCConFunc_UI_DumpControlsUnderCursor{};

  /**
   * Address: 0x00C03650 (FUN_00C03650, ??1CConFunc_cam_SetLOD@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `cam_SetLOD`.
   */
  void cleanup_CConFunc_cam_SetLOD()
  {
    CleanupStartupConCommand(gCConFunc_cam_SetLOD);
  }

  /**
   * Address: 0x00BDF7C0 (FUN_00BDF7C0, register_CConFunc_cam_SetLOD)
   *
   * What it does:
   * Registers startup console callback for `cam_SetLOD`.
   */
  void register_CConFunc_cam_SetLOD()
  {
    RegisterStartupConFunc(
      gCConFunc_cam_SetLOD,
      kConsoleStartupCamSetLODDescription,
      "cam_SetLOD",
      &moho::CAM_SetLOD,
      &cleanup_CConFunc_cam_SetLOD
    );
  }

  /**
   * Address: 0x00C03680 (FUN_00C03680, ??1CConFunc_DumpCamera@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DumpCamera`.
   */
  void cleanup_CConFunc_DumpCamera()
  {
    CleanupStartupConCommand(gCConFunc_DumpCamera);
  }

  /**
   * Address: 0x00BDF800 (FUN_00BDF800, register_CConFunc_DumpCamera)
   *
   * What it does:
   * Registers startup console callback for `DumpCamera`.
   */
  void register_CConFunc_DumpCamera()
  {
    RegisterStartupConFunc(
      gCConFunc_DumpCamera,
      kConsoleStartupDumpCameraDescription,
      "DumpCamera",
      &moho::CON_DumpCamera,
      &cleanup_CConFunc_DumpCamera
    );
  }

  /**
   * Address: 0x00C037A0 (FUN_00C037A0, ??1CON_PopupCreateUnitMenu@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `PopupCreateUnitMenu`.
   */
  void cleanup_CConFunc_PopupCreateUnitMenu()
  {
    CleanupStartupConCommand(gCConFunc_PopupCreateUnitMenu);
  }

  /**
   * Address: 0x00BDFA80 (FUN_00BDFA80, register_CConFunc_PopupCreateUnitMenu)
   *
   * What it does:
   * Registers startup console callback for `PopupCreateUnitMenu`.
   */
  void register_CConFunc_PopupCreateUnitMenu()
  {
    RegisterStartupConFunc(
      gCConFunc_PopupCreateUnitMenu,
      kConsoleStartupPopupCreateUnitMenuDescription,
      "PopupCreateUnitMenu",
      &moho::CON_PopupCreateUnitMenu,
      &cleanup_CConFunc_PopupCreateUnitMenu
    );
  }

  /**
   * Address: 0x00C03850 (FUN_00C03850, ??1CConFunc_PathDebug@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `PathDebug`.
   */
  void cleanup_CConFunc_PathDebug()
  {
    CleanupStartupConCommand(gCConFunc_PathDebug);
  }

  /**
   * Address: 0x00BDFB90 (FUN_00BDFB90, register_CConFunc_PathDebug)
   *
   * What it does:
   * Registers startup console callback for `PathDebug`.
   */
  void register_CConFunc_PathDebug()
  {
    RegisterStartupConFunc(
      gCConFunc_PathDebug,
      kConsoleStartupPathDebugDescription,
      "PathDebug",
      &moho::CON_PathDebug,
      &cleanup_CConFunc_PathDebug
    );
  }

  /**
   * Address: 0x00C06250 (FUN_00C06250, ??1CConFunc_TeleportSelectedUnits@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `TeleportSelectedUnits`.
   */
  void cleanup_CConFunc_TeleportSelectedUnits()
  {
    CleanupStartupConCommand(gCConFunc_TeleportSelectedUnits);
  }

  /**
   * Address: 0x00BE4130 (FUN_00BE4130, register_CConFunc_TeleportSelectedUnits)
   *
   * What it does:
   * Registers startup console callback for `TeleportSelectedUnits`.
   */
  void register_CConFunc_TeleportSelectedUnits()
  {
    RegisterStartupConFunc(
      gCConFunc_TeleportSelectedUnits,
      kConsoleStartupTeleportSelectedUnitsDescription,
      "TeleportSelectedUnits",
      &moho::CON_TeleportSelectedUnits,
      &cleanup_CConFunc_TeleportSelectedUnits
    );
  }

  /**
   * Address: 0x00C06460 (FUN_00C06460, ??1CConFunc_SetFocusArmy@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `SetFocusArmy`.
   */
  void cleanup_CConFunc_SetFocusArmy()
  {
    CleanupStartupConCommand(gCConFunc_SetFocusArmy);
  }

  /**
   * Address: 0x00BE43F0 (FUN_00BE43F0, register_CConFunc_SetFocusArmy)
   *
   * What it does:
   * Registers startup console callback for `SetFocusArmy`.
   */
  void register_CConFunc_SetFocusArmy()
  {
    RegisterStartupConFunc(
      gCConFunc_SetFocusArmy,
      kConsoleStartupSetFocusArmyDescription,
      "SetFocusArmy",
      &moho::SetFocusArmy,
      &cleanup_CConFunc_SetFocusArmy
    );
  }

  /**
   * Address: 0x00C062E0 (FUN_00C062E0, ??1CConFunc_UI_SetSkin@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_SetSkin`.
   */
  void cleanup_CConFunc_UI_SetSkin()
  {
    CleanupStartupConCommand(gCConFunc_UI_SetSkin);
  }

  /**
   * Address: 0x00BE41F0 (FUN_00BE41F0, register_CConFunc_UI_SetSkin)
   *
   * What it does:
   * Registers startup console callback for `UI_SetSkin`.
   */
  void register_CConFunc_UI_SetSkin()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_SetSkin,
      kConsoleStartupUISetSkinDescription,
      "UI_SetSkin",
      &moho::CON_UI_SetSkin,
      &cleanup_CConFunc_UI_SetSkin
    );
  }

  /**
   * Address: 0x00C06310 (FUN_00C06310, ??1CConFunc_UI_RotateSkin@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_RotateSkin`.
   */
  void cleanup_CConFunc_UI_RotateSkin()
  {
    CleanupStartupConCommand(gCConFunc_UI_RotateSkin);
  }

  /**
   * Address: 0x00BE4230 (FUN_00BE4230, register_CConFunc_UI_RotateSkin)
   *
   * What it does:
   * Registers startup console callback for `UI_RotateSkin`.
   */
  void register_CConFunc_UI_RotateSkin()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_RotateSkin,
      kConsoleStartupUIRotateSkinDescription,
      "UI_RotateSkin",
      &moho::UI_RotateSkin,
      &cleanup_CConFunc_UI_RotateSkin
    );
  }

  /**
   * Address: 0x00C06340 (FUN_00C06340, ??1CConFunc_UI_RotateLayout@Moho@@QAE@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_RotateLayout`.
   */
  void cleanup_CConFunc_UI_RotateLayout()
  {
    CleanupStartupConCommand(gCConFunc_UI_RotateLayout);
  }

  /**
   * Address: 0x00BE4270 (FUN_00BE4270, register_CConFunc_UI_RotateLayout)
   *
   * What it does:
   * Registers startup console callback for `UI_RotateLayout`.
   */
  void register_CConFunc_UI_RotateLayout()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_RotateLayout,
      kConsoleStartupUIRotateLayoutDescription,
      "UI_RotateLayout",
      &moho::UI_RotateLayout,
      &cleanup_CConFunc_UI_RotateLayout
    );
  }

  /**
   * Address: 0x00C063A0 (FUN_00C063A0, ??1CConFunc_UI_ToggleGamePanels@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_ToggleGamePanels`.
   */
  void cleanup_CConFunc_UI_ToggleGamePanels()
  {
    CleanupStartupConCommand(gCConFunc_UI_ToggleGamePanels);
  }

  /**
   * Address: 0x00BE42F0 (FUN_00BE42F0, register_CConFunc_UI_ToggleGamePanels)
   *
   * What it does:
   * Registers startup console callback for `UI_ToggleGamePanels`.
   */
  void register_CConFunc_UI_ToggleGamePanels()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_ToggleGamePanels,
      kConsoleStartupUIToggleGamePanelsDescription,
      "UI_ToggleGamePanels",
      &moho::CON_UI_ToggleGamePanels,
      &cleanup_CConFunc_UI_ToggleGamePanels
    );
  }

  /**
   * Address: 0x00C06370 (FUN_00C06370, ??1CConFunc_UI_Quit@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_Quit`.
   */
  void cleanup_CConFunc_UI_Quit()
  {
    CleanupStartupConCommand(gCConFunc_UI_Quit);
  }

  /**
   * Address: 0x00BE42B0 (FUN_00BE42B0, register_CConFunc_UI_Quit)
   *
   * What it does:
   * Registers startup console callback for `UI_Quit`.
   */
  void register_CConFunc_UI_Quit()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_Quit,
      kConsoleStartupUIQuitDescription,
      "UI_Quit",
      &moho::UI_Quit,
      &cleanup_CConFunc_UI_Quit
    );
  }

  /**
   * Address: 0x00C063D0 (FUN_00C063D0, ??1CConFunc_UI_MakeSelectionSet@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_MakeSelectionSet`.
   */
  void cleanup_CConFunc_UI_MakeSelectionSet()
  {
    CleanupStartupConCommand(gCConFunc_UI_MakeSelectionSet);
  }

  /**
   * Address: 0x00BE4330 (FUN_00BE4330, register_CConFunc_UI_MakeSelectionSet)
   *
   * What it does:
   * Registers startup console callback for `UI_MakeSelectionSet`.
   */
  void register_CConFunc_UI_MakeSelectionSet()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_MakeSelectionSet,
      kConsoleStartupUIMakeSelectionSetDescription,
      "UI_MakeSelectionSet",
      &moho::UI_MakeSelectionSet,
      &cleanup_CConFunc_UI_MakeSelectionSet
    );
  }

  /**
   * Address: 0x00C06400 (FUN_00C06400, ??1CConFunc_UI_ApplySelectionSet@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_ApplySelectionSet`.
   */
  void cleanup_CConFunc_UI_ApplySelectionSet()
  {
    CleanupStartupConCommand(gCConFunc_UI_ApplySelectionSet);
  }

  /**
   * Address: 0x00BE4370 (FUN_00BE4370, register_CConFunc_UI_ApplySelectionSet)
   *
   * What it does:
   * Registers startup console callback for `UI_ApplySelectionSet`.
   */
  void register_CConFunc_UI_ApplySelectionSet()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_ApplySelectionSet,
      kConsoleStartupUIApplySelectionSetDescription,
      "UI_ApplySelectionSet",
      &moho::UI_ApplySelectionSet,
      &cleanup_CConFunc_UI_ApplySelectionSet
    );
  }

  /**
   * Address: 0x00C06430 (FUN_00C06430, ??1CConFunc_UI_CreateHead1Map@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_CreateHead1Map`.
   */
  void cleanup_CConFunc_UI_CreateHead1Map()
  {
    CleanupStartupConCommand(gCConFunc_UI_CreateHead1Map);
  }

  /**
   * Address: 0x00BE43B0 (FUN_00BE43B0, register_CConFunc_UI_CreateHead1Map)
   *
   * What it does:
   * Registers startup console callback for `UI_CreateHead1Map`.
   */
  void register_CConFunc_UI_CreateHead1Map()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_CreateHead1Map,
      kConsoleStartupUICreateHead1MapDescription,
      "UI_CreateHead1Map",
      &moho::CON_UI_CreateHead1Map,
      &cleanup_CConFunc_UI_CreateHead1Map
    );
  }

  /**
   * Address: 0x00C064F0 (FUN_00C064F0, ??1CConFunc_UI_Lua@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_Lua`.
   */
  void cleanup_CConFunc_UI_Lua()
  {
    CleanupStartupConCommand(gCConFunc_UI_Lua);
  }

  /**
   * Address: 0x00BE44B0 (FUN_00BE44B0, register_CConFunc_UI_Lua)
   *
   * What it does:
   * Registers startup console callback for `UI_Lua`.
   */
  void register_CConFunc_UI_Lua()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_Lua,
      kConsoleStartupUILuaDescription,
      "UI_Lua",
      &moho::UI_Lua,
      &cleanup_CConFunc_UI_Lua
    );
  }

  /**
   * Address: 0x00C06550 (FUN_00C06550, ??1CConFunc_UI_ShowRenameDialog@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_ShowRenameDialog`.
   */
  void cleanup_CConFunc_UI_ShowRenameDialog()
  {
    CleanupStartupConCommand(gCConFunc_UI_ShowRenameDialog);
  }

  /**
   * Address: 0x00BE4530 (FUN_00BE4530, register_CConFunc_UI_ShowRenameDialog)
   *
   * What it does:
   * Registers startup console callback for `UI_ShowRenameDialog`.
   */
  void register_CConFunc_UI_ShowRenameDialog()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_ShowRenameDialog,
      kConsoleStartupUIShowRenameDialogDescription,
      "UI_ShowRenameDialog",
      reinterpret_cast<CConFunc::Callback>(&moho::UI_ShowRenameDialog),
      &cleanup_CConFunc_UI_ShowRenameDialog
    );
  }

  /**
   * Address: 0x00C06580 (FUN_00C06580, ??1CConFunc_UI_DumpControls@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_DumpControls`.
   */
  void cleanup_CConFunc_UI_DumpControls()
  {
    CleanupStartupConCommand(gCConFunc_UI_DumpControls);
  }

  /**
   * Address: 0x00BE4570 (FUN_00BE4570, register_CConFunc_UI_DumpControls)
   *
   * What it does:
   * Registers startup console callback for `UI_DumpControls`.
   */
  void register_CConFunc_UI_DumpControls()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_DumpControls,
      kConsoleStartupUIDumpControlsDescription,
      "UI_DumpControls",
      &moho::UI_DumpControls,
      &cleanup_CConFunc_UI_DumpControls
    );
  }

  /**
   * Address: 0x00C065B0 (FUN_00C065B0, ??1CConFunc_UI_DumpControlsUnderCursor@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `UI_DumpControlsUnderCursor`.
   */
  void cleanup_CConFunc_UI_DumpControlsUnderCursor()
  {
    CleanupStartupConCommand(gCConFunc_UI_DumpControlsUnderCursor);
  }

  /**
   * Address: 0x00BE45B0 (FUN_00BE45B0, register_CConFunc_UI_DumpControlsUnderCursor)
   *
   * What it does:
   * Registers startup console callback for `UI_DumpControlsUnderCursor`.
   */
  void register_CConFunc_UI_DumpControlsUnderCursor()
  {
    RegisterStartupConFunc(
      gCConFunc_UI_DumpControlsUnderCursor,
      kConsoleStartupUIDumpControlsUnderCursorDescription,
      "UI_DumpControlsUnderCursor",
      &moho::UI_DumpControlsUnderCursor,
      &cleanup_CConFunc_UI_DumpControlsUnderCursor
    );
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsUiMisc
  {
    ConsoleStartupRegistrationsUiMisc()
    {
      moho::register_CConFunc_cam_SetLOD();
      moho::register_CConFunc_DumpCamera();
      moho::register_CConFunc_PopupCreateUnitMenu();
      moho::register_CConFunc_PathDebug();
      moho::register_CConFunc_TeleportSelectedUnits();
      moho::register_CConFunc_SetFocusArmy();
      moho::register_CConFunc_UI_SetSkin();
      moho::register_CConFunc_UI_RotateSkin();
      moho::register_CConFunc_UI_RotateLayout();
      moho::register_CConFunc_UI_ToggleGamePanels();
      moho::register_CConFunc_UI_Quit();
      moho::register_CConFunc_UI_MakeSelectionSet();
      moho::register_CConFunc_UI_ApplySelectionSet();
      moho::register_CConFunc_UI_CreateHead1Map();
      moho::register_CConFunc_UI_Lua();
      moho::register_CConFunc_UI_ShowRenameDialog();
      moho::register_CConFunc_UI_DumpControls();
      moho::register_CConFunc_UI_DumpControlsUnderCursor();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsUiMisc gConsoleStartupRegistrationsUiMisc;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupDumpActiveLoopsDescription = "List all active entity loops";
  constexpr const char* kConsoleStartupShowArmyStatsDescription = "Show engine statistics";
  constexpr const char* kConsoleStartupShowStatsDescription = "Show engine statistics";
  constexpr const char* kConsoleStartupRenMapBorderAddDescription = "Add a mesh to the map border list";
  constexpr const char* kConsoleStartupRenMapBorderClearDescription = "Clear all map border meshes";
  constexpr const char* kConsoleStartupRenShowSkeletonsDescription = "Show mesh skeletons";
  constexpr const char* kConsoleStartupTimestampDescription = "Dump out EXE timestamp";
  constexpr const char* kConsoleStartupSCCreateEntityDialogDescription = "Create object editing box for the primary selected unit";
  constexpr const char* kConsoleStartupSCAntiAliasingSamplesDescription = "SC_AntiAliasingSamples console command.";
  constexpr const char* kConsoleStartupQuitDescription = "Quit the session.";
  constexpr const char* kConsoleStartupWLDIncreaseSimRateDescription = "Increase the game speed.";
  constexpr const char* kConsoleStartupWLDDecreaseSimRateDescription = "Decrease the game speed.";
  constexpr const char* kConsoleStartupWLDResetSimRateDescription = "Increase the game speed.";
} // namespace

namespace moho
{
  CConFunc gCConFunc_DumpActiveLoops{};
  CConFunc gCConFunc_ShowArmyStats{};
  CConFunc gCConFunc_ShowStats{};
  CConFunc gCConFunc_ren_MapBorderAdd{};
  CConFunc gCConFunc_ren_MapBorderClear{};
  CConFunc gCConFunc_ren_ShowSkeletons{};
  CConFunc gCConFunc_timestamp{};
  CConFunc gCConFunc_SC_CreateEntityDialog{};
  CConFunc gCConFunc_SC_AntiAliasingSamples{};
  CConFunc gCConFunc_quit{};
  CConFunc gCConFunc_WLD_IncreaseSimRate{};
  CConFunc gCConFunc_WLD_DecreaseSimRate{};
  CConFunc gCConFunc_WLD_ResetSimRate{};

  /**
   * Address: 0x00C085D0 (FUN_00C085D0, ??1CConFunc_DumpActiveLoops@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `DumpActiveLoops`.
   */
  void cleanup_CConFunc_DumpActiveLoops()
  {
    CleanupStartupConCommand(gCConFunc_DumpActiveLoops);
  }

  /**
   * Address: 0x00BE7F70 (FUN_00BE7F70, register_CConFunc_DumpActiveLoops)
   *
   * What it does:
   * Registers startup console callback for `DumpActiveLoops`.
   */
  void register_CConFunc_DumpActiveLoops()
  {
    RegisterStartupConFunc(
      gCConFunc_DumpActiveLoops,
      kConsoleStartupDumpActiveLoopsDescription,
      "DumpActiveLoops",
      reinterpret_cast<CConFunc::Callback>(&moho::Con_DumpActiveLoops),
      &cleanup_CConFunc_DumpActiveLoops
    );
  }

  /**
   * Address: 0x00C064C0 (FUN_00C064C0, ??1CConFunc_ShowArmyStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ShowArmyStats`.
   */
  void cleanup_CConFunc_ShowArmyStats()
  {
    CleanupStartupConCommand(gCConFunc_ShowArmyStats);
  }

  /**
   * Address: 0x00BE4470 (FUN_00BE4470, register_CConFunc_ShowArmyStats)
   *
   * What it does:
   * Registers startup console callback for `ShowArmyStats`.
   */
  void register_CConFunc_ShowArmyStats()
  {
    RegisterStartupConFunc(
      gCConFunc_ShowArmyStats,
      kConsoleStartupShowArmyStatsDescription,
      "ShowArmyStats",
      &moho::ShowArmyStats,
      &cleanup_CConFunc_ShowArmyStats
    );
  }

  /**
   * Address: 0x00C06490 (FUN_00C06490, ??1CConFunc_ShowStats@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ShowStats`.
   */
  void cleanup_CConFunc_ShowStats()
  {
    CleanupStartupConCommand(gCConFunc_ShowStats);
  }

  /**
   * Address: 0x00BE4430 (FUN_00BE4430, register_CConFunc_ShowStats)
   *
   * What it does:
   * Registers startup console callback for `ShowStats`.
   */
  void register_CConFunc_ShowStats()
  {
    RegisterStartupConFunc(
      gCConFunc_ShowStats,
      kConsoleStartupShowStatsDescription,
      "ShowStats",
      &moho::ShowStats,
      &cleanup_CConFunc_ShowStats
    );
  }

  /**
   * Address: 0x00C04AB0 (FUN_00C04AB0, ??1CConFunc_ren_MapBorderAdd@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ren_MapBorderAdd`.
   */
  void cleanup_CConFunc_ren_MapBorderAdd()
  {
    CleanupStartupConCommand(gCConFunc_ren_MapBorderAdd);
  }

  /**
   * Address: 0x00BE1B90 (FUN_00BE1B90, register_CConFunc_ren_MapBorderAdd)
   *
   * What it does:
   * Registers startup console callback for `ren_MapBorderAdd`.
   */
  void register_CConFunc_ren_MapBorderAdd()
  {
    RegisterStartupConFunc(
      gCConFunc_ren_MapBorderAdd,
      kConsoleStartupRenMapBorderAddDescription,
      "ren_MapBorderAdd",
      &moho::REN_MapBorderAdd,
      &cleanup_CConFunc_ren_MapBorderAdd
    );
  }

  /**
   * Address: 0x00C04AE0 (FUN_00C04AE0, ??1CConFunc_ren_MapBorderClear@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ren_MapBorderClear`.
   */
  void cleanup_CConFunc_ren_MapBorderClear()
  {
    CleanupStartupConCommand(gCConFunc_ren_MapBorderClear);
  }

  /**
   * Address: 0x00BE1BD0 (FUN_00BE1BD0, register_CConFunc_ren_MapBorderClear)
   *
   * What it does:
   * Registers startup console callback for `ren_MapBorderClear`.
   */
  void register_CConFunc_ren_MapBorderClear()
  {
    RegisterStartupConFunc(
      gCConFunc_ren_MapBorderClear,
      kConsoleStartupRenMapBorderClearDescription,
      "ren_MapBorderClear",
      &moho::REN_MapBorderClear,
      &cleanup_CConFunc_ren_MapBorderClear
    );
  }

  /**
   * Address: 0x00C04A80 (FUN_00C04A80, ??1CConFunc_ren_ShowSkeletons@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `ren_ShowSkeletons`.
   */
  void cleanup_CConFunc_ren_ShowSkeletons()
  {
    CleanupStartupConCommand(gCConFunc_ren_ShowSkeletons);
  }

  /**
   * Address: 0x00BE1B50 (FUN_00BE1B50, register_CConFunc_ren_ShowSkeletons)
   *
   * What it does:
   * Registers startup console callback for `ren_ShowSkeletons`.
   */
  void register_CConFunc_ren_ShowSkeletons()
  {
    RegisterStartupConFunc(
      gCConFunc_ren_ShowSkeletons,
      kConsoleStartupRenShowSkeletonsDescription,
      "ren_ShowSkeletons",
      reinterpret_cast<CConFunc::Callback>(&moho::REN_ShowSkeletons),
      &cleanup_CConFunc_ren_ShowSkeletons
    );
  }

  /**
   * Address: 0x00C08E50 (FUN_00C08E50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `timestamp`.
   */
  void cleanup_CConFunc_timestamp()
  {
    CleanupStartupConCommand(gCConFunc_timestamp);
  }

  /**
   * Address: 0x00BE9600 (FUN_00BE9600, register_CConFunc_timestamp)
   *
   * What it does:
   * Registers startup console callback for `timestamp`.
   */
  void register_CConFunc_timestamp()
  {
    RegisterStartupConFunc(
      gCConFunc_timestamp,
      kConsoleStartupTimestampDescription,
      "timestamp",
      reinterpret_cast<CConFunc::Callback>(&moho::PrintExecutableTimestampToConsole),
      &cleanup_CConFunc_timestamp
    );
  }

  /**
   * Address: 0x00C08E80 (FUN_00C08E80, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_CreateEntityDialog`.
   */
  void cleanup_CConFunc_SC_CreateEntityDialog()
  {
    CleanupStartupConCommand(gCConFunc_SC_CreateEntityDialog);
  }

  /**
   * Address: 0x00BE9640 (FUN_00BE9640, register_CConFunc_SC_CreateEntityDialog)
   *
   * What it does:
   * Registers startup console callback for `SC_CreateEntityDialog`.
   */
  void register_CConFunc_SC_CreateEntityDialog()
  {
    RegisterStartupConFunc(
      gCConFunc_SC_CreateEntityDialog,
      kConsoleStartupSCCreateEntityDialogDescription,
      "SC_CreateEntityDialog",
      reinterpret_cast<CConFunc::Callback>(&moho::funcl_SC_CreateEntityDialog),
      &cleanup_CConFunc_SC_CreateEntityDialog
    );
  }

  /**
   * Address: 0x00C08D90 (FUN_00C08D90, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `SC_AntiAliasingSamples`.
   */
  void cleanup_CConFunc_SC_AntiAliasingSamples()
  {
    CleanupStartupConCommand(gCConFunc_SC_AntiAliasingSamples);
  }

  /**
   * Address: 0x00BE9500 (FUN_00BE9500, register_CConFunc_SC_AntiAliasingSamples)
   *
   * What it does:
   * Registers startup console callback for `SC_AntiAliasingSamples`.
   */
  void register_CConFunc_SC_AntiAliasingSamples()
  {
    RegisterStartupConFunc(
      gCConFunc_SC_AntiAliasingSamples,
      kConsoleStartupSCAntiAliasingSamplesDescription,
      "SC_AntiAliasingSamples",
      &moho::CON_d3d_AntiAliasingSamplesSeedFromFirstToken,
      &cleanup_CConFunc_SC_AntiAliasingSamples
    );
  }

  /**
   * Address: 0x00C080B0 (FUN_00C080B0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `quit`.
   */
  void cleanup_CConFunc_quit()
  {
    CleanupStartupConCommand(gCConFunc_quit);
  }

  /**
   * Address: 0x00BE7550 (FUN_00BE7550, register_CConFunc_quit)
   *
   * What it does:
   * Registers startup console callback for `quit`.
   */
  void register_CConFunc_quit()
  {
    RegisterStartupConFunc(
      gCConFunc_quit,
      kConsoleStartupQuitDescription,
      "quit",
      &moho::CON_WLD_RequestEndSession,
      &cleanup_CConFunc_quit
    );
  }

  /**
   * Address: 0x00C07F60 (FUN_00C07F60, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_IncreaseSimRate`.
   */
  void cleanup_CConFunc_WLD_IncreaseSimRate()
  {
    CleanupStartupConCommand(gCConFunc_WLD_IncreaseSimRate);
  }

  /**
   * Address: 0x00BE7370 (FUN_00BE7370, register_CConFunc_WLD_IncreaseSimRate)
   *
   * What it does:
   * Registers startup console callback for `WLD_IncreaseSimRate`.
   */
  void register_CConFunc_WLD_IncreaseSimRate()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_IncreaseSimRate,
      kConsoleStartupWLDIncreaseSimRateDescription,
      "WLD_IncreaseSimRate",
      reinterpret_cast<CConFunc::Callback>(&moho::WLD_IncreaseSimRate),
      &cleanup_CConFunc_WLD_IncreaseSimRate
    );
  }

  /**
   * Address: 0x00C07FC0 (FUN_00C07FC0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_DecreaseSimRate`.
   */
  void cleanup_CConFunc_WLD_DecreaseSimRate()
  {
    CleanupStartupConCommand(gCConFunc_WLD_DecreaseSimRate);
  }

  /**
   * Address: 0x00BE73F0 (FUN_00BE73F0, register_CConFunc_WLD_DecreaseSimRate)
   *
   * What it does:
   * Registers startup console callback for `WLD_DecreaseSimRate`.
   */
  void register_CConFunc_WLD_DecreaseSimRate()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_DecreaseSimRate,
      kConsoleStartupWLDDecreaseSimRateDescription,
      "WLD_DecreaseSimRate",
      reinterpret_cast<CConFunc::Callback>(&moho::WLD_DecreaseSimRate),
      &cleanup_CConFunc_WLD_DecreaseSimRate
    );
  }

  /**
   * Address: 0x00C07F90 (FUN_00C07F90, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup command storage for `WLD_ResetSimRate`.
   */
  void cleanup_CConFunc_WLD_ResetSimRate()
  {
    CleanupStartupConCommand(gCConFunc_WLD_ResetSimRate);
  }

  /**
   * Address: 0x00BE73B0 (FUN_00BE73B0, register_CConFunc_WLD_ResetSimRate)
   *
   * What it does:
   * Registers startup console callback for `WLD_ResetSimRate`.
   */
  void register_CConFunc_WLD_ResetSimRate()
  {
    RegisterStartupConFunc(
      gCConFunc_WLD_ResetSimRate,
      kConsoleStartupWLDResetSimRateDescription,
      "WLD_ResetSimRate",
      reinterpret_cast<CConFunc::Callback>(&moho::WLD_ResetSimRate),
      &cleanup_CConFunc_WLD_ResetSimRate
    );
  }

} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsMisc2
  {
    ConsoleStartupRegistrationsMisc2()
    {
      moho::register_CConFunc_DumpActiveLoops();
      moho::register_CConFunc_ShowArmyStats();
      moho::register_CConFunc_ShowStats();
      moho::register_CConFunc_ren_MapBorderAdd();
      moho::register_CConFunc_ren_MapBorderClear();
      moho::register_CConFunc_ren_ShowSkeletons();
      moho::register_CConFunc_timestamp();
      moho::register_CConFunc_SC_CreateEntityDialog();
      moho::register_CConFunc_SC_AntiAliasingSamples();
      moho::register_CConFunc_quit();
      moho::register_CConFunc_WLD_IncreaseSimRate();
      moho::register_CConFunc_WLD_DecreaseSimRate();
      moho::register_CConFunc_WLD_ResetSimRate();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsMisc2 gConsoleStartupRegistrationsMisc2;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupWldClientDebugDumpDescription = "Dump out debug info about the network connections";
} // namespace

namespace moho
{
  CConFunc gCConFunc_wld_ClientDebugDump{};

  /**
   * Address: 0x00C08080 (FUN_00C08080, the `atexit` target the registrar
   * below installs)
   *
   * What it does:
   * Unregisters startup command storage for `wld_ClientDebugDump`.
   */
  void cleanup_CConFunc_wld_ClientDebugDump()
  {
    CleanupStartupConCommand(gCConFunc_wld_ClientDebugDump);
  }

  /**
   * Address: 0x00BE7510 (FUN_00BE7510, register_CConFunc_wld_ClientDebugDump)
   *
   * What it does:
   * Registers startup console callback for `wld_ClientDebugDump`.
   */
  void register_CConFunc_wld_ClientDebugDump()
  {
    RegisterStartupConFunc(
      gCConFunc_wld_ClientDebugDump,
      kConsoleStartupWldClientDebugDumpDescription,
      "wld_ClientDebugDump",
      reinterpret_cast<CConFunc::Callback>(&SimDriverDebugClientManagerRuntime),
      &cleanup_CConFunc_wld_ClientDebugDump
    );
  }
} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsMisc3
  {
    ConsoleStartupRegistrationsMisc3()
    {
      moho::register_CConFunc_wld_ClientDebugDump();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsMisc3 gConsoleStartupRegistrationsMisc3;
} // namespace

namespace
{
  constexpr const char* kConsoleStartupAiInitialMassCurrencyDescription = "Initial currency of mass economy.";
  constexpr const char* kConsoleStartupAiInitialMassCurrencyMaxDescription = "Initial currency of mass economy.";
  constexpr const char* kConsoleStartupRenShadowBiasDescription = "Constant shadow bias";
} // namespace

namespace moho
{
  extern float ren_ShadowBias;

  TConVar<float> gTConVar_ai_InitialMassCurrency(
    "ai_InitialMassCurrency",
    kConsoleStartupAiInitialMassCurrencyDescription,
    &moho::ai_InitialMassCurrency
  );
  TConVar<float> gTConVar_ai_InitialMassCurrencyMax(
    "ai_InitialMassCurrencyMax",
    kConsoleStartupAiInitialMassCurrencyMaxDescription,
    &moho::ai_InitialMassCurrencyMax
  );
  TConVar<float> gTConVar_ren_ShadowBias(
    "ren_ShadowBias",
    kConsoleStartupRenShadowBiasDescription,
    &moho::ren_ShadowBias
  );

  /**
   * Address: 0x00C02160 (FUN_00C02160, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ai_InitialMassCurrency`.
   */
  void cleanup_TConVar_ai_InitialMassCurrency()
  {
    CleanupStartupConCommand(gTConVar_ai_InitialMassCurrency);
  }

  /**
   * Address: 0x00BDCFF0 (FUN_00BDCFF0, register_TConVar_ai_InitialMassCurrency)
   *
   * What it does:
   * Registers startup convar for `ai_InitialMassCurrency`.
   */
  void register_TConVar_ai_InitialMassCurrency()
  {
    RegisterStartupConVar(gTConVar_ai_InitialMassCurrency, &cleanup_TConVar_ai_InitialMassCurrency);
  }

  /**
   * Address: 0x00C021C0 (FUN_00C021C0, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ai_InitialMassCurrencyMax`.
   */
  void cleanup_TConVar_ai_InitialMassCurrencyMax()
  {
    CleanupStartupConCommand(gTConVar_ai_InitialMassCurrencyMax);
  }

  /**
   * Address: 0x00BDD070 (FUN_00BDD070, register_TConVar_ai_InitialMassCurrencyMax)
   *
   * What it does:
   * Registers startup convar for `ai_InitialMassCurrencyMax`.
   */
  void register_TConVar_ai_InitialMassCurrencyMax()
  {
    RegisterStartupConVar(gTConVar_ai_InitialMassCurrencyMax, &cleanup_TConVar_ai_InitialMassCurrencyMax);
  }

  /**
   * Address: 0x00C04D50 (FUN_00C04D50, the `atexit` target the registrar below installs)
   *
   * What it does:
   * Unregisters startup convar storage for `ren_ShadowBias`.
   */
  void cleanup_TConVar_ren_ShadowBias()
  {
    CleanupStartupConCommand(gTConVar_ren_ShadowBias);
  }

  /**
   * Address: 0x00BE1F60 (FUN_00BE1F60, register_TConVar_ren_ShadowBias)
   *
   * What it does:
   * Registers startup convar for `ren_ShadowBias`, the shadow depth bias
   * `MeshRenderer::ConfigureShader`'s shadow lane already reads from the
   * plain `moho::ren_ShadowBias` global (Mesh.cpp).
   */
  void register_TConVar_ren_ShadowBias()
  {
    RegisterStartupConVar(gTConVar_ren_ShadowBias, &cleanup_TConVar_ren_ShadowBias);
  }
} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsMisc4
  {
    ConsoleStartupRegistrationsMisc4()
    {
      moho::register_TConVar_ai_InitialMassCurrency();
      moho::register_TConVar_ai_InitialMassCurrencyMax();
      moho::register_TConVar_ren_ShadowBias();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsMisc4 gConsoleStartupRegistrationsMisc4;
} // namespace
