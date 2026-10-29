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
#include <stdexcept>
#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/exceptions/StdExcept.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/animation/CAniSkel.h"
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
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/misc/IConOutputHandler.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

namespace moho
{
  extern bool sPathDebuggerEnabled;
}

namespace moho
{
  [[nodiscard]] msvc8::string ToString(const Wm3::Vec3f& value);
}

bool moho::con_TestVarBool = false;
int moho::con_TestVar = 0;
std::uint8_t moho::con_TestVarUByte = 0;
float moho::con_TestVarFloat = 0.0f;

/**
 * Address: 0x00BC3AB0 (FUN_00BC3AB0, dynamic initializer for `con_TestVarStr`)
 * Address: 0x00BEED60 (FUN_00BEED60, dynamic atexit destructor for `con_TestVarStr`)
 */
msvc8::string moho::con_TestVarStr("string");
bool moho::snd_ExtraDoWorkCalls = true; // 0x00F58026
int moho::recon_debug = -1; // 0x00F58AC8 is initialised .data: -1, no army selected
bool moho::sPathDebuggerEnabled = false;
int moho::rule_Paranoid = 0;
float moho::rule_BlueprintReloadDelay = 0.5f; // 0x00F58CC0

// Issue-thread pacing convars, read by `CSimDriver::ThreadRun`. `net_Lag` is
// subtracted from how far ahead of the last executed beat the thread is
// willing to run, so raising it issues beats earlier; the debug level gates
// the thread's running/waiting/exiting trace.
int moho::sim_IssueThreadDebugLevel = 0;
// 0x00F58134 holds 500 in the shipped .data (read by `subss` at 0x0073C006).
// FAF's userInit.lua reports any change to it to moderators, so games run at 500.
float moho::net_Lag = 500.0f;

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

  /**
   * Address: 0x00BC3890 (FUN_00BC3890, dynamic initializer for `gSavedConsoleCommands`)
   * Address: 0x00BEEAF0 (FUN_00BEEAF0, dynamic atexit destructor for `gSavedConsoleCommands`)
   *
   * What it does:
   * Saved console-command history, newest first.
   */
  msvc8::vector<msvc8::string> gSavedConsoleCommands;

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


  void PrintLocalizedConsoleLine(const char* const locToken)
  {
    const msvc8::string localizedText = Loc(USER_GetLuaState(), locToken != nullptr ? locToken : "");
    CON_Printf("%s", localizedText.c_str());
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


  static_assert(sizeof(Wm3::Vector2f) == 0x8, "Wm3::Vector2f size must be 0x8");


  [[nodiscard]]
  msvc8::string JoinConCommandTokens(const msvc8::vector<msvc8::string>& args, const std::size_t firstTokenIndex)
  {
    const std::size_t count = args.size();
    if (firstTokenIndex >= count) {
      return {};
    }

    return AppendJoinedStringRange(args.data() + firstTokenIndex, args.data() + count, " ");
  }

  template <typename TValue, typename ParseFn>
  void ApplyIntegralConVarCommand(const msvc8::vector<msvc8::string>& args, TValue* value, ParseFn parseFn)
  {
    if (value == nullptr) {
      return;
    }

    const msvc8::string* const op = ConCommandArg(args, 1);
    const msvc8::string* const rhs = ConCommandArg(args, 2);

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
  void HandleBoolConVarCommand(const msvc8::vector<msvc8::string>& args, const char* name, bool* value)
  {
    if (value == nullptr) {
      return;
    }

    if (args.size() < 2) {
      *value = !*value;
      gpg::Logf("toggled %s is now %s", name ? name : "", *value ? "on" : "off");
      return;
    }

    const msvc8::string* const op = ConCommandArg(args, 1);
    const msvc8::string* const rhs = ConCommandArg(args, 2);

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
  void HandleIntConVarCommand(const msvc8::vector<msvc8::string>& args, int* value)
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
  void HandleUInt8ConVarCommand(const msvc8::vector<msvc8::string>& args, std::uint8_t* value)
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
  void HandleUInt32ConVarCommand(const msvc8::vector<msvc8::string>& args, std::uint32_t* value)
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
  void HandleFloatConVarCommand(const msvc8::vector<msvc8::string>& args, float* value)
  {
    if (value == nullptr) {
      return;
    }

    const msvc8::string* const op = ConCommandArg(args, 1);
    const msvc8::string* const rhs = ConCommandArg(args, 2);

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
  void HandleStringConVarCommand(const msvc8::vector<msvc8::string>& args, const char* name, msvc8::string* value)
  {
    if (value == nullptr) {
      return;
    }

    if (args.size() >= 2) {
      const msvc8::string* const op = ConCommandArg(args, 1);
      const msvc8::string* const rhs = ConCommandArg(args, 2);

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

  [[nodiscard]]
  CConCommand* FindRegisteredConCommand(const std::string_view commandName)
  {
    auto& registry = GetConsoleCommandRegistry();
    std::scoped_lock lock{registry.lock};
    return FindCommandInMap(registry.commandsByName, commandName);
  }
} // namespace

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
{
  if (mName != nullptr) {
    RegisterConCommand(*this);
  }
}

/**
 * Address: 0x0041E5A0 (FUN_0041E5A0)
 *
 * What it does:
 * Unregisters the command when it has a name.
 */
moho::CConCommand::~CConCommand()
{
  if (mName != nullptr) {
    UnregisterConCommand(*this);
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
  // FUN_0041F190: the clear+copy loop is `vector<string>::operator=`'s
  // assign-from-source shape (cited on `operator=` in legacy/containers/Vector.h).
  out = matches;
  return out;
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
        // A failing command is logged and the chain carries on (runtime_error,
        // try state 3 around the Handle call at 0x0041CE08, handler 0x0041CE16).
        try {
          command->Handle(parsedTokens);
        } catch (const msvc8::runtime_error& error) {
          gpg::Warnf("Error running console command %s: %s", commandText, error.what());
        }
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
void moho::CON_Echo(const msvc8::vector<msvc8::string>& args)
{
  if (args.size() < 2u) {
    return;
  }

  std::string text(ConCommandArg(args, 1)->view());
  for (std::size_t index = 2; index < args.size(); ++index) {
    const msvc8::string* const token = ConCommandArg(args, index);
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
void moho::CON_ListCommands(const msvc8::vector<msvc8::string>& args)
{
  (void)args;

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
void moho::CON_GetVersion(const msvc8::vector<msvc8::string>& args)
{
  (void)args;
  const msvc8::string engineVersion = moho::GetEngineVersion();
  CON_Printf("%s", engineVersion.c_str());
}

/**
 * Address: 0x004CDC90 (FUN_004CDC90, Moho::CON_LUADOC)
 *
 * What it does:
 * Iterates all registered Lua init-form sets and dumps their binder docs.
 */
void moho::CON_LUADOC(const msvc8::vector<msvc8::string>& args)
{
  (void)args;

  for (CScrLuaInitFormSet* initSet = CScrLuaInitFormSet::sSets; initSet != nullptr; initSet = initSet->mNextSet) {
    initSet->DumpDocs();
  }
}


/**
 * Address: 0x0047A670 (FUN_0047A670, Moho::CON_Log)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and emits one info-severity
 * log line.
 */
void moho::CON_Log(const msvc8::vector<msvc8::string>& args)
{
  const msvc8::string message = JoinConCommandTokens(args, 1u);
  gpg::Logf("%s", message.c_str());
}

/**
 * Address: 0x0047A700 (FUN_0047A700, Moho::CON_Debug_Warn)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and emits one warn-severity
 * log line.
 */
void moho::CON_Debug_Warn(const msvc8::vector<msvc8::string>& args)
{
  const msvc8::string message = JoinConCommandTokens(args, 1u);
  gpg::Warnf("%s", message.c_str());
}

/**
 * Address: 0x0047A790 (FUN_0047A790, Moho::CON_Debug_Error)
 *
 * What it does:
 * Joins command tokens from index 1 with spaces and terminates through
 * `gpg::Die("%s", ...)`.
 */
void moho::CON_Debug_Error(const msvc8::vector<msvc8::string>& args)
{
  const msvc8::string message = JoinConCommandTokens(args, 1u);
  gpg::Die("%s", message.c_str());
}

/**
 * Address: 0x0047A810 (FUN_0047A810, Moho::CON_Debug_Assert)
 *
 * What it does:
 * Debug no-op callback slot.
 */
void moho::CON_Debug_Assert(const msvc8::vector<msvc8::string>& args)
{
  (void)args;
}

/**
 * Address: 0x0047A820 (FUN_0047A820, Moho::CON_Debug_Crash)
 *
 * What it does:
 * Intentionally crashes by writing zero to absolute address 0.
 */
void moho::CON_Debug_Crash(const msvc8::vector<msvc8::string>& args)
{
  (void)args;
  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
}

/**
 * Address: 0x0047A830 (FUN_0047A830, Moho::CON_Debug_Throw)
 *
 * What it does:
 * Throws `std::exception` with fixed debug text.
 */
void moho::CON_Debug_Throw(const msvc8::vector<msvc8::string>& args)
{
  (void)args;
#if defined(_WIN32)
  throw std::exception("Hope you really wanted to do this...");
#else
  // Engine addition (dedicated-server plan WPL.5): std::exception has no message
  // constructor outside MSVC's library.
  throw std::runtime_error("Hope you really wanted to do this...");
#endif
}

/**
 * Address: 0x00500AF0 (FUN_00500AF0, Moho::CON_p4_Edit)
 *
 * What it does:
 * Emits one no-support line when called with a filespec argument; otherwise
 * prints command usage.
 */
void moho::CON_p4_Edit(const msvc8::vector<msvc8::string>& args)
{
  const msvc8::string* const commandToken = ConCommandArg(args, 0u);
  GPG_ASSERT(commandToken != nullptr);

  if (commandToken != nullptr && args.size() >= 2u) {
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
void moho::CON_p4_IsOpenedForEdit(const msvc8::vector<msvc8::string>& args)
{
  const msvc8::string* const commandToken = ConCommandArg(args, 0u);
  GPG_ASSERT(commandToken != nullptr);

  if (commandToken != nullptr && args.size() >= 2u) {
    CON_Printf("No P4 support in this build.");
    return;
  }

  CON_Printf("usage: %s <filespec> [user]", commandToken->c_str());
}


namespace
{


} // namespace


/**
 * Address: 0x008D3810 (FUN_008D3810, sub_8D3810)
 *
 * What it does:
 * Legacy startup callback lane for anti-aliasing command wiring: when exactly
 * two command tokens are present, forwards token `0` to
 * `d3d_AntiAliasingSamples`.
 */
void moho::CON_d3d_AntiAliasingSamplesSeedFromFirstToken(const msvc8::vector<msvc8::string>& args)
{
  if (args.size() != 2u) {
    return;
  }

  const msvc8::string* const sampleToken = ConCommandArg(args, 0u);
  if (sampleToken == nullptr) {
    return;
  }

  CON_Executef("d3d_AntiAliasingSamples %s", sampleToken->c_str());
}


namespace
{
} // namespace


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

/**
 * Address: 0x0041F9C0 (FUN_0041F9C0, sub_41F9C0)
 * Address: 0x1001ED50 (FUN_1001ED50)
 *
 * What it does:
 * Dispatches bool convar command parsing and mutation.
 */
template <>
void moho::TConVar<bool>::Handle(const msvc8::vector<msvc8::string>& args)
{
  HandleBoolConVarCommand(args, mName, mValue);
}

/**
 * Address: 0x0041FA10 (FUN_0041FA10, sub_41FA10)
 * Address: 0x1001EDB0 (FUN_1001EDB0)
 *
 * What it does:
 * Handles int convar command; prints current value when no RHS command args are provided.
 */
template <>
void moho::TConVar<int>::Handle(const msvc8::vector<msvc8::string>& args)
{
  int* const value = mValue;
  if (value == nullptr) {
    return;
  }

  if (args.size() >= 2) {
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
void moho::TConVar<std::uint8_t>::Handle(const msvc8::vector<msvc8::string>& args)
{
  std::uint8_t* const value = mValue;
  if (value == nullptr) {
    return;
  }

  if (args.size() >= 2) {
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
void moho::TConVar<float>::Handle(const msvc8::vector<msvc8::string>& args)
{
  float* const value = mValue;
  if (value == nullptr) {
    return;
  }

  if (args.size() >= 2) {
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
void moho::TConVar<std::uint32_t>::Handle(const msvc8::vector<msvc8::string>& args)
{
  std::uint32_t* const value = mValue;
  if (value == nullptr) {
    return;
  }

  if (args.size() >= 2) {
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
void moho::TConVar<msvc8::string>::Handle(const msvc8::vector<msvc8::string>& args)
{
  HandleStringConVarCommand(args, mName, mValue);
}

namespace
{
  constexpr const char* kConsoleStartupTestVarDescription = "Test variable - not used.";
  constexpr const char* kConsoleStartupSndExtraDoWorkCallsDescription = "Enable mid-frame DoWork calls.";
  constexpr const char* kConsoleStartupConEchoDescription = "Echo out input to function.";
  constexpr const char* kConsoleStartupConListCommandsDescription = "List all console commands and variables.";
  constexpr const char* kConsoleStartupConLuaDocDescription = "Dump out documentation for Lua functions";
  constexpr const char* kConsoleStartupConGetVersionDescription = "Get game version";
  constexpr const char* kConsoleStartupConExecuteLastCommandDescription = "Repeat the last command.";
  constexpr const char* kConsoleStartupConPrintStatsDescription = "Test the stat system";
  constexpr const char* kConsoleStartupConClearStatsDescription = "Clear stats starting with given parent";
  constexpr const char* kConsoleStartupConBeginLoggingStatsDescription = "Begin logging stats";
  constexpr const char* kConsoleStartupConEndLoggingStatsDescription = "End logging stats";
  constexpr const char* kConsoleStartupConLogDescription = "Log a string (for debugging purposes)";
  constexpr const char* kConsoleStartupConDebugWarnDescription = "Log a warning string (for debugging purposes)";
  constexpr const char* kConsoleStartupConDebugErrorDescription = "Log an error string (for debugging purposes)";
  constexpr const char* kConsoleStartupConDebugAssertDescription = "Fail an assertion (for debugging purposes)";
  constexpr const char* kConsoleStartupConDebugCrashDescription = "Cause a crash (for debugging purposes)";
  constexpr const char* kConsoleStartupConDebugThrowDescription = "Throw a std::exception.";
  constexpr const char* kConsoleStartupConP4EditDescription = "Check out file(s) from perfoce";
  constexpr const char* kConsoleStartupConP4IsOpenedForEditDescription =
    "Is the specified file opened for edit?";
  constexpr const char* kConsoleStartupReconDebugDescription = "Show debug recon info for specified army index";
  constexpr const char* kConsoleStartupRuleParanoidDescription =
    "Paranoid mode for RULE system, print all error messages.";
  constexpr const char* kConsoleStartupRuleBlueprintReloadDelayDescription =
    "seconds to delay before reloading a blueprint once we notice that it has changed.";

  /**
   * Address: 0x00BC3910 (FUN_00BC3910, dynamic initializer for `gCConFunc_CON_Echo`)
   * Address: 0x00BEEC10 (FUN_00BEEC10, dynamic atexit destructor for `gCConFunc_CON_Echo`)
   */
  CConFunc gCConFunc_CON_Echo("CON_Echo", kConsoleStartupConEchoDescription, &moho::CON_Echo);

  /**
   * Address: 0x00BC3950 (FUN_00BC3950, dynamic initializer for `gCConFunc_CON_ListCommands`)
   * Address: 0x00BEEC40 (FUN_00BEEC40, dynamic atexit destructor for `gCConFunc_CON_ListCommands`)
   */
  CConFunc gCConFunc_CON_ListCommands("CON_ListCommands", kConsoleStartupConListCommandsDescription, &moho::CON_ListCommands);

  /**
   * Address: 0x00BC3440 (FUN_00BC3440, dynamic initializer for `gCConFunc_PrintStats`)
   * Address: 0x00BEE7F0 (FUN_00BEE7F0, dynamic atexit destructor for `gCConFunc_PrintStats`)
   */
  CConFunc gCConFunc_PrintStats("PrintStats", kConsoleStartupConPrintStatsDescription, &moho::CON_PrintStats);

  /**
   * Address: 0x00BC3480 (FUN_00BC3480, dynamic initializer for `gCConFunc_ClearStats`)
   * Address: 0x00BEE820 (FUN_00BEE820, dynamic atexit destructor for `gCConFunc_ClearStats`)
   */
  CConFunc gCConFunc_ClearStats("ClearStats", kConsoleStartupConClearStatsDescription, &moho::CON_ClearStats);

  /**
   * Address: 0x00BC34C0 (FUN_00BC34C0, dynamic initializer for `gCConFunc_BeginLoggingStats`)
   * Address: 0x00BEE850 (FUN_00BEE850, dynamic atexit destructor for `gCConFunc_BeginLoggingStats`)
   */
  CConFunc gCConFunc_BeginLoggingStats("BeginLoggingStats", kConsoleStartupConBeginLoggingStatsDescription, &moho::CON_BeginLoggingStats);

  /**
   * Address: 0x00BC3500 (FUN_00BC3500, dynamic initializer for `gCConFunc_EndLoggingStats`)
   * Address: 0x00BEE880 (FUN_00BEE880, dynamic atexit destructor for `gCConFunc_EndLoggingStats`)
   */
  CConFunc gCConFunc_EndLoggingStats("EndLoggingStats", kConsoleStartupConEndLoggingStatsDescription, &moho::CON_EndLoggingStats);

  /**
   * Address: 0x00BC6450 (FUN_00BC6450, dynamic initializer for `gCConFunc_LUADOC`)
   * Address: 0x00BF0C90 (FUN_00BF0C90, dynamic atexit destructor for `gCConFunc_LUADOC`)
   */
  CConFunc gCConFunc_LUADOC("LUADOC", kConsoleStartupConLuaDocDescription, &moho::CON_LUADOC);


  /**
   * Address: 0x00BC6630 (FUN_00BC6630, dynamic initializer for `gCConFunc_GetVersion`)
   * Address: 0x00BF0D10 (FUN_00BF0D10, dynamic atexit destructor for `gCConFunc_GetVersion`)
   */
  CConFunc gCConFunc_GetVersion("GetVersion", kConsoleStartupConGetVersionDescription, &moho::CON_GetVersion);

  /**
   * Address: 0x00BC3990 (FUN_00BC3990, dynamic initializer for `gCConFunc_CON_ExecuteLastCommand`)
   * Address: 0x00BEEC70 (FUN_00BEEC70, dynamic atexit destructor for `gCConFunc_CON_ExecuteLastCommand`)
   */
  CConFunc gCConFunc_CON_ExecuteLastCommand("CON_ExecuteLastCommand", kConsoleStartupConExecuteLastCommandDescription, reinterpret_cast<CConFunc::Callback>(&moho::CON_ExecuteLastCommand));


  /**
   * Address: 0x00BC4B70 (FUN_00BC4B70, dynamic initializer for `gCConFunc_Log`)
   * Address: 0x00BEF8C0 (FUN_00BEF8C0, dynamic atexit destructor for `gCConFunc_Log`)
   */
  CConFunc gCConFunc_Log("Log", kConsoleStartupConLogDescription, &CON_Log);

  /**
   * Address: 0x00BC4BB0 (FUN_00BC4BB0, dynamic initializer for `gCConFunc_Debug_Warn`)
   * Address: 0x00BEF8F0 (FUN_00BEF8F0, dynamic atexit destructor for `gCConFunc_Debug_Warn`)
   */
  CConFunc gCConFunc_Debug_Warn("Debug_Warn", kConsoleStartupConDebugWarnDescription, &CON_Debug_Warn);

  /**
   * Address: 0x00BC4BF0 (FUN_00BC4BF0, dynamic initializer for `gCConFunc_Debug_Error`)
   * Address: 0x00BEF920 (FUN_00BEF920, dynamic atexit destructor for `gCConFunc_Debug_Error`)
   */
  CConFunc gCConFunc_Debug_Error("Debug_Error", kConsoleStartupConDebugErrorDescription, &CON_Debug_Error);

  /**
   * Address: 0x00BC4C30 (FUN_00BC4C30, dynamic initializer for `gCConFunc_Debug_Assert`)
   * Address: 0x00BEF950 (FUN_00BEF950, dynamic atexit destructor for `gCConFunc_Debug_Assert`)
   */
  CConFunc gCConFunc_Debug_Assert("Debug_Assert", kConsoleStartupConDebugAssertDescription, &CON_Debug_Assert);

  /**
   * Address: 0x00BC4C70 (FUN_00BC4C70, dynamic initializer for `gCConFunc_Debug_Crash`)
   * Address: 0x00BEF980 (FUN_00BEF980, dynamic atexit destructor for `gCConFunc_Debug_Crash`)
   */
  CConFunc gCConFunc_Debug_Crash("Debug_Crash", kConsoleStartupConDebugCrashDescription, &CON_Debug_Crash);

  /**
   * Address: 0x00BC4CB0 (FUN_00BC4CB0, dynamic initializer for `gCConFunc_Debug_Throw`)
   * Address: 0x00BEF9B0 (FUN_00BEF9B0, dynamic atexit destructor for `gCConFunc_Debug_Throw`)
   */
  CConFunc gCConFunc_Debug_Throw("Debug_Throw", kConsoleStartupConDebugThrowDescription, &CON_Debug_Throw);


  /**
   * Address: 0x00BC76F0 (FUN_00BC76F0, dynamic initializer for `gCConFunc_p4_Edit`)
   * Address: 0x00BF1C20 (FUN_00BF1C20, dynamic atexit destructor for `gCConFunc_p4_Edit`)
   */
  CConFunc gCConFunc_p4_Edit("p4_Edit", kConsoleStartupConP4EditDescription, &moho::CON_p4_Edit);

  /**
   * Address: 0x00BC7730 (FUN_00BC7730, dynamic initializer for `gCConFunc_p4_IsOpenedForEdit`)
   * Address: 0x00BF1C50 (FUN_00BF1C50, dynamic atexit destructor for `gCConFunc_p4_IsOpenedForEdit`)
   */
  CConFunc gCConFunc_p4_IsOpenedForEdit("p4_IsOpenedForEdit", kConsoleStartupConP4IsOpenedForEditDescription, &moho::CON_p4_IsOpenedForEdit);


  /**
   * Address: 0x00BC39D0 (FUN_00BC39D0, dynamic initializer for `gTConVar_con_TestVarBool`)
   * Address: 0x00BEECA0 (FUN_00BEECA0, dynamic atexit destructor for `gTConVar_con_TestVarBool`)
   */
  TConVar<bool> gTConVar_con_TestVarBool(
    "con_TestVarBool",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarBool
  );

  /**
   * Address: 0x00BC3A10 (FUN_00BC3A10, dynamic initializer for `gTConVar_con_TestVar`)
   * Address: 0x00BEECD0 (FUN_00BEECD0, dynamic atexit destructor for `gTConVar_con_TestVar`)
   */
  TConVar<int> gTConVar_con_TestVar("con_TestVar", kConsoleStartupTestVarDescription, &moho::con_TestVar);

  /**
   * Address: 0x00BC3A70 (FUN_00BC3A70, dynamic initializer for `gTConVar_con_TestVarFloat`)
   * Address: 0x00BEED30 (FUN_00BEED30, dynamic atexit destructor for `gTConVar_con_TestVarFloat`)
   */
  TConVar<float> gTConVar_con_TestVarFloat(
    "con_TestVarFloat",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarFloat
  );

  /**
   * Address: 0x00BC3AD0 (FUN_00BC3AD0, dynamic initializer for `gTConVar_con_TestVarStr`)
   * Address: 0x00BEED90 (FUN_00BEED90, dynamic atexit destructor for `gTConVar_con_TestVarStr`)
   */
  TConVar<msvc8::string> gTConVar_con_TestVarStr(
    "con_TestVarStr",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarStr
  );

  /**
   * Address: 0x00BCDB70 (FUN_00BCDB70, dynamic initializer for `gTConVar_recon_debug`)
   * Address: 0x00BF77B0 (FUN_00BF77B0, dynamic atexit destructor for `gTConVar_recon_debug`)
   */
  TConVar<int> gTConVar_recon_debug("recon_debug", kConsoleStartupReconDebugDescription, &moho::recon_debug);

  /**
   * Address: 0x00BC8DC0 (FUN_00BC8DC0, dynamic initializer for `gTConVar_rule_Paranoid`)
   * Address: 0x00BF3950 (FUN_00BF3950, dynamic atexit destructor for `gTConVar_rule_Paranoid`)
   */
  TConVar<int> gTConVar_rule_Paranoid(
    "rule_Paranoid",
    kConsoleStartupRuleParanoidDescription,
    &moho::rule_Paranoid
  );

  /**
   * Address: 0x00BC8E00 (FUN_00BC8E00, dynamic initializer for `gTConVar_rule_BlueprintReloadDelay`)
   * Address: 0x00BF3980 (FUN_00BF3980, dynamic atexit destructor for `gTConVar_rule_BlueprintReloadDelay`)
   */
  TConVar<float> gTConVar_rule_BlueprintReloadDelay(
    "rule_BlueprintReloadDelay",
    kConsoleStartupRuleBlueprintReloadDelayDescription,
    &moho::rule_BlueprintReloadDelay
  );


  /**
   * Address: 0x00BC6780 (FUN_00BC6780, dynamic initializer for `gTConVar_snd_ExtraDoWorkCalls`)
   * Address: 0x00BF0D80 (FUN_00BF0D80, dynamic atexit destructor for `gTConVar_snd_ExtraDoWorkCalls`)
   */
  TConVar<bool> gTConVar_snd_ExtraDoWorkCalls(
    "snd_ExtraDoWorkCalls",
    kConsoleStartupSndExtraDoWorkCallsDescription,
    &moho::snd_ExtraDoWorkCalls
  );

  /**
   * Address: 0x00BC3A50 (FUN_00BC3A50, dynamic initializer for `gTConVar_con_TestVarUByte`)
   * Address: 0x0041FA70 (FUN_0041FA70, the initializer's constructor call:
   *   `TConVar<uint8_t>`'s constructor cloned with `this` bound to this global)
   * Address: 0x00BEED00 (FUN_00BEED00, dynamic atexit destructor for `gTConVar_con_TestVarUByte`)
   */
  TConVar<std::uint8_t> gTConVar_con_TestVarUByte(
    "con_TestVarUByte",
    kConsoleStartupTestVarDescription,
    &moho::con_TestVarUByte
  );
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
  /**
   * Address: 0x00BDCFB0 (FUN_00BDCFB0, dynamic initializer for `gTConVar_ai_InitialEnergyCurrency`)
   * Address: 0x00C02130 (FUN_00C02130, dynamic atexit destructor for `gTConVar_ai_InitialEnergyCurrency`)
   */
  TConVar<float> gTConVar_ai_InitialEnergyCurrency(
    "ai_InitialEnergyCurrency",
    kConsoleStartupAiInitialEnergyCurrencyDescription,
    &moho::ai_InitialEnergyCurrency
  );

  /**
   * Address: 0x00BDD030 (FUN_00BDD030, dynamic initializer for `gTConVar_ai_InitialEnergyCurrencyMax`)
   * Address: 0x00C02190 (FUN_00C02190, dynamic atexit destructor for `gTConVar_ai_InitialEnergyCurrencyMax`)
   */
  TConVar<float> gTConVar_ai_InitialEnergyCurrencyMax(
    "ai_InitialEnergyCurrencyMax",
    kConsoleStartupAiInitialEnergyCurrencyMaxDescription,
    &moho::ai_InitialEnergyCurrencyMax
  );

} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupNetLagDescription = "Lag, in milliseconds.";
} // namespace

// The other net_* convars (0x00BC4E70..0x00BC5130) are registered once, in net/NetConVars.cpp.
namespace moho
{
  /**
   * Address: 0x00BDB8E0 (FUN_00BDB8E0, dynamic initializer for `gTConVar_net_Lag`)
   * Address: 0x00C00C00 (FUN_00C00C00, dynamic atexit destructor for `gTConVar_net_Lag`)
   */
  TConVar<float> gTConVar_net_Lag(
    "net_Lag",
    kConsoleStartupNetLagDescription,
    &moho::net_Lag
  );

} // namespace moho


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

  /**
   * Address: 0x00BDBA50 (FUN_00BDBA50, dynamic initializer for `gTConVar_sim_DebugCheats`)
   * Address: 0x00C00CE0 (FUN_00C00CE0, dynamic atexit destructor for `gTConVar_sim_DebugCheats`)
   */
  TConVar<bool> gTConVar_sim_DebugCheats(
    "sim_DebugCheats",
    kConsoleStartupSimDebugCheatsDescription,
    &moho::sim_DebugCheats
  );

  /**
   * Address: 0x00BDB920 (FUN_00BDB920, dynamic initializer for `gTConVar_sim_DebugDelay`)
   * Address: 0x00C00C30 (FUN_00C00C30, dynamic atexit destructor for `gTConVar_sim_DebugDelay`)
   */
  TConVar<int> gTConVar_sim_DebugDelay(
    "sim_DebugDelay",
    kConsoleStartupSimDebugDelayDescription,
    &moho::sim_DebugDelay
  );

  /**
   * Address: 0x00BDB860 (FUN_00BDB860, dynamic initializer for `gTConVar_sim_Interlocked`)
   * Address: 0x00C00BA0 (FUN_00C00BA0, dynamic atexit destructor for `gTConVar_sim_Interlocked`)
   */
  TConVar<bool> gTConVar_sim_Interlocked(
    "sim_Interlocked",
    kConsoleStartupSimInterlockedDescription,
    &moho::sim_Interlocked
  );

  /**
   * Address: 0x00BDB8A0 (FUN_00BDB8A0, dynamic initializer for `gTConVar_sim_IssueThreadDebugLevel`)
   * Address: 0x00C00BD0 (FUN_00C00BD0, dynamic atexit destructor for `gTConVar_sim_IssueThreadDebugLevel`)
   */
  TConVar<int> gTConVar_sim_IssueThreadDebugLevel(
    "sim_IssueThreadDebugLevel",
    kConsoleStartupSimIssueThreadDebugLevelDescription,
    &moho::sim_IssueThreadDebugLevel
  );

  /**
   * Address: 0x00BDBA10 (FUN_00BDBA10, dynamic initializer for `gTConVar_sim_KeepAllLogFiles`)
   * Address: 0x00C00CB0 (FUN_00C00CB0, dynamic atexit destructor for `gTConVar_sim_KeepAllLogFiles`)
   */
  TConVar<bool> gTConVar_sim_KeepAllLogFiles(
    "sim_KeepAllLogFiles",
    kConsoleStartupSimKeepAllLogFilesDescription,
    &moho::sim_KeepAllLogFiles
  );

  /**
   * Address: 0x00BDB9D0 (FUN_00BDB9D0, dynamic initializer for `gTConVar_sim_LogSize`)
   * Address: 0x00C00C80 (FUN_00C00C80, dynamic atexit destructor for `gTConVar_sim_LogSize`)
   */
  TConVar<int> gTConVar_sim_LogSize(
    "sim_LogSize",
    kConsoleStartupSimLogSizeDescription,
    &moho::sim_LogSize
  );

  /**
   * Address: 0x00BDBA90 (FUN_00BDBA90, dynamic initializer for `gTConVar_sim_ReportCheats`)
   * Address: 0x00C00D10 (FUN_00C00D10, dynamic atexit destructor for `gTConVar_sim_ReportCheats`)
   */
  TConVar<bool> gTConVar_sim_ReportCheats(
    "sim_ReportCheats",
    kConsoleStartupSimReportCheatsDescription,
    &moho::sim_ReportCheats
  );

  /**
   * Address: 0x00BDB6B0 (FUN_00BDB6B0, dynamic initializer for `gTConVar_sim_ShowDamage`)
   * Address: 0x00C00AE0 (FUN_00C00AE0, dynamic atexit destructor for `gTConVar_sim_ShowDamage`)
   */
  TConVar<bool> gTConVar_sim_ShowDamage(
    "sim_ShowDamage",
    kConsoleStartupSimShowDamageDescription,
    &moho::sim_ShowDamage
  );

} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupCamEntityBoxExpandDescription = "How much to expand the entity box when targetting entity";
  constexpr const char* kConsoleStartupCamFarFOVDescription = "FOV to use for perspective camera at farthest zoom, in degrees";
  constexpr const char* kConsoleStartupCamFarPitchDescription = "Pitch of camera at farthest zoom, in degrees";
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
  extern float cam_EntityBoxExpand;
  extern float cam_FarFOV;
  extern float cam_FarPitch;
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


  /**
   * Address: 0x00BDF540 (FUN_00BDF540, dynamic initializer for `gTConVar_cam_EntityBoxExpand`)
   * Address: 0x00C03550 (FUN_00C03550, dynamic atexit destructor for `gTConVar_cam_EntityBoxExpand`)
   */
  TConVar<float> gTConVar_cam_EntityBoxExpand(
    "cam_EntityBoxExpand",
    kConsoleStartupCamEntityBoxExpandDescription,
    &moho::cam_EntityBoxExpand
  );

  /**
   * Address: 0x00BDF2C0 (FUN_00BDF2C0, dynamic initializer for `gTConVar_cam_FarFOV`)
   * Address: 0x00C03370 (FUN_00C03370, dynamic atexit destructor for `gTConVar_cam_FarFOV`)
   */
  TConVar<float> gTConVar_cam_FarFOV(
    "cam_FarFOV",
    kConsoleStartupCamFarFOVDescription,
    &moho::cam_FarFOV
  );

  /**
   * Address: 0x00BDF340 (FUN_00BDF340, dynamic initializer for `gTConVar_cam_FarPitch`)
   * Address: 0x00C033D0 (FUN_00C033D0, dynamic atexit destructor for `gTConVar_cam_FarPitch`)
   */
  TConVar<float> gTConVar_cam_FarPitch(
    "cam_FarPitch",
    kConsoleStartupCamFarPitchDescription,
    &moho::cam_FarPitch
  );


  /**
   * Address: 0x00BDF580 (FUN_00BDF580, dynamic initializer for `gTConVar_cam_MinSpinPitch`)
   * Address: 0x00C03580 (FUN_00C03580, dynamic atexit destructor for `gTConVar_cam_MinSpinPitch`)
   */
  TConVar<float> gTConVar_cam_MinSpinPitch(
    "cam_MinSpinPitch",
    kConsoleStartupCamMinSpinPitchDescription,
    &moho::cam_MinSpinPitch
  );

  /**
   * Address: 0x00BDF280 (FUN_00BDF280, dynamic initializer for `gTConVar_cam_NearFOV`)
   * Address: 0x00C03340 (FUN_00C03340, dynamic atexit destructor for `gTConVar_cam_NearFOV`)
   */
  TConVar<float> gTConVar_cam_NearFOV(
    "cam_NearFOV",
    kConsoleStartupCamNearFOVDescription,
    &moho::cam_NearFOV
  );

  /**
   * Address: 0x00BDF300 (FUN_00BDF300, dynamic initializer for `gTConVar_cam_NearPitch`)
   * Address: 0x00C033A0 (FUN_00C033A0, dynamic atexit destructor for `gTConVar_cam_NearPitch`)
   */
  TConVar<float> gTConVar_cam_NearPitch(
    "cam_NearPitch",
    kConsoleStartupCamNearPitchDescription,
    &moho::cam_NearPitch
  );

  /**
   * Address: 0x00BDF240 (FUN_00BDF240, dynamic initializer for `gTConVar_cam_NearZoom`)
   * Address: 0x00C03310 (FUN_00C03310, dynamic atexit destructor for `gTConVar_cam_NearZoom`)
   */
  TConVar<float> gTConVar_cam_NearZoom(
    "cam_NearZoom",
    kConsoleStartupCamNearZoomDescription,
    &moho::cam_NearZoom
  );

  /**
   * Address: 0x00BDF4C0 (FUN_00BDF4C0, dynamic initializer for `gTConVar_cam_PanSpeed`)
   * Address: 0x00C034F0 (FUN_00C034F0, dynamic atexit destructor for `gTConVar_cam_PanSpeed`)
   */
  TConVar<float> gTConVar_cam_PanSpeed(
    "cam_PanSpeed",
    kConsoleStartupCamPanSpeedDescription,
    &moho::cam_PanSpeed
  );

  /**
   * Address: 0x00BDF500 (FUN_00BDF500, dynamic initializer for `gTConVar_cam_ShakeMult`)
   * Address: 0x00C03520 (FUN_00C03520, dynamic atexit destructor for `gTConVar_cam_ShakeMult`)
   */
  TConVar<float> gTConVar_cam_ShakeMult(
    "cam_ShakeMult",
    kConsoleStartupCamShakeMultDescription,
    &moho::cam_ShakeMult
  );

  /**
   * Address: 0x00BDF480 (FUN_00BDF480, dynamic initializer for `gTConVar_cam_SpinSpeed`)
   * Address: 0x00C034C0 (FUN_00C034C0, dynamic atexit destructor for `gTConVar_cam_SpinSpeed`)
   */
  TConVar<float> gTConVar_cam_SpinSpeed(
    "cam_SpinSpeed",
    kConsoleStartupCamSpinSpeedDescription,
    &moho::cam_SpinSpeed
  );

  /**
   * Address: 0x00BDF440 (FUN_00BDF440, dynamic initializer for `gTConVar_cam_TrackProjectileTimeout`)
   * Address: 0x00C03490 (FUN_00C03490, dynamic atexit destructor for `gTConVar_cam_TrackProjectileTimeout`)
   */
  TConVar<float> gTConVar_cam_TrackProjectileTimeout(
    "cam_TrackProjectileTimeout",
    kConsoleStartupCamTrackProjectileTimeoutDescription,
    &moho::cam_TrackProjectileTimeout
  );

  /**
   * Address: 0x00BDF380 (FUN_00BDF380, dynamic initializer for `gTConVar_cam_ZoomAmount`)
   * Address: 0x00C03400 (FUN_00C03400, dynamic atexit destructor for `gTConVar_cam_ZoomAmount`)
   */
  TConVar<float> gTConVar_cam_ZoomAmount(
    "cam_ZoomAmount",
    kConsoleStartupCamZoomAmountDescription,
    &moho::cam_ZoomAmount
  );

  /**
   * Address: 0x00BDF400 (FUN_00BDF400, dynamic initializer for `gTConVar_cam_ZoomSpeedLarge`)
   * Address: 0x00C03460 (FUN_00C03460, dynamic atexit destructor for `gTConVar_cam_ZoomSpeedLarge`)
   */
  TConVar<float> gTConVar_cam_ZoomSpeedLarge(
    "cam_ZoomSpeedLarge",
    kConsoleStartupCamZoomSpeedLargeDescription,
    &moho::cam_ZoomSpeedLarge
  );

  /**
   * Address: 0x00BDF3C0 (FUN_00BDF3C0, dynamic initializer for `gTConVar_cam_ZoomSpeedSmall`)
   * Address: 0x00C03430 (FUN_00C03430, dynamic atexit destructor for `gTConVar_cam_ZoomSpeedSmall`)
   */
  TConVar<float> gTConVar_cam_ZoomSpeedSmall(
    "cam_ZoomSpeedSmall",
    kConsoleStartupCamZoomSpeedSmallDescription,
    &moho::cam_ZoomSpeedSmall
  );

} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupDbgMetronomeDescription = "Tick a metronome every tick.";
  constexpr const char* kConsoleStartupDbgMonitorAddressSpaceDescription = "If true, monitor address space usage.";
  constexpr const char* kConsoleStartupDebugMovieDescription = "debug movie output";
  constexpr const char* kConsoleStartupDumpRateDescription = "Frame rate to use for movie dumps";
  constexpr const char* kConsoleStartupEdEnableHookDescription = "";
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
  extern bool ed_EnableHook;
  extern bool fog_DistanceFog;
  extern float fog_OffsetMultiplier;
  extern bool snd_CheckDistance;
  extern bool snd_CheckLOS;
  extern bool snd_SpewSound;
  extern bool wld_RunWithTheWind;
  extern float wld_SkewRateAdjustBase;
  extern float wld_SkewRateAdjustMax;

  /**
   * Address: 0x00BE76F0 (FUN_00BE76F0, dynamic initializer for `gTConVar_dbg_Metronome`)
   * Address: 0x00C08160 (FUN_00C08160, dynamic atexit destructor for `gTConVar_dbg_Metronome`)
   */
  TConVar<bool> gTConVar_dbg_Metronome(
    "dbg_Metronome",
    kConsoleStartupDbgMetronomeDescription,
    &moho::dbg_Metronome
  );

  /**
   * Address: 0x00BE8F60 (FUN_00BE8F60, dynamic initializer for `gTConVar_dbg_MonitorAddressSpace`)
   * Address: 0x00C08C10 (FUN_00C08C10, dynamic atexit destructor for `gTConVar_dbg_MonitorAddressSpace`)
   */
  TConVar<bool> gTConVar_dbg_MonitorAddressSpace(
    "dbg_MonitorAddressSpace",
    kConsoleStartupDbgMonitorAddressSpaceDescription,
    &moho::dbg_MonitorAddressSpace
  );

  /**
   * Address: 0x00BE6C40 (FUN_00BE6C40, dynamic initializer for `gTConVar_debug_movie`)
   * Address: 0x00C07B10 (FUN_00C07B10, dynamic atexit destructor for `gTConVar_debug_movie`)
   */
  TConVar<bool> gTConVar_debug_movie(
    "debug_movie",
    kConsoleStartupDebugMovieDescription,
    &moho::debug_movie
  );

  /**
   * Address: 0x00BE0F10 (FUN_00BE0F10, dynamic initializer for `gTConVar_dump_Rate`)
   * Address: 0x00C04210 (FUN_00C04210, dynamic atexit destructor for `gTConVar_dump_Rate`)
   */
  TConVar<float> gTConVar_dump_Rate(
    "dump_Rate",
    kConsoleStartupDumpRateDescription,
    &moho::dump_Rate
  );


  /**
   * Address: 0x00BE1A10 (FUN_00BE1A10, dynamic initializer for `gTConVar_ed_EnableHook`)
   * Address: 0x00C04990 (FUN_00C04990, dynamic atexit destructor for `gTConVar_ed_EnableHook`)
   */
  TConVar<bool> gTConVar_ed_EnableHook(
    "ed_EnableHook",
    kConsoleStartupEdEnableHookDescription,
    &moho::ed_EnableHook
  );

  /**
   * Address: 0x00BE71B0 (FUN_00BE71B0, dynamic initializer for `gTConVar_efx_WaveCutoff`)
   * Address: 0x00C07E60 (FUN_00C07E60, dynamic atexit destructor for `gTConVar_efx_WaveCutoff`)
   */
  TConVar<float> gTConVar_efx_WaveCutoff(
    "efx_WaveCutoff",
    kConsoleStartupEfxWaveCutoffDescription,
    &moho::efx_WaveCutoff
  );

  /**
   * Address: 0x00BE16D0 (FUN_00BE16D0, dynamic initializer for `gTConVar_fog_DistanceFog`)
   * Address: 0x00C04720 (FUN_00C04720, dynamic atexit destructor for `gTConVar_fog_DistanceFog`)
   */
  TConVar<bool> gTConVar_fog_DistanceFog(
    "fog_DistanceFog",
    kConsoleStartupFogDistanceFogDescription,
    &moho::fog_DistanceFog
  );

  /**
   * Address: 0x00BE1C10 (FUN_00BE1C10, dynamic initializer for `gTConVar_fog_OffsetMultiplier`)
   * Address: 0x00C04B10 (FUN_00C04B10, dynamic atexit destructor for `gTConVar_fog_OffsetMultiplier`)
   */
  TConVar<float> gTConVar_fog_OffsetMultiplier(
    "fog_OffsetMultiplier",
    kConsoleStartupFogOffsetMultiplierDescription,
    &moho::fog_OffsetMultiplier
  );

  /**
   * Address: 0x00BE8DA0 (FUN_00BE8DA0, dynamic initializer for `gTConVar_sc_FrameTimeClamp`)
   * Address: 0x00C08AC0 (FUN_00C08AC0, dynamic atexit destructor for `gTConVar_sc_FrameTimeClamp`)
   */
  TConVar<float> gTConVar_sc_FrameTimeClamp(
    "sc_FrameTimeClamp",
    kConsoleStartupScFrameTimeClampDescription,
    &moho::sc_FrameTimeClamp
  );

  /**
   * Address: 0x00BE8D60 (FUN_00BE8D60, dynamic initializer for `gTConVar_sc_SkipIntro`)
   * Address: 0x00C08A90 (FUN_00C08A90, dynamic atexit destructor for `gTConVar_sc_SkipIntro`)
   */
  TConVar<bool> gTConVar_sc_SkipIntro(
    "sc_SkipIntro",
    kConsoleStartupScSkipIntroDescription,
    &moho::sc_SkipIntro
  );

  /**
   * Address: 0x00BE7E40 (FUN_00BE7E40, dynamic initializer for `gTConVar_snd_CheckDistance`)
   * Address: 0x00C08520 (FUN_00C08520, dynamic atexit destructor for `gTConVar_snd_CheckDistance`)
   */
  TConVar<bool> gTConVar_snd_CheckDistance(
    "snd_CheckDistance",
    kConsoleStartupSndCheckDistanceDescription,
    &moho::snd_CheckDistance
  );

  /**
   * Address: 0x00BE7E80 (FUN_00BE7E80, dynamic initializer for `gTConVar_snd_CheckLOS`)
   * Address: 0x00C08550 (FUN_00C08550, dynamic atexit destructor for `gTConVar_snd_CheckLOS`)
   */
  TConVar<bool> gTConVar_snd_CheckLOS(
    "snd_CheckLOS",
    kConsoleStartupSndCheckLOSDescription,
    &moho::snd_CheckLOS
  );

  /**
   * Address: 0x00BE7EC0 (FUN_00BE7EC0, dynamic initializer for `gTConVar_snd_SpewSound`)
   * Address: 0x00C08580 (FUN_00C08580, dynamic atexit destructor for `gTConVar_snd_SpewSound`)
   */
  TConVar<bool> gTConVar_snd_SpewSound(
    "snd_SpewSound",
    kConsoleStartupSndSpewSoundDescription,
    &moho::snd_SpewSound
  );

  /**
   * Address: 0x00BE7730 (FUN_00BE7730, dynamic initializer for `gTConVar_wld_RunWithTheWind`)
   * Address: 0x00C08190 (FUN_00C08190, dynamic atexit destructor for `gTConVar_wld_RunWithTheWind`)
   */
  TConVar<bool> gTConVar_wld_RunWithTheWind(
    "wld_RunWithTheWind",
    kConsoleStartupWldRunWithTheWindDescription,
    &moho::wld_RunWithTheWind
  );

  /**
   * Address: 0x00BE7290 (FUN_00BE7290, dynamic initializer for `gTConVar_wld_SkewRateAdjustBase`)
   * Address: 0x00C07F00 (FUN_00C07F00, dynamic atexit destructor for `gTConVar_wld_SkewRateAdjustBase`)
   */
  TConVar<float> gTConVar_wld_SkewRateAdjustBase(
    "wld_SkewRateAdjustBase",
    kConsoleStartupWldSkewRateAdjustBaseDescription,
    &moho::wld_SkewRateAdjustBase
  );

  /**
   * Address: 0x00BE72D0 (FUN_00BE72D0, dynamic initializer for `gTConVar_wld_SkewRateAdjustMax`)
   * Address: 0x00C07F30 (FUN_00C07F30, dynamic atexit destructor for `gTConVar_wld_SkewRateAdjustMax`)
   */
  TConVar<float> gTConVar_wld_SkewRateAdjustMax(
    "wld_SkewRateAdjustMax",
    kConsoleStartupWldSkewRateAdjustMaxDescription,
    &moho::wld_SkewRateAdjustMax
  );


} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupUIShowControlUnderMouseDescription = "Highlights the control currently under the mouse";
  constexpr const char* kConsoleStartupUiBuildPlaceTarmacAlphaDescription = "Tarmac alpha for buildings that are about to be placed";
  constexpr const char* kConsoleStartupUiCommandClickScaleDescription = "Scale applied to the click distance size of command waypoints";
  constexpr const char* kConsoleStartupUiFuelbarHeightDescription = "size of the fuel bar as a fraction of the bar height";
} // namespace

// New console-tunable storage with no other subsystem owner (default read from the
// binary's .data image at the registrar's value-pointer field).
float moho::ui_BuildPlaceTarmacAlpha = 0.5f;
float moho::ui_CommandClickScale = 1.0f;
float moho::ui_fuelbarHeight = 0.25f;

namespace moho
{
  extern bool UI_ShowControlUnderMouse;


  /**
   * Address: 0x00BE19D0 (FUN_00BE19D0, dynamic initializer for `gTConVar_UI_ShowControlUnderMouse`)
   * Address: 0x00C04960 (FUN_00C04960, dynamic atexit destructor for `gTConVar_UI_ShowControlUnderMouse`)
   */
  TConVar<bool> gTConVar_UI_ShowControlUnderMouse(
    "UI_ShowControlUnderMouse",
    kConsoleStartupUIShowControlUnderMouseDescription,
    &moho::UI_ShowControlUnderMouse
  );


  /**
   * Address: 0x00BE50E0 (FUN_00BE50E0, dynamic initializer for `gTConVar_ui_BuildPlaceTarmacAlpha`)
   * Address: 0x00C06950 (FUN_00C06950, dynamic atexit destructor for `gTConVar_ui_BuildPlaceTarmacAlpha`)
   */
  TConVar<float> gTConVar_ui_BuildPlaceTarmacAlpha(
    "ui_BuildPlaceTarmacAlpha",
    kConsoleStartupUiBuildPlaceTarmacAlphaDescription,
    &moho::ui_BuildPlaceTarmacAlpha
  );

  /**
   * Address: 0x00BE3E40 (FUN_00BE3E40, dynamic initializer for `gTConVar_ui_CommandClickScale`)
   * Address: 0x00C06050 (FUN_00C06050, dynamic atexit destructor for `gTConVar_ui_CommandClickScale`)
   */
  TConVar<float> gTConVar_ui_CommandClickScale(
    "ui_CommandClickScale",
    kConsoleStartupUiCommandClickScaleDescription,
    &moho::ui_CommandClickScale
  );


  /**
   * Address: 0x00BE5420 (FUN_00BE5420, dynamic initializer for `gTConVar_ui_fuelbarHeight`)
   * Address: 0x00C06BA0 (FUN_00C06BA0, dynamic atexit destructor for `gTConVar_ui_fuelbarHeight`)
   */
  TConVar<float> gTConVar_ui_fuelbarHeight(
    "ui_fuelbarHeight",
    kConsoleStartupUiFuelbarHeightDescription,
    &moho::ui_fuelbarHeight
  );


  // Not in the binary: the attack-ground deviation switch's cleanup and
  // registrar, shaped like every retail convar pair around it.
} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupRenBandwidthDisplayKernelDescription = "Width of bandwidth filter (in seconds).";
  constexpr const char* kConsoleStartupRenBandwidthDisplaySecondsDescription = "Number of seconds of bandwidth data to display.";
  constexpr const char* kConsoleStartupRenBloomDescription = "Render Blooms?";
  constexpr const char* kConsoleStartupRenBloomBlurCountDescription = "Bloom Blur Count";
  constexpr const char* kConsoleStartupRenBorderSizeDescription = "Size of edge border";
  constexpr const char* kConsoleStartupRenClipDecalLevelDescription = "Level at which we clip decals for super quick reject";
  constexpr const char* kConsoleStartupRenClipDecalsDescription = "Clip Decals vertex count";
  constexpr const char* kConsoleStartupRenClutterDescription = "Render clutter";
  constexpr const char* kConsoleStartupRenDecalAlbedoLodCutoffDescription = "Fudge factor for decal cutoff on zoom out for albedos";
  constexpr const char* kConsoleStartupRenDecalFadeFractionDescription = "fraction (0..1) of their range that decals start to fade";
  constexpr const char* kConsoleStartupRenDecalFidelityDescription = "";
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
  constexpr const char* kConsoleStartupRenNewFogUpdateDescription = "Use new fog update code";
  constexpr const char* kConsoleStartupRenNewPipelineDescription = "";
  constexpr const char* kConsoleStartupRenNormalDecalsDescription = "Render Normal Decals";
  constexpr const char* kConsoleStartupRenOblivionDescription = "";
  constexpr const char* kConsoleStartupRenOnlyFirstViewDescription = "Render only the first view in the list";
  constexpr const char* kConsoleStartupRenPlayableBoundaryDescription = "";
  constexpr const char* kConsoleStartupRenReflectionDescription = "Render reflection?";
  constexpr const char* kConsoleStartupRenRefractionDescription = "Render refraction?";
  constexpr const char* kConsoleStartupRenRegenShoreDescription = "Regenerate shoreline (editor only)";
  constexpr const char* kConsoleStartupRenRenderNothingDescription = "Render nothing?";
  constexpr const char* kConsoleStartupRenSelectDescription = "Render select meshes?";
  constexpr const char* kConsoleStartupRenShadowBlurDescription = "Toggle shadow blurring";
  constexpr const char* kConsoleStartupRenShadowCoeffDescription = "";
  constexpr const char* kConsoleStartupRenShadowLODDescription = "At what LODMetric do we stop rendering shadows";
  constexpr const char* kConsoleStartupRenShadowSizeDescription = "Sizeof shadow texture";
  constexpr const char* kConsoleStartupRenShadowsDescription = "Render Shadows?";
  constexpr const char* kConsoleStartupRenShoreErrorCoeffDescription = "";
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
  constexpr const char* kConsoleStartupRenUnitSilhouetteDescription = "";
  constexpr const char* kConsoleStartupRenViewErrorDescription = "";
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
bool moho::ren_ShowSkeletons = false;
bool moho::ren_TTerrainGlow = false;
int moho::ren_TeamColorLookupCount = 32;
bool moho::ren_Trees = false;
float moho::ren_ViewError = 0.003000000026077032f;

namespace moho
{
  extern float ren_BandwidthDisplayKernel;
  extern float ren_BandwidthDisplaySeconds;
  extern bool ren_Bloom;
  extern int ren_BloomBlurCount;
  extern float ren_BorderSize;
  extern int ren_ClipDecalLevel;
  extern bool ren_ClipDecals;
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
  extern bool ren_NormalDecals;
  extern bool ren_Oblivion;
  extern bool ren_OnlyFirstView;
  extern bool ren_PlayableBoundary;
  extern bool ren_Reflection;
  extern bool ren_RenderNothing;
  extern bool ren_Select;
  extern bool ren_ShadowBlur;
  extern float ren_ShadowCoeff;
  extern float ren_ShadowLOD;
  extern int ren_ShadowSize;
  extern bool ren_Shadows;
  extern float ren_ShoreErrorCoeff;
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
  extern bool ren_UnitSilhouette;
  extern bool ren_Water;
  extern bool ren_WorldBorder;
  extern bool ren_bicubicnormals;
  extern bool ren_fog;
  extern bool ren_glowingDecals;

  /**
   * Address: 0x00BE0D40 (FUN_00BE0D40, dynamic initializer for `gTConVar_ren_BandwidthDisplayKernel`)
   * Address: 0x00C040E0 (FUN_00C040E0, dynamic atexit destructor for `gTConVar_ren_BandwidthDisplayKernel`)
   */
  TConVar<float> gTConVar_ren_BandwidthDisplayKernel(
    "ren_BandwidthDisplayKernel",
    kConsoleStartupRenBandwidthDisplayKernelDescription,
    &moho::ren_BandwidthDisplayKernel
  );

  /**
   * Address: 0x00BE0D00 (FUN_00BE0D00, dynamic initializer for `gTConVar_ren_BandwidthDisplaySeconds`)
   * Address: 0x00C040B0 (FUN_00C040B0, dynamic atexit destructor for `gTConVar_ren_BandwidthDisplaySeconds`)
   */
  TConVar<float> gTConVar_ren_BandwidthDisplaySeconds(
    "ren_BandwidthDisplaySeconds",
    kConsoleStartupRenBandwidthDisplaySecondsDescription,
    &moho::ren_BandwidthDisplaySeconds
  );


  /**
   * Address: 0x00BE1710 (FUN_00BE1710, dynamic initializer for `gTConVar_ren_Bloom`)
   * Address: 0x00C04750 (FUN_00C04750, dynamic atexit destructor for `gTConVar_ren_Bloom`)
   */
  TConVar<bool> gTConVar_ren_Bloom(
    "ren_Bloom",
    kConsoleStartupRenBloomDescription,
    &moho::ren_Bloom
  );

  /**
   * Address: 0x00BE0E00 (FUN_00BE0E00, dynamic initializer for `gTConVar_ren_BloomBlurCount`)
   * Address: 0x00C04130 (FUN_00C04130, dynamic atexit destructor for `gTConVar_ren_BloomBlurCount`)
   */
  TConVar<int> gTConVar_ren_BloomBlurCount(
    "ren_BloomBlurCount",
    kConsoleStartupRenBloomBlurCountDescription,
    &moho::ren_BloomBlurCount
  );


  /**
   * Address: 0x00BE31D0 (FUN_00BE31D0, dynamic initializer for `gTConVar_ren_BorderSize`)
   * Address: 0x00C05A00 (FUN_00C05A00, dynamic atexit destructor for `gTConVar_ren_BorderSize`)
   */
  TConVar<float> gTConVar_ren_BorderSize(
    "ren_BorderSize",
    kConsoleStartupRenBorderSizeDescription,
    &moho::ren_BorderSize
  );

  /**
   * Address: 0x00BE3190 (FUN_00BE3190, dynamic initializer for `gTConVar_ren_ClipDecalLevel`)
   * Address: 0x00C059D0 (FUN_00C059D0, dynamic atexit destructor for `gTConVar_ren_ClipDecalLevel`)
   */
  TConVar<int> gTConVar_ren_ClipDecalLevel(
    "ren_ClipDecalLevel",
    kConsoleStartupRenClipDecalLevelDescription,
    &moho::ren_ClipDecalLevel
  );

  /**
   * Address: 0x00BE3150 (FUN_00BE3150, dynamic initializer for `gTConVar_ren_ClipDecals`)
   * Address: 0x00C059A0 (FUN_00C059A0, dynamic atexit destructor for `gTConVar_ren_ClipDecals`)
   */
  TConVar<bool> gTConVar_ren_ClipDecals(
    "ren_ClipDecals",
    kConsoleStartupRenClipDecalsDescription,
    &moho::ren_ClipDecals
  );

  /**
   * Address: 0x00BE1810 (FUN_00BE1810, dynamic initializer for `gTConVar_ren_Clutter`)
   * Address: 0x00C04810 (FUN_00C04810, dynamic atexit destructor for `gTConVar_ren_Clutter`)
   */
  TConVar<bool> gTConVar_ren_Clutter(
    "ren_Clutter",
    kConsoleStartupRenClutterDescription,
    &moho::ren_Clutter
  );


  /**
   * Address: 0x00BE7A40 (FUN_00BE7A40, dynamic initializer for `gTConVar_ren_DecalAlbedoLodCutoff`)
   * Address: 0x00C083C0 (FUN_00C083C0, dynamic atexit destructor for `gTConVar_ren_DecalAlbedoLodCutoff`)
   */
  TConVar<float> gTConVar_ren_DecalAlbedoLodCutoff(
    "ren_DecalAlbedoLodCutoff",
    kConsoleStartupRenDecalAlbedoLodCutoffDescription,
    &moho::ren_DecalAlbedoLodCutoff
  );

  /**
   * Address: 0x00BE7A80 (FUN_00BE7A80, dynamic initializer for `gTConVar_ren_DecalFadeFraction`)
   * Address: 0x00C083F0 (FUN_00C083F0, dynamic atexit destructor for `gTConVar_ren_DecalFadeFraction`)
   */
  TConVar<float> gTConVar_ren_DecalFadeFraction(
    "ren_DecalFadeFraction",
    kConsoleStartupRenDecalFadeFractionDescription,
    &moho::ren_DecalFadeFraction
  );

  /**
   * Address: 0x00BE2550 (FUN_00BE2550, dynamic initializer for `gTConVar_ren_DecalFidelity`)
   * Address: 0x00C05180 (FUN_00C05180, dynamic atexit destructor for `gTConVar_ren_DecalFidelity`)
   */
  TConVar<int> gTConVar_ren_DecalFidelity(
    "ren_DecalFidelity",
    kConsoleStartupRenDecalFidelityDescription,
    &moho::ren_DecalFidelity
  );

  /**
   * Address: 0x00BE7AC0 (FUN_00BE7AC0, dynamic initializer for `gTConVar_ren_DecalFlatTol`)
   * Address: 0x00C08420 (FUN_00C08420, dynamic atexit destructor for `gTConVar_ren_DecalFlatTol`)
   */
  TConVar<float> gTConVar_ren_DecalFlatTol(
    "ren_DecalFlatTol",
    kConsoleStartupRenDecalFlatTolDescription,
    &moho::ren_DecalFlatTol
  );

  /**
   * Address: 0x00BE7A00 (FUN_00BE7A00, dynamic initializer for `gTConVar_ren_DecalNormalLodCutoff`)
   * Address: 0x00C08390 (FUN_00C08390, dynamic atexit destructor for `gTConVar_ren_DecalNormalLodCutoff`)
   */
  TConVar<float> gTConVar_ren_DecalNormalLodCutoff(
    "ren_DecalNormalLodCutoff",
    kConsoleStartupRenDecalNormalLodCutoffDescription,
    &moho::ren_DecalNormalLodCutoff
  );

  /**
   * Address: 0x00BE2410 (FUN_00BE2410, dynamic initializer for `gTConVar_ren_DecalOverDraw`)
   * Address: 0x00C05090 (FUN_00C05090, dynamic atexit destructor for `gTConVar_ren_DecalOverDraw`)
   */
  TConVar<bool> gTConVar_ren_DecalOverDraw(
    "ren_DecalOverDraw",
    kConsoleStartupRenDecalOverDrawDescription,
    &moho::ren_DecalOverDraw
  );

  /**
   * Address: 0x00BE2290 (FUN_00BE2290, dynamic initializer for `gTConVar_ren_Decals`)
   * Address: 0x00C04F70 (FUN_00C04F70, dynamic atexit destructor for `gTConVar_ren_Decals`)
   */
  TConVar<bool> gTConVar_ren_Decals(
    "ren_Decals",
    kConsoleStartupRenDecalsDescription,
    &moho::ren_Decals
  );

  /**
   * Address: 0x00BE3250 (FUN_00BE3250, dynamic initializer for `gTConVar_ren_ErrorCache`)
   * Address: 0x00C05A60 (FUN_00C05A60, dynamic atexit destructor for `gTConVar_ren_ErrorCache`)
   */
  TConVar<bool> gTConVar_ren_ErrorCache(
    "ren_ErrorCache",
    kConsoleStartupRenErrorCacheDescription,
    &moho::ren_ErrorCache
  );

  /**
   * Address: 0x00BE8120 (FUN_00BE8120, dynamic initializer for `gTConVar_ren_FogIntensity`)
   * Address: 0x00C08640 (FUN_00C08640, dynamic atexit destructor for `gTConVar_ren_FogIntensity`)
   */
  TConVar<int> gTConVar_ren_FogIntensity(
    "ren_FogIntensity",
    kConsoleStartupRenFogIntensityDescription,
    &moho::ren_FogIntensity
  );

  /**
   * Address: 0x00BE2210 (FUN_00BE2210, dynamic initializer for `gTConVar_ren_FogOfWar`)
   * Address: 0x00C04F10 (FUN_00C04F10, dynamic atexit destructor for `gTConVar_ren_FogOfWar`)
   */
  TConVar<bool> gTConVar_ren_FogOfWar(
    "ren_FogOfWar",
    kConsoleStartupRenFogOfWarDescription,
    &moho::ren_FogOfWar
  );

  /**
   * Address: 0x00BE2450 (FUN_00BE2450, dynamic initializer for `gTConVar_ren_ForceUpdateMinimapTerrain`)
   * Address: 0x00C050C0 (FUN_00C050C0, dynamic atexit destructor for `gTConVar_ren_ForceUpdateMinimapTerrain`)
   */
  TConVar<bool> gTConVar_ren_ForceUpdateMinimapTerrain(
    "ren_ForceUpdateMinimapTerrain",
    kConsoleStartupRenForceUpdateMinimapTerrainDescription,
    &moho::ren_ForceUpdateMinimapTerrain
  );

  /**
   * Address: 0x00BE1A90 (FUN_00BE1A90, dynamic initializer for `gTConVar_ren_FrameTimeSeconds`)
   * Address: 0x00C049F0 (FUN_00C049F0, dynamic atexit destructor for `gTConVar_ren_FrameTimeSeconds`)
   */
  TConVar<float> gTConVar_ren_FrameTimeSeconds(
    "ren_FrameTimeSeconds",
    kConsoleStartupRenFrameTimeSecondsDescription,
    &moho::ren_FrameTimeSeconds
  );

  /**
   * Address: 0x00BE14D0 (FUN_00BE14D0, dynamic initializer for `gTConVar_ren_Fx`)
   * Address: 0x00C045A0 (FUN_00C045A0, dynamic atexit destructor for `gTConVar_ren_Fx`)
   */
  TConVar<bool> gTConVar_ren_Fx(
    "ren_Fx",
    kConsoleStartupRenFxDescription,
    &moho::ren_Fx
  );

  /**
   * Address: 0x00BE2350 (FUN_00BE2350, dynamic initializer for `gTConVar_ren_GenerateMesh`)
   * Address: 0x00C05000 (FUN_00C05000, dynamic atexit destructor for `gTConVar_ren_GenerateMesh`)
   */
  TConVar<bool> gTConVar_ren_GenerateMesh(
    "ren_GenerateMesh",
    kConsoleStartupRenGenerateMeshDescription,
    &moho::ren_GenerateMesh
  );

  /**
   * Address: 0x00BE1950 (FUN_00BE1950, dynamic initializer for `gTConVar_ren_HideSecondary`)
   * Address: 0x00C04900 (FUN_00C04900, dynamic atexit destructor for `gTConVar_ren_HideSecondary`)
   */
  TConVar<bool> gTConVar_ren_HideSecondary(
    "ren_HideSecondary",
    kConsoleStartupRenHideSecondaryDescription,
    &moho::ren_HideSecondary
  );

  /**
   * Address: 0x00BE2390 (FUN_00BE2390, dynamic initializer for `gTConVar_ren_IgnoreDecalLOD`)
   * Address: 0x00C05030 (FUN_00C05030, dynamic atexit destructor for `gTConVar_ren_IgnoreDecalLOD`)
   */
  TConVar<bool> gTConVar_ren_IgnoreDecalLOD(
    "ren_IgnoreDecalLOD",
    kConsoleStartupRenIgnoreDecalLODDescription,
    &moho::ren_IgnoreDecalLOD
  );


  /**
   * Address: 0x00BE24D0 (FUN_00BE24D0, dynamic initializer for `gTConVar_ren_NewFogUpdate`)
   * Address: 0x00C05120 (FUN_00C05120, dynamic atexit destructor for `gTConVar_ren_NewFogUpdate`)
   */
  TConVar<bool> gTConVar_ren_NewFogUpdate(
    "ren_NewFogUpdate",
    kConsoleStartupRenNewFogUpdateDescription,
    &moho::ren_NewFogUpdate
  );

  /**
   * Address: 0x00BE1390 (FUN_00BE1390, dynamic initializer for `gTConVar_ren_NewPipeline`)
   * Address: 0x00C044B0 (FUN_00C044B0, dynamic atexit destructor for `gTConVar_ren_NewPipeline`)
   */
  TConVar<bool> gTConVar_ren_NewPipeline(
    "ren_NewPipeline",
    kConsoleStartupRenNewPipelineDescription,
    &moho::ren_NewPipeline
  );

  /**
   * Address: 0x00BE22D0 (FUN_00BE22D0, dynamic initializer for `gTConVar_ren_NormalDecals`)
   * Address: 0x00C04FA0 (FUN_00C04FA0, dynamic atexit destructor for `gTConVar_ren_NormalDecals`)
   */
  TConVar<bool> gTConVar_ren_NormalDecals(
    "ren_NormalDecals",
    kConsoleStartupRenNormalDecalsDescription,
    &moho::ren_NormalDecals
  );

  /**
   * Address: 0x00BE1410 (FUN_00BE1410, dynamic initializer for `gTConVar_ren_Oblivion`)
   * Address: 0x00C04510 (FUN_00C04510, dynamic atexit destructor for `gTConVar_ren_Oblivion`)
   */
  TConVar<bool> gTConVar_ren_Oblivion(
    "ren_Oblivion",
    kConsoleStartupRenOblivionDescription,
    &moho::ren_Oblivion
  );

  /**
   * Address: 0x00BE1750 (FUN_00BE1750, dynamic initializer for `gTConVar_ren_OnlyFirstView`)
   * Address: 0x00C04780 (FUN_00C04780, dynamic atexit destructor for `gTConVar_ren_OnlyFirstView`)
   */
  TConVar<bool> gTConVar_ren_OnlyFirstView(
    "ren_OnlyFirstView",
    kConsoleStartupRenOnlyFirstViewDescription,
    &moho::ren_OnlyFirstView
  );

  /**
   * Address: 0x00BE1650 (FUN_00BE1650, dynamic initializer for `gTConVar_ren_PlayableBoundary`)
   * Address: 0x00C046C0 (FUN_00C046C0, dynamic atexit destructor for `gTConVar_ren_PlayableBoundary`)
   */
  TConVar<bool> gTConVar_ren_PlayableBoundary(
    "ren_PlayableBoundary",
    kConsoleStartupRenPlayableBoundaryDescription,
    &moho::ren_PlayableBoundary
  );

  /**
   * Address: 0x00BE1510 (FUN_00BE1510, dynamic initializer for `gTConVar_ren_Reflection`)
   * Address: 0x00C045D0 (FUN_00C045D0, dynamic atexit destructor for `gTConVar_ren_Reflection`)
   */
  TConVar<bool> gTConVar_ren_Reflection(
    "ren_Reflection",
    kConsoleStartupRenReflectionDescription,
    &moho::ren_Reflection
  );

  /**
   * Address: 0x00BE1550 (FUN_00BE1550, dynamic initializer for `gTConVar_ren_Refraction`)
   * Address: 0x00C04600 (FUN_00C04600, dynamic atexit destructor for `gTConVar_ren_Refraction`)
   */
  TConVar<bool> gTConVar_ren_Refraction(
    "ren_Refraction",
    kConsoleStartupRenRefractionDescription,
    &moho::ren_Refraction
  );

  /**
   * Address: 0x00BE18D0 (FUN_00BE18D0, dynamic initializer for `gTConVar_ren_RegenShore`)
   * Address: 0x00C048A0 (FUN_00C048A0, dynamic atexit destructor for `gTConVar_ren_RegenShore`)
   */
  TConVar<bool> gTConVar_ren_RegenShore(
    "ren_RegenShore",
    kConsoleStartupRenRegenShoreDescription,
    &moho::ren_RegenShore
  );

  /**
   * Address: 0x00BE13D0 (FUN_00BE13D0, dynamic initializer for `gTConVar_ren_RenderNothing`)
   * Address: 0x00C044E0 (FUN_00C044E0, dynamic atexit destructor for `gTConVar_ren_RenderNothing`)
   */
  TConVar<bool> gTConVar_ren_RenderNothing(
    "ren_RenderNothing",
    kConsoleStartupRenRenderNothingDescription,
    &moho::ren_RenderNothing
  );

  /**
   * Address: 0x00BE1590 (FUN_00BE1590, dynamic initializer for `gTConVar_ren_Select`)
   * Address: 0x00C04630 (FUN_00C04630, dynamic atexit destructor for `gTConVar_ren_Select`)
   */
  TConVar<bool> gTConVar_ren_Select(
    "ren_Select",
    kConsoleStartupRenSelectDescription,
    &moho::ren_Select
  );


  /**
   * Address: 0x00BE1850 (FUN_00BE1850, dynamic initializer for `gTConVar_ren_ShadowBlur`)
   * Address: 0x00C04840 (FUN_00C04840, dynamic atexit destructor for `gTConVar_ren_ShadowBlur`)
   */
  TConVar<bool> gTConVar_ren_ShadowBlur(
    "ren_ShadowBlur",
    kConsoleStartupRenShadowBlurDescription,
    &moho::ren_ShadowBlur
  );

  /**
   * Address: 0x00BE1FA0 (FUN_00BE1FA0, dynamic initializer for `gTConVar_ren_ShadowCoeff`)
   * Address: 0x00C04D80 (FUN_00C04D80, dynamic atexit destructor for `gTConVar_ren_ShadowCoeff`)
   */
  TConVar<float> gTConVar_ren_ShadowCoeff(
    "ren_ShadowCoeff",
    kConsoleStartupRenShadowCoeffDescription,
    &moho::ren_ShadowCoeff
  );

  /**
   * Address: 0x00BE1FE0 (FUN_00BE1FE0, dynamic initializer for `gTConVar_ren_ShadowLOD`)
   * Address: 0x00C04DB0 (FUN_00C04DB0, dynamic atexit destructor for `gTConVar_ren_ShadowLOD`)
   */
  TConVar<float> gTConVar_ren_ShadowLOD(
    "ren_ShadowLOD",
    kConsoleStartupRenShadowLODDescription,
    &moho::ren_ShadowLOD
  );

  /**
   * Address: 0x00BE1890 (FUN_00BE1890, dynamic initializer for `gTConVar_ren_ShadowSize`)
   * Address: 0x00C04870 (FUN_00C04870, dynamic atexit destructor for `gTConVar_ren_ShadowSize`)
   */
  TConVar<int> gTConVar_ren_ShadowSize(
    "ren_ShadowSize",
    kConsoleStartupRenShadowSizeDescription,
    &moho::ren_ShadowSize
  );

  /**
   * Address: 0x00BE17D0 (FUN_00BE17D0, dynamic initializer for `gTConVar_ren_Shadows`)
   * Address: 0x00C047E0 (FUN_00C047E0, dynamic atexit destructor for `gTConVar_ren_Shadows`)
   */
  TConVar<bool> gTConVar_ren_Shadows(
    "ren_Shadows",
    kConsoleStartupRenShadowsDescription,
    &moho::ren_Shadows
  );

  /**
   * Address: 0x00BE3210 (FUN_00BE3210, dynamic initializer for `gTConVar_ren_ShoreErrorCoeff`)
   * Address: 0x00C05A30 (FUN_00C05A30, dynamic atexit destructor for `gTConVar_ren_ShoreErrorCoeff`)
   */
  TConVar<float> gTConVar_ren_ShoreErrorCoeff(
    "ren_ShoreErrorCoeff",
    kConsoleStartupRenShoreErrorCoeffDescription,
    &moho::ren_ShoreErrorCoeff
  );


  /**
   * Address: 0x00BE1B10 (FUN_00BE1B10, dynamic initializer for `gTConVar_ren_ShowBandwidthUsage`)
   * Address: 0x00C04A50 (FUN_00C04A50, dynamic atexit destructor for `gTConVar_ren_ShowBandwidthUsage`)
   */
  TConVar<bool> gTConVar_ren_ShowBandwidthUsage(
    "ren_ShowBandwidthUsage",
    kConsoleStartupRenShowBandwidthUsageDescription,
    &moho::ren_ShowBandwidthUsage
  );

  /**
   * Address: 0x00BE1910 (FUN_00BE1910, dynamic initializer for `gTConVar_ren_ShowBoneNames`)
   * Address: 0x00C048D0 (FUN_00C048D0, dynamic atexit destructor for `gTConVar_ren_ShowBoneNames`)
   */
  TConVar<bool> gTConVar_ren_ShowBoneNames(
    "ren_ShowBoneNames",
    kConsoleStartupRenShowBoneNamesDescription,
    &moho::ren_ShowBoneNames
  );

  /**
   * Address: 0x00BE2190 (FUN_00BE2190, dynamic initializer for `gTConVar_ren_ShowDirtyTerrain`)
   * Address: 0x00C04EB0 (FUN_00C04EB0, dynamic atexit destructor for `gTConVar_ren_ShowDirtyTerrain`)
   */
  TConVar<bool> gTConVar_ren_ShowDirtyTerrain(
    "ren_ShowDirtyTerrain",
    kConsoleStartupRenShowDirtyTerrainDescription,
    &moho::ren_ShowDirtyTerrain
  );

  /**
   * Address: 0x00BE1A50 (FUN_00BE1A50, dynamic initializer for `gTConVar_ren_ShowFrameTimes`)
   * Address: 0x00C049C0 (FUN_00C049C0, dynamic atexit destructor for `gTConVar_ren_ShowFrameTimes`)
   */
  TConVar<bool> gTConVar_ren_ShowFrameTimes(
    "ren_ShowFrameTimes",
    kConsoleStartupRenShowFrameTimesDescription,
    &moho::ren_ShowFrameTimes
  );

  /**
   * Address: 0x00BE1AD0 (FUN_00BE1AD0, dynamic initializer for `gTConVar_ren_ShowNetworkStats`)
   * Address: 0x00C04A20 (FUN_00C04A20, dynamic atexit destructor for `gTConVar_ren_ShowNetworkStats`)
   */
  TConVar<bool> gTConVar_ren_ShowNetworkStats(
    "ren_ShowNetworkStats",
    kConsoleStartupRenShowNetworkStatsDescription,
    &moho::ren_ShowNetworkStats
  );

  /**
   * Address: 0x00BE2110 (FUN_00BE2110, dynamic initializer for `gTConVar_ren_ShowNormals`)
   * Address: 0x00C04E50 (FUN_00C04E50, dynamic atexit destructor for `gTConVar_ren_ShowNormals`)
   */
  TConVar<bool> gTConVar_ren_ShowNormals(
    "ren_ShowNormals",
    kConsoleStartupRenShowNormalsDescription,
    &moho::ren_ShowNormals
  );

  /**
   * Address: 0x00BE15D0 (FUN_00BE15D0, dynamic initializer for `gTConVar_ren_ShowWireframe`)
   * Address: 0x00C04660 (FUN_00C04660, dynamic atexit destructor for `gTConVar_ren_ShowWireframe`)
   */
  TConVar<bool> gTConVar_ren_ShowWireframe(
    "ren_ShowWireframe",
    kConsoleStartupRenShowWireframeDescription,
    &moho::ren_ShowWireframe
  );

  /**
   * Address: 0x00BE2510 (FUN_00BE2510, dynamic initializer for `gTConVar_ren_Skirt`)
   * Address: 0x00C05150 (FUN_00C05150, dynamic atexit destructor for `gTConVar_ren_Skirt`)
   */
  TConVar<bool> gTConVar_ren_Skirt(
    "ren_Skirt",
    kConsoleStartupRenSkirtDescription,
    &moho::ren_Skirt
  );

  /**
   * Address: 0x00BE1790 (FUN_00BE1790, dynamic initializer for `gTConVar_ren_SkyDome`)
   * Address: 0x00C047B0 (FUN_00C047B0, dynamic atexit destructor for `gTConVar_ren_SkyDome`)
   */
  TConVar<bool> gTConVar_ren_SkyDome(
    "ren_SkyDome",
    kConsoleStartupRenSkyDomeDescription,
    &moho::ren_SkyDome
  );

  /**
   * Address: 0x00BE2310 (FUN_00BE2310, dynamic initializer for `gTConVar_ren_Splats`)
   * Address: 0x00C04FD0 (FUN_00C04FD0, dynamic atexit destructor for `gTConVar_ren_Splats`)
   */
  TConVar<bool> gTConVar_ren_Splats(
    "ren_Splats",
    kConsoleStartupRenSplatsDescription,
    &moho::ren_Splats
  );

  /**
   * Address: 0x00BE7D90 (FUN_00BE7D90, dynamic initializer for `gTConVar_ren_SyncTerrainLOD`)
   * Address: 0x00C084D0 (FUN_00C084D0, dynamic atexit destructor for `gTConVar_ren_SyncTerrainLOD`)
   */
  TConVar<float> gTConVar_ren_SyncTerrainLOD(
    "ren_SyncTerrainLOD",
    kConsoleStartupRenSyncTerrainLODDescription,
    &moho::ren_SyncTerrainLOD
  );

  /**
   * Address: 0x00BE2490 (FUN_00BE2490, dynamic initializer for `gTConVar_ren_TTerrainGlow`)
   * Address: 0x00C050F0 (FUN_00C050F0, dynamic atexit destructor for `gTConVar_ren_TTerrainGlow`)
   */
  TConVar<bool> gTConVar_ren_TTerrainGlow(
    "ren_TTerrainGlow",
    kConsoleStartupRenTTerrainGlowDescription,
    &moho::ren_TTerrainGlow
  );

  /**
   * Address: 0x00BE86E0 (FUN_00BE86E0, dynamic initializer for `gTConVar_ren_TeamColorLookupCount`)
   * Address: 0x00C08750 (FUN_00C08750, dynamic atexit destructor for `gTConVar_ren_TeamColorLookupCount`)
   */
  TConVar<int> gTConVar_ren_TeamColorLookupCount(
    "ren_TeamColorLookupCount",
    kConsoleStartupRenTeamColorLookupCountDescription,
    &moho::ren_TeamColorLookupCount
  );

  /**
   * Address: 0x00BE2150 (FUN_00BE2150, dynamic initializer for `gTConVar_ren_Terrain`)
   * Address: 0x00C04E80 (FUN_00C04E80, dynamic atexit destructor for `gTConVar_ren_Terrain`)
   */
  TConVar<bool> gTConVar_ren_Terrain(
    "ren_Terrain",
    kConsoleStartupRenTerrainDescription,
    &moho::ren_Terrain
  );

  /**
   * Address: 0x00BE21D0 (FUN_00BE21D0, dynamic initializer for `gTConVar_ren_Trees`)
   * Address: 0x00C04EE0 (FUN_00C04EE0, dynamic atexit destructor for `gTConVar_ren_Trees`)
   */
  TConVar<bool> gTConVar_ren_Trees(
    "ren_Trees",
    kConsoleStartupRenTreesDescription,
    &moho::ren_Trees
  );

  /**
   * Address: 0x00BE1450 (FUN_00BE1450, dynamic initializer for `gTConVar_ren_Ui`)
   * Address: 0x00C04540 (FUN_00C04540, dynamic atexit destructor for `gTConVar_ren_Ui`)
   */
  TConVar<bool> gTConVar_ren_Ui(
    "ren_Ui",
    kConsoleStartupRenUiDescription,
    &moho::ren_Ui
  );


  /**
   * Address: 0x00BE1990 (FUN_00BE1990, dynamic initializer for `gTConVar_ren_UnitSilhouette`)
   * Address: 0x00C04930 (FUN_00C04930, dynamic atexit destructor for `gTConVar_ren_UnitSilhouette`)
   */
  TConVar<bool> gTConVar_ren_UnitSilhouette(
    "ren_UnitSilhouette",
    kConsoleStartupRenUnitSilhouetteDescription,
    &moho::ren_UnitSilhouette
  );

  /**
   * Address: 0x00BE3110 (FUN_00BE3110, dynamic initializer for `gTConVar_ren_ViewError`)
   * Address: 0x00C05970 (FUN_00C05970, dynamic atexit destructor for `gTConVar_ren_ViewError`)
   */
  TConVar<float> gTConVar_ren_ViewError(
    "ren_ViewError",
    kConsoleStartupRenViewErrorDescription,
    &moho::ren_ViewError
  );

  /**
   * Address: 0x00BE2250 (FUN_00BE2250, dynamic initializer for `gTConVar_ren_Water`)
   * Address: 0x00C04F40 (FUN_00C04F40, dynamic atexit destructor for `gTConVar_ren_Water`)
   */
  TConVar<bool> gTConVar_ren_Water(
    "ren_Water",
    kConsoleStartupRenWaterDescription,
    &moho::ren_Water
  );

  /**
   * Address: 0x00BE1490 (FUN_00BE1490, dynamic initializer for `gTConVar_ren_WorldBorder`)
   * Address: 0x00C04570 (FUN_00C04570, dynamic atexit destructor for `gTConVar_ren_WorldBorder`)
   */
  TConVar<bool> gTConVar_ren_WorldBorder(
    "ren_WorldBorder",
    kConsoleStartupRenWorldBorderDescription,
    &moho::ren_WorldBorder
  );

  /**
   * Address: 0x00BE20D0 (FUN_00BE20D0, dynamic initializer for `gTConVar_ren_bicubicnormals`)
   * Address: 0x00C04E20 (FUN_00C04E20, dynamic atexit destructor for `gTConVar_ren_bicubicnormals`)
   */
  TConVar<bool> gTConVar_ren_bicubicnormals(
    "ren_bicubicnormals",
    kConsoleStartupRenBicubicnormalsDescription,
    &moho::ren_bicubicnormals
  );

  /**
   * Address: 0x00BE1610 (FUN_00BE1610, dynamic initializer for `gTConVar_ren_fog`)
   * Address: 0x00C04690 (FUN_00C04690, dynamic atexit destructor for `gTConVar_ren_fog`)
   */
  TConVar<bool> gTConVar_ren_fog(
    "ren_fog",
    kConsoleStartupRenFogDescription,
    &moho::ren_fog
  );

  /**
   * Address: 0x00BE23D0 (FUN_00BE23D0, dynamic initializer for `gTConVar_ren_glowingDecals`)
   * Address: 0x00C05060 (FUN_00C05060, dynamic atexit destructor for `gTConVar_ren_glowingDecals`)
   */
  TConVar<bool> gTConVar_ren_glowingDecals(
    "ren_glowingDecals",
    kConsoleStartupRenGlowingDecalsDescription,
    &moho::ren_glowingDecals
  );

} // namespace moho


namespace
{
} // namespace

namespace moho
{


} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupSCAntiAliasingSamplesDescription = "";
} // namespace

namespace moho
{


  /**
   * Address: 0x00BE9500 (FUN_00BE9500, dynamic initializer for `gCConFunc_SC_AntiAliasingSamples`)
   * Address: 0x00C08D90 (FUN_00C08D90, dynamic atexit destructor for `gCConFunc_SC_AntiAliasingSamples`)
   */
  CConFunc gCConFunc_SC_AntiAliasingSamples("SC_AntiAliasingSamples", kConsoleStartupSCAntiAliasingSamplesDescription, &moho::CON_d3d_AntiAliasingSamplesSeedFromFirstToken);


} // namespace moho


namespace
{
} // namespace

namespace moho
{

} // namespace moho


namespace
{
  constexpr const char* kConsoleStartupAiInitialMassCurrencyDescription = "Initial currency of mass economy.";
  constexpr const char* kConsoleStartupAiInitialMassCurrencyMaxDescription = "Initial currency of mass economy.";
} // namespace

namespace moho
{

  /**
   * Address: 0x00BDCFF0 (FUN_00BDCFF0, dynamic initializer for `gTConVar_ai_InitialMassCurrency`)
   * Address: 0x00C02160 (FUN_00C02160, dynamic atexit destructor for `gTConVar_ai_InitialMassCurrency`)
   */
  TConVar<float> gTConVar_ai_InitialMassCurrency(
    "ai_InitialMassCurrency",
    kConsoleStartupAiInitialMassCurrencyDescription,
    &moho::ai_InitialMassCurrency
  );

  /**
   * Address: 0x00BDD070 (FUN_00BDD070, dynamic initializer for `gTConVar_ai_InitialMassCurrencyMax`)
   * Address: 0x00C021C0 (FUN_00C021C0, dynamic atexit destructor for `gTConVar_ai_InitialMassCurrencyMax`)
   */
  TConVar<float> gTConVar_ai_InitialMassCurrencyMax(
    "ai_InitialMassCurrencyMax",
    kConsoleStartupAiInitialMassCurrencyMaxDescription,
    &moho::ai_InitialMassCurrencyMax
  );


} // namespace moho

