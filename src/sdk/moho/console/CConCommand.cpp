#include "moho/console/CConCommand.h"

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
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/console/CConFunc.h"
#include "moho/core/Thread.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/IConOutputHandler.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

bool moho::con_TestVarBool = false;
int moho::con_TestVar = 0;
std::uint8_t moho::con_TestVarUByte = 0;
float moho::con_TestVarFloat = 0.0f;
msvc8::string moho::con_TestVarStr;
int moho::recon_debug = 0;

namespace
{
  constexpr std::size_t kSavedConsoleCommandLimit = 0x64u;
  constexpr const char* kConTextMatchesHelpText = "strings ContextMatches(string)";
  constexpr const char* kConExecuteHelpText = "ConExecute('command string') -- Perform a console command";
  constexpr const char* kConExecuteSaveHelpText =
    "ConExecuteSave('command string') -- Perform a console command, saved to stack";
  constexpr const char* kNoSessionLocToken = "<LOC _No_session>";
  constexpr const char* kUIMakeSelectionSetUsageText =
    "USAGE: UI_MakeSelectionSet [name] - create a named selection set based on the current selection";
  constexpr const char* kUIApplySelectionSetUsageText =
    "USAGE: UI_ApplySelectionSet [name] - apply a named selections et";

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

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    static CScrLuaInitFormSet sSet("user");
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
    return userUnit ? reinterpret_cast<IUnit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
  }

  [[nodiscard]] UserEntity* ResolveUserEntityView(UserUnit* const userUnit) noexcept
  {
    return reinterpret_cast<UserEntity*>(userUnit);
  }

  [[nodiscard]] const STIMap* ResolveTerrainMapForTeleport(const CWldSession* const session) noexcept
  {
    return reinterpret_cast<const STIMap*>(session->mWldMap->mTerrainRes->mPlayableRectSource);
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
   * Address: 0x004203D0 (FUN_004203D0, std::map_string_CConCommand::Iterator::inc)
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
 * Address: 0x0041FF10 (FUN_0041FF10, std::map_string_CConCommand::_Lbound)
 * Address: 0x004203D0 (FUN_004203D0, std::map_string_CConCommand::Iterator::inc)
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
 * Address: 0x0041CC90 (FUN_0041CC90, ?CON_Execute@Moho@@YAXPBD@Z)
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
 * Address: 0x004203D0 (FUN_004203D0, std::map_string_CConCommand::Iterator::inc)
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

  const STIMap* const terrainMap = ResolveTerrainMapForTeleport(session);
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
 * Address: 0x103C8880 (FUN_103C8880)
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
    gpg::Logf("uint32 %s == %u (%x)", mName ? mName : "", *value, *value);
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
  constexpr const char* kConsoleStartupConEchoDescription = "Echo command arguments to console output.";
  constexpr const char* kConsoleStartupConListCommandsDescription = "List all registered console commands.";
  constexpr const char* kConsoleStartupConExecuteLastCommandDescription = "Execute the most recently saved command.";
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
  constexpr const char* kConsoleStartupReconDebugDescription = "Army index for recon debug rendering output.";

  CConFunc gCConFunc_CON_Echo{};
  CConFunc gCConFunc_CON_ListCommands{};
  CConFunc gCConFunc_CON_ExecuteLastCommand{};
  CConFunc gCConFunc_d3d_AntiAliasingSamples{};
  CConFunc gCConFunc_ren_MipSkipLevels{};
  CConFunc gCConFunc_DumpPreloadedTextures{};
  CConFunc gCConFunc_Log{};
  CConFunc gCConFunc_Debug_Warn{};
  CConFunc gCConFunc_Debug_Error{};
  CConFunc gCConFunc_Debug_Assert{};
  CConFunc gCConFunc_Debug_Crash{};
  CConFunc gCConFunc_Debug_Throw{};

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

  template <typename TCommand>
  void CleanupStartupConCommand(TCommand& command) noexcept
  {
    TeardownConCommandRegistration(command);
  }

  template <typename TConVarLike>
  void RegisterStartupConVar(TConVarLike& conVar, void (*cleanupFn)()) noexcept
  {
    RegisterConCommand(conVar);
    (void)std::atexit(cleanupFn);
  }

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
} // namespace moho

namespace
{
  struct ConsoleStartupRegistrationsRender
  {
    ConsoleStartupRegistrationsRender()
    {
      moho::register_CConFunc_CON_Echo();
      moho::register_CConFunc_CON_ListCommands();
      moho::register_CConFunc_CON_ExecuteLastCommand();
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
      moho::register_CConFunc_Log();
      moho::register_CConFunc_Debug_Warn();
      moho::register_CConFunc_Debug_Error();
      moho::register_CConFunc_Debug_Assert();
      moho::register_CConFunc_Debug_Crash();
      moho::register_CConFunc_Debug_Throw();
      moho::register_TConVar_recon_debug();
    }
  };

  [[maybe_unused]] ConsoleStartupRegistrationsDebug gConsoleStartupRegistrationsDebug;
} // namespace
