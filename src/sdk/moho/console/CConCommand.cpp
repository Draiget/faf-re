#include "moho/console/CConCommand.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

namespace
{
  struct ConCommandArgsWireView
  {
    void* vftable;
    msvc8::string* begin;
    msvc8::string* end;
    msvc8::string* cap;
  };

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

  struct ConsoleCommandRegistry
  {
    std::unordered_map<std::string, CConCommand*> commandsByName;
    std::mutex lock;
  };

  /**
   * Address: 0x0041BEB0 (FUN_0041BEB0)
   *
   * What it does:
   * Returns the global console command registry used by register/unregister paths.
   */
  ConsoleCommandRegistry& GetConsoleCommandRegistry()
  {
    static ConsoleCommandRegistry sRegistry;
    return sRegistry;
  }

  std::string CanonicalizeName(const char* name)
  {
    if (name == nullptr) {
      return {};
    }

    std::string out{name};
    std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    return out;
  }

  [[nodiscard]]
  bool IsConsoleWhitespace(const char ch) noexcept
  {
    return std::isspace(static_cast<unsigned char>(ch)) != 0;
  }

  [[nodiscard]]
  bool IsConsoleLineTerminator(const char ch) noexcept
  {
    return ch == ';' || ch == '#';
  }

  [[nodiscard]]
  std::vector<std::string> TokenizeConsoleCommandText(const std::string_view text)
  {
    std::vector<std::string> tokens;
    std::string current;
    current.reserve(text.size());

    bool inQuotes = false;
    bool escaping = false;

    for (const char ch : text) {
      if (escaping) {
        current.push_back(ch);
        escaping = false;
        continue;
      }

      if (inQuotes && ch == '\\') {
        escaping = true;
        continue;
      }

      if (ch == '"') {
        inQuotes = !inQuotes;
        continue;
      }

      if (!inQuotes && IsConsoleLineTerminator(ch)) {
        break;
      }

      if (!inQuotes && IsConsoleWhitespace(ch)) {
        if (!current.empty()) {
          tokens.push_back(current);
          current.clear();
        }
        continue;
      }

      current.push_back(ch);
    }

    if (escaping) {
      current.push_back('\\');
    }

    if (!current.empty()) {
      tokens.push_back(current);
    }

    return tokens;
  }

  void BuildWireTokenViews(const std::vector<std::string>& tokens, std::vector<msvc8::string>& outViews)
  {
    outViews.clear();
    outViews.reserve(tokens.size());

    for (const std::string& token : tokens) {
      if (token.size() <= 15u) {
        outViews.emplace_back(token.c_str(), token.size());
      } else {
        outViews.push_back(
          msvc8::string::adopt(
            const_cast<char*>(token.data()),
            static_cast<std::uint32_t>(token.size()),
            static_cast<std::uint32_t>(token.size())
          )
        );
      }
    }
  }

  [[nodiscard]]
  CConCommand* FindRegisteredConCommand(const std::string_view commandName)
  {
    if (commandName.empty()) {
      return nullptr;
    }

    std::string key{commandName};
    std::transform(key.begin(), key.end(), key.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (key.empty()) {
      return nullptr;
    }

    auto& registry = GetConsoleCommandRegistry();
    std::scoped_lock lock{registry.lock};
    const auto it = registry.commandsByName.find(key);
    if (it == registry.commandsByName.end()) {
      return nullptr;
    }

    return it->second;
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
 * Address: 0x0041E390 (FUN_0041E390)
 *
 * What it does:
 * Inserts command definition into the console command map keyed by case-insensitive name.
 */
void moho::RegisterConCommand(CConCommand& command)
{
  const std::string key = CanonicalizeName(command.mName);
  if (key.empty()) {
    return;
  }

  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};
  registry.commandsByName[key] = &command;
}

/**
 * Address: 0x0041E4E0 (FUN_0041E4E0)
 *
 * What it does:
 * Removes command definition from the console command map when current mapping points to this command.
 */
void moho::UnregisterConCommand(CConCommand& command)
{
  const std::string key = CanonicalizeName(command.mName);
  if (key.empty()) {
    return;
  }

  auto& registry = GetConsoleCommandRegistry();
  std::scoped_lock lock{registry.lock};
  const auto it = registry.commandsByName.find(key);
  if (it != registry.commandsByName.end() && it->second == &command) {
    registry.commandsByName.erase(it);
  }
}

/**
 * Address: 0x0041E5A0 (FUN_0041E5A0)
 *
 * What it does:
 * Mirrors base teardown semantics by unregistering command when it has a name.
 */
void moho::TeardownConCommandRegistration(CConCommand& command)
{
  if (command.mName != nullptr) {
    UnregisterConCommand(command);
  }
}

/**
 * Address: 0x0041CC90 (FUN_0041CC90)
 *
 * What it does:
 * Tokenizes a command line, resolves command name in registry, and dispatches handler.
 */
void moho::ExecuteConsoleCommandText(const char* commandText)
{
  if (commandText == nullptr || *commandText == '\0') {
    return;
  }

  const std::vector<std::string> parsedTokens = TokenizeConsoleCommandText(commandText);
  if (parsedTokens.empty()) {
    return;
  }

  CConCommand* const command = FindRegisteredConCommand(parsedTokens.front());
  if (command == nullptr) {
    return;
  }

  std::vector<msvc8::string> wireTokenViews;
  BuildWireTokenViews(parsedTokens, wireTokenViews);
  if (wireTokenViews.empty()) {
    return;
  }

  ConCommandArgsWireView wireArgs{};
  wireArgs.vftable = nullptr;
  wireArgs.begin = wireTokenViews.data();
  wireArgs.end = wireTokenViews.data() + wireTokenViews.size();
  wireArgs.cap = wireArgs.end;
  command->Handle(&wireArgs);
}

/**
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
