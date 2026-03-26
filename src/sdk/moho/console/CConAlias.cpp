#include "moho/console/CConAlias.h"

#include <new>
#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"

namespace
{
  constexpr std::size_t kAliasCommandOffset = 0x0C;

  [[nodiscard]]
  bool AliasArgNeedsQuotes(const std::string_view token) noexcept
  {
    if (token.empty()) {
      return true;
    }

    for (const char ch : token) {
      if (ch == '#' || ch == ';' || ch == '"') {
        return true;
      }
      if (gpg::STR_IsAsciiWhitespace(ch)) {
        return true;
      }
    }

    return false;
  }

  void AppendQuotedAliasArg(std::string& out, const std::string_view token)
  {
    out.push_back('"');
    for (const char ch : token) {
      if (ch == '\\' || ch == '"') {
        out.push_back('\\');
      }
      out.push_back(ch);
    }
    out.push_back('"');
  }

  [[nodiscard]]
  std::string BuildAliasArgumentSuffix(const moho::ConCommandArgsView& args)
  {
    std::string suffix;
    const std::size_t count = args.Count();

    for (std::size_t index = 1; index < count; ++index) {
      const msvc8::string* const token = args.At(index);
      if (token == nullptr) {
        continue;
      }

      if (!suffix.empty()) {
        suffix.push_back(' ');
      }

      const std::string_view tokenText = token->view();
      if (AliasArgNeedsQuotes(tokenText)) {
        AppendQuotedAliasArg(suffix, tokenText);
      } else {
        suffix.append(tokenText);
      }
    }

    return suffix;
  }
} // namespace

moho::CConAlias::CConAlias() noexcept
{
  mName = nullptr;
  mDescription = nullptr;
  new (AliasCommandStorageAddress()) msvc8::string{};
}

/**
 * Address: 0x0041E600 (FUN_0041E600)
 *
 * const char* description, const char* name, const char* aliasCommandText
 *
 * What it does:
 * Rebuilds constructor-style alias initialization, including command registration.
 */
void moho::CConAlias::InitializeRecovered(const char* description, const char* name, const char* aliasCommandText)
{
  mName = name;
  mDescription = description;

  if (mName != nullptr) {
    RegisterConCommand(*this);
  }

  const char* const text = aliasCommandText != nullptr ? aliasCommandText : "";
  new (AliasCommandStorageAddress()) msvc8::string(text);
}

/**
 * Address: 0x0041E6A0 (FUN_0041E6A0)
 *
 * What it does:
 * Builds expanded alias command text and forwards it into console command execution.
 */
void moho::CConAlias::Handle(void* commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

  std::string expandedCommand{AliasCommandStorage().view()};
  if (args.Count() > 1) {
    expandedCommand.push_back(' ');
    expandedCommand.append(BuildAliasArgumentSuffix(args));
  }

  ExecuteConsoleCommandText(expandedCommand.c_str());
}

const msvc8::string& moho::CConAlias::AliasCommandText() const noexcept
{
  return AliasCommandStorage();
}

msvc8::string& moho::CConAlias::AliasCommandStorage() noexcept
{
  auto* const rawStorage = static_cast<msvc8::string*>(AliasCommandStorageAddress());
  return *std::launder(rawStorage);
}

const msvc8::string& moho::CConAlias::AliasCommandStorage() const noexcept
{
  const auto* const rawStorage = static_cast<const msvc8::string*>(AliasCommandStorageAddress());
  return *std::launder(rawStorage);
}

void* moho::CConAlias::AliasCommandStorageAddress() noexcept
{
  return reinterpret_cast<std::uint8_t*>(this) + kAliasCommandOffset;
}

const void* moho::CConAlias::AliasCommandStorageAddress() const noexcept
{
  return reinterpret_cast<const std::uint8_t*>(this) + kAliasCommandOffset;
}
