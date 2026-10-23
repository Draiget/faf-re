#include "moho/console/CConAlias.h"

#include <string>
#include <string_view>

#include "gpg/core/containers/String.h"

namespace
{
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
  std::string BuildAliasArgumentSuffix(const msvc8::vector<msvc8::string>& args)
  {
    std::string suffix;
    const std::size_t count = args.size();

    for (std::size_t index = 1; index < count; ++index) {
      const msvc8::string* const token = moho::ConCommandArg(args, index);
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

/**
 * Address: 0x0041E600 (FUN_0041E600)
 *
 * const char* name, const char* description, const char* aliasText
 *
 * What it does:
 * Initializes/registers the base command, then copies the expansion text.
 */
moho::CConAlias::CConAlias(const char* const name, const char* const description, const char* const aliasText)
  : CConCommand(name, description)
  , mAliasText(aliasText)
{}

/**
 * Address: 0x0041E6A0 (FUN_0041E6A0)
 *
 * What it does:
 * Builds expanded alias command text and forwards it into console command execution.
 */
void moho::CConAlias::Handle(const msvc8::vector<msvc8::string>& args)
{
  std::string expandedCommand{mAliasText.view()};
  if (args.size() > 1) {
    expandedCommand.push_back(' ');
    expandedCommand.append(BuildAliasArgumentSuffix(args));
  }

  ExecuteConsoleCommandText(expandedCommand.c_str());
}
