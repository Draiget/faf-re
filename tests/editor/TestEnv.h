#pragma once

#include <cstdlib>
#include <string>

namespace faf::editor::test
{
  /** An environment variable's text, or "" when it isn't set (the tests that read retail files take their folder so).
   */
  [[nodiscard]] inline std::string EnvText(
    const char* const name
  )
  {
#if defined(_MSC_VER)
    // The MSVC runtime marks getenv unsafe (C4996, clang's -Wdeprecated-declarations); _dupenv_s is its own.
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
      return {};
    }
    std::string text(value);
    std::free(value);
    return text;
#else
    const char* const value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
#endif
  }
} // namespace faf::editor::test
