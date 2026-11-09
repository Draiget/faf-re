// Engine addition, not in the shipped binary: the switch for the flat A* node table (AStarSearch.h).

#include "gpg/core/algorithms/AStarSearch.h"

#include <Windows.h>

#include <cwchar>

#include "gpg/core/utils/Logging.h"

namespace
{
  /// `/astartable 0` on the command line or FAF_ASTARTABLE=0, as `/smallpool 0` is read.
  [[nodiscard]] bool TurnedOff() noexcept
  {
    char value[4] = {};
    const DWORD written = ::GetEnvironmentVariableA("FAF_ASTARTABLE", value, static_cast<DWORD>(sizeof(value)));
    if (written == 1u && value[0] == '0') {
      return true;
    }
    const wchar_t* const commandLine = ::GetCommandLineW();
    const wchar_t* const flag = (commandLine != nullptr) ? std::wcsstr(commandLine, L"/astartable") : nullptr;
    if (flag == nullptr) {
      return false;
    }
    const wchar_t* cursor = flag + std::wcslen(L"/astartable");
    while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'=') {
      ++cursor;
    }
    return *cursor == L'0';
  }
} // namespace

bool gpg::AStarFlatNodeTableEnabled() noexcept
{
  static const bool enabled = [] {
    const bool on = !TurnedOff();
    gpg::Logf("path: flat A* node table %s", on ? "on" : "off");
    return on;
  }();
  return enabled;
}
