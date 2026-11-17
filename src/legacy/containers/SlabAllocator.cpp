// Engine addition, not in the shipped binary: the switch for per-tree node slabs (SlabAllocator.h).

#include "legacy/containers/SlabAllocator.h"

#include <Windows.h>

#include <cwchar>

namespace
{
  /// `/treeslabs 0` on the command line or FAF_TREESLABS=0, as `/smallpool 0` is read.
  /// An AddressSanitizer build never uses slabs: ASan can't see inside them (the small-block pool does the same).
  [[nodiscard]] bool TurnedOff() noexcept
  {
#if defined(__SANITIZE_ADDRESS__)
    return true;
#elifdef __has_feature
#if __has_feature(address_sanitizer)
    return true;
#endif
#endif
    char value[4] = {};
    const DWORD written = ::GetEnvironmentVariableA("FAF_TREESLABS", value, static_cast<DWORD>(sizeof(value)));
    if (written == 1u && value[0] == '0') {
      return true;
    }
    const wchar_t* const commandLine = ::GetCommandLineW();
    const wchar_t* const flag = (commandLine != nullptr) ? std::wcsstr(commandLine, L"/treeslabs") : nullptr;
    if (flag == nullptr) {
      return false;
    }
    const wchar_t* cursor = flag + std::wcslen(L"/treeslabs");
    while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'=') {
      ++cursor;
    }
    return *cursor == L'0';
  }
} // namespace

bool fa::TreeSlabsEnabled() noexcept
{
  // Global trees are built during static initialisation, before logging exists, so this only reads the
  // switch; gpg::LogHighMemoryReservation reports it at startup.
  static const bool enabled = !TurnedOff();
  return enabled;
}
