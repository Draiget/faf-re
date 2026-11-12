#include "moho/app/AllowedUrl.h"

#include <cwctype>
#include <string>
#include <vector>

#include <Windows.h>
#if FAFRE_PLATFORM_WINDOWS
#include <shellapi.h>
#else
#include <strings.h>

#include "gpg/core/containers/String.h"
#include "platform/posix/Win32WindowPosix.h"
#endif

#include "moho/misc/StartupHelpers.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] bool SameProtocol(
      const std::wstring& left,
      const std::wstring& right
    )
    {
      if (left.size() != right.size()) {
        return false;
      }
      for (std::size_t index = 0; index < left.size(); ++index) {
        if (
          std::towlower(static_cast<std::wint_t>(left[index])) != std::towlower(static_cast<std::wint_t>(right[index]))
        ) {
          return false;
        }
      }
      return true;
    }
  } // namespace

  // wxURL (0x00848050's parse) took the scheme as the text before the first ':' (a letter, then
  // letters, digits, '+', '-' or '.') and refused a URL without one.
  void OpenAllowedUrl(
    const std::wstring& url
  )
  {
    const std::size_t colon = url.find(L':');
    if (colon == 0 || colon == std::wstring::npos || !std::iswalpha(static_cast<std::wint_t>(url[0]))) {
      return;
    }
    for (std::size_t index = 1; index < colon; ++index) {
      const wchar_t character = url[index];
      if (
        !std::iswalnum(static_cast<std::wint_t>(character)) && character != L'+' && character != L'-' &&
        character != L'.'
      ) {
        return;
      }
    }
    const std::wstring protocolName = url.substr(0, colon);

    const std::vector<std::wstring> allowedProtocols = DISK_GetAllowedProtocols();
    for (const std::wstring& allowedProtocol : allowedProtocols) {
      if (SameProtocol(protocolName, allowedProtocol)) {
#if FAFRE_PLATFORM_WINDOWS
        (void)::ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
        platform::posix::OpenUrl(gpg::STR_WideToUtf8(url.c_str()).c_str());
#endif
        break;
      }
    }
  }
} // namespace moho
