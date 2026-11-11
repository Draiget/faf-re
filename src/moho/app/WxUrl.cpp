#include "moho/app/WxUrl.h"

#if FAFRE_PLATFORM_WINDOWS
#include "platform/WxWidgets.h"
#endif

#include <cwchar>
#include <vector>
#if FAFRE_PLATFORM_WINDOWS
#include <windows.h>
#include <shellapi.h>
#include <wx/url.h>
#else
#include <cwctype>
#include <string>

#include "gpg/core/containers/String.h"
#include "platform/posix/Win32WindowPosix.h"
#endif

#include "moho/misc/StartupHelpers.h"

#if FAFRE_PLATFORM_WINDOWS
// The shipped binary linked a Unicode wxWidgets: `wxApp::RegisterWindowClasses`
// (0x00991E70) builds a `WNDCLASSW` and calls `RegisterClassW` with `wxChar*`
// class names. FUN_00848050 - the block this file is lifted from - reads that
// straight through: `wxURL::GetProtocolName` hands back a `const wchar_t**` and
// it goes directly into `wcsicmp`, with no conversion anywhere in the body.
#if !wxUSE_UNICODE
#error WxUrl.cpp needs the Unicode configuration of the vendored wx (wxmswu.lib)
#endif

namespace moho
{
  namespace
  {
    bool ProtocolNamesEqual(
      const wxString& protocolName,
      const std::wstring& allowedProtocol
    )
    {
      return ::_wcsicmp(protocolName.c_str(), allowedProtocol.c_str()) == 0;
    }
  } // namespace

  void OpenAllowedUrlByWx(
    const std::wstring& url
  )
  {
    const wxString parsedUrlText(url.c_str());
    const wxURL parsedUrl(parsedUrlText);
    if (parsedUrl.GetError() != wxURL_NOERR) {
      return;
    }

    const std::vector<std::wstring> allowedProtocols = DISK_GetAllowedProtocols();
    for (const std::wstring& allowedProtocol : allowedProtocols) {
      const wxString protocolName = parsedUrl.GetProtocolName();
      if (ProtocolNamesEqual(protocolName, allowedProtocol)) {
        (void)::ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        break;
      }
    }
  }
} // namespace moho
#else
namespace moho
{
  // The Linux client (issue #255) has no wxURL: the same check on the URL's scheme, the text before
  // its first ':' (a letter, then letters, digits, '+', '-' or '.'), then the desktop opens it.
  void OpenAllowedUrlByWx(
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
      if (::wcscasecmp(protocolName.c_str(), allowedProtocol.c_str()) == 0) {
        platform::posix::OpenUrl(gpg::STR_WideToUtf8(url.c_str()).c_str());
        break;
      }
    }
  }
} // namespace moho
#endif
