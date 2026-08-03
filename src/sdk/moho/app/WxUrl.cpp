#include "moho/app/WxUrl.h"

#include <cwchar>
#include <vector>
#include <windows.h>
#include <shellapi.h>
#include <wx/url.h>

#include "moho/misc/StartupHelpers.h"

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
    bool ProtocolNamesEqual(const wxString& protocolName, const std::wstring& allowedProtocol)
    {
      return ::_wcsicmp(protocolName.c_str(), allowedProtocol.c_str()) == 0;
    }
  }

  void OpenAllowedUrlByWx(const std::wstring& url)
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
