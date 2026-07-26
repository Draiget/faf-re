#include "moho/app/WxUrl.h"

#include <cwchar>
#include <vector>
#include <windows.h>
#include <shellapi.h>
#include <wx/url.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/StartupHelpers.h"

#if wxUSE_UNICODE
#error WxUrl.cpp must use the ANSI configuration of the vendored wxmsw.lib
#endif

namespace moho
{
  namespace
  {
    bool ProtocolNamesEqual(const wxString& protocolName, const std::wstring& allowedProtocol)
    {
      // URL schemes are restricted to ASCII, which is also valid UTF-8.
      const std::wstring wideProtocolName = gpg::STR_Utf8ToWide(protocolName.c_str());
      return ::_wcsicmp(wideProtocolName.c_str(), allowedProtocol.c_str()) == 0;
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
