#include "editor/doc/EdHttp.h"

#include <cctype>
#include <cstdio>
#include <iterator>

#include <Windows.h>
#include <winhttp.h>

namespace faf::editor
{
  namespace
  {
    std::wstring Widen(const std::string& text)
    {
      if (text.empty()) {
        return {};
      }
      const int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring out(static_cast<std::size_t>(count), L'\0');
      (void)::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count);
      return out;
    }
  } // namespace

  bool HttpRequest(const HttpCall& call, long& status, std::string& body, std::string& error, std::atomic<std::uint64_t>* const received,
                   std::atomic<std::uint64_t>* const total)
  {
    status = 0;
    body.clear();
    const std::wstring wide = Widen(call.url);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256]{};
    std::wstring path(4096, L'\0');
    parts.lpszHostName = host;
    parts.dwHostNameLength = static_cast<DWORD>(std::size(host));
    parts.lpszUrlPath = path.data();
    parts.dwUrlPathLength = static_cast<DWORD>(path.size());
    wchar_t extra[4096]{};
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = static_cast<DWORD>(std::size(extra));
    if (!::WinHttpCrackUrl(wide.c_str(), 0, 0, &parts)) {
      error = "not a link: " + call.url;
      return false;
    }
    const std::wstring object = std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength) + std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    HINTERNET session = ::WinHttpOpen(L"FAF-RE map editor", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session != nullptr ? ::WinHttpConnect(session, host, parts.nPort, 0) : nullptr;
    HINTERNET request =
      connection != nullptr ? ::WinHttpOpenRequest(connection, Widen(call.method).c_str(), object.c_str(), nullptr, WINHTTP_NO_REFERER,
                                                   WINHTTP_DEFAULT_ACCEPT_TYPES, parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0)
                            : nullptr;
    const std::wstring headers = Widen(call.headers);
    bool ok = request != nullptr &&
              ::WinHttpSendRequest(request, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(), headers.empty() ? 0 : static_cast<DWORD>(-1L),
                                   call.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(call.body.data()),
                                   static_cast<DWORD>(call.body.size()), static_cast<DWORD>(call.body.size()), 0) &&
              ::WinHttpReceiveResponse(request, nullptr);
    if (ok) {
      DWORD code = 0;
      DWORD size = sizeof(code);
      ok = ::WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &size,
                                 WINHTTP_NO_HEADER_INDEX) != FALSE;
      status = static_cast<long>(code);
      // The body's size, when the server says it (for a progress bar).
      DWORD64 length = 0;
      wchar_t lengthText[32]{};
      DWORD lengthSize = sizeof(lengthText);
      if (total != nullptr && ::WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lengthText, &lengthSize,
                                                    WINHTTP_NO_HEADER_INDEX)) {
        length = _wcstoui64(lengthText, nullptr, 10);
        *total = length;
        body.reserve(static_cast<std::size_t>(length));
      }
    }
    if (!ok) {
      error = "no answer from " + std::string(call.url.substr(0, call.url.find('/', 8))) + " (error " + std::to_string(::GetLastError()) + ")";
    }
    while (ok) {
      DWORD available = 0;
      if (!::WinHttpQueryDataAvailable(request, &available)) {
        error = "the answer broke off";
        ok = false;
        break;
      }
      if (available == 0) {
        break;
      }
      const std::size_t at = body.size();
      body.resize(at + available);
      DWORD read = 0;
      if (!::WinHttpReadData(request, body.data() + at, available, &read)) {
        error = "the answer broke off";
        ok = false;
        break;
      }
      body.resize(at + read);
      if (received != nullptr) {
        *received = body.size();
      }
    }
    if (request != nullptr) {
      ::WinHttpCloseHandle(request);
    }
    if (connection != nullptr) {
      ::WinHttpCloseHandle(connection);
    }
    if (session != nullptr) {
      ::WinHttpCloseHandle(session);
    }
    return ok;
  }

  std::string UrlEncode(const std::string& text)
  {
    std::string out;
    for (const char c : text) {
      if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
        out += c;
      } else {
        char hex[4];
        (void)std::snprintf(hex, sizeof(hex), "%%%02X", static_cast<unsigned char>(c));
        out += hex;
      }
    }
    return out;
  }
} // namespace faf::editor
