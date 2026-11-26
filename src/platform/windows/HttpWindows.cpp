// Engine addition (in-game launcher plan, WP1): platform::http on WinHTTP (src/platform/Http.h).

#include "platform/Http.h"

#include <cstdio>
#include <iterator>
#include <mutex>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winhttp.h>

namespace platform::http
{
  namespace
  {
    std::mutex gAgentLock;
    std::string gDefaultAgent = "FAF-RE map editor";

    std::wstring Widen(
      const std::string& text
    )
    {
      if (text.empty()) {
        return {};
      }
      const int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring out(static_cast<std::size_t>(count), L'\0');
      (void)::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), count);
      return out;
    }

    std::wstring Agent(
      const std::string& agent
    )
    {
      if (!agent.empty()) {
        return Widen(agent);
      }
      std::lock_guard<std::mutex> lock(gAgentLock);
      return Widen(gDefaultAgent);
    }

    /** A link's host, port, path with query, and whether it is TLS; `ws`/`wss` read as `http`/`https`. */
    struct Target
    {
      wchar_t host[256]{};
      INTERNET_PORT port = 0;
      std::wstring object;
      bool secure = false;
    };

    bool Crack(
      std::string url,
      Target& out
    )
    {
      if (url.starts_with("wss://")) {
        url = "https://" + url.substr(6);
      } else if (url.starts_with("ws://")) {
        url = "http://" + url.substr(5);
      }
      const std::wstring wide = Widen(url);
      URL_COMPONENTS parts{};
      parts.dwStructSize = sizeof(parts);
      std::wstring path(4096, L'\0');
      parts.lpszHostName = out.host;
      parts.dwHostNameLength = static_cast<DWORD>(std::size(out.host));
      parts.lpszUrlPath = path.data();
      parts.dwUrlPathLength = static_cast<DWORD>(path.size());
      wchar_t extra[4096]{};
      parts.lpszExtraInfo = extra;
      parts.dwExtraInfoLength = static_cast<DWORD>(std::size(extra));
      if (!::WinHttpCrackUrl(wide.c_str(), 0, 0, &parts)) {
        return false;
      }
      out.object = std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength) +
        std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);
      out.port = parts.nPort;
      out.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
      return true;
    }
  } // namespace

  void SetDefaultUserAgent(
    std::string agent
  )
  {
    std::lock_guard<std::mutex> lock(gAgentLock);
    gDefaultAgent = std::move(agent);
  }

  std::expected<void, std::string> Request(
    const Call& call,
    long& status,
    std::string& body,
    std::atomic<std::uint64_t>* const received,
    std::atomic<std::uint64_t>* const total
  )
  {
    status = 0;
    body.clear();
    Target target;
    if (!Crack(call.url, target)) {
      return std::unexpected("not a link: " + call.url);
    }
    HINTERNET session = ::WinHttpOpen(
      Agent(call.userAgent).c_str(),
      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS,
      0
    );
    HINTERNET connection = session != nullptr ? ::WinHttpConnect(session, target.host, target.port, 0) : nullptr;
    HINTERNET request = connection != nullptr ? ::WinHttpOpenRequest(
                                                  connection,
                                                  Widen(call.method).c_str(),
                                                  target.object.c_str(),
                                                  nullptr,
                                                  WINHTTP_NO_REFERER,
                                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                  target.secure ? WINHTTP_FLAG_SECURE : 0
                                                )
                                              : nullptr;
    const std::wstring headers = Widen(call.headers);
    bool ok = request != nullptr &&
      ::WinHttpSendRequest(
                request,
                headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                headers.empty() ? 0 : static_cast<DWORD>(-1L),
                call.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(call.body.data()),
                static_cast<DWORD>(call.body.size()),
                static_cast<DWORD>(call.body.size()),
                0
      ) &&
      ::WinHttpReceiveResponse(request, nullptr);
    std::string error;
    if (ok) {
      DWORD code = 0;
      DWORD size = sizeof(code);
      ok = ::WinHttpQueryHeaders(
             request,
             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
             WINHTTP_HEADER_NAME_BY_INDEX,
             &code,
             &size,
             WINHTTP_NO_HEADER_INDEX
           ) != FALSE;
      status = static_cast<long>(code);
      // The body's size, when the server says it (for a progress bar).
      DWORD64 length = 0;
      wchar_t lengthText[32]{};
      DWORD lengthSize = sizeof(lengthText);
      if (
        total != nullptr &&
        ::WinHttpQueryHeaders(
          request,
          WINHTTP_QUERY_CONTENT_LENGTH,
          WINHTTP_HEADER_NAME_BY_INDEX,
          lengthText,
          &lengthSize,
          WINHTTP_NO_HEADER_INDEX
        )
      ) {
        length = _wcstoui64(lengthText, nullptr, 10);
        *total = length;
        body.reserve(static_cast<std::size_t>(length));
      }
    }
    if (!ok) {
      error = "no answer from " + std::string(call.url.substr(0, call.url.find('/', 8))) + " (error " +
        std::to_string(::GetLastError()) + ")";
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
    if (!ok) {
      return std::unexpected(std::move(error));
    }
    return {};
  }

  struct Stream::State
  {
    std::mutex lock;
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;

    void Drop()
    {
      for (HINTERNET* handle : {&request, &connection, &session}) {
        if (*handle != nullptr) {
          ::WinHttpCloseHandle(*handle);
          *handle = nullptr;
        }
      }
    }
  };

  Stream::Stream()
    : mState(std::make_unique<State>())
  {}

  Stream::~Stream()
  {
    Close();
  }

  std::expected<long, std::string> Stream::Open(
    const Call& call
  )
  {
    Close();
    Target target;
    if (!Crack(call.url, target)) {
      return std::unexpected("not a link: " + call.url);
    }
    HINTERNET session = ::WinHttpOpen(
      Agent(call.userAgent).c_str(),
      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS,
      0
    );
    HINTERNET connection = session != nullptr ? ::WinHttpConnect(session, target.host, target.port, 0) : nullptr;
    HINTERNET request = connection != nullptr ? ::WinHttpOpenRequest(
                                                  connection,
                                                  Widen(call.method).c_str(),
                                                  target.object.c_str(),
                                                  nullptr,
                                                  WINHTTP_NO_REFERER,
                                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                  target.secure ? WINHTTP_FLAG_SECURE : 0
                                                )
                                              : nullptr;
    {
      // Published before the request goes out, so Close from another thread can end a slow answer too.
      std::lock_guard<std::mutex> lock(mState->lock);
      mState->session = session;
      mState->connection = connection;
      mState->request = request;
    }
    if (request != nullptr) {
      // An event stream stays quiet between events: no receive timeout (Close ends a wait).
      (void)::WinHttpSetTimeouts(request, 0, 60000, 30000, 0);
    }
    const std::wstring headers = Widen(call.headers);
    const bool ok = request != nullptr &&
      ::WinHttpSendRequest(
                      request,
                      headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                      headers.empty() ? 0 : static_cast<DWORD>(-1L),
                      call.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(call.body.data()),
                      static_cast<DWORD>(call.body.size()),
                      static_cast<DWORD>(call.body.size()),
                      0
      ) &&
      ::WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
      const DWORD error = ::GetLastError();
      Close();
      return std::unexpected(
        "no answer from " + call.url.substr(0, call.url.find('/', 8)) + " (error " + std::to_string(error) + ")"
      );
    }
    DWORD code = 0;
    DWORD size = sizeof(code);
    (void)::WinHttpQueryHeaders(
      request,
      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX,
      &code,
      &size,
      WINHTTP_NO_HEADER_INDEX
    );
    return static_cast<long>(code);
  }

  std::expected<std::string, std::string> Stream::Read()
  {
    HINTERNET request = nullptr;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      request = mState->request;
    }
    if (request == nullptr) {
      return std::unexpected("not open");
    }
    char buffer[16384];
    DWORD read = 0;
    if (!::WinHttpReadData(request, buffer, sizeof(buffer), &read)) {
      return std::unexpected("the answer broke off (error " + std::to_string(::GetLastError()) + ")");
    }
    return std::string(buffer, read);
  }

  void Stream::Close()
  {
    std::lock_guard<std::mutex> lock(mState->lock);
    mState->Drop();
  }

  struct WebSocket::State
  {
    mutable std::mutex lock;
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET socket = nullptr;

    /** Closes every handle (the caller holds `lock`). A Receive blocked on `socket` then fails and returns. */
    void Drop()
    {
      if (socket != nullptr) {
        ::WinHttpCloseHandle(socket);
        socket = nullptr;
      }
      if (connection != nullptr) {
        ::WinHttpCloseHandle(connection);
        connection = nullptr;
      }
      if (session != nullptr) {
        ::WinHttpCloseHandle(session);
        session = nullptr;
      }
    }
  };

  WebSocket::WebSocket()
    : mState(std::make_unique<State>())
  {}

  WebSocket::~WebSocket()
  {
    Close();
  }

  bool WebSocket::IsOpen() const
  {
    std::lock_guard<std::mutex> lock(mState->lock);
    return mState->socket != nullptr;
  }

  std::expected<void, std::string> WebSocket::Open(
    const std::string& url,
    const std::string& headers,
    const std::string& userAgent
  )
  {
    Close();
    Target target;
    if (!Crack(url, target)) {
      return std::unexpected("not a link: " + url);
    }
    HINTERNET session = ::WinHttpOpen(
      Agent(userAgent).c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
    );
    HINTERNET connection = session != nullptr ? ::WinHttpConnect(session, target.host, target.port, 0) : nullptr;
    HINTERNET request = connection != nullptr ? ::WinHttpOpenRequest(
                                                  connection,
                                                  L"GET",
                                                  target.object.c_str(),
                                                  nullptr,
                                                  WINHTTP_NO_REFERER,
                                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                  target.secure ? WINHTTP_FLAG_SECURE : 0
                                                )
                                              : nullptr;
    const std::wstring wideHeaders = Widen(headers);
    std::string error;
    bool ok = request != nullptr && ::WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) &&
      ::WinHttpSendRequest(
                request,
                wideHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wideHeaders.c_str(),
                wideHeaders.empty() ? 0 : static_cast<DWORD>(-1L),
                WINHTTP_NO_REQUEST_DATA,
                0,
                0,
                0
      ) &&
      ::WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
      error = "no answer from " + url.substr(0, url.find('/', 8)) + " (error " + std::to_string(::GetLastError()) + ")";
    }
    HINTERNET socket = nullptr;
    if (ok) {
      DWORD code = 0;
      DWORD size = sizeof(code);
      (void)::WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &code,
        &size,
        WINHTTP_NO_HEADER_INDEX
      );
      if (code != 101) {
        error = "the server answered " + std::to_string(code) + " instead of switching to a WebSocket";
        ok = false;
      } else {
        socket = ::WinHttpWebSocketCompleteUpgrade(request, 0);
        if (socket == nullptr) {
          error = "the WebSocket upgrade failed (error " + std::to_string(::GetLastError()) + ")";
          ok = false;
        }
      }
    }
    if (request != nullptr) {
      ::WinHttpCloseHandle(request);
    }
    std::lock_guard<std::mutex> lock(mState->lock);
    mState->session = session;
    mState->connection = connection;
    mState->socket = socket;
    if (!ok) {
      mState->Drop();
      return std::unexpected(std::move(error));
    }
    return {};
  }

  std::expected<void, std::string> WebSocket::SendText(
    const std::string_view text
  )
  {
    return Send(text, true);
  }

  std::expected<void, std::string> WebSocket::SendBinary(
    const std::string_view bytes
  )
  {
    return Send(bytes, false);
  }

  std::expected<void, std::string> WebSocket::Send(
    const std::string_view text,
    const bool utf8
  )
  {
    HINTERNET socket = nullptr;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      socket = mState->socket;
    }
    if (socket == nullptr) {
      return std::unexpected("not connected");
    }
    const DWORD result = ::WinHttpWebSocketSend(
      socket,
      utf8 ? WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE : WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
      const_cast<char*>(text.data()),
      static_cast<DWORD>(text.size())
    );
    if (result != NO_ERROR) {
      return std::unexpected("sending failed (error " + std::to_string(result) + ")");
    }
    return {};
  }

  std::expected<WebSocket::Received, std::string> WebSocket::Receive(
    std::string& message
  )
  {
    message.clear();
    HINTERNET socket = nullptr;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      socket = mState->socket;
    }
    if (socket == nullptr) {
      return std::unexpected("not connected");
    }
    char buffer[65536];
    for (;;) {
      DWORD read = 0;
      WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
      const DWORD result = ::WinHttpWebSocketReceive(socket, buffer, sizeof(buffer), &read, &type);
      if (result != NO_ERROR) {
        return std::unexpected("the connection broke off (error " + std::to_string(result) + ")");
      }
      if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
        return Received::Closed;
      }
      message.append(buffer, read);
      if (
        type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE
      ) {
        return Received::Message;
      }
      // A fragment: the rest of the message follows.
    }
  }

  void WebSocket::Close()
  {
    std::lock_guard<std::mutex> lock(mState->lock);
    if (mState->socket != nullptr) {
      (void)::WinHttpWebSocketShutdown(mState->socket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
    }
    mState->Drop();
  }
} // namespace platform::http
