#pragma once

/**
 * Engine addition (in-game launcher plan, WP1): HTTPS requests and WebSocket connections, one interface with one
 * implementation per platform, for the map editor's FAF vault and the game's launcher.
 *
 * - Windows (src/platform/windows/HttpWindows.cpp): WinHTTP, so the system's proxy settings and certificate store
 *   apply. The request code is the map editor's (src/editor/doc/EdHttp.cpp before WP1), unchanged.
 * - POSIX: not written yet; the Linux and macOS clients bring theirs.
 */

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace platform::http
{
  /** One request: GET without a body, POST (or any method) with one. */
  struct Call
  {
    std::string method = "GET";
    std::string url;
    /** Extra request headers, each ending in "\r\n" (`Authorization: Bearer ...\r\n`). */
    std::string headers;
    std::string body;
    /** The User-Agent; empty: the process's default (SetDefaultUserAgent). */
    std::string userAgent;
  };

  /**
   * The User-Agent of requests that don't name one. "FAF-RE map editor" until a program sets its own (the editor's
   * requests have always sent that text).
   */
  void SetDefaultUserAgent(std::string agent);

  /**
   * Runs `call`; the response's status and body come back whatever the status. The error when there was no answer at
   * all (no network, a broken link). `received`, when given, follows the body's bytes as they come, and `total` gets
   * the body's size when the server says it.
   */
  [[nodiscard]] std::expected<void, std::string> Request(
    const Call& call,
    long& status,
    std::string& body,
    std::atomic<std::uint64_t>* received = nullptr,
    std::atomic<std::uint64_t>* total = nullptr
  );

  /**
   * A response read as it comes (Server-Sent Events, a large download): Open sends the request and reads the status,
   * Read returns the next part of the body. Close from another thread ends a blocked Read.
   */
  class Stream
  {
  public:
    Stream();
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    /** Sends `call`; the HTTP status once the server answered. */
    [[nodiscard]] std::expected<long, std::string> Open(const Call& call);
    /** The next part of the body (empty: the body ended). */
    [[nodiscard]] std::expected<std::string, std::string> Read();
    void Close();

  private:
    struct State;
    std::unique_ptr<State> mState;
  };

  /**
   * A WebSocket client (`ws://` or `wss://`), text messages in and out. One thread may block in Receive while another
   * sends; Close from any thread ends a blocked Receive.
   */
  class WebSocket
  {
  public:
    enum class Received
    {
      Message,
      Closed,
    };

    WebSocket();
    ~WebSocket();
    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;

    /** Connects and upgrades. `headers` as in Call; the error names the HTTP status when the server refused. */
    [[nodiscard]] std::expected<void, std::string>
    Open(const std::string& url, const std::string& headers = {}, const std::string& userAgent = {});
    /** One whole text message. */
    [[nodiscard]] std::expected<void, std::string> SendText(std::string_view text);
    /** One whole binary message. */
    [[nodiscard]] std::expected<void, std::string> SendBinary(std::string_view bytes);
    /** Blocks until one whole message (text or binary) has come, the server closed, or the connection failed. */
    [[nodiscard]] std::expected<Received, std::string> Receive(std::string& message);
    /** Sends a normal close and drops the connection; a blocked Receive returns. Safe to call more than once. */
    void Close();
    [[nodiscard]] bool IsOpen() const;

  private:
    [[nodiscard]] std::expected<void, std::string> Send(std::string_view bytes, bool utf8);

    struct State;
    std::unique_ptr<State> mState;
  };
} // namespace platform::http
