#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace faf::editor
{
  /** One HTTPS request (WinHTTP): GET without a body, POST with one. */
  struct HttpCall
  {
    std::string method = "GET";
    std::string url;
    /** Extra request headers, each ending in "\r\n" (`Authorization: Bearer ...\r\n`). */
    std::string headers;
    std::string body;
  };

  /**
   * Runs `call`; the response's status and body come back whatever the status. False with `error` when there was no
   * answer at all (no network, a broken link). `received`, when given, follows the body's bytes as they come.
   */
  bool HttpRequest(const HttpCall& call, long& status, std::string& body, std::string& error,
                   std::atomic<std::uint64_t>* received = nullptr);

  /** `text` as an `application/x-www-form-urlencoded` or query value. */
  std::string UrlEncode(const std::string& text);
} // namespace faf::editor
