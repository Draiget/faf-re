#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "remote/net/UdpSocket.h"
#include "server/ControlListener.h"

// Engine addition, dedicated server (plan WP17.11): the control API over plain HTTP/1.1 and JSON, for a dashboard,
// beside the sealed control channel (ControlListener.h), Linux only. Every request carries
// `Authorization: Bearer <admin token>` (the server's --rest-token-file); one without it, or with another, is answered
// 401. Routes:
//
//   GET  /api/v1/status        the `status` op
//   POST /api/v1/ops/<op>      any control op; the body is a JSON object of its fields (uid, reason, options, ...)
//   GET  /api/v1/events        Server-Sent Events: each control event as `event: <name>` and `data: <json>`
//   OPTIONS (any)              a browser's CORS preflight, answered without the token
//
// A request becomes an `SControlRequest` with a negative id (the sealed channel's services choose their own ids, so
// these never meet them), which the server's main loop answers as any other: 200 and `{"id": .., "ok": true, ...}`, or
// 400 and `{"id": .., "ok": false, "error": ..}`. Each connection carries one request and is closed after its answer,
// except an event stream. Limits: `kMaxRestConnections` at once, 8 KB of headers, 64 KB of body, 5 s to send a whole
// request. Plain HTTP carries the token in the clear: bind to 127.0.0.1, or put a TLS proxy in front.

namespace faf::server
{
  inline constexpr std::size_t kMaxRestConnections = 16;

  class CRestListener
  {
  public:
    CRestListener();
    ~CRestListener();
    CRestListener(const CRestListener&) = delete;
    CRestListener& operator=(const CRestListener&) = delete;

    /**
     * Listens at `at`. `token`: the admin token every request must carry (at least 16 characters); `corsOrigin`: the
     * one web origin a browser may call from (`Access-Control-Allow-Origin`), empty for none.
     */
    [[nodiscard]] bool
    Open(const remote::net::SEndpoint& at, std::string token, std::string corsOrigin, std::string& error);
    /** Accepts, reads and writes what it can without waiting; the requests that came, in order. */
    void Poll(std::vector<SControlRequest>& requests, std::uint64_t nowUs);
    /** The answer to request `id` (negative), as `CControlListener::Reply`/`Refuse` make it. */
    void Answer(std::int64_t id, bool ok, std::string_view json);
    /** `json` (`{"event": name, ...}`) to every event stream. */
    void Event(std::string_view name, std::string_view json);
    /** Whether an event stream is open. */
    [[nodiscard]] bool Connected() const noexcept;
    /** Lines worth the console: a refused token, a malformed request, an event stream opened or closed. */
    [[nodiscard]] std::vector<std::string> TakeNews()
    {
      return std::exchange(mNews, {});
    }

  private:
    struct SConnection;
    void Read(SConnection& connection, std::vector<SControlRequest>& requests, std::uint64_t nowUs);
    /** A whole request in `connection.in`: routed, answered at once, or handed out as a control request. */
    void Handle(
      SConnection& connection,
      std::string_view method,
      std::string_view path,
      std::string_view body,
      std::vector<SControlRequest>& requests
    );
    void Respond(SConnection& connection, int status, std::string_view json);
    void Flush(SConnection& connection);
    void Close(SConnection& connection, const char* why);
    [[nodiscard]] std::string CorsHeaders(const SConnection& connection) const;

    int mListenSocket = -1;
    std::string mToken;
    std::string mCorsOrigin;
    std::vector<std::unique_ptr<SConnection>> mConnections;
    std::int64_t mNextId = -1;
    std::vector<std::string> mNews;
  };

  /** Plan WP17.11: whether `given` equals `expected`, in time that doesn't depend on where they differ. */
  [[nodiscard]] bool TokensEqual(std::string_view given, std::string_view expected) noexcept;
} // namespace faf::server
