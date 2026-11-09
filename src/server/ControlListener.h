#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "remote/net/UdpSocket.h"
#include "server/ControlChannel.h"

// Engine addition, dedicated server (plan WP17.2, research/WP17.2-control-api.md): the control API's TCP listener,
// Linux only (as the server). Up to `kMaxControlConnections` at once (a service's event stream beside its requests;
// one hung connection doesn't lock the service out), each with the server's half of the handshake (ControlChannel.h),
// then requests and replies as JSON text in sealed frames. Polled from the server's main loop, which answers the
// requests: a reply goes to the connection its request came from, an event to every connection. One more connection
// is closed at once, and so is one that doesn't prove the key within 5 s.

namespace faf::server
{
  /** One request: `{"id": n, "op": "...", "uid": n, "reason": "...", "address": "a.b.c.d"}`; other keys are ignored. */
  struct SControlRequest
  {
    std::int64_t id = 0;
    std::string op;
    std::int64_t uid = 0;
    std::string reason;
    std::string address;
    std::string options; // "Key=Value,Key=Value": `set_options`
    std::string results; // "1=victory,2=defeat": `end`, by army number from 1
    std::int64_t count = 0; // `extend_timeouts`
    std::string token;      // `substitute`: the substitute's admission token
    std::string name;       // `substitute`: the substitute's name
  };

  /** A flat JSON object's request fields; nothing when it isn't one, or has no `op`. */
  [[nodiscard]] std::optional<SControlRequest> ParseControlRequest(std::string_view text);
  /** `text` as a JSON string, quotes included. */
  [[nodiscard]] std::string JsonString(std::string_view text);

  /** Plan WP15.6: how many control connections the server holds at once. */
  inline constexpr std::size_t kMaxControlConnections = 4;

  class CControlListener
  {
  public:
    CControlListener();
    ~CControlListener();
    CControlListener(const CControlListener&) = delete;
    CControlListener& operator=(const CControlListener&) = delete;

    [[nodiscard]] bool Open(const remote::net::SEndpoint& at, const ControlKey& key, std::string& error);
    /** Accepts, reads and writes what it can without waiting; the requests that came, in order. */
    void Poll(std::vector<SControlRequest>& requests, std::uint64_t nowUs);
    /**
     * `{"id": id, "ok": true, ...fields}`, to the connection the oldest unanswered request with this id came from;
     * `fields` is JSON object members without braces, or empty.
     */
    void Reply(std::int64_t id, std::string_view fields);
    void Refuse(std::int64_t id, std::string_view error);
    /** `{"event": name, ...fields}` to every connected service. */
    void Event(std::string_view name, std::string_view fields);
    /** Whether a service has proved the key on a connection still open. */
    [[nodiscard]] bool Connected() const noexcept;
    /** Lines worth the console: who connected, a refused key, a malformed request. */
    [[nodiscard]] std::vector<std::string> TakeNews();

  private:
    struct SConnection;
    /** A connection's reads: handshake, frames, requests, and the handshake's deadline. */
    void ReadConnection(SConnection& connection, std::vector<SControlRequest>& requests, std::uint64_t nowUs);
    /** Its peer has closed (a read would end), though nothing has read it yet. */
    [[nodiscard]] static bool PeerClosed(const SConnection& connection);
    /** Marks it closed (`socket` -1); `DropClosed` takes it out of the list. */
    void Close(SConnection& connection, const char* why);
    void DropClosed();
    void Send(SConnection& connection, std::string_view json);
    /** To the connection the oldest unanswered request with `id` came from (any connection's, when none is waiting). */
    void Answer(std::int64_t id, std::string_view json);
    void Flush(SConnection& connection);

    ControlKey mKey{};
    int mListenSocket = -1;
    std::vector<std::unique_ptr<SConnection>> mConnections;
    std::uint64_t mNextSerial = 1;
    std::vector<std::pair<std::int64_t, std::uint64_t>> mWaiting; // requests handed out, not answered: id, connection serial
    std::vector<std::string> mNews;
  };
} // namespace faf::server
