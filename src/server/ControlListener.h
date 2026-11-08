#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "remote/net/UdpSocket.h"
#include "server/ControlChannel.h"

// Engine addition, dedicated server (plan WP17.2, research/WP17.2-control-api.md): the control API's TCP listener,
// Linux only (as the server). One connection at a time: the server's half of the handshake (ControlChannel.h), then
// requests and replies as JSON text in sealed frames. Polled from the server's main loop, which answers the requests;
// a second connection while one is open is closed at once, and so is one that doesn't prove the key within 5 s.

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
    /** `{"id": id, "ok": true, ...fields}`; `fields` is JSON object members without braces, or empty. */
    void Reply(std::int64_t id, std::string_view fields);
    void Refuse(std::int64_t id, std::string_view error);
    /** `{"event": name, ...fields}` to the connected service, if one is. */
    void Event(std::string_view name, std::string_view fields);
    [[nodiscard]] bool Connected() const noexcept;
    /** Lines worth the console: who connected, a refused key, a malformed request. */
    [[nodiscard]] std::vector<std::string> TakeNews();

  private:
    struct SConnection;
    /** The open connection's reads: handshake, frames, requests, and the handshake's deadline. */
    void ReadConnection(std::vector<SControlRequest>& requests, std::uint64_t nowUs);
    /** The open connection's peer has closed (a read would end), though nothing has read it yet. */
    [[nodiscard]] bool PeerClosed() const;
    void Close(const char* why);
    void Send(std::string_view json);
    void Flush();

    ControlKey mKey{};
    int mListenSocket = -1;
    std::unique_ptr<SConnection> mConnection;
    std::vector<std::string> mNews;
  };
} // namespace faf::server
