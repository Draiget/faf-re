#include "server/ControlListener.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <utility>
#include <cstdio>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "monocypher.h"
#include "remote/net/Handshake.h"

// Engine addition, dedicated server: see ControlListener.h.

namespace faf::server
{
  namespace
  {
    constexpr std::uint64_t kHandshakeUs = 5'000'000u;
    constexpr std::size_t kMaxPendingOutBytes = 4u * 1024u * 1024u; // a service that stops reading is dropped

    void SkipSpace(std::string_view text, std::size_t& at) noexcept
    {
      while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) {
        ++at;
      }
    }

    [[nodiscard]] bool ReadString(std::string_view text, std::size_t& at, std::string& out)
    {
      if (at >= text.size() || text[at] != '"') {
        return false;
      }
      ++at;
      out.clear();
      while (at < text.size()) {
        const char c = text[at++];
        if (c == '"') {
          return true;
        }
        if (c != '\\') {
          out += c;
          continue;
        }
        if (at >= text.size()) {
          return false;
        }
        const char e = text[at++];
        switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'u': {
          if (at + 4 > text.size()) {
            return false;
          }
          unsigned value = 0;
          for (int i = 0; i < 4; ++i) {
            const char h = text[at++];
            value <<= 4;
            if (h >= '0' && h <= '9') {
              value |= static_cast<unsigned>(h - '0');
            } else if (h >= 'a' && h <= 'f') {
              value |= static_cast<unsigned>(h - 'a' + 10);
            } else if (h >= 'A' && h <= 'F') {
              value |= static_cast<unsigned>(h - 'A' + 10);
            } else {
              return false;
            }
          }
          // UTF-8 for the basic plane; a request names ops and uids, so surrogate pairs aren't needed.
          if (value < 0x80u) {
            out += static_cast<char>(value);
          } else if (value < 0x800u) {
            out += static_cast<char>(0xC0u | (value >> 6));
            out += static_cast<char>(0x80u | (value & 0x3Fu));
          } else {
            out += static_cast<char>(0xE0u | (value >> 12));
            out += static_cast<char>(0x80u | ((value >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (value & 0x3Fu));
          }
          break;
        }
        default:
          return false;
        }
      }
      return false;
    }

    /** A number, true, false or null; numbers as whole values (ids and uids). */
    [[nodiscard]] bool ReadScalar(std::string_view text, std::size_t& at, std::int64_t& number, bool& isNumber)
    {
      isNumber = false;
      for (const std::string_view word : {std::string_view("true"), std::string_view("false"), std::string_view("null")}) {
        if (text.substr(at, word.size()) == word) {
          at += word.size();
          return true;
        }
      }
      const std::size_t start = at;
      bool negative = false;
      if (at < text.size() && text[at] == '-') {
        negative = true;
        ++at;
      }
      std::int64_t value = 0;
      std::size_t digits = 0;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9') {
        if (value > (INT64_MAX - 9) / 10) {
          return false;
        }
        value = value * 10 + (text[at] - '0');
        ++at;
        ++digits;
      }
      if (digits == 0u) {
        at = start;
        return false;
      }
      if (at < text.size() && (text[at] == '.' || text[at] == 'e' || text[at] == 'E')) {
        return false; // no fractions: ids and uids are whole
      }
      number = negative ? -value : value;
      isNumber = true;
      return true;
    }

    [[nodiscard]] bool WouldBlock() noexcept
    {
      return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }

    void SetNonBlocking(const int socket) noexcept
    {
      const int flags = ::fcntl(socket, F_GETFL, 0);
      (void)::fcntl(socket, F_SETFL, flags | O_NONBLOCK);
    }
  } // namespace

  std::optional<SControlRequest> ParseControlRequest(const std::string_view text)
  {
    SControlRequest request;
    std::size_t at = 0;
    SkipSpace(text, at);
    if (at >= text.size() || text[at] != '{') {
      return std::nullopt;
    }
    ++at;
    SkipSpace(text, at);
    bool first = true;
    while (at < text.size() && text[at] != '}') {
      if (!first) {
        if (text[at] != ',') {
          return std::nullopt;
        }
        ++at;
        SkipSpace(text, at);
        if (at >= text.size() || text[at] == '}') {
          return std::nullopt; // a comma with no member after it
        }
      }
      first = false;
      std::string key;
      if (!ReadString(text, at, key)) {
        return std::nullopt;
      }
      SkipSpace(text, at);
      if (at >= text.size() || text[at] != ':') {
        return std::nullopt;
      }
      ++at;
      SkipSpace(text, at);
      if (at < text.size() && text[at] == '"') {
        std::string value;
        if (!ReadString(text, at, value)) {
          return std::nullopt;
        }
        if (key == "op") {
          request.op = std::move(value);
        } else if (key == "reason") {
          request.reason = std::move(value);
        } else if (key == "address") {
          request.address = std::move(value);
        }
      } else {
        std::int64_t number = 0;
        bool isNumber = false;
        if (!ReadScalar(text, at, number, isNumber)) {
          return std::nullopt; // objects and arrays included: a request is flat
        }
        if (isNumber && key == "id") {
          request.id = number;
        } else if (isNumber && key == "uid") {
          request.uid = number;
        }
      }
      SkipSpace(text, at);
    }
    if (at >= text.size() || text[at] != '}') {
      return std::nullopt;
    }
    ++at;
    SkipSpace(text, at);
    if (at != text.size() || request.op.empty()) {
      return std::nullopt;
    }
    return request;
  }

  std::string JsonString(const std::string_view text)
  {
    std::string out = "\"";
    for (const char c : text) {
      switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20u) {
          char escaped[8];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += escaped;
        } else {
          out += c;
        }
      }
    }
    out += '"';
    return out;
  }

  struct CControlListener::SConnection
  {
    int socket = -1;
    std::string peer;
    std::uint64_t acceptedUs = 0;
    std::unique_ptr<CControlChannel> channel;
    bool sentProof = false;
    std::vector<std::uint8_t> raw;      // handshake bytes before the channel is ready
    std::vector<std::uint8_t> outgoing; // bytes not yet taken by the socket
  };

  CControlListener::CControlListener() = default;

  CControlListener::~CControlListener()
  {
    Close(nullptr);
    if (mListenSocket >= 0) {
      ::close(mListenSocket);
    }
    crypto_wipe(mKey.data(), mKey.size());
  }

  bool CControlListener::Open(const remote::net::SEndpoint& at, const ControlKey& key, std::string& error)
  {
    mKey = key;
    mListenSocket = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (mListenSocket < 0) {
      error = "control: no TCP socket";
      return false;
    }
    const int yes = 1;
    (void)::setsockopt(mListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(at.port);
    address.sin_addr.s_addr = htonl(at.ip);
    if (::bind(mListenSocket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 || ::listen(mListenSocket, 4) != 0) {
      error = "control: can't listen on " + at.Text();
      ::close(mListenSocket);
      mListenSocket = -1;
      return false;
    }
    SetNonBlocking(mListenSocket);
    return true;
  }

  bool CControlListener::Connected() const noexcept
  {
    return mConnection && mConnection->channel && mConnection->channel->Ready();
  }

  std::vector<std::string> CControlListener::TakeNews()
  {
    return std::exchange(mNews, {});
  }

  void CControlListener::Close(const char* const why)
  {
    if (!mConnection) {
      return;
    }
    if (why != nullptr) {
      mNews.push_back("control: " + mConnection->peer + " " + why);
    }
    ::close(mConnection->socket);
    mConnection.reset();
  }

  void CControlListener::Flush()
  {
    while (mConnection && !mConnection->outgoing.empty()) {
      const ssize_t sent = ::send(mConnection->socket, mConnection->outgoing.data(), mConnection->outgoing.size(), MSG_NOSIGNAL);
      if (sent < 0) {
        if (!WouldBlock()) {
          Close(errno == EPIPE || errno == ECONNRESET ? "disconnected" : "closed (send failed)");
        }
        return;
      }
      mConnection->outgoing.erase(mConnection->outgoing.begin(), mConnection->outgoing.begin() + sent);
    }
  }

  void CControlListener::Send(const std::string_view json)
  {
    if (!Connected()) {
      return;
    }
    const std::vector<std::uint8_t> frame =
      mConnection->channel->Seal(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(json.data()), json.size()));
    if (frame.empty()) {
      return; // too large for one message
    }
    if (mConnection->outgoing.size() + frame.size() > kMaxPendingOutBytes) {
      Close("closed (it doesn't read what the server sends)");
      return;
    }
    mConnection->outgoing.insert(mConnection->outgoing.end(), frame.begin(), frame.end());
    Flush();
  }

  void CControlListener::Reply(const std::int64_t id, const std::string_view fields)
  {
    Send("{\"id\":" + std::to_string(id) + ",\"ok\":true" + (fields.empty() ? std::string() : "," + std::string(fields)) + "}");
  }

  void CControlListener::Refuse(const std::int64_t id, const std::string_view error)
  {
    Send("{\"id\":" + std::to_string(id) + ",\"ok\":false,\"error\":" + JsonString(error) + "}");
  }

  void CControlListener::Event(const std::string_view name, const std::string_view fields)
  {
    Send("{\"event\":" + JsonString(name) + (fields.empty() ? std::string() : "," + std::string(fields)) + "}");
  }

  void CControlListener::Poll(std::vector<SControlRequest>& requests, const std::uint64_t nowUs)
  {
    if (mListenSocket < 0) {
      return;
    }
    // The open connection first: a service that closed after its reply is gone before the next one is looked at.
    ReadConnection(requests, nowUs);
    // New connections: the first is taken, any other while a live one is open is closed at once.
    for (;;) {
      sockaddr_in from{};
      socklen_t size = sizeof(from);
      const int socket = ::accept4(mListenSocket, reinterpret_cast<sockaddr*>(&from), &size, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (socket < 0) {
        break;
      }
      remote::net::SEndpoint peer;
      peer.ip = ntohl(from.sin_addr.s_addr);
      peer.port = ntohs(from.sin_port);
      if (mConnection && PeerClosed()) {
        Close(Connected() ? "disconnected" : "disconnected during the handshake");
      }
      if (mConnection) {
        mNews.push_back("control: " + peer.Text() + " refused: a control connection is open");
        ::close(socket);
        continue;
      }
      const int yes = 1;
      (void)::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
      ControlNonce nonce{};
      if (!remote::net::FillRandom(nonce.data(), nonce.size())) {
        ::close(socket);
        continue;
      }
      mConnection = std::make_unique<SConnection>();
      mConnection->socket = socket;
      mConnection->peer = peer.Text();
      mConnection->acceptedUs = nowUs;
      mConnection->channel = std::make_unique<CControlChannel>(mKey, EControlRole::Server, nonce);
      mConnection->outgoing.assign(nonce.begin(), nonce.end()); // the server's nonce goes first
      Flush();
    }
    ReadConnection(requests, nowUs);
  }

  bool CControlListener::PeerClosed() const
  {
    std::uint8_t byte = 0;
    const ssize_t got = ::recv(mConnection->socket, &byte, 1u, MSG_PEEK | MSG_DONTWAIT);
    return got == 0 || (got < 0 && !WouldBlock());
  }

  void CControlListener::ReadConnection(std::vector<SControlRequest>& requests, const std::uint64_t nowUs)
  {
    if (!mConnection) {
      return;
    }
    Flush();
    std::uint8_t buffer[16384];
    for (;;) {
      if (!mConnection) {
        return;
      }
      const ssize_t got = ::recv(mConnection->socket, buffer, sizeof(buffer), 0);
      if (got == 0) {
        Close(Connected() ? "disconnected" : "disconnected during the handshake");
        return;
      }
      if (got < 0) {
        if (!WouldBlock()) {
          // A peer that closes with our events unread resets the connection: that's a disconnect too.
          Close(errno == ECONNRESET ? (Connected() ? "disconnected" : "disconnected during the handshake") : "closed (receive failed)");
        }
        break;
      }
      CControlChannel& channel = *mConnection->channel;
      if (!channel.Ready()) {
        std::vector<std::uint8_t>& raw = mConnection->raw;
        raw.insert(raw.end(), buffer, buffer + got);
        if (!mConnection->sentProof && raw.size() >= sizeof(ControlNonce)) {
          ControlNonce peerNonce{};
          std::copy_n(raw.begin(), peerNonce.size(), peerNonce.begin());
          const ControlProof proof = channel.Proof(peerNonce);
          mConnection->outgoing.insert(mConnection->outgoing.end(), proof.begin(), proof.end());
          mConnection->sentProof = true;
          Flush();
          if (!mConnection) {
            return;
          }
        }
        if (mConnection->sentProof && raw.size() >= sizeof(ControlNonce) + sizeof(ControlProof)) {
          ControlProof peerProof{};
          std::copy_n(raw.begin() + sizeof(ControlNonce), peerProof.size(), peerProof.begin());
          if (!channel.CheckPeerProof(peerProof)) {
            Close("refused: it doesn't hold the control key");
            return;
          }
          mNews.push_back("control: " + mConnection->peer + " connected");
          const std::vector<std::uint8_t> rest(raw.begin() + sizeof(ControlNonce) + sizeof(ControlProof), raw.end());
          raw.clear();
          if (!rest.empty() && !channel.Feed(rest)) {
            Close("closed (a frame didn't open)");
            return;
          }
        }
        continue;
      }
      if (!channel.Feed(std::span<const std::uint8_t>(buffer, static_cast<std::size_t>(got)))) {
        Close("closed (a frame didn't open)");
        return;
      }
    }
    if (!mConnection) {
      return;
    }
    if (!Connected() && nowUs - mConnection->acceptedUs > kHandshakeUs) {
      Close("closed: no handshake in 5 s");
      return;
    }
    std::vector<std::uint8_t> message;
    while (mConnection && mConnection->channel->Take(message)) {
      const std::string_view text(reinterpret_cast<const char*>(message.data()), message.size());
      std::optional<SControlRequest> request = ParseControlRequest(text);
      if (!request) {
        Refuse(0, "not a request: a flat JSON object with an \"op\"");
        continue;
      }
      requests.push_back(std::move(*request));
    }
  }
} // namespace faf::server
