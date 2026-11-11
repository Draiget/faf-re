#include "server/RestListener.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

// Engine addition, dedicated server: see RestListener.h.

namespace faf::server
{
  namespace
  {
    constexpr std::size_t kMaxHeaderBytes = 8u * 1024u;
    constexpr std::size_t kMaxBodyBytes = 64u * 1024u;
    constexpr std::uint64_t kRequestTimeUs = 5'000'000u;
    constexpr std::size_t kMaxPendingOutBytes = 4u * 1024u * 1024u; // an event stream that stops reading is dropped

    [[nodiscard]] bool WouldBlock() noexcept
    {
      return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }

    [[nodiscard]] std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return out;
    }

    [[nodiscard]] std::string_view Trim(
      std::string_view text
    ) noexcept
    {
      while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
      }
      while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
      }
      return text;
    }

    [[nodiscard]] const char* StatusText(
      const int status
    ) noexcept
    {
      switch (status) {
      case 200:
        return "OK";
      case 204:
        return "No Content";
      case 400:
        return "Bad Request";
      case 401:
        return "Unauthorized";
      case 404:
        return "Not Found";
      case 405:
        return "Method Not Allowed";
      case 413:
        return "Payload Too Large";
      default:
        return "Error";
      }
    }

    /** An op name as a path segment: lowercase letters and underscores. */
    [[nodiscard]] bool ValidOp(
      std::string_view op
    ) noexcept
    {
      return !op.empty() && op.size() <= 32 && std::all_of(op.begin(), op.end(), [](const char c) {
        return (c >= 'a' && c <= 'z') || c == '_';
      });
    }
  } // namespace

  bool TokensEqual(
    const std::string_view given,
    const std::string_view expected
  ) noexcept
  {
    // Every byte of the expected token is looked at whatever the given one is, so the time says only its length.
    unsigned char difference = given.size() == expected.size() ? 0u : 1u;
    for (std::size_t i = 0; i < expected.size(); ++i) {
      const unsigned char a = i < given.size() ? static_cast<unsigned char>(given[i]) : 0u;
      difference |= static_cast<unsigned char>(a ^ static_cast<unsigned char>(expected[i]));
    }
    return difference == 0u;
  }

  struct CRestListener::SConnection
  {
    int socket = -1;
    std::string peer;
    std::uint64_t acceptedUs = 0;
    std::string in;       // what arrived of the request
    std::string out;      // what the socket hasn't taken yet
    std::string origin;   // the request's Origin header
    bool handled = false; // its request was read whole
    bool events = false;  // an event stream: stays open
    bool closeWhenSent = false;
    std::int64_t waitingId = 0; // a control request handed out and not answered yet (0: none)
  };

  CRestListener::CRestListener() = default;

  CRestListener::~CRestListener()
  {
    for (const std::unique_ptr<SConnection>& connection : mConnections) {
      if (connection->socket >= 0) {
        ::close(connection->socket);
      }
    }
    if (mListenSocket >= 0) {
      ::close(mListenSocket);
    }
  }

  bool CRestListener::Open(
    const remote::net::SEndpoint& at,
    std::string token,
    std::string corsOrigin,
    std::string& error
  )
  {
    if (token.size() < 16u) {
      error = "rest: the admin token needs at least 16 characters";
      return false;
    }
    mToken = std::move(token);
    mCorsOrigin = std::move(corsOrigin);
    mListenSocket = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (mListenSocket < 0) {
      error = "rest: no TCP socket";
      return false;
    }
    const int yes = 1;
    (void)::setsockopt(mListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(at.port);
    address.sin_addr.s_addr = htonl(at.ip);
    if (
      ::bind(mListenSocket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
      ::listen(mListenSocket, 16) != 0
    ) {
      error = "rest: can't listen on " + at.Text();
      ::close(mListenSocket);
      mListenSocket = -1;
      return false;
    }
    (void)::fcntl(mListenSocket, F_SETFL, ::fcntl(mListenSocket, F_GETFL, 0) | O_NONBLOCK);
    return true;
  }

  bool CRestListener::Connected() const noexcept
  {
    return std::any_of(mConnections.begin(), mConnections.end(), [](const std::unique_ptr<SConnection>& connection) {
      return connection->socket >= 0 && connection->events;
    });
  }

  std::string CRestListener::CorsHeaders(
    const SConnection& connection
  ) const
  {
    if (mCorsOrigin.empty() || connection.origin != mCorsOrigin) {
      return {};
    }
    return "Access-Control-Allow-Origin: " + mCorsOrigin +
      "\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\n"
      "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
  }

  void CRestListener::Close(
    SConnection& connection,
    const char* why
  )
  {
    if (connection.socket < 0) {
      return;
    }
    if (why != nullptr) {
      mNews.push_back("rest: " + connection.peer + " " + why);
    }
    ::close(connection.socket);
    connection.socket = -1;
  }

  void CRestListener::Flush(
    SConnection& connection
  )
  {
    while (connection.socket >= 0 && !connection.out.empty()) {
      const ssize_t sent = ::send(connection.socket, connection.out.data(), connection.out.size(), MSG_NOSIGNAL);
      if (sent < 0) {
        if (!WouldBlock()) {
          Close(connection, connection.events ? "event stream closed" : nullptr);
        }
        return;
      }
      connection.out.erase(0, static_cast<std::size_t>(sent));
    }
    if (connection.socket >= 0 && connection.out.empty() && connection.closeWhenSent) {
      Close(connection, nullptr);
    }
  }

  void CRestListener::Respond(
    SConnection& connection,
    const int status,
    const std::string_view json
  )
  {
    std::string head = "HTTP/1.1 " + std::to_string(status) + " " + StatusText(status) + "\r\n" +
      CorsHeaders(connection) + "Cache-Control: no-store\r\nConnection: close\r\n";
    if (status == 204) {
      head += "\r\n";
    } else {
      head += "Content-Type: application/json\r\nContent-Length: " + std::to_string(json.size()) + "\r\n\r\n";
      head.append(json);
    }
    connection.out += head;
    connection.closeWhenSent = true;
    Flush(connection);
  }

  void CRestListener::Answer(
    const std::int64_t id,
    const bool ok,
    const std::string_view json
  )
  {
    for (const std::unique_ptr<SConnection>& connection : mConnections) {
      if (connection->waitingId == id && connection->socket >= 0) {
        connection->waitingId = 0;
        Respond(*connection, ok ? 200 : 400, json);
        return;
      }
    }
  }

  void CRestListener::Event(
    const std::string_view name,
    const std::string_view json
  )
  {
    const std::string message = "event: " + std::string(name) + "\ndata: " + std::string(json) + "\n\n";
    for (const std::unique_ptr<SConnection>& connection : mConnections) {
      if (connection->socket < 0 || !connection->events) {
        continue;
      }
      if (connection->out.size() + message.size() > kMaxPendingOutBytes) {
        Close(*connection, "event stream closed (it doesn't read what the server sends)");
        continue;
      }
      connection->out += message;
      Flush(*connection);
    }
  }

  void CRestListener::Handle(
    SConnection& connection,
    const std::string_view method,
    const std::string_view path,
    const std::string_view body,
    std::vector<SControlRequest>& requests
  )
  {
    if (method == "OPTIONS") {
      Respond(connection, 204, {}); // a browser's preflight carries no token
      return;
    }
    const std::string_view kOps = "/api/v1/ops/";
    std::string op;
    if (path == "/api/v1/status") {
      if (method != "GET") {
        Respond(connection, 405, "{\"ok\":false,\"error\":\"status is GET\"}");
        return;
      }
      op = "status";
    } else if (path == "/api/v1/armies") {
      if (method != "GET") {
        Respond(connection, 405, "{\"ok\":false,\"error\":\"armies is GET\"}");
        return;
      }
      op = "armies"; // plan WP17.15: each army's economy, units, commander and score during the game
    } else if (path == "/api/v1/events") {
      if (method != "GET") {
        Respond(connection, 405, "{\"ok\":false,\"error\":\"events is GET\"}");
        return;
      }
      connection.events = true;
      connection.out += "HTTP/1.1 200 OK\r\n" + CorsHeaders(connection) +
        "Content-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n: events\n\n";
      Flush(connection);
      mNews.push_back("rest: " + connection.peer + " opened an event stream");
      return;
    } else if (path.starts_with(kOps)) {
      op = std::string(path.substr(kOps.size()));
      if (method != "POST") {
        Respond(connection, 405, "{\"ok\":false,\"error\":\"ops are POST\"}");
        return;
      }
      if (!ValidOp(op)) {
        Respond(connection, 404, "{\"ok\":false,\"error\":\"no such op\"}");
        return;
      }
    } else {
      Respond(
        connection, 404, "{\"ok\":false,\"error\":\"no such path: /api/v1/status, /api/v1/ops/<op>, /api/v1/events\"}"
      );
      return;
    }
    // The fields from the body (a JSON object, or nothing), with the op from the path.
    const std::string_view object = Trim(body);
    std::string text = "{\"op\":\"" + op + "\"";
    if (!object.empty()) {
      if (object.front() != '{' || object.back() != '}') {
        Respond(connection, 400, "{\"ok\":false,\"error\":\"the body is a JSON object of the op's fields\"}");
        return;
      }
      const std::string_view inner = Trim(object.substr(1, object.size() - 2));
      if (!inner.empty()) {
        text += ",";
        text += inner;
      }
    }
    text += "}";
    std::optional<SControlRequest> request = ParseControlRequest(text);
    if (!request) {
      Respond(connection, 400, "{\"ok\":false,\"error\":\"the body is a JSON object of the op's fields\"}");
      return;
    }
    request->id = mNextId--;
    request->op = op; // the path's, whatever the body said
    connection.waitingId = request->id;
    requests.push_back(std::move(*request));
  }

  void CRestListener::Read(
    SConnection& connection,
    std::vector<SControlRequest>& requests,
    const std::uint64_t nowUs
  )
  {
    char buffer[4096];
    for (;;) {
      const ssize_t got = ::recv(connection.socket, buffer, sizeof(buffer), 0);
      if (got == 0) {
        Close(connection, connection.events ? "event stream closed" : nullptr);
        return;
      }
      if (got < 0) {
        if (!WouldBlock()) {
          Close(connection, connection.events ? "event stream closed" : nullptr);
          return;
        }
        break;
      }
      if (!connection.handled) {
        connection.in.append(buffer, static_cast<std::size_t>(got));
      }
    }
    if (connection.handled) {
      return; // one request a connection; an event stream reads nothing more
    }
    const std::size_t headerEnd = connection.in.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
      if (connection.in.size() > kMaxHeaderBytes) {
        connection.handled = true;
        Respond(connection, 413, "{\"ok\":false,\"error\":\"headers too large\"}");
      } else if (nowUs - connection.acceptedUs > kRequestTimeUs) {
        Close(connection, "closed (no whole request in 5 s)");
      }
      return;
    }
    const std::string_view head(connection.in.data(), headerEnd);
    const std::size_t lineEnd = head.find("\r\n");
    const std::string_view requestLine = head.substr(0, lineEnd);
    const std::size_t space1 = requestLine.find(' ');
    const std::size_t space2 =
      space1 == std::string_view::npos ? std::string_view::npos : requestLine.find(' ', space1 + 1);
    if (space2 == std::string_view::npos) {
      connection.handled = true;
      Respond(connection, 400, "{\"ok\":false,\"error\":\"not an HTTP request\"}");
      mNews.push_back("rest: " + connection.peer + " sent something that isn't an HTTP request");
      return;
    }
    const std::string_view method = requestLine.substr(0, space1);
    std::string_view path = requestLine.substr(space1 + 1, space2 - space1 - 1);
    if (const std::size_t query = path.find('?'); query != std::string_view::npos) {
      path = path.substr(0, query);
    }
    std::size_t contentLength = 0;
    std::string authorization;
    for (std::size_t at = lineEnd == std::string_view::npos ? head.size() : lineEnd + 2; at < head.size();) {
      std::size_t end = head.find("\r\n", at);
      if (end == std::string_view::npos) {
        end = head.size();
      }
      const std::string_view line = head.substr(at, end - at);
      at = end + 2;
      const std::size_t colon = line.find(':');
      if (colon == std::string_view::npos) {
        continue;
      }
      const std::string name = Lower(Trim(line.substr(0, colon)));
      const std::string_view value = Trim(line.substr(colon + 1));
      if (name == "content-length") {
        contentLength = static_cast<std::size_t>(std::strtoull(std::string(value).c_str(), nullptr, 10));
      } else if (name == "authorization") {
        authorization = std::string(value);
      } else if (name == "origin") {
        connection.origin = std::string(value);
      }
    }
    if (contentLength > kMaxBodyBytes) {
      connection.handled = true;
      Respond(connection, 413, "{\"ok\":false,\"error\":\"body too large\"}");
      return;
    }
    if (connection.in.size() < headerEnd + 4u + contentLength) {
      if (nowUs - connection.acceptedUs > kRequestTimeUs) {
        Close(connection, "closed (no whole request in 5 s)");
      }
      return; // the body isn't all here yet
    }
    connection.handled = true;
    const std::string_view body(connection.in.data() + headerEnd + 4u, contentLength);
    if (method != "OPTIONS") {
      constexpr std::string_view kBearer = "Bearer ";
      const bool bearer =
        authorization.size() > kBearer.size() && Lower(authorization.substr(0, kBearer.size())) == "bearer ";
      if (!bearer || !TokensEqual(std::string_view(authorization).substr(kBearer.size()), mToken)) {
        Respond(connection, 401, "{\"ok\":false,\"error\":\"this needs Authorization: Bearer <admin token>\"}");
        mNews.push_back("rest: " + connection.peer + " refused: no admin token, or a wrong one");
        return;
      }
    }
    Handle(connection, method, path, body, requests);
  }

  void CRestListener::Poll(
    std::vector<SControlRequest>& requests,
    const std::uint64_t nowUs
  )
  {
    if (mListenSocket < 0) {
      return;
    }
    for (;;) {
      sockaddr_in from{};
      socklen_t size = sizeof(from);
      const int socket =
        ::accept4(mListenSocket, reinterpret_cast<sockaddr*>(&from), &size, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (socket < 0) {
        break;
      }
      remote::net::SEndpoint peer;
      peer.ip = ntohl(from.sin_addr.s_addr);
      peer.port = ntohs(from.sin_port);
      std::erase_if(mConnections, [](const std::unique_ptr<SConnection>& connection) {
        return connection->socket < 0;
      });
      if (mConnections.size() >= kMaxRestConnections) {
        mNews.push_back(
          "rest: " + peer.Text() + " refused: " + std::to_string(kMaxRestConnections) + " connections are open"
        );
        ::close(socket);
        continue;
      }
      const int yes = 1;
      (void)::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
      auto connection = std::make_unique<SConnection>();
      connection->socket = socket;
      connection->peer = peer.Text();
      connection->acceptedUs = nowUs;
      mConnections.push_back(std::move(connection));
    }
    for (const std::unique_ptr<SConnection>& connection : mConnections) {
      if (connection->socket >= 0) {
        Read(*connection, requests, nowUs);
      }
      if (connection->socket >= 0) {
        Flush(*connection);
      }
    }
    std::erase_if(mConnections, [](const std::unique_ptr<SConnection>& connection) {
      return connection->socket < 0;
    });
  }
} // namespace faf::server
