#include "server/ObserverListener.h"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

// Engine addition, dedicated server: see ObserverListener.h.

namespace faf::server
{
  namespace
  {
    constexpr std::size_t kMaxObservers = 64;
    constexpr std::size_t kMaxRequestBytes = 1024;      // 'G', the path, its NUL
    constexpr std::uint64_t kRequestUs = 5'000'000u;     // to send the request
    constexpr std::size_t kChunkBytes = 64u * 1024u;
    constexpr std::uint64_t kHeldUs = 300'000'000u;     // a request the organiser hasn't answered (plan WP17.9)

    [[nodiscard]] bool WouldBlock() noexcept
    {
      return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }
  } // namespace

  struct CObserverListener::SConnection
  {
    int socket = -1;
    std::string peer;
    std::uint64_t acceptedUs = 0;
    std::string request;            // until its NUL
    std::string token;              // once the request is whole
    bool held = false;              // waiting for the organiser's answer
    std::uint64_t heldUs = 0;
    bool watching = false;
    std::size_t offset = 0;         // the log's bytes sent so far
    std::uint64_t delayUs = 0;      // the observers' delay, or 0 for a referee (plan WP13.2)
    std::vector<std::uint8_t> pending;
  };

  CObserverListener::CObserverListener(std::shared_ptr<const CReplayLog> log, Clock clock, const double delaySeconds)
    : mLog(std::move(log))
    , mClock(std::move(clock))
    , mDelayUs(static_cast<std::uint64_t>(std::max(0.0, delaySeconds) * 1e6))
  {}

  CObserverListener::~CObserverListener()
  {
    Stop();
  }

  bool CObserverListener::Start(const remote::net::SEndpoint& at, std::string& error)
  {
    mListenSocket = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (mListenSocket < 0) {
      error = "observe: no TCP socket";
      return false;
    }
    const int yes = 1;
    (void)::setsockopt(mListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(at.port);
    address.sin_addr.s_addr = htonl(at.ip);
    if (::bind(mListenSocket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 || ::listen(mListenSocket, 16) != 0) {
      error = "observe: can't listen on " + at.Text();
      ::close(mListenSocket);
      mListenSocket = -1;
      return false;
    }
    mThread = std::thread([this] { Run(); });
    return true;
  }

  void CObserverListener::Stop()
  {
    mStop.store(true, std::memory_order_relaxed);
    if (mThread.joinable()) {
      mThread.join();
    }
    if (mListenSocket >= 0) {
      ::close(mListenSocket);
      mListenSocket = -1;
    }
  }

  void CObserverListener::AllowToken(std::string token)
  {
    const std::scoped_lock lock(mLock);
    mRefused.erase(token);
    mTokens.insert(std::move(token));
  }

  void CObserverListener::AllowReferee(std::string token)
  {
    const std::scoped_lock lock(mLock);
    mRefused.erase(token);
    mTokens.insert(token);
    mReferees.insert(std::move(token));
  }

  void CObserverListener::RefuseToken(std::string token)
  {
    const std::scoped_lock lock(mLock);
    mTokens.erase(token);
    mRefused.insert(std::move(token));
  }

  std::vector<CObserverListener::SRequest> CObserverListener::TakeRequests()
  {
    const std::scoped_lock lock(mLock);
    return std::exchange(mRequests, {});
  }

  std::vector<std::string> CObserverListener::TakeNews()
  {
    const std::scoped_lock lock(mLock);
    return std::exchange(mNews, {});
  }

  void CObserverListener::Say(std::string line)
  {
    const std::scoped_lock lock(mLock);
    mNews.push_back(std::move(line));
  }

  void CObserverListener::Run()
  {
    std::vector<SConnection> connections;
    std::vector<pollfd> polls;
    std::vector<std::uint8_t> chunk;
    while (!mStop.load(std::memory_order_relaxed)) {
      const std::uint64_t now = mClock();
      // New connections, up to the cap.
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
        if (connections.size() >= kMaxObservers) {
          Say("observe: " + peer.Text() + " refused: " + std::to_string(kMaxObservers) + " connections already");
          ::close(socket);
          continue;
        }
        SConnection connection;
        connection.socket = socket;
        connection.peer = peer.Text();
        connection.acceptedUs = now;
        connections.push_back(std::move(connection));
      }

      // Requests, then bytes as they come of age.
      const bool finished = mLog->Finished();
      const std::size_t logSize = mLog->Size();
      for (SConnection& connection : connections) {
        if (connection.socket < 0) {
          continue;
        }
        const auto close = [&](std::string why) {
          Say("observe: " + connection.peer + " " + why);
          ::close(connection.socket);
          connection.socket = -1;
        };
        if (connection.held) {
          // Plan WP17.9: waiting for the organiser.
          bool allowed = false;
          bool refused = false;
          {
            const std::scoped_lock lock(mLock);
            allowed = mTokens.contains(connection.token);
            refused = mRefused.contains(connection.token);
          }
          char probe = 0;
          const ssize_t got = ::recv(connection.socket, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
          if (got == 0 || (got < 0 && !WouldBlock())) {
            close("left while waiting for the organiser");
            continue;
          }
          if (refused) {
            close("refused by the organiser");
            continue;
          }
          if (!allowed) {
            if (now - connection.heldUs > kHeldUs) {
              close("closed: the organiser didn't answer in 5 minutes");
            }
            continue;
          }
          connection.held = false;
          connection.watching = true;
          connection.delayUs = mDelayUs; // an approved observer is no referee
          Say("observe: " + connection.peer + " approved, watches " + std::to_string(mDelayUs / 1000000u) + " s behind the game");
        }
        if (!connection.watching) {
          char buffer[256];
          const ssize_t got = ::recv(connection.socket, buffer, sizeof(buffer), 0);
          if (got == 0 || (got < 0 && !WouldBlock())) {
            close("left before its request");
            continue;
          }
          if (got > 0) {
            connection.request.append(buffer, static_cast<std::size_t>(got));
          }
          const std::size_t nul = connection.request.find('\0');
          if (nul == std::string::npos) {
            if (connection.request.size() > kMaxRequestBytes) {
              close("refused: a request past " + std::to_string(kMaxRequestBytes) + " bytes");
            } else if (now - connection.acceptedUs > kRequestUs) {
              close("closed: no request in 5 s");
            }
            continue;
          }
          // 'G' and the path: "/<token>" (`gpgnet://host:port/<token>`).
          if (nul == 0u || connection.request[0] != 'G') {
            close("refused: not a request to read a replay");
            continue;
          }
          const std::string path = connection.request.substr(1, nul - 1);
          const std::string token = !path.empty() && path[0] == '/' ? path.substr(1) : path;
          bool allowed = false;
          bool refused = false;
          {
            const std::scoped_lock lock(mLock);
            allowed = mTokens.contains(token);
            refused = mRefused.contains(token);
          }
          if (!token.empty() && !allowed && !refused && mHoldUnknown) {
            // Plan WP17.9: the organiser decides; the connection waits, sending nothing.
            connection.token = token;
            connection.held = true;
            connection.heldUs = now;
            {
              const std::scoped_lock lock(mLock);
              mRequests.push_back(SRequest{token, connection.peer});
            }
            Say("observe: " + connection.peer + " asks to watch; waiting for the organiser");
            continue;
          }
          if (token.empty() || !allowed) {
            close(refused ? "refused: the organiser said no to this token" : "refused: not an observer's token");
            continue;
          }
          connection.watching = true;
          bool referee = false;
          {
            const std::scoped_lock lock(mLock);
            referee = mReferees.contains(token);
          }
          connection.delayUs = referee ? 0u : mDelayUs;
          Say("observe: " + connection.peer + (referee ? std::string(" referees, with no delay") :
                                               " watches, " + std::to_string(mDelayUs / 1000000u) + " s behind the game"));
        }
        // What's old enough and not sent yet.
        if (connection.pending.empty()) {
          chunk.clear();
          const std::uint64_t until = now > connection.delayUs ? now - connection.delayUs : 0u;
          if (mLog->Read(connection.offset, until, kChunkBytes, chunk) > 0u) {
            connection.offset += chunk.size();
            connection.pending = chunk;
          }
        }
        while (!connection.pending.empty()) {
          const ssize_t sent = ::send(connection.socket, connection.pending.data(), connection.pending.size(), MSG_NOSIGNAL);
          if (sent < 0) {
            if (!WouldBlock()) {
              close("disconnected");
            }
            break;
          }
          connection.pending.erase(connection.pending.begin(), connection.pending.begin() + sent);
        }
        if (connection.socket >= 0 && finished && connection.pending.empty() && connection.offset >= logSize) {
          close("has seen the whole game (" + std::to_string(connection.offset) + " bytes)");
        }
      }
      std::erase_if(connections, [](const SConnection& connection) { return connection.socket < 0; });
      const std::size_t watching =
        static_cast<std::size_t>(std::count_if(connections.begin(), connections.end(), [](const SConnection& c) { return c.watching; }));
      mObservers.store(watching, std::memory_order_relaxed);
      mAllSent.store(finished && watching == 0u, std::memory_order_relaxed);

      // Wake for a new connection, a request, room to send, or the next bytes of age (every 50 ms at most).
      polls.clear();
      polls.push_back(pollfd{mListenSocket, POLLIN, 0});
      for (const SConnection& connection : connections) {
        polls.push_back(pollfd{connection.socket,
                               static_cast<short>(connection.watching ? (connection.pending.empty() ? 0 : POLLOUT) : (connection.held ? 0 : POLLIN)), 0});
      }
      (void)::poll(polls.data(), polls.size(), 50);
    }
    for (SConnection& connection : connections) {
      if (connection.socket >= 0) {
        ::close(connection.socket);
      }
    }
    mObservers.store(0u, std::memory_order_relaxed);
  }
} // namespace faf::server
