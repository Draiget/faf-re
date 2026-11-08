#include "server/LiveReplaySender.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <string_view>
#include <utility>

// Engine addition, dedicated server: see LiveReplaySender.h.

namespace faf::server
{
  namespace
  {
    constexpr int kAttempts = 10;                    // connections made before giving up
    constexpr int kRetrySeconds = 5;
    constexpr std::size_t kChunkBytes = 64u * 1024u;

    /** A connected TCP socket to `host:port`, or -1. */
    [[nodiscard]] int Connect(const SGpgNetAddress& to)
    {
      addrinfo hints{};
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;
      addrinfo* found = nullptr;
      if (::getaddrinfo(to.host.c_str(), std::to_string(to.port).c_str(), &hints, &found) != 0 || found == nullptr) {
        return -1;
      }
      int socket = ::socket(found->ai_family, found->ai_socktype | SOCK_CLOEXEC, found->ai_protocol);
      if (socket >= 0 && ::connect(socket, found->ai_addr, found->ai_addrlen) != 0) {
        ::close(socket);
        socket = -1;
      }
      ::freeaddrinfo(found);
      if (socket >= 0) {
        const int yes = 1;
        (void)::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
      }
      return socket;
    }

    /** All of `data` or false (a closed connection, an error). Waits up to a second at a time so `stop` is heard. */
    [[nodiscard]] bool SendAll(const int socket, const std::uint8_t* data, std::size_t size, const std::atomic<bool>& stop)
    {
      while (size > 0u && !stop.load(std::memory_order_relaxed)) {
        pollfd ready{socket, POLLOUT, 0};
        if (::poll(&ready, 1, 1000) <= 0) {
          continue;
        }
        const ssize_t sent = ::send(socket, data, size, MSG_NOSIGNAL);
        if (sent < 0) {
          if (errno == EINTR || errno == EAGAIN) {
            continue;
          }
          return false;
        }
        data += sent;
        size -= static_cast<std::size_t>(sent);
      }
      return size == 0u;
    }
  } // namespace

  std::optional<SGpgNetAddress> ParseGpgNetAddress(const std::string& uri)
  {
    static constexpr std::string_view kScheme = "gpgnet://";
    if (uri.size() <= kScheme.size() || uri.compare(0, kScheme.size(), kScheme) != 0) {
      return std::nullopt;
    }
    const std::string rest = uri.substr(kScheme.size());
    const std::size_t slash = rest.find('/');
    const std::string authority = rest.substr(0, slash);
    SGpgNetAddress address;
    address.path = slash == std::string::npos ? std::string("/") : rest.substr(slash);
    const std::size_t colon = authority.rfind(':');
    address.host = authority.substr(0, colon);
    if (colon != std::string::npos) {
      const std::string port = authority.substr(colon + 1);
      if (port.empty() || port.size() > 5 || !std::all_of(port.begin(), port.end(), [](const char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
      }
      const long value = std::strtol(port.c_str(), nullptr, 10);
      if (value < 1 || value > 65535) {
        return std::nullopt;
      }
      address.port = static_cast<std::uint16_t>(value);
    }
    if (address.host.empty() || address.path.size() > 1000u) {
      return std::nullopt;
    }
    return address;
  }

  CLiveReplaySender::CLiveReplaySender(std::shared_ptr<const CReplayLog> log, Clock clock, const double delaySeconds, SGpgNetAddress to)
    : mLog(std::move(log))
    , mClock(std::move(clock))
    , mDelayUs(static_cast<std::uint64_t>(std::max(0.0, delaySeconds) * 1e6))
    , mTo(std::move(to))
  {}

  CLiveReplaySender::~CLiveReplaySender()
  {
    Stop();
  }

  void CLiveReplaySender::Start()
  {
    mThread = std::thread([this] { Run(); });
  }

  void CLiveReplaySender::Stop()
  {
    mStop.store(true, std::memory_order_relaxed);
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  std::vector<std::string> CLiveReplaySender::TakeNews()
  {
    const std::scoped_lock lock(mLock);
    return std::exchange(mNews, {});
  }

  void CLiveReplaySender::Say(std::string line)
  {
    const std::scoped_lock lock(mLock);
    mNews.push_back(std::move(line));
  }

  void CLiveReplaySender::Run()
  {
    const std::string where = mTo.host + ":" + std::to_string(mTo.port) + mTo.path;
    std::vector<std::uint8_t> chunk;
    for (int attempt = 1; attempt <= kAttempts && !mStop.load(std::memory_order_relaxed); ++attempt) {
      const int socket = Connect(mTo);
      if (socket < 0) {
        Say("live replay: no connection to " + where + " (try " + std::to_string(attempt) + " of " + std::to_string(kAttempts) + ")");
        for (int i = 0; i < kRetrySeconds * 10 && !mStop.load(std::memory_order_relaxed); ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        continue;
      }
      // The engine's write request: 'P', then the path with its NUL (`Stream::Write(const fa::string&)`).
      std::vector<std::uint8_t> request;
      request.push_back(static_cast<std::uint8_t>('P'));
      request.insert(request.end(), mTo.path.begin(), mTo.path.end());
      request.push_back(0u);
      bool ok = SendAll(socket, request.data(), request.size(), mStop);
      Say(std::string("live replay: sending to ") + where + (attempt > 1 ? " again, from the start" : ""));
      std::size_t offset = 0;
      while (ok && !mStop.load(std::memory_order_relaxed)) {
        const std::uint64_t now = mClock();
        chunk.clear();
        const bool finished = mLog->Finished(); // before the read: a finished log has nothing after this read
        if (mLog->Read(offset, now > mDelayUs ? now - mDelayUs : 0u, kChunkBytes, chunk) > 0u) {
          ok = SendAll(socket, chunk.data(), chunk.size(), mStop);
          offset += chunk.size();
          continue;
        }
        if (finished && offset >= mLog->Size()) {
          ::shutdown(socket, SHUT_WR);
          ::close(socket);
          Say("live replay: the whole game sent to " + where + " (" + std::to_string(offset) + " bytes)");
          mDone.store(true, std::memory_order_relaxed);
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      ::close(socket);
      if (!ok) {
        Say("live replay: the connection to " + where + " dropped after " + std::to_string(offset) + " bytes");
      }
    }
    if (!mStop.load(std::memory_order_relaxed)) {
      Say("live replay: gave up on " + where + " after " + std::to_string(kAttempts) + " tries");
    }
    mDone.store(true, std::memory_order_relaxed);
  }
} // namespace faf::server
