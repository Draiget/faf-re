// Engine addition (in-game launcher plan, WP1-WP4): platform::http on POSIX (src/platform/Http.h): BSD sockets with
// Mbed TLS (the build's faf_mbedtls) for https and wss, HTTP/1.1 written here. Certificates come from the system's
// CA bundle. No proxy support yet.
//
// One connection is never used by two threads at once: Mbed TLS keeps one state for both directions. The WebSocket
// and the stream run their socket non-blocking and wait in poll() without holding the connection's lock, so a send
// gets in while a receive waits, and Close (shutdown) ends a wait.

#include "platform/Http.h"
#include "platform/PlatformDefines.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <random>
#include <string_view>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha1.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

namespace platform::http
{
  namespace
  {
    std::mutex gAgentLock;
    std::string gDefaultAgent = "FAF-RE map editor";

    std::string Agent(
      const std::string& agent
    )
    {
      if (!agent.empty()) {
        return agent;
      }
      std::lock_guard<std::mutex> lock(gAgentLock);
      return gDefaultAgent;
    }

    // --- The system's CA certificates, read once --------------------------------------------------------------------

    struct Roots
    {
      mbedtls_x509_crt chain;
      int loaded = 0;
    };

    Roots& SystemRoots()
    {
      static Roots roots;
      static std::once_flag once;
      std::call_once(once, [] {
        (void)psa_crypto_init(); // TLS 1.3 in Mbed TLS 3.6 runs on PSA crypto
        mbedtls_x509_crt_init(&roots.chain);
        // Linux distributions' bundles, then macOS's (and the BSDs').
        static constexpr const char* kBundles[] = {
          "/etc/ssl/certs/ca-certificates.crt",
          "/etc/pki/tls/certs/ca-bundle.crt",
          "/etc/ssl/ca-bundle.pem",
          "/etc/pki/tls/cacert.pem",
          "/etc/ssl/cert.pem",
          "/usr/local/etc/openssl/cert.pem",
        };
        for (const char* bundle : kBundles) {
          if (::access(bundle, R_OK) == 0 && mbedtls_x509_crt_parse_file(&roots.chain, bundle) >= 0) {
            ++roots.loaded;
          }
        }
        if (roots.loaded == 0 && mbedtls_x509_crt_parse_path(&roots.chain, "/etc/ssl/certs") >= 0) {
          ++roots.loaded;
        }
      });
      return roots;
    }

    // --- A link, cracked ------------------------------------------------------------------------------------------

    struct Target
    {
      std::string host;
      std::string port;
      std::string object; ///< path and query
      bool secure = false;
      bool bracketed = false; ///< an IPv6 address, written in brackets in the link and in the Host header
    };

    bool Crack(
      const std::string& url,
      Target& out
    )
    {
      const std::size_t scheme = url.find("://");
      if (scheme == std::string::npos) {
        return false;
      }
      std::string kind = url.substr(0, scheme);
      std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) {
        return std::tolower(c);
      });
      if (kind == "https" || kind == "wss") {
        out.secure = true;
      } else if (kind != "http" && kind != "ws") {
        return false;
      }
      const std::size_t hostStart = scheme + 3;
      const std::size_t pathStart = url.find_first_of("/?", hostStart);
      std::string authority =
        url.substr(hostStart, pathStart == std::string::npos ? std::string::npos : pathStart - hostStart);
      out.object = pathStart == std::string::npos ? "/" : url.substr(pathStart);
      if (out.object.front() == '?') {
        out.object.insert(0, "/");
      }
      out.port = out.secure ? "443" : "80";
      if (!authority.empty() && authority.front() == '[') {
        // An IPv6 address: "[::1]" or "[::1]:8080" (RFC 3986 3.2.2). getaddrinfo takes it without the brackets.
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
          return false;
        }
        out.host = authority.substr(1, close - 1);
        out.bracketed = true;
        if (close + 1 < authority.size()) {
          if (authority[close + 1] != ':') {
            return false;
          }
          out.port = authority.substr(close + 2);
        }
      } else if (const std::size_t colon = authority.rfind(':'); colon != std::string::npos) {
        out.host = authority.substr(0, colon);
        out.port = authority.substr(colon + 1);
      } else {
        out.host = authority;
      }
      return !out.host.empty() && !out.port.empty();
    }

    // --- One connection: TCP, with TLS over it for https and wss -----------------------------------------------------

    class Connection
    {
    public:
      ~Connection()
      {
        Close();
        if (mFd >= 0) {
          ::close(mFd); // only here: until the last owner lets go, no other socket can take its number
        }
        if (mTls) {
          mbedtls_ssl_free(&mSsl);
          mbedtls_ssl_config_free(&mConfig);
          mbedtls_ctr_drbg_free(&mDrbg);
          mbedtls_entropy_free(&mEntropy);
        }
      }

      std::expected<void, std::string> Open(
        const Target& target
      )
      {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* found = nullptr;
        if (const int failed = ::getaddrinfo(target.host.c_str(), target.port.c_str(), &hints, &found); failed != 0) {
          return std::unexpected("can't find " + target.host + " (" + ::gai_strerror(failed) + ")");
        }
        std::string why = "no address";
        bool connected = false;
        for (addrinfo* at = found; at != nullptr && !connected; at = at->ai_next) {
          const auto tried = Connect(*at);
          if (tried) {
            connected = true;
          } else {
            why = tried.error();
          }
        }
        ::freeaddrinfo(found);
        if (!connected) {
          return std::unexpected("no answer from " + target.host + " (" + why + ")");
        }
#if FAFRE_PLATFORM_MACOS // SO_NOSIGPIPE, the socket option only macOS has
        // A write to a closed socket is an error, not a signal (Linux uses MSG_NOSIGNAL below).
        int on = 1;
        (void)::setsockopt(mFd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
        int noDelay = 1;
        (void)::setsockopt(mFd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay));
        if (!target.secure) {
          return {};
        }
        Roots& roots = SystemRoots();
        if (roots.loaded == 0) {
          return std::unexpected("no CA certificates found on this system");
        }
        {
          std::lock_guard<std::mutex> lock(mLock);
          if (mClosed) {
            return std::unexpected("closed");
          }
          mTls = true;
          mbedtls_ssl_init(&mSsl);
          mbedtls_ssl_config_init(&mConfig);
          mbedtls_ctr_drbg_init(&mDrbg);
          mbedtls_entropy_init(&mEntropy);
          if (
            mbedtls_ctr_drbg_seed(&mDrbg, mbedtls_entropy_func, &mEntropy, nullptr, 0) != 0 ||
            mbedtls_ssl_config_defaults(
              &mConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT
            ) != 0
          ) {
            return std::unexpected("TLS setup failed");
          }
          mbedtls_ssl_conf_authmode(&mConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
          mbedtls_ssl_conf_ca_chain(&mConfig, &roots.chain, nullptr);
          mbedtls_ssl_conf_rng(&mConfig, mbedtls_ctr_drbg_random, &mDrbg);
          if (mbedtls_ssl_setup(&mSsl, &mConfig) != 0 || mbedtls_ssl_set_hostname(&mSsl, target.host.c_str()) != 0) {
            return std::unexpected("TLS setup failed");
          }
          mbedtls_ssl_set_bio(&mSsl, this, &Connection::BioSend, &Connection::BioRecv, nullptr);
        }
        for (;;) {
          // Each step under the lock: Close from another thread uses the same TLS state.
          int step = 0;
          {
            std::lock_guard<std::mutex> lock(mLock);
            if (mClosed) {
              return std::unexpected("closed");
            }
            step = mbedtls_ssl_handshake(&mSsl);
            if (step == 0) {
              mHandshakeDone = true;
              break;
            }
          }
          if (step != MBEDTLS_ERR_SSL_WANT_READ && step != MBEDTLS_ERR_SSL_WANT_WRITE) {
            const std::uint32_t flags = mbedtls_ssl_get_verify_result(&mSsl);
            return std::unexpected(
              flags != 0 ? "the server's certificate for " + target.host + " isn't trusted"
                         : "TLS with " + target.host + " failed (" + std::to_string(step) + ")"
            );
          }
          if (!Wait(step == MBEDTLS_ERR_SSL_WANT_READ ? POLLIN : POLLOUT, 30000)) {
            return std::unexpected("TLS with " + target.host + " timed out");
          }
        }
        return {};
      }

      /** Writes all of `data`; waits up to 30 s for room. One caller at a time, so frames never interleave. */
      bool WriteAll(
        const char* data,
        std::size_t size
      )
      {
        // A TLS write that waits for room must be repeated with the same bytes, so no other write may come between.
        std::lock_guard<std::mutex> writer(mWriteLock);
        while (size > 0) {
          std::ptrdiff_t wrote = 0;
          {
            std::lock_guard<std::mutex> lock(mLock);
            if (mClosed || mFd < 0) {
              return false;
            }
            if (mTls) {
              const int n = mbedtls_ssl_write(&mSsl, reinterpret_cast<const unsigned char*>(data), size);
              wrote = n >= 0 ? n : (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ? 0 : -1);
            } else {
#if FAFRE_PLATFORM_LINUX // MSG_NOSIGNAL; macOS has no such send flag
              const ssize_t n = ::send(mFd, data, size, MSG_NOSIGNAL);
#else
              const ssize_t n = ::send(mFd, data, size, 0);
#endif
              wrote = n >= 0 ? n : (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1);
            }
          }
          if (wrote < 0) {
            return false;
          }
          if (wrote == 0 && !Wait(POLLOUT, 30000)) {
            return false;
          }
          data += wrote;
          size -= static_cast<std::size_t>(wrote);
        }
        return true;
      }

      /**
       * Reads what is there, waiting up to `timeoutMs` (-1: until data, the end, or Close). 0 bytes with true: the
       * peer closed. False: an error or a timeout.
       */
      bool ReadSome(
        std::string& out,
        int timeoutMs
      )
      {
        char buffer[16384];
        for (;;) {
          std::ptrdiff_t got = 0;
          bool again = false;
          {
            std::lock_guard<std::mutex> lock(mLock);
            if (mClosed || mFd < 0) {
              return false;
            }
            if (mTls) {
              const int n = mbedtls_ssl_read(&mSsl, reinterpret_cast<unsigned char*>(buffer), sizeof(buffer));
              if (
                n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE ||
                n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
              ) {
                again = true;
              } else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0) {
                return true;
              } else if (n < 0) {
                return false;
              } else {
                got = n;
              }
            } else {
              const ssize_t n = ::recv(mFd, buffer, sizeof(buffer), 0);
              if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                again = true;
              } else if (n == 0) {
                return true;
              } else if (n < 0) {
                return false;
              } else {
                got = n;
              }
            }
          }
          if (got > 0) {
            out.append(buffer, static_cast<std::size_t>(got));
            return true;
          }
          if (again && !Wait(POLLIN, timeoutMs)) {
            return false;
          }
        }
      }

      /**
       * Ends the connection; a wait in another thread returns. The descriptor stays allocated until the destructor,
       * so a thread still polling it can't end up on a socket that reused its number.
       */
      void Close()
      {
        std::lock_guard<std::mutex> lock(mLock);
        if (mClosed) {
          return;
        }
        mClosed = true;
        if (mFd >= 0) {
          if (mTls && mHandshakeDone) {
            (void)mbedtls_ssl_close_notify(&mSsl);
          }
          ::shutdown(mFd, SHUT_RDWR);
        }
      }

      [[nodiscard]] bool IsOpen()
      {
        std::lock_guard<std::mutex> lock(mLock);
        return !mClosed && mFd >= 0;
      }

    private:
      /** Connects to one address without blocking, giving up after 10 s or when Close is called. */
      std::expected<void, std::string> Connect(
        const addrinfo& address
      )
      {
        const int fd = ::socket(address.ai_family, address.ai_socktype, address.ai_protocol);
        if (fd < 0) {
          return std::unexpected(std::string(std::strerror(errno)));
        }
        // Non-blocking from the start: every connect, read and write waits in poll(), never in the socket.
        (void)::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        {
          std::lock_guard<std::mutex> lock(mLock);
          if (mClosed) {
            ::close(fd);
            return std::unexpected(std::string("closed"));
          }
          mFd = fd; // published before connecting, so Close can end the wait below
        }
        const auto failed = [this, fd](std::string why) {
          std::lock_guard<std::mutex> lock(mLock);
          mFd = -1;
          ::close(fd);
          return std::unexpected(std::move(why));
        };
        if (::connect(fd, address.ai_addr, address.ai_addrlen) == 0) {
          return {};
        }
        if (errno != EINPROGRESS && errno != EINTR) {
          return failed(std::strerror(errno));
        }
        pollfd entry{fd, POLLOUT, 0};
        for (int waited = 0;; waited += 200) {
          if (!IsOpen()) {
            return failed("closed");
          }
          if (waited >= kConnectTimeoutMs) {
            return failed("timed out");
          }
          const int ready = ::poll(&entry, 1, 200);
          if (ready < 0 && errno != EINTR) {
            return failed(std::strerror(errno));
          }
          if (ready > 0) {
            break;
          }
        }
        int error = 0;
        socklen_t length = sizeof(error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0) {
          error = errno;
        }
        if (error != 0) {
          return failed(std::strerror(error));
        }
        return {};
      }

      bool Wait(
        short events,
        int timeoutMs
      )
      {
        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(mLock);
          if (mClosed) {
            return false;
          }
          fd = mFd;
        }
        if (fd < 0) {
          return false;
        }
        pollfd entry{fd, events, 0};
        // In slices, so a Close from another thread (which shuts the socket down) is seen soon.
        for (int waited = 0; timeoutMs < 0 || waited < timeoutMs; waited += 200) {
          const int ready = ::poll(&entry, 1, 200);
          if (ready > 0) {
            return (entry.revents & (POLLERR | POLLNVAL)) == 0 || (entry.revents & POLLIN) != 0;
          }
          if (ready < 0 && errno != EINTR) {
            return false;
          }
          if (!IsOpen()) {
            return false;
          }
        }
        return false;
      }

      // Mbed TLS calls these only from inside a call made under mLock.
      static int BioSend(
        void* self,
        const unsigned char* data,
        std::size_t size
      )
      {
#if FAFRE_PLATFORM_LINUX // MSG_NOSIGNAL; macOS has no such send flag
        const ssize_t n = ::send(static_cast<Connection*>(self)->mFd, data, size, MSG_NOSIGNAL);
#else
        const ssize_t n = ::send(static_cast<Connection*>(self)->mFd, data, size, 0);
#endif
        if (n < 0) {
          return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_WRITE : -1;
        }
        return static_cast<int>(n);
      }

      static int BioRecv(
        void* self,
        unsigned char* data,
        std::size_t size
      )
      {
        const ssize_t n = ::recv(static_cast<Connection*>(self)->mFd, data, size, 0);
        if (n < 0) {
          return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_READ : -1;
        }
        return static_cast<int>(n);
      }

      static constexpr int kConnectTimeoutMs = 10000;

      std::mutex mLock;      ///< the descriptor and the TLS state
      std::mutex mWriteLock; ///< one WriteAll at a time
      int mFd = -1;
      bool mClosed = false;
      bool mTls = false;
      bool mHandshakeDone = false;
      mbedtls_ssl_context mSsl{};
      mbedtls_ssl_config mConfig{};
      mbedtls_ctr_drbg_context mDrbg{};
      mbedtls_entropy_context mEntropy{};
    };

    // --- HTTP/1.1 ---------------------------------------------------------------------------------------------------

    std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return std::tolower(c);
      });
      return text;
    }

    struct ResponseHead
    {
      long status = 0;
      bool chunked = false;
      long long length = -1; ///< -1: until the connection closes
      std::string extra;     ///< body bytes read with the head
      std::string headers;   ///< the raw header lines, for the WebSocket's checks
    };

    std::string RequestText(
      const Call& call,
      const Target& target,
      const std::string& upgradeHeaders
    )
    {
      std::string text = call.method + " " + target.object +
        " HTTP/1.1\r\nHost: " + (target.bracketed ? "[" + target.host + "]" : target.host);
      const bool defaultPort = (target.secure && target.port == "443") || (!target.secure && target.port == "80");
      if (!defaultPort) {
        text += ":" + target.port;
      }
      text += "\r\nUser-Agent: " + Agent(call.userAgent) + "\r\n";
      if (upgradeHeaders.empty()) {
        text += "Connection: close\r\n";
      } else {
        text += upgradeHeaders;
      }
      if (!call.body.empty() || call.method == "POST" || call.method == "PUT") {
        text += "Content-Length: " + std::to_string(call.body.size()) + "\r\n";
      }
      text += call.headers;
      text += "\r\n";
      return text;
    }

    std::expected<ResponseHead, std::string> ReadHead(
      Connection& connection,
      const std::string& host
    )
    {
      std::string buffer;
      std::size_t end = std::string::npos;
      while ((end = buffer.find("\r\n\r\n")) == std::string::npos) {
        const std::size_t before = buffer.size();
        if (!connection.ReadSome(buffer, 30000)) {
          return std::unexpected("no answer from " + host);
        }
        if (buffer.size() == before) {
          return std::unexpected(host + " closed the connection before answering");
        }
        if (buffer.size() > 65536) {
          return std::unexpected(host + " sent an answer head too long");
        }
      }
      ResponseHead head;
      const std::string top = buffer.substr(0, end);
      head.extra = buffer.substr(end + 4);
      const std::size_t space = top.find(' ');
      head.status = space == std::string::npos ? 0 : std::strtol(top.c_str() + space + 1, nullptr, 10);
      head.headers = top;
      for (std::size_t at = top.find("\r\n"); at != std::string::npos;) {
        const std::size_t lineEnd = top.find("\r\n", at + 2);
        const std::string line =
          top.substr(at + 2, lineEnd == std::string::npos ? std::string::npos : lineEnd - at - 2);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
          const std::string name = Lower(line.substr(0, colon));
          std::string value = line.substr(colon + 1);
          value.erase(0, value.find_first_not_of(' '));
          if (name == "content-length") {
            head.length = std::strtoll(value.c_str(), nullptr, 10);
          } else if (name == "transfer-encoding" && Lower(value).find("chunked") != std::string::npos) {
            head.chunked = true;
          }
        }
        at = lineEnd;
      }
      return head;
    }

    /** Takes the decoded body bytes out of `raw` as chunked encoding allows; true once the last chunk was seen. */
    struct ChunkDecoder
    {
      enum class Step
      {
        Size,
        Data,
        DataEnd,
        Done,
      };
      std::string raw;
      Step step = Step::Size;
      long long left = 0;
      bool bad = false; ///< a size line that isn't one (RFC 9112 7.1): the body can't be trusted

      /** The chunk size at the start of `line`: hex digits, then nothing or `;` extensions. -1 if it isn't one. */
      static long long ParseSize(
        const std::string_view line
      )
      {
        long long size = 0;
        std::size_t digits = 0;
        for (; digits < line.size(); ++digits) {
          const char c = line[digits];
          int value = -1;
          if (c >= '0' && c <= '9') {
            value = c - '0';
          } else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
          } else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
          } else {
            break;
          }
          if (size > (std::numeric_limits<long long>::max() >> 4)) {
            return -1;
          }
          size = (size << 4) | value;
        }
        if (digits == 0) {
          return -1;
        }
        const std::string_view rest = line.substr(digits);
        const std::size_t extension = rest.find_first_not_of(" \t");
        if (extension != std::string_view::npos && rest[extension] != ';') {
          return -1;
        }
        return size;
      }

      /** True once the last chunk was seen, or when the encoding is broken (`bad`). */
      bool Take(
        std::string& out
      )
      {
        for (;;) {
          switch (step) {
          case Step::Size: {
            const std::size_t lineEnd = raw.find("\r\n");
            if (lineEnd == std::string::npos) {
              return false;
            }
            left = ParseSize(std::string_view(raw).substr(0, lineEnd));
            if (left < 0) {
              bad = true;
              step = Step::Done;
              return true;
            }
            raw.erase(0, lineEnd + 2);
            step = left == 0 ? Step::Done : Step::Data;
            break;
          }
          case Step::Data: {
            const std::size_t take =
              static_cast<std::size_t>(std::min<long long>(left, static_cast<long long>(raw.size())));
            out.append(raw, 0, take);
            raw.erase(0, take);
            left -= static_cast<long long>(take);
            if (left > 0) {
              return false;
            }
            step = Step::DataEnd;
            break;
          }
          case Step::DataEnd:
            if (raw.size() < 2) {
              return false;
            }
            raw.erase(0, 2);
            step = Step::Size;
            break;
          case Step::Done:
            return true;
          }
        }
      }
    };
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
    Connection connection;
    if (auto opened = connection.Open(target); !opened) {
      return std::unexpected(opened.error());
    }
    const std::string request = RequestText(call, target, {}) + call.body;
    if (!connection.WriteAll(request.data(), request.size())) {
      return std::unexpected("sending to " + target.host + " failed");
    }
    auto head = ReadHead(connection, target.host);
    if (!head) {
      return std::unexpected(head.error());
    }
    status = head->status;
    if (total != nullptr && head->length >= 0) {
      *total = static_cast<std::uint64_t>(head->length);
    }
    ChunkDecoder chunks;
    std::string raw = std::move(head->extra);
    for (;;) {
      if (head->chunked) {
        chunks.raw += raw;
        raw.clear();
        if (chunks.Take(body)) {
          if (chunks.bad) {
            return std::unexpected("a broken chunked answer from " + target.host);
          }
          break;
        }
      } else {
        body += raw;
        raw.clear();
        if (head->length >= 0 && static_cast<long long>(body.size()) >= head->length) {
          body.resize(static_cast<std::size_t>(head->length));
          break;
        }
      }
      if (received != nullptr) {
        *received = body.size();
      }
      const std::size_t before = raw.size();
      if (!connection.ReadSome(raw, 30000)) {
        return std::unexpected("the answer broke off");
      }
      if (raw.size() == before) { // the server closed: the body ends here unless it said otherwise
        if (head->chunked || head->length >= 0) {
          return std::unexpected("the answer broke off");
        }
        break;
      }
    }
    if (received != nullptr) {
      *received = body.size();
    }
    return {};
  }

  // --- Stream
  // ---------------------------------------------------------------------------------------------------------

  struct Stream::State
  {
    std::mutex lock;
    std::shared_ptr<Connection> connection;
    ResponseHead head;
    ChunkDecoder chunks;
    long long left = -1;
    std::string pending; ///< body bytes read with the head, handed out first
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
    auto connection = std::make_shared<Connection>();
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      mState->connection = connection; // published first, so Close from another thread can end a slow answer
    }
    if (auto opened = connection->Open(target); !opened) {
      return std::unexpected(opened.error());
    }
    const std::string request = RequestText(call, target, {}) + call.body;
    if (!connection->WriteAll(request.data(), request.size())) {
      return std::unexpected("sending to " + target.host + " failed");
    }
    auto head = ReadHead(*connection, target.host);
    if (!head) {
      return std::unexpected(head.error());
    }
    std::lock_guard<std::mutex> lock(mState->lock);
    mState->head = *head;
    mState->chunks = {};
    mState->left = head->length;
    mState->pending = std::move(head->extra);
    return head->status;
  }

  std::expected<std::string, std::string> Stream::Read()
  {
    std::shared_ptr<Connection> connection;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      connection = mState->connection;
    }
    if (!connection) {
      return std::unexpected("not open");
    }
    for (;;) {
      std::string raw;
      {
        std::lock_guard<std::mutex> lock(mState->lock);
        raw.swap(mState->pending);
      }
      if (raw.empty()) {
        if (!connection->ReadSome(raw, -1)) {
          return std::unexpected("the answer broke off");
        }
        if (raw.empty()) {
          return std::string(); // the server closed: the body ended
        }
      }
      std::lock_guard<std::mutex> lock(mState->lock);
      std::string out;
      if (mState->head.chunked) {
        mState->chunks.raw += raw;
        const bool done = mState->chunks.Take(out);
        if (mState->chunks.bad) {
          return std::unexpected("a broken chunked answer");
        }
        if (!out.empty() || done) {
          return out;
        }
        continue;
      }
      if (mState->left >= 0) {
        if (mState->left == 0) {
          return std::string();
        }
        raw.resize(static_cast<std::size_t>(std::min<long long>(mState->left, static_cast<long long>(raw.size()))));
        mState->left -= static_cast<long long>(raw.size());
      }
      return raw;
    }
  }

  void Stream::Close()
  {
    std::shared_ptr<Connection> connection;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      connection.swap(mState->connection);
    }
    if (connection) {
      connection->Close();
    }
  }

  // --- WebSocket
  // ------------------------------------------------------------------------------------------------------

  namespace
  {
    /// The largest message Receive takes; FAF's lobby sends far less, even its whole game list.
    constexpr std::uint64_t kMaxMessageBytes = 64ull << 20;
  } // namespace

  struct WebSocket::State
  {
    std::mutex lock;
    std::shared_ptr<Connection> connection;
    std::shared_ptr<Connection> opening; ///< while Open runs, so Close can end it
    std::string buffer;                  ///< received bytes not yet made into frames; the reader's own
    std::mt19937 masks{std::random_device{}()};
    std::mutex maskLock;
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
    return mState->connection && mState->connection->IsOpen();
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
    auto connection = std::make_shared<Connection>();
    {
      // Known before it connects, so Close from another thread can end the connect, the handshake or the upgrade.
      std::lock_guard<std::mutex> lock(mState->lock);
      mState->opening = connection;
    }
    // On every way out that didn't publish it, the opening connection is forgotten.
    struct Forget
    {
      State& state;
      const std::shared_ptr<Connection>& connection;
      ~Forget()
      {
        std::lock_guard<std::mutex> lock(state.lock);
        if (state.opening == connection) {
          state.opening.reset();
        }
      }
    } forget{*mState, connection};
    if (auto opened = connection->Open(target); !opened) {
      return std::unexpected(opened.error());
    }
    unsigned char nonce[16];
    {
      std::lock_guard<std::mutex> lock(mState->maskLock);
      for (unsigned char& byte : nonce) {
        byte = static_cast<unsigned char>(mState->masks());
      }
    }
    unsigned char keyText[32];
    std::size_t keyLength = 0;
    (void)mbedtls_base64_encode(keyText, sizeof(keyText), &keyLength, nonce, sizeof(nonce));
    const std::string key(reinterpret_cast<const char*>(keyText), keyLength);
    Call call;
    call.url = url;
    call.headers = headers;
    call.userAgent = userAgent;
    const std::string request = RequestText(
      call,
      target,
      "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n"
    );
    if (!connection->WriteAll(request.data(), request.size())) {
      return std::unexpected("sending to " + target.host + " failed");
    }
    auto head = ReadHead(*connection, target.host);
    if (!head) {
      return std::unexpected(head.error());
    }
    if (head->status != 101) {
      return std::unexpected(
        "the server answered " + std::to_string(head->status) + " instead of switching to a WebSocket"
      );
    }
    // RFC 6455 4.2.2: the server proves it read our key.
    const std::string proof = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char digest[20];
    (void)mbedtls_sha1(reinterpret_cast<const unsigned char*>(proof.data()), proof.size(), digest);
    unsigned char acceptText[40];
    std::size_t acceptLength = 0;
    (void)mbedtls_base64_encode(acceptText, sizeof(acceptText), &acceptLength, digest, sizeof(digest));
    const std::string accept(reinterpret_cast<const char*>(acceptText), acceptLength);
    if (
      Lower(head->headers).find("sec-websocket-accept: " + Lower(accept)) == std::string::npos &&
      head->headers.find(accept) == std::string::npos
    ) {
      return std::unexpected("the server's WebSocket answer doesn't match our key");
    }
    std::lock_guard<std::mutex> lock(mState->lock);
    if (mState->opening != connection) {
      return std::unexpected(std::string("closed")); // Close ran while this opened
    }
    mState->opening.reset();
    mState->connection = connection;
    mState->buffer = std::move(head->extra);
    return {};
  }

  std::expected<void, std::string> WebSocket::Send(
    const std::string_view bytes,
    const bool utf8
  )
  {
    std::shared_ptr<Connection> connection;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      connection = mState->connection;
    }
    if (!connection) {
      return std::unexpected("not connected");
    }
    std::string frame;
    frame += static_cast<char>(0x80 | (utf8 ? 0x1 : 0x2));
    const std::uint64_t size = bytes.size();
    if (size < 126) {
      frame += static_cast<char>(0x80 | size);
    } else if (size < 65536) {
      frame += static_cast<char>(0x80 | 126);
      frame += static_cast<char>((size >> 8) & 0xFF);
      frame += static_cast<char>(size & 0xFF);
    } else {
      frame += static_cast<char>(0x80 | 127);
      for (int shift = 56; shift >= 0; shift -= 8) {
        frame += static_cast<char>((size >> shift) & 0xFF);
      }
    }
    unsigned char mask[4];
    {
      std::lock_guard<std::mutex> lock(mState->maskLock);
      for (unsigned char& byte : mask) {
        byte = static_cast<unsigned char>(mState->masks());
      }
    }
    frame.append(reinterpret_cast<const char*>(mask), 4);
    const std::size_t at = frame.size();
    frame += bytes;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      frame[at + i] = static_cast<char>(frame[at + i] ^ mask[i % 4]);
    }
    if (!connection->WriteAll(frame.data(), frame.size())) {
      return std::unexpected("sending failed");
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

  std::expected<WebSocket::Received, std::string> WebSocket::Receive(
    std::string& message
  )
  {
    message.clear();
    std::shared_ptr<Connection> connection;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      connection = mState->connection;
    }
    if (!connection) {
      return std::unexpected("not connected");
    }
    std::string& buffer = mState->buffer;
    for (;;) {
      // One whole frame in the buffer?
      if (buffer.size() >= 2) {
        const auto byte = [&](std::size_t i) {
          return static_cast<unsigned char>(buffer[i]);
        };
        const bool fin = (byte(0) & 0x80) != 0;
        const int opcode = byte(0) & 0x0F;
        const bool masked = (byte(1) & 0x80) != 0;
        std::uint64_t length = byte(1) & 0x7F;
        std::size_t at = 2;
        if (length == 126 && buffer.size() >= 4) {
          length = (static_cast<std::uint64_t>(byte(2)) << 8) | byte(3);
          at = 4;
        } else if (length == 127 && buffer.size() >= 10) {
          length = 0;
          for (int i = 0; i < 8; ++i) {
            length = (length << 8) | byte(2 + i);
          }
          at = 10;
        } else if (length >= 126) {
          at = 0; // its length isn't all here yet
        }
        // RFC 6455 5.2: the 64-bit length's top bit is 0. A frame, or a message of fragments, over the limit ends the
        // connection: a length near 2^64 would wrap the sum below, and any length makes the buffer grow to it.
        if (at != 0 && (length > kMaxMessageBytes || message.size() + length > kMaxMessageBytes)) {
          return std::unexpected("a WebSocket message over " + std::to_string(kMaxMessageBytes >> 20) + " MB");
        }
        if (at != 0 && buffer.size() >= at + (masked ? 4 : 0) + length) {
          std::string payload = buffer.substr(at + (masked ? 4 : 0), static_cast<std::size_t>(length));
          if (masked) {
            for (std::size_t i = 0; i < payload.size(); ++i) {
              payload[i] = static_cast<char>(payload[i] ^ buffer[at + i % 4]);
            }
          }
          buffer.erase(0, at + (masked ? 4 : 0) + static_cast<std::size_t>(length));
          if (opcode == 0x8) {
            return Received::Closed;
          }
          if (opcode == 0x9) { // ping: the same bytes back as a pong
            std::string pong;
            pong += static_cast<char>(0x8A);
            pong += static_cast<char>(0x80 | std::min<std::size_t>(payload.size(), 125));
            pong.append("\0\0\0\0", 4); // a zero mask leaves the bytes as they are
            pong += payload.substr(0, 125);
            (void)connection->WriteAll(pong.data(), pong.size());
            continue;
          }
          if (opcode == 0xA) {
            continue;
          }
          message += payload;
          if (fin) {
            return Received::Message;
          }
          continue; // a fragment: the rest follows
        }
      }
      const std::size_t before = buffer.size();
      if (!connection->ReadSome(buffer, -1)) {
        return std::unexpected("the connection broke off");
      }
      if (buffer.size() == before) {
        return Received::Closed;
      }
    }
  }

  void WebSocket::Close()
  {
    std::shared_ptr<Connection> connection;
    std::shared_ptr<Connection> opening;
    {
      std::lock_guard<std::mutex> lock(mState->lock);
      connection.swap(mState->connection);
      opening.swap(mState->opening);
    }
    if (opening) {
      opening->Close(); // a connect or upgrade still under way: no WebSocket to say goodbye on yet
    }
    if (connection) {
      static constexpr char kClose[] = {
        static_cast<char>(0x88), static_cast<char>(0x82), 0, 0, 0, 0, 0x03, static_cast<char>(0xE8)
      };
      (void)connection->WriteAll(kClose, sizeof(kClose)); // a normal close, 1000
      connection->Close();
    }
  }
} // namespace platform::http
