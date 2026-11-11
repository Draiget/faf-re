// Engine addition (issue #259): platform/Net.h on BSD sockets, with the Winsock behaviour the
// recovered moho/net code relies on.
//
// Socket events. WSAEventSelect signals an event when a selected condition holds on a socket and
// then waits until the program re-enables that condition by the matching call: recv/recvfrom for
// read, accept for accept, a send that would block for write; connect and close are reported
// once. Here one background thread poll()s every socket that has an armed condition and signals
// the event (the Win32 shim's, so the main loop's wait set and the engine's threads wait on it as
// on Windows), disarming what it reported; the calls below re-arm as Winsock re-enables. The
// thread starts with the first selection, so programs that never select (the headless replay
// runner, the server) never start it.
//
// Winsock behaviour BSD sockets lack, given here:
// - error numbers: LastError reports Winsock's (platform::net::error), per thread;
// - a non-blocking connect under way fails with error::kWouldBlock (BSD: EINPROGRESS);
// - an accepted socket inherits the listener's non-blocking mode and event selection;
// - send never raises SIGPIPE (MSG_NOSIGNAL; SO_NOSIGPIPE on macOS).

#include "platform/Net.h"

#include <Windows.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <sys/select.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace platform::net
{
  namespace
  {
    thread_local int tLastError = error::kNone;

    [[nodiscard]] int WinsockErrorFromErrno(
      const int code
    ) noexcept
    {
      switch (code) {
      case 0:
        return error::kNone;
      case EINTR:
        return error::kInterrupted;
      case EBADF:
        return error::kBadFile;
      case EACCES:
      case EPERM:
        return error::kAccess;
      case EFAULT:
        return error::kFault;
      case EINVAL:
        return error::kInvalid;
      case EMFILE:
      case ENFILE:
        return error::kTooManyFiles;
#if EAGAIN != EWOULDBLOCK
      case EAGAIN:
#endif
      case EWOULDBLOCK:
        return error::kWouldBlock;
      case EINPROGRESS:
        return error::kInProgress;
      case EALREADY:
        return error::kAlready;
      case ENOTSOCK:
        return error::kNotSocket;
      case EDESTADDRREQ:
        return error::kDestinationRequired;
      case EMSGSIZE:
        return error::kMessageSize;
      case EPROTOTYPE:
        return error::kProtocolType;
      case ENOPROTOOPT:
        return error::kNoProtocolOption;
      case EPROTONOSUPPORT:
        return error::kProtocolNotSupported;
      case ESOCKTNOSUPPORT:
        return error::kSocketTypeNotSupported;
      case EOPNOTSUPP:
        return error::kOperationNotSupported;
      case EPFNOSUPPORT:
        return error::kFamilyNotSupported;
      case EAFNOSUPPORT:
        return error::kAddressFamily;
      case EADDRINUSE:
        return error::kAddressInUse;
      case EADDRNOTAVAIL:
        return error::kAddressNotAvailable;
      case ENETDOWN:
        return error::kNetworkDown;
      case ENETUNREACH:
        return error::kNetworkUnreachable;
      case ENETRESET:
        return error::kNetworkReset;
      case ECONNABORTED:
        return error::kConnectionAborted;
      case ECONNRESET:
      case EPIPE:
        return error::kConnectionReset;
      case ENOBUFS:
      case ENOMEM:
        return error::kNoBuffers;
      case EISCONN:
        return error::kIsConnected;
      case ENOTCONN:
        return error::kNotConnected;
      case ESHUTDOWN:
        return error::kShutdown;
      case ETOOMANYREFS:
        return error::kTooManyReferences;
      case ETIMEDOUT:
        return error::kTimedOut;
      case ECONNREFUSED:
        return error::kConnectionRefused;
      case ELOOP:
        return error::kLoop;
      case ENAMETOOLONG:
        return error::kNameTooLong;
      case EHOSTDOWN:
        return error::kHostDown;
      case EHOSTUNREACH:
        return error::kHostUnreachable;
      case ENOTEMPTY:
        return error::kNotEmpty;
      case EUSERS:
        return error::kUsers;
      case EDQUOT:
        return error::kDiskQuota;
      case ESTALE:
        return error::kStale;
      case EREMOTE:
        return error::kRemote;
      default:
        return code;
      }
    }

    /// Records errno as the thread's socket error and returns what a failed call returns.
    int Fail() noexcept
    {
      tLastError = WinsockErrorFromErrno(errno);
      return kSocketError;
    }

    [[nodiscard]] bool IsNonBlocking(
      const Socket socket
    ) noexcept
    {
      const int flags = ::fcntl(socket, F_GETFL, 0);
      return flags != -1 && (flags & O_NONBLOCK) != 0;
    }

    [[nodiscard]] bool IsListening(
      const Socket socket
    ) noexcept
    {
      int listening = 0;
      socklen_t length = sizeof(listening);
      return ::getsockopt(socket, SOL_SOCKET, SO_ACCEPTCONN, &listening, &length) == 0 && listening != 0;
    }

    /**
     * The sockets selected for events and the thread that watches them. Never destroyed: the
     * thread runs until the process ends, and sockets may be closed from static destructors.
     */
    class Poller
    {
    public:
      static Poller& Get()
      {
        static Poller* const sPoller = new Poller();
        return *sPoller;
      }

      /// Whether any socket is selected: the re-arm calls skip the lock while none is.
      [[nodiscard]] bool Active() const noexcept
      {
        return mCount.load(std::memory_order_acquire) != 0;
      }

      bool Select(
        const Socket socket,
        const EventHandle event,
        const long interest
      )
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        if (event == nullptr || interest == 0) {
          EraseLocked(socket);
          WakeLocked();
          return true;
        }
        if (!StartLocked()) {
          return false;
        }
        Registration& registration = mRegistrations[socket];
        registration.event = event;
        registration.interest = interest;
        registration.armed = interest;
        registration.listening = IsListening(socket);
        registration.serial = mNextSerial++;
        mCount.store(mRegistrations.size(), std::memory_order_release);
        WakeLocked();
        return true;
      }

      /// The accepted socket takes the listener's event and conditions, as in Winsock.
      void Inherit(
        const Socket listener,
        const Socket accepted
      )
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        const auto found = mRegistrations.find(listener);
        if (found == mRegistrations.end()) {
          return;
        }
        Registration registration = found->second;
        registration.armed = registration.interest;
        registration.listening = false;
        registration.serial = mNextSerial++;
        mRegistrations[accepted] = registration;
        mCount.store(mRegistrations.size(), std::memory_order_release);
        WakeLocked();
      }

      void Forget(
        const Socket socket
      )
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        if (EraseLocked(socket)) {
          WakeLocked();
        }
      }

      /// Ends every selection that signals `event`, before the event is closed.
      void ForgetEvent(
        const EventHandle event
      )
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        bool erased = false;
        for (auto it = mRegistrations.begin(); it != mRegistrations.end();) {
          if (it->second.event == event) {
            it = mRegistrations.erase(it);
            erased = true;
          } else {
            ++it;
          }
        }
        if (erased) {
          mCount.store(mRegistrations.size(), std::memory_order_release);
          WakeLocked();
        }
      }

      /// Re-enables the selected conditions among `conditions` on `socket`.
      void Rearm(
        const Socket socket,
        const long conditions
      )
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        const auto found = mRegistrations.find(socket);
        if (found == mRegistrations.end()) {
          return;
        }
        Registration& registration = found->second;
        const long rearmed = registration.interest & conditions & ~registration.armed;
        if (rearmed != 0) {
          registration.armed |= rearmed;
          WakeLocked();
        }
      }

    private:
      struct Registration
      {
        EventHandle event = nullptr;
        long interest = 0;
        long armed = 0;
        bool listening = false;
        std::uint64_t serial = 0;
      };

      Poller() = default;

      bool EraseLocked(
        const Socket socket
      )
      {
        const bool erased = mRegistrations.erase(socket) != 0;
        mCount.store(mRegistrations.size(), std::memory_order_release);
        return erased;
      }

      bool StartLocked()
      {
        if (mStarted) {
          return true;
        }
        int pipeEnds[2] = {-1, -1};
        if (::pipe(pipeEnds) != 0) {
          return false;
        }
        for (const int end : pipeEnds) {
          ::fcntl(end, F_SETFL, ::fcntl(end, F_GETFL, 0) | O_NONBLOCK);
          ::fcntl(end, F_SETFD, FD_CLOEXEC);
        }
        mWakeRead = pipeEnds[0];
        mWakeWrite = pipeEnds[1];
        std::thread([this] {
          Run();
        }).detach();
        mStarted = true;
        return true;
      }

      void WakeLocked() const noexcept
      {
        if (mWakeWrite != -1) {
          const char byte = 0;
          // A full pipe already holds a wake-up.
          (void)!::write(mWakeWrite, &byte, 1);
        }
      }

      [[nodiscard]] static short PollEventsFor(
        const Registration& registration
      ) noexcept
      {
        short events = 0;
        if (
          (registration.armed & (kEventRead | kEventClose)) != 0 ||
          (registration.listening && (registration.armed & kEventAccept) != 0)
        ) {
          events |= POLLIN;
        }
        if ((registration.armed & (kEventWrite | kEventConnect)) != 0) {
          events |= POLLOUT;
        }
        return events;
      }

      void Run()
      {
        std::vector<pollfd> fds;
        std::vector<std::pair<Socket, std::uint64_t>> watched;
        for (;;) {
          fds.clear();
          watched.clear();
          fds.push_back(pollfd{mWakeRead, POLLIN, 0});
          {
            const std::lock_guard<std::mutex> lock(mMutex);
            for (const auto& [socket, registration] : mRegistrations) {
              const short events = PollEventsFor(registration);
              if (events != 0) {
                fds.push_back(pollfd{socket, events, 0});
                watched.emplace_back(socket, registration.serial);
              }
            }
          }

          if (::poll(fds.data(), static_cast<nfds_t>(fds.size()), -1) < 0) {
            continue; // EINTR; nothing else is expected with valid arguments.
          }

          if (fds[0].revents != 0) {
            char drain[64];
            while (::read(mWakeRead, drain, sizeof(drain)) > 0) {}
          }

          const std::lock_guard<std::mutex> lock(mMutex);
          for (std::size_t index = 1; index < fds.size(); ++index) {
            const short revents = fds[index].revents;
            if (revents == 0) {
              continue;
            }
            const auto found = mRegistrations.find(watched[index - 1].first);
            if (found == mRegistrations.end() || found->second.serial != watched[index - 1].second) {
              continue; // closed or selected again meanwhile
            }
            Registration& registration = found->second;
            long fired = 0;
            if ((revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
              fired |= registration.armed & (kEventRead | kEventClose | (registration.listening ? kEventAccept : 0));
            }
            if ((revents & (POLLOUT | POLLHUP | POLLERR | POLLNVAL)) != 0) {
              fired |= registration.armed & (kEventWrite | kEventConnect);
            }
            if (fired != 0) {
              registration.armed &= ~fired;
              ::SetEvent(registration.event);
            }
          }
        }
      }

      std::mutex mMutex;
      std::unordered_map<Socket, Registration> mRegistrations;
      std::atomic<std::size_t> mCount{0};
      std::uint64_t mNextSerial = 1;
      bool mStarted = false;
      int mWakeRead = -1;
      int mWakeWrite = -1;
    };

    void Rearm(
      const Socket socket,
      const long conditions
    )
    {
      Poller& poller = Poller::Get();
      if (poller.Active()) {
        poller.Rearm(socket, conditions);
      }
    }

    constexpr int kSendFlags =
#if FAFRE_PLATFORM_LINUX
      MSG_NOSIGNAL;
#else
      0; // macOS: SO_NOSIGPIPE, set by OpenSocket and Accept
#endif

    void NoSigPipe(
      [[maybe_unused]] const Socket socket
    ) noexcept
    {
#if FAFRE_PLATFORM_MACOS
      const int on = 1;
      (void)::setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    }
  } // namespace

  int Startup() noexcept
  {
    return 0;
  }

  int LastError() noexcept
  {
    return tLastError;
  }

  Socket OpenSocket(
    const int family,
    const int type,
    const int protocol
  ) noexcept
  {
    const Socket socket = ::socket(family, type, protocol);
    if (socket == kInvalidSocket) {
      Fail();
      return kInvalidSocket;
    }
    ::fcntl(socket, F_SETFD, FD_CLOEXEC);
    NoSigPipe(socket);
    return socket;
  }

  int CloseSocket(
    const Socket socket
  ) noexcept
  {
    if (Poller::Get().Active()) {
      Poller::Get().Forget(socket);
    }
    return ::close(socket) == 0 ? 0 : Fail();
  }

  int SetNonBlocking(
    const Socket socket
  ) noexcept
  {
    const int flags = ::fcntl(socket, F_GETFL, 0);
    if (flags == -1 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
      return Fail();
    }
    return 0;
  }

  int SetOption(
    const Socket socket,
    const int level,
    const int name,
    const void* const value,
    const int length
  ) noexcept
  {
    return ::setsockopt(socket, level, name, value, static_cast<socklen_t>(length)) == 0 ? 0 : Fail();
  }

  int Bind(
    const Socket socket,
    const sockaddr_in& address
  ) noexcept
  {
    return ::bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0 ? 0 : Fail();
  }

  int Listen(
    const Socket socket,
    const int backlog
  ) noexcept
  {
    return ::listen(socket, backlog) == 0 ? 0 : Fail();
  }

  int Connect(
    const Socket socket,
    const sockaddr_in& address
  ) noexcept
  {
    if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
      return 0;
    }
    if (errno == EINPROGRESS) {
      tLastError = error::kWouldBlock;
      return kSocketError;
    }
    return Fail();
  }

  Socket Accept(
    const Socket listener,
    sockaddr_in* const address
  ) noexcept
  {
    sockaddr_in ignored{};
    sockaddr_in* const out = address != nullptr ? address : &ignored;
    socklen_t addressLen = sizeof(*out);
    const Socket accepted = ::accept(listener, reinterpret_cast<sockaddr*>(out), &addressLen);
    const int acceptError = errno;
    Rearm(listener, kEventAccept);
    if (accepted == kInvalidSocket) {
      errno = acceptError;
      Fail();
      return kInvalidSocket;
    }
    ::fcntl(accepted, F_SETFD, FD_CLOEXEC);
    NoSigPipe(accepted);
    if (IsNonBlocking(listener)) {
      (void)SetNonBlocking(accepted);
    }
    if (Poller::Get().Active()) {
      Poller::Get().Inherit(listener, accepted);
    }
    return accepted;
  }

  int Send(
    const Socket socket,
    const char* const data,
    const int length
  ) noexcept
  {
    const ssize_t sent = ::send(socket, data, static_cast<std::size_t>(length), kSendFlags);
    if (sent < 0) {
      Fail();
      if (tLastError == error::kWouldBlock) {
        Rearm(socket, kEventWrite);
      }
      return kSocketError;
    }
    return static_cast<int>(sent);
  }

  int Recv(
    const Socket socket,
    char* const buffer,
    const int length
  ) noexcept
  {
    const ssize_t received = ::recv(socket, buffer, static_cast<std::size_t>(length), 0);
    const int recvError = errno;
    Rearm(socket, kEventRead);
    if (received < 0) {
      errno = recvError;
      return Fail();
    }
    return static_cast<int>(received);
  }

  int SendTo(
    const Socket socket,
    const char* const data,
    const int length,
    const sockaddr_in& to
  ) noexcept
  {
    const ssize_t sent = ::sendto(
      socket, data, static_cast<std::size_t>(length), kSendFlags, reinterpret_cast<const sockaddr*>(&to), sizeof(to)
    );
    if (sent < 0) {
      Fail();
      if (tLastError == error::kWouldBlock) {
        Rearm(socket, kEventWrite);
      }
      return kSocketError;
    }
    return static_cast<int>(sent);
  }

  int RecvFrom(
    const Socket socket,
    char* const buffer,
    const int length,
    sockaddr_in* const from
  ) noexcept
  {
    socklen_t fromLen = sizeof(*from);
    const ssize_t received =
      ::recvfrom(socket, buffer, static_cast<std::size_t>(length), 0, reinterpret_cast<sockaddr*>(from), &fromLen);
    const int recvError = errno;
    Rearm(socket, kEventRead);
    if (received < 0) {
      errno = recvError;
      return Fail();
    }
    return static_cast<int>(received);
  }

  int Shutdown(
    const Socket socket,
    const ShutdownHow how
  ) noexcept
  {
    return ::shutdown(socket, how == ShutdownHow::kSend ? SHUT_WR : SHUT_RD) == 0 ? 0 : Fail();
  }

  int GetLocalAddress(
    const Socket socket,
    sockaddr_in* const address
  ) noexcept
  {
    socklen_t nameLen = sizeof(*address);
    return ::getsockname(socket, reinterpret_cast<sockaddr*>(address), &nameLen) == 0 ? 0 : Fail();
  }

  int GetPeerAddress(
    const Socket socket,
    sockaddr_in* const address
  ) noexcept
  {
    socklen_t nameLen = sizeof(*address);
    return ::getpeername(socket, reinterpret_cast<sockaddr*>(address), &nameLen) == 0 ? 0 : Fail();
  }

  int PollReadable(
    const Socket socket
  ) noexcept
  {
    pollfd entry{socket, POLLIN, 0};
    const int selected = ::poll(&entry, 1, 0);
    return selected < 0 ? Fail() : selected;
  }

  ConnectPoll PollConnect(
    const Socket socket
  ) noexcept
  {
    pollfd entry{socket, POLLOUT, 0};
    const int selected = ::poll(&entry, 1, 0);
    if (selected == 0) {
      return ConnectPoll::kPending;
    }
    if (selected < 0) {
      Fail();
      return ConnectPoll::kNeither;
    }
    // Winsock's select reports a failed connect in the exception set and a finished one as
    // writable; poll reports both as POLLOUT, so the socket's pending error tells them apart.
    int pending = 0;
    socklen_t length = sizeof(pending);
    if (
      (entry.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
      ::getsockopt(socket, SOL_SOCKET, SO_ERROR, &pending, &length) != 0 || pending != 0
    ) {
      return ConnectPoll::kFailed;
    }
    return (entry.revents & POLLOUT) != 0 ? ConnectPoll::kConnected : ConnectPoll::kNeither;
  }

  EventHandle CreateSocketEvent() noexcept
  {
    return ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  }

  bool CloseSocketEvent(
    const EventHandle event
  ) noexcept
  {
    if (event == nullptr) {
      return false;
    }
    if (Poller::Get().Active()) {
      Poller::Get().ForgetEvent(event);
    }
    return ::CloseHandle(event) != FALSE;
  }

  bool SignalSocketEvent(
    const EventHandle event
  ) noexcept
  {
    return ::SetEvent(event) != FALSE;
  }

  bool ResetSocketEvent(
    const EventHandle event
  ) noexcept
  {
    return ::ResetEvent(event) != FALSE;
  }

  int SelectSocketEvents(
    const Socket socket,
    const EventHandle event,
    const long interest
  ) noexcept
  {
    if (event == nullptr && interest != 0) {
      // Winsock refuses a null event (WSA_INVALID_HANDLE); the socket keeps no selection here.
      Poller::Get().Forget(socket);
      tLastError = error::kInvalid;
      return kSocketError;
    }
    if (event != nullptr && interest != 0 && SetNonBlocking(socket) != 0) {
      return kSocketError;
    }
    if (!Poller::Get().Select(socket, event, interest)) {
      return Fail();
    }
    return 0;
  }

  void WaitSocketEvent(
    const EventHandle event,
    const std::uint32_t timeoutMs
  ) noexcept
  {
    // Not alertable: the shim's alertable wait polls in 1 ms slices, and nothing queues calls to
    // the threads that wait here.
    (void)::WaitForSingleObject(event, static_cast<DWORD>(timeoutMs));
  }
} // namespace platform::net
