// Engine addition (issue #259): platform/Net.h on Winsock. Every function is the Winsock call the
// recovered moho/net code made before platform::net existed, with the same arguments.

#include "platform/Net.h"

#include <ws2tcpip.h>
#include <Windows.h>

namespace platform::net
{
  static_assert(kSocketError == SOCKET_ERROR);
  static_assert(kEventRead == FD_READ && kEventWrite == FD_WRITE && kEventAccept == FD_ACCEPT);
  static_assert(kEventConnect == FD_CONNECT && kEventClose == FD_CLOSE);
  static_assert(error::kInterrupted == WSAEINTR && error::kBadFile == WSAEBADF && error::kAccess == WSAEACCES);
  static_assert(error::kFault == WSAEFAULT && error::kInvalid == WSAEINVAL && error::kTooManyFiles == WSAEMFILE);
  static_assert(error::kWouldBlock == WSAEWOULDBLOCK && error::kInProgress == WSAEINPROGRESS);
  static_assert(error::kAlready == WSAEALREADY && error::kNotSocket == WSAENOTSOCK);
  static_assert(error::kDestinationRequired == WSAEDESTADDRREQ && error::kMessageSize == WSAEMSGSIZE);
  static_assert(error::kProtocolType == WSAEPROTOTYPE && error::kNoProtocolOption == WSAENOPROTOOPT);
  static_assert(error::kProtocolNotSupported == WSAEPROTONOSUPPORT);
  static_assert(error::kSocketTypeNotSupported == WSAESOCKTNOSUPPORT);
  static_assert(error::kOperationNotSupported == WSAEOPNOTSUPP && error::kFamilyNotSupported == WSAEPFNOSUPPORT);
  static_assert(error::kAddressFamily == WSAEAFNOSUPPORT && error::kAddressInUse == WSAEADDRINUSE);
  static_assert(error::kAddressNotAvailable == WSAEADDRNOTAVAIL && error::kNetworkDown == WSAENETDOWN);
  static_assert(error::kNetworkUnreachable == WSAENETUNREACH && error::kNetworkReset == WSAENETRESET);
  static_assert(error::kConnectionAborted == WSAECONNABORTED && error::kConnectionReset == WSAECONNRESET);
  static_assert(error::kNoBuffers == WSAENOBUFS && error::kIsConnected == WSAEISCONN);
  static_assert(error::kNotConnected == WSAENOTCONN && error::kShutdown == WSAESHUTDOWN);
  static_assert(error::kTooManyReferences == WSAETOOMANYREFS && error::kTimedOut == WSAETIMEDOUT);
  static_assert(error::kConnectionRefused == WSAECONNREFUSED && error::kLoop == WSAELOOP);
  static_assert(error::kNameTooLong == WSAENAMETOOLONG && error::kHostDown == WSAEHOSTDOWN);
  static_assert(error::kHostUnreachable == WSAEHOSTUNREACH && error::kNotEmpty == WSAENOTEMPTY);
  static_assert(error::kProcessLimit == WSAEPROCLIM && error::kUsers == WSAEUSERS && error::kDiskQuota == WSAEDQUOT);
  static_assert(error::kStale == WSAESTALE && error::kRemote == WSAEREMOTE);
  static_assert(error::kSystemNotReady == WSASYSNOTREADY && error::kVersionNotSupported == WSAVERNOTSUPPORTED);
  static_assert(error::kNotInitialised == WSANOTINITIALISED && error::kDisconnected == WSAEDISCON);
  static_assert(error::kHostNotFound == WSAHOST_NOT_FOUND && error::kTryAgain == WSATRY_AGAIN);
  static_assert(error::kNoRecovery == WSANO_RECOVERY && error::kNoData == WSANO_DATA);
  static_assert(sizeof(EventHandle) == sizeof(WSAEVENT));

  int Startup() noexcept
  {
    WSAData wsaData;
    return ::WSAStartup(MAKEWORD(1, 1), &wsaData);
  }

  int LastError() noexcept
  {
    return ::WSAGetLastError();
  }

  Socket OpenSocket(
    const int family,
    const int type,
    const int protocol
  ) noexcept
  {
    return ::socket(family, type, protocol);
  }

  int CloseSocket(
    const Socket socket
  ) noexcept
  {
    return ::closesocket(socket);
  }

  int SetNonBlocking(
    const Socket socket
  ) noexcept
  {
    u_long nonBlocking = 1;
    return ::ioctlsocket(socket, FIONBIO, &nonBlocking);
  }

  int SetOption(
    const Socket socket,
    const int level,
    const int name,
    const void* const value,
    const int length
  ) noexcept
  {
    return ::setsockopt(socket, level, name, static_cast<const char*>(value), length);
  }

  int Bind(
    const Socket socket,
    const sockaddr_in& address
  ) noexcept
  {
    return ::bind(socket, reinterpret_cast<const sockaddr*>(&address), static_cast<int>(sizeof(address)));
  }

  int Listen(
    const Socket socket,
    const int backlog
  ) noexcept
  {
    return ::listen(socket, backlog);
  }

  int Connect(
    const Socket socket,
    const sockaddr_in& address
  ) noexcept
  {
    return ::connect(socket, reinterpret_cast<const sockaddr*>(&address), static_cast<int>(sizeof(address)));
  }

  Socket Accept(
    const Socket listener,
    sockaddr_in* const address
  ) noexcept
  {
    sockaddr_in ignored{};
    sockaddr_in* const out = address != nullptr ? address : &ignored;
    int addressLen = static_cast<int>(sizeof(*out));
    return ::accept(listener, reinterpret_cast<sockaddr*>(out), &addressLen);
  }

  int Send(
    const Socket socket,
    const char* const data,
    const int length
  ) noexcept
  {
    return ::send(socket, data, length, 0);
  }

  int Recv(
    const Socket socket,
    char* const buffer,
    const int length
  ) noexcept
  {
    return ::recv(socket, buffer, length, 0);
  }

  int SendTo(
    const Socket socket,
    const char* const data,
    const int length,
    const sockaddr_in& to
  ) noexcept
  {
    return ::sendto(socket, data, length, 0, reinterpret_cast<const sockaddr*>(&to), static_cast<int>(sizeof(to)));
  }

  int RecvFrom(
    const Socket socket,
    char* const buffer,
    const int length,
    sockaddr_in* const from
  ) noexcept
  {
    int fromLen = static_cast<int>(sizeof(*from));
    return ::recvfrom(socket, buffer, length, 0, reinterpret_cast<sockaddr*>(from), &fromLen);
  }

  int Shutdown(
    const Socket socket,
    const ShutdownHow how
  ) noexcept
  {
    return ::shutdown(socket, how == ShutdownHow::kSend ? SD_SEND : SD_RECEIVE);
  }

  int GetLocalAddress(
    const Socket socket,
    sockaddr_in* const address
  ) noexcept
  {
    int nameLen = static_cast<int>(sizeof(*address));
    return ::getsockname(socket, reinterpret_cast<sockaddr*>(address), &nameLen);
  }

  int GetPeerAddress(
    const Socket socket,
    sockaddr_in* const address
  ) noexcept
  {
    int nameLen = static_cast<int>(sizeof(*address));
    return ::getpeername(socket, reinterpret_cast<sockaddr*>(address), &nameLen);
  }

  int PollReadable(
    const Socket socket
  ) noexcept
  {
    fd_set readFds{};
    readFds.fd_count = 1;
    readFds.fd_array[0] = socket;
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return ::select(1, &readFds, nullptr, nullptr, &timeout);
  }

  ConnectPoll PollConnect(
    const Socket socket
  ) noexcept
  {
    fd_set writeFds{};
    writeFds.fd_count = 1;
    writeFds.fd_array[0] = socket;

    fd_set exceptFds = writeFds;
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    const int selected = ::select(0, nullptr, &writeFds, &exceptFds, &timeout);
    if (selected == 0) {
      return ConnectPoll::kPending;
    }
    if (FD_ISSET(socket, &writeFds)) {
      return ConnectPoll::kConnected;
    }
    if (FD_ISSET(socket, &exceptFds)) {
      return ConnectPoll::kFailed;
    }
    return ConnectPoll::kNeither;
  }

  EventHandle CreateSocketEvent() noexcept
  {
    return ::WSACreateEvent();
  }

  bool CloseSocketEvent(
    const EventHandle event
  ) noexcept
  {
    return ::WSACloseEvent(event) != FALSE;
  }

  bool SignalSocketEvent(
    const EventHandle event
  ) noexcept
  {
    return ::WSASetEvent(event) != FALSE;
  }

  bool ResetSocketEvent(
    const EventHandle event
  ) noexcept
  {
    return ::WSAResetEvent(event) != FALSE;
  }

  int SelectSocketEvents(
    const Socket socket,
    const EventHandle event,
    const long interest
  ) noexcept
  {
    return ::WSAEventSelect(socket, static_cast<WSAEVENT>(event), interest);
  }

  void WaitSocketEvent(
    EventHandle event,
    const std::uint32_t timeoutMs
  ) noexcept
  {
    ::WSAWaitForMultipleEvents(1, &event, false, static_cast<DWORD>(timeoutMs), true);
  }
} // namespace platform::net
