#pragma once

/**
 * Engine addition (issue #259): the socket calls of the lockstep transport (moho/net) and the
 * events that report socket readiness, one interface with one implementation per platform.
 *
 * - Windows (src/platform/windows/NetWindows.cpp) makes exactly the Winsock calls the recovered
 *   functions made before this interface existed, with the same arguments and in the same order.
 * - POSIX (src/platform/posix/NetPosix.cpp) runs BSD sockets and gives them Winsock's behaviour
 *   where the recovered code depends on it: error numbers (LastError), WSAEventSelect's
 *   readiness events (SelectSocketEvents) and non-blocking mode inherited by accepted sockets.
 *
 * A socket event is a Win32 event HANDLE on every platform (on POSIX, one of the Win32 shim's,
 * src/platform/posix/Win32Shim.cpp), because the engine hands these events to the main loop's
 * wait set (WIN_GetWaitHandleSet) and to its own threads' waits, which take HANDLEs.
 */

#include <cstdint>

#include "platform/PlatformDefines.h"

#if FAFRE_PLATFORM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace platform::net
{
#if FAFRE_PLATFORM_WINDOWS
  /// A socket: Winsock's SOCKET.
  using Socket = SOCKET;
  inline constexpr Socket kInvalidSocket = INVALID_SOCKET;
#else
  /// A socket: a file descriptor.
  using Socket = int;
  inline constexpr Socket kInvalidSocket = -1;
#endif

  /// What a failed call returns (Winsock's SOCKET_ERROR).
  inline constexpr int kSocketError = -1;

  /// A socket event: a Win32 event HANDLE (see the file comment).
  using EventHandle = void*;

  /// The conditions a socket event waits for: Winsock's FD_* bits, with their values.
  inline constexpr long kEventRead = 0x01;
  inline constexpr long kEventWrite = 0x02;
  inline constexpr long kEventAccept = 0x08;
  inline constexpr long kEventConnect = 0x10;
  inline constexpr long kEventClose = 0x20;

  /// Shutdown directions (Winsock's SD_RECEIVE and SD_SEND).
  enum class ShutdownHow
  {
    kReceive,
    kSend,
  };

  /// What PollConnect saw on a socket whose non-blocking connect is under way.
  enum class ConnectPoll
  {
    kPending,   ///< select() reported nothing (or no socket at all).
    kConnected, ///< the socket is writable: the connection succeeded.
    kFailed,    ///< the socket has an exception: the connection failed.
    kNeither,   ///< select() returned non-zero with neither set (an error).
  };

  /**
   * The error numbers LastError returns: Winsock's on every platform (POSIX maps errno to
   * them), so moho/net's checks and its error-name table (NET_GetWinsockErrorString) are the
   * same everywhere.
   */
  namespace error
  {
    inline constexpr int kNone = 0;
    inline constexpr int kInterrupted = 10004;            // WSAEINTR
    inline constexpr int kBadFile = 10009;                // WSAEBADF
    inline constexpr int kAccess = 10013;                 // WSAEACCES
    inline constexpr int kFault = 10014;                  // WSAEFAULT
    inline constexpr int kInvalid = 10022;                // WSAEINVAL
    inline constexpr int kTooManyFiles = 10024;           // WSAEMFILE
    inline constexpr int kWouldBlock = 10035;             // WSAEWOULDBLOCK
    inline constexpr int kInProgress = 10036;             // WSAEINPROGRESS
    inline constexpr int kAlready = 10037;                // WSAEALREADY
    inline constexpr int kNotSocket = 10038;              // WSAENOTSOCK
    inline constexpr int kDestinationRequired = 10039;    // WSAEDESTADDRREQ
    inline constexpr int kMessageSize = 10040;            // WSAEMSGSIZE
    inline constexpr int kProtocolType = 10041;           // WSAEPROTOTYPE
    inline constexpr int kNoProtocolOption = 10042;       // WSAENOPROTOOPT
    inline constexpr int kProtocolNotSupported = 10043;   // WSAEPROTONOSUPPORT
    inline constexpr int kSocketTypeNotSupported = 10044; // WSAESOCKTNOSUPPORT
    inline constexpr int kOperationNotSupported = 10045;  // WSAEOPNOTSUPP
    inline constexpr int kFamilyNotSupported = 10046;     // WSAEPFNOSUPPORT
    inline constexpr int kAddressFamily = 10047;          // WSAEAFNOSUPPORT
    inline constexpr int kAddressInUse = 10048;           // WSAEADDRINUSE
    inline constexpr int kAddressNotAvailable = 10049;    // WSAEADDRNOTAVAIL
    inline constexpr int kNetworkDown = 10050;            // WSAENETDOWN
    inline constexpr int kNetworkUnreachable = 10051;     // WSAENETUNREACH
    inline constexpr int kNetworkReset = 10052;           // WSAENETRESET
    inline constexpr int kConnectionAborted = 10053;      // WSAECONNABORTED
    inline constexpr int kConnectionReset = 10054;        // WSAECONNRESET
    inline constexpr int kNoBuffers = 10055;              // WSAENOBUFS
    inline constexpr int kIsConnected = 10056;            // WSAEISCONN
    inline constexpr int kNotConnected = 10057;           // WSAENOTCONN
    inline constexpr int kShutdown = 10058;               // WSAESHUTDOWN
    inline constexpr int kTooManyReferences = 10059;      // WSAETOOMANYREFS
    inline constexpr int kTimedOut = 10060;               // WSAETIMEDOUT
    inline constexpr int kConnectionRefused = 10061;      // WSAECONNREFUSED
    inline constexpr int kLoop = 10062;                   // WSAELOOP
    inline constexpr int kNameTooLong = 10063;            // WSAENAMETOOLONG
    inline constexpr int kHostDown = 10064;               // WSAEHOSTDOWN
    inline constexpr int kHostUnreachable = 10065;        // WSAEHOSTUNREACH
    inline constexpr int kNotEmpty = 10066;               // WSAENOTEMPTY
    inline constexpr int kProcessLimit = 10067;           // WSAEPROCLIM
    inline constexpr int kUsers = 10068;                  // WSAEUSERS
    inline constexpr int kDiskQuota = 10069;              // WSAEDQUOT
    inline constexpr int kStale = 10070;                  // WSAESTALE
    inline constexpr int kRemote = 10071;                 // WSAEREMOTE
    inline constexpr int kSystemNotReady = 10091;         // WSASYSNOTREADY
    inline constexpr int kVersionNotSupported = 10092;    // WSAVERNOTSUPPORTED
    inline constexpr int kNotInitialised = 10093;         // WSANOTINITIALISED
    inline constexpr int kDisconnected = 10101;           // WSAEDISCON
    inline constexpr int kHostNotFound = 11001;           // WSAHOST_NOT_FOUND
    inline constexpr int kTryAgain = 11002;               // WSATRY_AGAIN
    inline constexpr int kNoRecovery = 11003;             // WSANO_RECOVERY
    inline constexpr int kNoData = 11004;                 // WSANO_DATA
  } // namespace error

  /// Starts the socket library: WSAStartup(MAKEWORD(1, 1)) on Windows. 0 on success.
  [[nodiscard]] int Startup() noexcept;

  /// The calling thread's last socket error (WSAGetLastError), in Winsock's numbers.
  [[nodiscard]] int LastError() noexcept;

  [[nodiscard]] Socket OpenSocket(int family, int type, int protocol) noexcept;
  /// Closes `socket`; on POSIX this also ends its socket-event registration.
  int CloseSocket(Socket socket) noexcept;
  /// Makes `socket` non-blocking: ioctlsocket(FIONBIO, 1) on Windows.
  int SetNonBlocking(Socket socket) noexcept;
  int SetOption(Socket socket, int level, int name, const void* value, int length) noexcept;
  int Bind(Socket socket, const sockaddr_in& address) noexcept;
  int Listen(Socket socket, int backlog) noexcept;
  /// A non-blocking connect that is under way fails with error::kWouldBlock, as in Winsock.
  int Connect(Socket socket, const sockaddr_in& address) noexcept;
  /// `address` may be null. The new socket inherits the listener's non-blocking mode and its
  /// socket-event selection, as in Winsock.
  [[nodiscard]] Socket Accept(Socket listener, sockaddr_in* address) noexcept;
  int Send(Socket socket, const char* data, int length) noexcept;
  int Recv(Socket socket, char* buffer, int length) noexcept;
  int SendTo(Socket socket, const char* data, int length, const sockaddr_in& to) noexcept;
  int RecvFrom(Socket socket, char* buffer, int length, sockaddr_in* from) noexcept;
  int Shutdown(Socket socket, ShutdownHow how) noexcept;
  /// getsockname / getpeername into an IPv4 address.
  int GetLocalAddress(Socket socket, sockaddr_in* address) noexcept;
  int GetPeerAddress(Socket socket, sockaddr_in* address) noexcept;

  /// select() on `socket` for readability with a zero timeout: select's result.
  [[nodiscard]] int PollReadable(Socket socket) noexcept;
  /// select() on `socket` for writability and exceptions with a zero timeout.
  [[nodiscard]] ConnectPoll PollConnect(Socket socket) noexcept;

  /// A manual-reset, non-signalled socket event (WSACreateEvent); null on failure.
  [[nodiscard]] EventHandle CreateSocketEvent() noexcept;
  bool CloseSocketEvent(EventHandle event) noexcept;
  bool SignalSocketEvent(EventHandle event) noexcept;
  bool ResetSocketEvent(EventHandle event) noexcept;
  /**
   * Signals `event` when one of the `interest` conditions (kEvent*) holds on `socket`
   * (WSAEventSelect); this makes the socket non-blocking. The same event may serve many
   * sockets. On POSIX the conditions are re-enabled as Winsock re-enables them: read by Recv
   * and RecvFrom, accept by Accept, write by a Send or SendTo that would block.
   */
  int SelectSocketEvents(Socket socket, EventHandle event, long interest) noexcept;
  /// Waits for `event` (WSAWaitForMultipleEvents with one event, alertable); 0xFFFFFFFF waits
  /// without a timeout.
  void WaitSocketEvent(EventHandle event, std::uint32_t timeoutMs) noexcept;
} // namespace platform::net
