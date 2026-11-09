#pragma once

// Engine addition (dedicated-server plan WPL.5): the subset of <winsock2.h> that the shared
// network code names, for the Linux build, on BSD sockets. The lockstep transport (the
// WSAEventSelect connectors in moho/net/CNet*Connector.cpp and the sockets under them) is
// not part of the Linux build; what remains here is enough for the code that names its
// types and for moho/net/Common.cpp's helpers.

#if defined(_WIN32)
#error "platform/posix/win32/winsock2.h is for builds without the Windows SDK"
#endif

#include <Windows.h>

#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

using SOCKET = int;
using WSAEVENT = HANDLE;
using SOCKADDR = sockaddr;
using SOCKADDR_IN = sockaddr_in;
using ADDRINFOA = addrinfo;
using PADDRINFOA = addrinfo*;
using u_long = unsigned long;
using u_short = unsigned short;

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR

struct WSADATA
{
  WORD wVersion;
  WORD wHighVersion;
  char szDescription[257];
  char szSystemStatus[129];
  unsigned short iMaxSockets;
  unsigned short iMaxUdpDg;
  char* lpVendorInfo;
};

inline int WSAStartup(WORD, WSADATA* const data) noexcept
{
  if (data != nullptr) {
    *data = WSADATA{};
    data->wVersion = data->wHighVersion = 0x0101;
  }
  return 0;
}

inline int WSACleanup() noexcept
{
  return 0;
}

inline int closesocket(const SOCKET socket) noexcept
{
  return ::close(socket);
}

inline int ioctlsocket(const SOCKET socket, const unsigned long command, u_long* const argument) noexcept
{
  int value = argument != nullptr ? static_cast<int>(*argument) : 0;
  const int result = ::ioctl(socket, command, &value);
  if (argument != nullptr) {
    *argument = static_cast<u_long>(value);
  }
  return result;
}

// Winsock's error codes are its own numbers; WSAGetLastError reports errno mapped to them.
#define WSABASEERR 10000
#define WSAEINTR (WSABASEERR + 4)
#define WSAEBADF (WSABASEERR + 9)
#define WSAEACCES (WSABASEERR + 13)
#define WSAEFAULT (WSABASEERR + 14)
#define WSAEINVAL (WSABASEERR + 22)
#define WSAEMFILE (WSABASEERR + 24)
#define WSAEWOULDBLOCK (WSABASEERR + 35)
#define WSAEINPROGRESS (WSABASEERR + 36)
#define WSAEALREADY (WSABASEERR + 37)
#define WSAENOTSOCK (WSABASEERR + 38)
#define WSAEDESTADDRREQ (WSABASEERR + 39)
#define WSAEMSGSIZE (WSABASEERR + 40)
#define WSAEPROTOTYPE (WSABASEERR + 41)
#define WSAENOPROTOOPT (WSABASEERR + 42)
#define WSAEPROTONOSUPPORT (WSABASEERR + 43)
#define WSAESOCKTNOSUPPORT (WSABASEERR + 44)
#define WSAEOPNOTSUPP (WSABASEERR + 45)
#define WSAEPFNOSUPPORT (WSABASEERR + 46)
#define WSAEAFNOSUPPORT (WSABASEERR + 47)
#define WSAEADDRINUSE (WSABASEERR + 48)
#define WSAEADDRNOTAVAIL (WSABASEERR + 49)
#define WSAENETDOWN (WSABASEERR + 50)
#define WSAENETUNREACH (WSABASEERR + 51)
#define WSAENETRESET (WSABASEERR + 52)
#define WSAECONNABORTED (WSABASEERR + 53)
#define WSAECONNRESET (WSABASEERR + 54)
#define WSAENOBUFS (WSABASEERR + 55)
#define WSAEISCONN (WSABASEERR + 56)
#define WSAENOTCONN (WSABASEERR + 57)
#define WSAESHUTDOWN (WSABASEERR + 58)
#define WSAETOOMANYREFS (WSABASEERR + 59)
#define WSAETIMEDOUT (WSABASEERR + 60)
#define WSAECONNREFUSED (WSABASEERR + 61)
#define WSAELOOP (WSABASEERR + 62)
#define WSAENAMETOOLONG (WSABASEERR + 63)
#define WSAEHOSTDOWN (WSABASEERR + 64)
#define WSAEHOSTUNREACH (WSABASEERR + 65)
#define WSAENOTEMPTY (WSABASEERR + 66)
#define WSAEPROCLIM (WSABASEERR + 67)
#define WSAEUSERS (WSABASEERR + 68)
#define WSAEDQUOT (WSABASEERR + 69)
#define WSAESTALE (WSABASEERR + 70)
#define WSAEREMOTE (WSABASEERR + 71)
#define WSASYSNOTREADY (WSABASEERR + 91)
#define WSAVERNOTSUPPORTED (WSABASEERR + 92)
#define WSANOTINITIALISED (WSABASEERR + 93)
#define WSAEDISCON (WSABASEERR + 101)
#define WSAHOST_NOT_FOUND (WSABASEERR + 1001)
#define WSATRY_AGAIN (WSABASEERR + 1002)
#define WSANO_RECOVERY (WSABASEERR + 1003)
#define WSANO_DATA (WSABASEERR + 1004)

inline int WSAGetLastError() noexcept
{
  switch (errno) {
  case EINTR:
    return WSAEINTR;
  case EBADF:
    return WSAEBADF;
  case EACCES:
    return WSAEACCES;
  case EFAULT:
    return WSAEFAULT;
  case EINVAL:
    return WSAEINVAL;
  case EMFILE:
    return WSAEMFILE;
  case EWOULDBLOCK:
    return WSAEWOULDBLOCK;
  case EINPROGRESS:
    return WSAEINPROGRESS;
  case EALREADY:
    return WSAEALREADY;
  case ENOTSOCK:
    return WSAENOTSOCK;
  case EMSGSIZE:
    return WSAEMSGSIZE;
  case EADDRINUSE:
    return WSAEADDRINUSE;
  case EADDRNOTAVAIL:
    return WSAEADDRNOTAVAIL;
  case ENETDOWN:
    return WSAENETDOWN;
  case ENETUNREACH:
    return WSAENETUNREACH;
  case ECONNABORTED:
    return WSAECONNABORTED;
  case ECONNRESET:
    return WSAECONNRESET;
  case ENOBUFS:
    return WSAENOBUFS;
  case EISCONN:
    return WSAEISCONN;
  case ENOTCONN:
    return WSAENOTCONN;
  case ETIMEDOUT:
    return WSAETIMEDOUT;
  case ECONNREFUSED:
    return WSAECONNREFUSED;
  case EHOSTUNREACH:
    return WSAEHOSTUNREACH;
  default:
    return errno;
  }
}
