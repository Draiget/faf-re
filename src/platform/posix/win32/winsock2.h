#pragma once

#include "../../PlatformDefines.h"

// Engine addition (dedicated-server plan WPL.5): the BSD socket headers and the few <winsock2.h>
// type names that the shared code still spells, for builds without the Windows SDK. Socket calls
// go through platform::net (src/platform/Net.h, issue #259), not through Winsock names here.

#if FAFRE_PLATFORM_WINDOWS
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
