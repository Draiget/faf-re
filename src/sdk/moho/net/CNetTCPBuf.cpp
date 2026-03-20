#include "CNetTCPBuf.h"

#include <cstring>
#include <stdexcept>

#include "Common.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x004827C0 (FUN_004827C0)
 * Address: 0x1007C610 (sub_1007C610)
 *
 * What it does:
 * Closes active stream directions and tears down the socket stream.
 */
CNetTCPBuf::~CNetTCPBuf()
{
  VirtClose(static_cast<Mode>(mMode));
}

/**
 * Address: 0x00482880 (FUN_00482880)
 * Address: 0x1007C690 (sub_1007C690)
 *
 * What it does:
 * Returns local socket port.
 */
u_short CNetTCPBuf::GetPort()
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  int nameLen = static_cast<int>(sizeof(name));
  getsockname(mSocket, reinterpret_cast<sockaddr*>(&name), &nameLen);
  return ntohs(name.sin_port);
}

/**
 * Address: 0x00482930 (FUN_00482930)
 * Address: 0x1007C720 (sub_1007C720)
 *
 * What it does:
 * Returns connected peer IPv4 address in host byte order.
 */
u_long CNetTCPBuf::GetPeerAddr()
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  int nameLen = static_cast<int>(sizeof(name));
  getpeername(mSocket, reinterpret_cast<sockaddr*>(&name), &nameLen);
  return ntohl(name.sin_addr.s_addr);
}

/**
 * Address: 0x004829E0 (FUN_004829E0)
 * Address: 0x1007C7B0 (sub_1007C7B0)
 *
 * What it does:
 * Returns connected peer port in host byte order.
 */
u_short CNetTCPBuf::GetPeerPort()
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  int nameLen = static_cast<int>(sizeof(name));
  getpeername(mSocket, reinterpret_cast<sockaddr*>(&name), &nameLen);
  return ntohs(name.sin_port);
}

/**
 * Address: 0x00482A90 (FUN_00482A90)
 * Address: 0x1007C840 (sub_1007C840)
 *
 * What it does:
 * Reads bytes using blocking socket behavior.
 */
size_t CNetTCPBuf::VirtRead(char* const buff, const size_t len)
{
  return Read(buff, len, true);
}

/**
 * Address: 0x00482AB0 (FUN_00482AB0)
 * Address: 0x1007C860 (sub_1007C860)
 *
 * What it does:
 * Reads bytes without blocking.
 */
size_t CNetTCPBuf::VirtReadNonBlocking(char* const buf, const size_t len)
{
  return Read(buf, len, false);
}

/**
 * Address: 0x00482AD0 (FUN_00482AD0)
 * Address: 0x1007C880 (sub_1007C880)
 *
 * What it does:
 * Reports read-end-of-stream/failure state.
 */
bool CNetTCPBuf::VirtAtEnd()
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }
  return mFailed != 0;
}

/**
 * Address: 0x00482B50 (FUN_00482B50)
 * Address: 0x1007C8F0 (sub_1007C8F0)
 *
 * What it does:
 * Writes bytes into the pending send window or directly to socket.
 */
void CNetTCPBuf::VirtWrite(const char* data, size_t size)
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  if ((mMode & static_cast<std::uint32_t>(ModeSend)) == 0) {
    throw std::runtime_error("output shutdown");
  }

  if (size == 0) {
    return;
  }

  char* const writeHead = mWriteHead;
  const size_t pendingSpace = static_cast<size_t>(mWriteEnd - writeHead);
  if (size > pendingSpace) {
    if (pendingSpace != 0) {
      std::memcpy(writeHead, data, pendingSpace);
      mWriteHead += pendingSpace;
      data += pendingSpace;
      size -= pendingSpace;
    }

    VirtFlush();

    if (size < kChunkSize) {
      std::memcpy(mBuffer + kChunkSize, data, size);
      mWriteHead = mBuffer + kChunkSize + size;
    } else if (send(mSocket, data, static_cast<int>(size), 0) == SOCKET_ERROR) {
      gpg::Logf("CNetTCPBuf::Write(): send() failed: %s", NET_GetWinsockErrorString());
    }
  } else {
    std::memcpy(writeHead, data, size);
    mWriteHead += size;
  }
}

/**
 * Address: 0x00482CE0 (FUN_00482CE0)
 * Address: 0x1007CA70 (sub_1007CA70)
 *
 * What it does:
 * Flushes pending write-buffer bytes to socket.
 */
void CNetTCPBuf::VirtFlush()
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  const int pendingSize = static_cast<int>(mWriteHead - mWriteStart);
  if (pendingSize == 0) {
    return;
  }

  if (send(mSocket, mBuffer + kChunkSize, pendingSize, 0) == SOCKET_ERROR) {
    gpg::Logf("CNetTCPBuf::Flush(): send() failed: %s", NET_GetWinsockErrorString());
  }
  mWriteHead = mBuffer + kChunkSize;
}

/**
 * Address: 0x00482DA0 (FUN_00482DA0)
 * Address: 0x1007CB20 (sub_1007CB20)
 *
 * What it does:
 * Shuts down selected socket directions and closes when both are off.
 */
void CNetTCPBuf::VirtClose(const Mode mode)
{
  if (mSocket == INVALID_SOCKET) {
    return;
  }

  if ((mMode & static_cast<std::uint32_t>(mode) & static_cast<std::uint32_t>(ModeSend)) != 0) {
    VirtFlush();
    shutdown(mSocket, SD_SEND);
    mMode &= ~static_cast<std::uint32_t>(ModeSend);
    mWriteStart = nullptr;
    mWriteHead = nullptr;
    mWriteEnd = nullptr;
  }

  if ((mMode & static_cast<std::uint32_t>(mode) & static_cast<std::uint32_t>(ModeReceive)) != 0) {
    shutdown(mSocket, SD_RECEIVE);
    mMode &= ~static_cast<std::uint32_t>(ModeReceive);
    mReadStart = nullptr;
    mReadHead = nullptr;
    mReadEnd = nullptr;
  }

  if (mMode == static_cast<std::uint32_t>(ModeNone)) {
    closesocket(mSocket);
    mSocket = INVALID_SOCKET;
  }
}

/**
 * Address: 0x00482770 (FUN_00482770)
 * Address: 0x1007C5C0 (sub_1007C5C0)
 *
 * What it does:
 * Initializes stream pointers/mode around an already-connected socket.
 */
CNetTCPBuf::CNetTCPBuf(const SOCKET socket) noexcept
  : INetTCPSocket()
  , mSocket(socket)
  , mMode(static_cast<std::uint32_t>(ModeBoth))
  , mFailed(0)
{
  mReadStart = mBuffer;
  mReadHead = mBuffer;
  mReadEnd = mBuffer;

  mWriteStart = mBuffer + kChunkSize;
  mWriteHead = mBuffer + kChunkSize;
  mWriteEnd = mBuffer + kBufferSize;
}

/**
 * Address: 0x00482E20 (FUN_00482E20)
 * Address: 0x1007CBA0 (sub_1007CBA0)
 *
 * What it does:
 * Shared buffered read routine used by blocking/non-blocking variants.
 */
size_t CNetTCPBuf::Read(char* buf, size_t len, const bool isBlocking)
{
  if (mSocket == INVALID_SOCKET) {
    ThrowSocketClosed();
  }

  if (mFailed != 0 || len == 0) {
    return 0;
  }

  size_t bufferedSize = static_cast<size_t>(mReadEnd - mReadHead);
  size_t copiedFromBuffer = 0;

  if (len > bufferedSize) {
    while (true) {
      if (bufferedSize != 0) {
        std::memcpy(buf, mReadHead, bufferedSize);
        buf += bufferedSize;
        len -= bufferedSize;
        copiedFromBuffer += bufferedSize;
      }

      mReadHead = mBuffer;
      mReadEnd = mBuffer;

      if (buf != nullptr) {
        while (len >= kChunkSize) {
          if (!isBlocking) {
            fd_set readFds{};
            readFds.fd_count = 1;
            readFds.fd_array[0] = mSocket;
            timeval timeout{};
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            const int selectRes = select(1, &readFds, nullptr, nullptr, &timeout);
            if (selectRes != SOCKET_ERROR && selectRes <= 0) {
              return copiedFromBuffer;
            }
          }

          const int received = recv(mSocket, buf, static_cast<int>(len), 0);
          if (received == SOCKET_ERROR) {
            gpg::Logf("CNetTCPBuf::Read(): recv() failed: %s", NET_GetWinsockErrorString());
            mFailed = 1;
            return copiedFromBuffer;
          }
          if (received == 0) {
            mFailed = 1;
            return copiedFromBuffer;
          }

          buf += received;
          len -= static_cast<size_t>(received);
          if (len == 0) {
            // Intentionally matches binary behavior (returns copied-from-buffer count only).
            return copiedFromBuffer;
          }

          if (buf == nullptr) {
            break;
          }
        }
      }

      if (!isBlocking && !Select()) {
        return copiedFromBuffer;
      }

      const int received = recv(mSocket, mBuffer, static_cast<int>(kChunkSize), 0);
      if (received < 0) {
        gpg::Logf("CNetTCPBuf::Read(): recv() failed: %s", NET_GetWinsockErrorString());
        mFailed = 1;
        return copiedFromBuffer;
      }
      if (received == 0) {
        mFailed = 1;
        return copiedFromBuffer;
      }

      mReadEnd = mBuffer + received;
      bufferedSize = static_cast<size_t>(mReadEnd - mReadHead);
      if (len <= bufferedSize) {
        std::memcpy(buf, mReadHead, len);
        mReadHead += len;
        return copiedFromBuffer + len;
      }
    }
  }

  std::memcpy(buf, mReadHead, len);
  mReadHead += len;
  return len;
}

/**
 * Address: 0x00483040 (FUN_00483040)
 * Address: 0x1007CDA0 (sub_1007CDA0)
 *
 * What it does:
 * Polls the socket with zero-timeout select for readability.
 */
bool CNetTCPBuf::Select() const
{
  fd_set readFds{};
  readFds.fd_count = 1;
  readFds.fd_array[0] = mSocket;

  timeval timeout{};
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  const int selected = select(1, &readFds, nullptr, nullptr, &timeout);
  return selected == SOCKET_ERROR || selected > 0;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Throws `std::runtime_error("socket closed")`.
 */
void CNetTCPBuf::ThrowSocketClosed() const
{
  throw std::runtime_error("socket closed");
}
