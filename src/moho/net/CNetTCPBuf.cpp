#include "CNetTCPBuf.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "Common.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x004827C0 (FUN_004827C0)
 * Address: 0x00482820 (FUN_00482820, deleting destructor thunk)
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
  if (mSocket == platform::net::kInvalidSocket) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  platform::net::GetLocalAddress(mSocket, &name);
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
  if (mSocket == platform::net::kInvalidSocket) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  platform::net::GetPeerAddress(mSocket, &name);
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
  if (mSocket == platform::net::kInvalidSocket) {
    ThrowSocketClosed();
  }

  sockaddr_in name{};
  platform::net::GetPeerAddress(mSocket, &name);
  return ntohs(name.sin_port);
}

/**
 * Address: 0x00482A90 (FUN_00482A90)
 * Address: 0x1007C840 (sub_1007C840)
 *
 * What it does:
 * Reads bytes using blocking socket behavior.
 */
size_t CNetTCPBuf::VirtRead(
  char* const buff,
  const size_t len
)
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
size_t CNetTCPBuf::VirtReadNonBlocking(
  char* const buf,
  const size_t len
)
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
  if (mSocket == platform::net::kInvalidSocket) {
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
void CNetTCPBuf::VirtWrite(
  const char* data,
  size_t size
)
{
  if (mSocket == platform::net::kInvalidSocket) {
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
      // Raw TCP send-buffer blob copy.
      std::copy_n(data, pendingSpace, writeHead);
      mWriteHead += pendingSpace;
      data += pendingSpace;
      size -= pendingSpace;
    }

    VirtFlush();

    if (size < kChunkSize) {
      // Raw TCP send-buffer blob copy.
      std::copy_n(data, size, mBuffer + kChunkSize);
      mWriteHead = mBuffer + kChunkSize + size;
    } else if (platform::net::Send(mSocket, data, static_cast<int>(size)) == platform::net::kSocketError) {
      gpg::Logf("CNetTCPBuf::Write(): send() failed: %s", NET_GetWinsockErrorString());
    }
  } else {
    // Raw TCP send-buffer blob copy.
    std::copy_n(data, size, writeHead);
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
  if (mSocket == platform::net::kInvalidSocket) {
    ThrowSocketClosed();
  }

  const int pendingSize = static_cast<int>(mWriteHead - mWriteStart);
  if (pendingSize == 0) {
    return;
  }

  if (platform::net::Send(mSocket, mBuffer + kChunkSize, pendingSize) == platform::net::kSocketError) {
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
void CNetTCPBuf::VirtClose(
  const Mode mode
)
{
  if (mSocket == platform::net::kInvalidSocket) {
    return;
  }

  if ((mMode & static_cast<std::uint32_t>(mode) & static_cast<std::uint32_t>(ModeSend)) != 0) {
    VirtFlush();
    platform::net::Shutdown(mSocket, platform::net::ShutdownHow::kSend);
    mMode &= ~static_cast<std::uint32_t>(ModeSend);
    mWriteStart = nullptr;
    mWriteHead = nullptr;
    mWriteEnd = nullptr;
  }

  if ((mMode & static_cast<std::uint32_t>(mode) & static_cast<std::uint32_t>(ModeReceive)) != 0) {
    platform::net::Shutdown(mSocket, platform::net::ShutdownHow::kReceive);
    mMode &= ~static_cast<std::uint32_t>(ModeReceive);
    mReadStart = nullptr;
    mReadHead = nullptr;
    mReadEnd = nullptr;
  }

  if (mMode == static_cast<std::uint32_t>(ModeNone)) {
    platform::net::CloseSocket(mSocket);
    mSocket = platform::net::kInvalidSocket;
  }
}

/**
 * Address: 0x00482770 (FUN_00482770)
 * Address: 0x1007C5C0 (sub_1007C5C0)
 *
 * What it does:
 * Initializes stream pointers/mode around an already-connected socket.
 */
CNetTCPBuf::CNetTCPBuf(
  const platform::net::Socket socket
) noexcept
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
size_t CNetTCPBuf::Read(
  char* buf,
  size_t len,
  const bool isBlocking
)
{
  if (mSocket == platform::net::kInvalidSocket) {
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
        // Raw TCP recv-buffer blob copy.
        std::copy_n(mReadHead, bufferedSize, buf);
        buf += bufferedSize;
        len -= bufferedSize;
        copiedFromBuffer += bufferedSize;
      }

      mReadHead = mBuffer;
      mReadEnd = mBuffer;

      if (buf != nullptr) {
        while (len >= kChunkSize) {
          if (!isBlocking) {
            const int selectRes = platform::net::PollReadable(mSocket);
            if (selectRes != platform::net::kSocketError && selectRes <= 0) {
              return copiedFromBuffer;
            }
          }

          const int received = platform::net::Recv(mSocket, buf, static_cast<int>(len));
          if (received == platform::net::kSocketError) {
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

      const int received = platform::net::Recv(mSocket, mBuffer, static_cast<int>(kChunkSize));
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
        // Raw TCP recv-buffer blob copy.
        std::copy_n(mReadHead, len, buf);
        mReadHead += len;
        return copiedFromBuffer + len;
      }
    }
  }

  // Raw TCP recv-buffer blob copy.
  std::copy_n(mReadHead, len, buf);
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
  const int selected = platform::net::PollReadable(mSocket);
  return selected == platform::net::kSocketError || selected > 0;
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
