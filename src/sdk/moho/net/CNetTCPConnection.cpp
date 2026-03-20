#include "CNetTCPConnection.h"

#include <cstring>

#include "CNetTCPConnector.h"
#include "Common.h"
#include "ELobbyMsg.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x004835B0 (FUN_004835B0)
 * Address: 0x1007D3A0 (sub_1007D3A0)
 *
 * What it does:
 * Returns remote IPv4 address in host byte order.
 */
u_long CNetTCPConnection::GetAddr()
{
  return mAddr;
}

/**
 * Address: 0x004835C0 (FUN_004835C0)
 * Address: 0x1007D3B0 (sub_1007D3B0)
 *
 * What it does:
 * Returns remote TCP port in host byte order.
 */
u_short CNetTCPConnection::GetPort()
{
  return mPort;
}

/**
 * Address: 0x004835D0 (FUN_004835D0)
 * Address: 0x1007D3C0 (sub_1007D3C0)
 *
 * What it does:
 * Returns fixed placeholder ping value used by legacy TCP path.
 */
float CNetTCPConnection::GetPing()
{
  return 100.0f;
}

/**
 * Address: 0x00484520 (FUN_00484520)
 * Address: 0x1007E190 (sub_1007E190)
 *
 * What it does:
 * Returns elapsed time in milliseconds since last timer reset.
 */
float CNetTCPConnection::GetTime()
{
  return gpg::time::CyclesToMilliseconds(mTimer.ElapsedCycles());
}

/**
 * Address: 0x00484540 (FUN_00484540)
 * Address: 0x1007E1A0 (sub_1007E1A0)
 *
 * What it does:
 * Queues span bytes into outbound pipe stream.
 */
void CNetTCPConnection::Write(NetDataSpan* const data)
{
  const auto* const begin = reinterpret_cast<const char*>(data->start);
  const size_t size = static_cast<size_t>(data->end - data->start);

  char* const writeHead = mOutputStream.mWriteHead;
  const size_t capacity = static_cast<size_t>(mOutputStream.mWriteEnd - writeHead);
  if (size > capacity) {
    mOutputStream.VirtWrite(begin, size);
    return;
  }

  if (size != 0) {
    std::memcpy(writeHead, begin, size);
    mOutputStream.mWriteHead += size;
  }
}

/**
 * Address: 0x00484590 (FUN_00484590)
 * Address: 0x1007E1C0 (sub_1007E1C0)
 *
 * What it does:
 * Closes outbound direction for this connection.
 */
void CNetTCPConnection::Close()
{
  mOutputStream.Close(gpg::Stream::ModeSend);
}

/**
 * Address: 0x004845B0 (FUN_004845B0)
 * Address: 0x1007E1D0 (sub_1007E1D0)
 *
 * What it does:
 * Returns "host:port" textual identity for logs/debug.
 */
msvc8::string CNetTCPConnection::ToString()
{
  const auto host = NET_GetHostName(mAddr);
  return gpg::STR_Printf("%s:%d", host.c_str(), mPort);
}

/**
 * Address: 0x004835E0 (FUN_004835E0)
 * Address: 0x1007D3D0 (sub_1007D3D0)
 *
 * What it does:
 * Marks connection for deferred destroy.
 */
void CNetTCPConnection::ScheduleDestroy()
{
  mScheduleDestroy = 1;
}

/**
 * Address: 0x00483650 (FUN_00483650)
 *
 * What it does:
 * Initializes TCP connection object and links it into connector list.
 */
CNetTCPConnection::CNetTCPConnection(
  CNetTCPConnector* const connector,
  const SOCKET socket,
  const u_long address,
  const u_short port,
  const ENetConnectionState state
)
  : INetConnection()
  , TDatListItem<CNetTCPConnection, void>()
  , mConnector(connector)
  , mSocket(socket)
  , mAddr(address)
  , mPort(port)
  , mPad0x426(0)
  , mState(state)
  , mPad0x42C(0)
  , mTimer()
  , mInputStream()
  , mOutputStream()
  , mSendBuffer{}
  , mSendBufferSize(0)
  , mHasShutdownOutput(0)
  , mPad0xCCD{}
  , mDatagram()
  , mPad0xD24(0)
  , mPushFailed(0)
  , mPullFailed(0)
  , mScheduleDestroy(0)
  , mPad0xD2B{}
{
  std::memset(mReceivers, 0, sizeof(mReceivers));

  if (mConnector) {
    mConnector->mConnections.push_back(this);
    if (mConnector->mHandle) {
      ::WSAEventSelect(mSocket, mConnector->mHandle, FD_READ | FD_CONNECT | FD_CLOSE);
    }
  }
}

/**
 * Address: 0x004837E0 (FUN_004837E0)
 *
 * What it does:
 * Closes socket/streams and unlinks from connector intrusive list.
 */
CNetTCPConnection::~CNetTCPConnection()
{
  auto* const dispatchHead =
    static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(static_cast<CMessageDispatcher*>(this));
  while (dispatchHead->mNext != dispatchHead) {
    auto* const linkage = static_cast<SMsgReceiverLinkage*>(dispatchHead->mNext);
    RemoveLinkage(linkage);
  }

  if (mSocket != INVALID_SOCKET) {
    ::closesocket(mSocket);
    mSocket = INVALID_SOCKET;
  }

  TDatListItem<CNetTCPConnection, void>::ListUnlink();
}

/**
 * Address: 0x00483A60 (FUN_00483A60)
 *
 * What it does:
 * Polls socket input/connect state and dispatches buffered messages.
 */
void CNetTCPConnection::Pull()
{
  if (mScheduleDestroy) {
    delete this;
    return;
  }

  if (mState == kNetStateConnecting) {
    fd_set writeFds{};
    writeFds.fd_count = 1;
    writeFds.fd_array[0] = mSocket;

    fd_set exceptFds = writeFds;
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    const int selected = ::select(0, nullptr, &writeFds, &exceptFds, &timeout);
    if (selected > 0) {
      if (FD_ISSET(mSocket, &writeFds)) {
        gpg::Logf("CNetTCPConnection<%s:%d>::Pull(): connection succeeded", NET_GetHostName(mAddr).c_str(), mPort);
        mState = kNetStateEstablishing;
        CMessage connMade{ELobbyMsg::LOBMSG_ConnMade};
        mInputStream.Write(connMade.mBuff.start_, connMade.mBuff.Size());
      } else if (FD_ISSET(mSocket, &exceptFds)) {
        gpg::Logf("CNetTCPConnection<%s:%d>::Pull(): connection failed", NET_GetHostName(mAddr).c_str(), mPort);
        mState = kNetStateErrored;
        CMessage connFailed{ELobbyMsg::LOBMSG_ConnFailed};
        Dispatch(&connFailed);
      }
    }
  }

  if (mState != kNetStateEstablishing) {
    return;
  }

  char recvBuf[kNetTcpIoChunkSize];
  while (!mPullFailed) {
    const int received = ::recv(mSocket, recvBuf, static_cast<int>(sizeof(recvBuf)), 0);
    if (received < 0) {
      if (::WSAGetLastError() == WSAEWOULDBLOCK) {
        break;
      }

      gpg::Logf(
        "CNetTCPConnection<%s:%d>::Pull(): recv() failed: %s",
        NET_GetHostName(mAddr).c_str(),
        mPort,
        NET_GetWinsockErrorString()
      );
      mInputStream.Close(gpg::Stream::ModeSend);
      mPullFailed = 1;
      break;
    }

    mTimer.Reset();
    if (received == 0) {
      gpg::Logf("CNetTCPConnection<%s:%d>::Pull(): at end of stream.", NET_GetHostName(mAddr).c_str(), mPort);
      mInputStream.Close(gpg::Stream::ModeSend);
      mPullFailed = 1;
      break;
    }

    mInputStream.Write(recvBuf, static_cast<size_t>(received));
  }

  while (mDatagram.Read(&mInputStream)) {
    auto* const receiver = mReceivers[mDatagram.GetType().raw()];
    if (receiver) {
      receiver->ReceiveMessage(&mDatagram, this);
    } else {
      gpg::Logf(
        "No receiver for message type %d received from %s:%d.",
        mDatagram.GetType().raw(),
        NET_GetHostName(mAddr).c_str(),
        mPort
      );
    }
    mDatagram.Clear();
  }

  if (mPullFailed && mState != kNetStateErrored) {
    mState = kNetStateTimedOut;
    CMessage msg{ELobbyMsg::LOBMSG_ConnLostEof};
    Dispatch(&msg);
  }

  if (mPushFailed && mState != kNetStateErrored) {
    mState = kNetStateErrored;
    CMessage msg{ELobbyMsg::LOBMSG_ConnLostErrored};
    Dispatch(&msg);
  }
}

/**
 * Address: 0x004838D0 (FUN_004838D0)
 *
 * What it does:
 * Flushes outbound stream bytes to socket and handles send-side shutdown.
 */
void CNetTCPConnection::Push()
{
  if (mScheduleDestroy) {
    delete this;
    return;
  }

  if (mHasShutdownOutput || mPushFailed) {
    return;
  }
  if (mState != kNetStateEstablishing && mState != kNetStateTimedOut) {
    return;
  }

  while (true) {
    if (mSendBufferSize < sizeof(mSendBuffer)) {
      const size_t available = mOutputStream.GetLength();
      if (available != 0) {
        size_t chunk = sizeof(mSendBuffer) - mSendBufferSize;
        if (chunk > available) {
          chunk = available;
        }

        char* const dst = mSendBuffer + mSendBufferSize;
        const size_t readable = static_cast<size_t>(mOutputStream.mReadEnd - mOutputStream.mReadHead);
        if (chunk > readable) {
          mOutputStream.VirtRead(dst, chunk);
        } else if (chunk != 0) {
          std::memcpy(dst, mOutputStream.mReadHead, chunk);
          mOutputStream.mReadHead += chunk;
        }
        mSendBufferSize += static_cast<std::uint32_t>(chunk);
      }
    }

    if (mSendBufferSize == 0) {
      if (mOutputStream.Empty()) {
        ::shutdown(mSocket, SD_SEND);
        mHasShutdownOutput = 1;
      }
      return;
    }

    const int sent = ::send(mSocket, mSendBuffer, static_cast<int>(mSendBufferSize), 0);
    if (sent < 0) {
      if (::WSAGetLastError() == WSAEWOULDBLOCK) {
        return;
      }

      gpg::Logf("CNetTCPConnection::Push: send() failed: %s", NET_GetWinsockErrorString());
      mPushFailed = 1;
      if (mConnector && mConnector->mHandle) {
        ::SetEvent(mConnector->mHandle);
      }
      return;
    }

    if (static_cast<std::uint32_t>(sent) < mSendBufferSize) {
      std::memmove(mSendBuffer, mSendBuffer + sent, mSendBufferSize - static_cast<std::uint32_t>(sent));
    }
    mSendBufferSize -= static_cast<std::uint32_t>(sent);
  }
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Attaches accepted socket stream payload to this connection.
 */
void CNetTCPConnection::AdoptIncomingStream(const SOCKET socket, gpg::PipeStream& stream)
{
  mSocket = socket;

  CMessage connMade{ELobbyMsg::LOBMSG_ConnMade};
  mInputStream.Write(connMade.mBuff.start_, connMade.mBuff.Size());

  stream.Close(gpg::Stream::ModeSend);
  char temp[kNetTcpIoChunkSize];
  while (true) {
    if (stream.mReadHead == stream.mReadEnd && stream.VirtAtEnd()) {
      break;
    }

    size_t chunk = kNetTcpIoChunkSize;
    const size_t readable = static_cast<size_t>(stream.mReadEnd - stream.mReadHead);
    if (readable < chunk) {
      chunk = stream.VirtRead(temp, chunk);
    } else {
      std::memcpy(temp, stream.mReadHead, chunk);
      stream.mReadHead += chunk;
    }
    mInputStream.Write(temp, chunk);
  }
}
