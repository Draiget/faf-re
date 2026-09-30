#include "CNetTCPConnector.h"

#include <cstddef>
#include <cstring>
#include <new>

#include "CMessageStream.h"
#include "CNetTCPConnection.h"
#include "Common.h"
#include "ELobbyMsg.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/WeakPtr.h"

using namespace moho;

namespace moho
{
  /**
   * An accepted socket that has not yet said which port its peer listens on.
   * It buffers the stream until the first message -- the peer's local port --
   * decodes, then hands socket and stream to `CNetTCPConnector::ReadFromStream`.
   *
   * The name is the binary's: the constructor is
   * `??0SPartialConnection@Moho@@QAE@@Z` and `Pull` logs as
   * `SPartialConnection<%s:%d>::Pull()`.
   */
  struct SPartialConnection : TDatListItem<SPartialConnection, void>
  {
    CNetTCPConnector* mConnector;
    SOCKET mSocket;
    u_long mAddr;
    u_short mPort;
    std::uint16_t mPad0x16;
    gpg::PipeStream mStream;
    CMessage mMessage;
    // Binary allocates 0xB8 bytes for this object; 0xB4..0xB7 is tail padding.
    std::uint32_t mPad0xB4;

    /**
     * Address: 0x00484660 (FUN_00484660, Moho::SPartialConnection::SPartialConnection)
     */
    SPartialConnection(CNetTCPConnector* connector, const SOCKET socket, const u_long address, const u_short port)
      : TDatListItem<SPartialConnection, void>()
      , mConnector(connector)
      , mSocket(socket)
      , mAddr(address)
      , mPort(port)
      , mPad0x16(0)
      , mStream()
      , mMessage()
    {}

    /**
     * Address: 0x004846E0 (FUN_004846E0)
     * Address: 0x00484980 (FUN_00484980, deleting destructor thunk)
     */
    ~SPartialConnection()
    {
      if (mSocket != INVALID_SOCKET) {
        ::closesocket(mSocket);
        mSocket = INVALID_SOCKET;
      }
    }

    /**
     * Address: 0x00484770 (FUN_00484770)
     *
     * What it does:
     * Receives initial stream bytes and hands completed payload to connector.
     */
    void Pull()
    {
      char buffer[kNetTcpIoChunkSize];

      int received = ::recv(mSocket, buffer, static_cast<int>(sizeof(buffer)), 0);
      while (received >= 0) {
        if (received == 0) {
          gpg::Logf("SPartialConnection<%s:%d>::Pull(): at end of stream.", NET_GetHostName(mAddr).c_str(), mPort);
          delete this;
          return;
        }

        char* const writeHead = mStream.mWriteHead;
        const size_t capacity = static_cast<size_t>(mStream.mWriteEnd - writeHead);
        if (static_cast<size_t>(received) > capacity) {
          mStream.VirtWrite(buffer, static_cast<size_t>(received));
        } else {
          std::memcpy(writeHead, buffer, static_cast<size_t>(received));
          mStream.mWriteHead += received;
        }

        if (mMessage.Read(&mStream)) {
          CMessageStream stream{mMessage};
          u_short port = 0;
          stream.Read(reinterpret_cast<char*>(&port), sizeof(port));

          mConnector->ReadFromStream(mSocket, mAddr, port, mStream);
          mSocket = INVALID_SOCKET;
          delete this;
          return;
        }

        received = ::recv(mSocket, buffer, static_cast<int>(sizeof(buffer)), 0);
      }

      if (::WSAGetLastError() == WSAEWOULDBLOCK) {
        return;
      }

      gpg::Logf(
        "SPartialConnection<%s:%d>::Pull(): recv() failed: %s",
        NET_GetHostName(mAddr).c_str(),
        mPort,
        NET_GetWinsockErrorString()
      );
      delete this;
    }
  };
  static_assert(offsetof(SPartialConnection, mConnector) == 0x08, "SPartialConnection::mConnector must be +0x08");
  static_assert(offsetof(SPartialConnection, mSocket) == 0x0C, "SPartialConnection::mSocket must be +0x0C");
  static_assert(offsetof(SPartialConnection, mAddr) == 0x10, "SPartialConnection::mAddr must be +0x10");
  static_assert(offsetof(SPartialConnection, mPort) == 0x14, "SPartialConnection::mPort must be +0x14");
  static_assert(offsetof(SPartialConnection, mStream) == 0x18, "SPartialConnection::mStream must be +0x18");
  static_assert(offsetof(SPartialConnection, mMessage) == 0x60, "SPartialConnection::mMessage must be +0x60");
  static_assert(offsetof(SPartialConnection, mPad0xB4) == 0xB4, "SPartialConnection::mPad0xB4 must be +0xB4");
  static_assert(sizeof(SPartialConnection) == 0xB8, "SPartialConnection size must be 0xB8");
} // namespace moho

/**
 * Address: 0x00484B40 (FUN_00484B40)
 * Address: 0x00484AE0 (FUN_00484AE0, scalar deleting destructor)
 * Address: 0x1007E6E0 (sub_1007E6E0)
 *
 * What it does:
 * Deletes every connection -- each unlinks itself from `mConnections` as it
 * goes -- and closes the listening socket. Partial connections are left
 * alone: the binary never deletes them here, and `mPartials`' own destructor
 * (0x00484BA8) only unlinks the head from their ring. `mConnections`
 * unlinks in its destructor at 0x00484BC1.
 *
 * The weak-reference detach at 0x00484BD5 runs after both of those member
 * destructors: it is the `WeakObject` base's destructor. Any `Pull` frame still
 * on the stack sees its `WeakPtr<CNetTCPConnector>` go null.
 */
CNetTCPConnector::~CNetTCPConnector()
{
  while (!mConnections.empty()) {
    delete mConnections.front();
  }

  if (mSocket != INVALID_SOCKET) {
    ::closesocket(mSocket);
  }
}

/**
 * Address: 0x00483600 (FUN_00483600)
 * Address: 0x1007D3F0 (sub_1007D3F0)
 *
 * What it does:
 * Self-destruct helper (equivalent to deleting this connector).
 */
void CNetTCPConnector::Destroy()
{
  delete this;
}

/**
 * Address: 0x00483610 (FUN_00483610)
 * Address: 0x1007D400 (sub_1007D400)
 *
 * What it does:
 * Returns TCP protocol tag.
 */
ENetProtocolType CNetTCPConnector::GetProtocol()
{
  return ENetProtocolType::kTcp;
}

/**
 * Address: 0x00484C20 (FUN_00484C20)
 * Address: 0x1007E820 (sub_1007E820)
 *
 * What it does:
 * Returns local listening port.
 */
u_short CNetTCPConnector::GetLocalPort()
{
  sockaddr_in name{};
  int nameLen = static_cast<int>(sizeof(name));
  ::getsockname(mSocket, reinterpret_cast<sockaddr*>(&name), &nameLen);
  return ::ntohs(name.sin_port);
}

/**
 * Address: 0x00484C50 (FUN_00484C50)
 * Address: 0x1007E850 (sub_1007E850)
 *
 * What it does:
 * Creates an outbound non-blocking TCP connection object.
 */
INetConnection* CNetTCPConnector::Connect(const u_long address, const u_short port)
{
  const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == INVALID_SOCKET) {
    gpg::Logf(
      "CNetTCPConnector::Connect(%s:%d): socket() failed: %s",
      NET_GetHostName(address).c_str(),
      port,
      NET_GetWinsockErrorString()
    );
    return nullptr;
  }

  u_long arg = 1;
  if (::ioctlsocket(socket, FIONBIO, &arg) == SOCKET_ERROR) {
    gpg::Logf(
      "CNetTCPConnector::Connect(%s:%d): ioctlsocket(FIONBIO) failed: %s",
      NET_GetHostName(address).c_str(),
      port,
      NET_GetWinsockErrorString()
    );
    ::closesocket(socket);
    return nullptr;
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = ::htons(port);
  name.sin_addr.s_addr = ::htonl(address);
  if (::connect(socket, reinterpret_cast<const sockaddr*>(&name), static_cast<int>(sizeof(name))) == SOCKET_ERROR &&
      ::WSAGetLastError() != WSAEWOULDBLOCK) {
    gpg::Logf(
      "CNetTCPConnector::Connect(%s:%d): connect() failed: %s",
      NET_GetHostName(address).c_str(),
      port,
      NET_GetWinsockErrorString()
    );
    ::closesocket(socket);
    return nullptr;
  }

  gpg::Logf("CNetTCPConnector::Connect(%s:%d)...", NET_GetHostName(address).c_str(), port);

  auto* const connection = new (std::nothrow) CNetTCPConnection(this, socket, address, port, kNetStateConnecting);
  if (!connection) {
    // FA/Moho behavior: allocation failure returns null without closing opened socket.
    return nullptr;
  }
  return connection;
}

/**
 * Address: 0x00484EA0 (FUN_00484EA0)
 * Address: 0x1007EA80 (sub_1007EA80)
 *
 * What it does:
 * Finds next pending remote endpoint awaiting accept.
 */
bool CNetTCPConnector::FindNextAddress(u_long& outAddress, u_short& outPort)
{
  for (CNetTCPConnection* const connection : mConnections) {
    if (connection->mState == kNetStatePending) {
      outAddress = connection->GetAddr();
      outPort = connection->GetPort();
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x00484F00 (FUN_00484F00)
 * Address: 0x1007EAE0 (sub_1007EAE0)
 *
 * What it does:
 * Accepts endpoint into active connection list or creates placeholder.
 */
INetConnection* CNetTCPConnector::Accept(const u_long address, const u_short port)
{
  gpg::Logf("CNetTCPConnector::Accept(%s:%d)", NET_GetHostName(address).c_str(), port);

  for (CNetTCPConnection* const connection : mConnections) {
    if (connection->GetAddr() == address && connection->GetPort() == port && connection->mState == kNetStatePending) {
      connection->mState = kNetStateEstablishing;
      return connection;
    }
  }

  return new (std::nothrow) CNetTCPConnection(this, INVALID_SOCKET, address, port, kNetStateAnswering);
}

/**
 * Address: 0x00485050 (FUN_00485050)
 * Address: 0x1007EC20 (sub_1007EC20)
 *
 * What it does:
 * Rejects endpoint pending connection.
 */
void CNetTCPConnector::Reject(const u_long address, const u_short port)
{
  gpg::Logf("CNetTCPConnector::Reject(%s:%d)", NET_GetHostName(address).c_str(), port);

  for (CNetTCPConnection* const connection : mConnections) {
    if (connection->GetAddr() == address && connection->GetPort() == port && connection->mState == kNetStatePending) {
      connection->ScheduleDestroy();
      return;
    }
  }

  gpg::Warnf("CNetTCPConnector::Reject(%s:%d): No such connection pending.", NET_GetHostName(address).c_str(), port);
}

/**
 * Address: 0x00485190 (FUN_00485190)
 * Address: 0x1007ED50 (sub_1007ED50)
 *
 * What it does:
 * Polls listener/partials/connections and advances TCP handshake/data flow.
 */
void CNetTCPConnector::Pull()
{
  sockaddr_in address{};
  int addressLen = static_cast<int>(sizeof(address));
  const SOCKET accepted = ::accept(mSocket, reinterpret_cast<sockaddr*>(&address), &addressLen);
  if (accepted == INVALID_SOCKET) {
    if (::WSAGetLastError() != WSAEWOULDBLOCK) {
      gpg::Logf("CNetTCPConnector::Pull: accept() failed: %s", NET_GetWinsockErrorString());
    }
  } else {
    const u_long hostAddress = ::ntohl(address.sin_addr.s_addr);
    const u_short hostPort = ::ntohs(address.sin_port);
    gpg::Logf(
      "CNetTCPConnector::Pull(): accepted connection from %s:%d", NET_GetHostName(hostAddress).c_str(), hostPort
    );

    // 0x004852B3 splices the node in ahead of the head, so a new partial is
    // pulled last.
    mPartials.push_back(new SPartialConnection(this, accepted, hostAddress, hostPort));
  }

  // A connection's message handlers may destroy this connector (and with it
  // every connection); the weak reference going null is how the loop learns.
  const WeakPtr<CNetTCPConnector> self{this};

  for (SPartialConnection* const partial : mPartials.owners_safe()) {
    partial->Pull();
  }

  for (CNetTCPConnection* const connection : mConnections.owners_safe()) {
    connection->Pull();
    if (self.GetObjectPtr() == nullptr) {
      return;
    }
  }
}

/**
 * Address: 0x00485610 (FUN_00485610)
 * Address: 0x1007F140 (sub_1007F140)
 *
 * What it does:
 * Flushes all TCP connection outbound queues.
 */
void CNetTCPConnector::Push()
{
  for (auto* current : mConnections.owners_safe()) {
    current->Push();
  }
}

/**
 * Address: 0x00485640 (FUN_00485640)
 * Address: 0x1007F170 (sub_1007F170)
 *
 * What it does:
 * Redirects socket network events to supplied event handle.
 */
void CNetTCPConnector::SelectEvent(const HANDLE ev)
{
  ::WSAEventSelect(mSocket, ev, FD_ACCEPT);

  for (CNetTCPConnection* const connection : mConnections) {
    ::WSAEventSelect(connection->mSocket, ev, FD_READ | FD_CONNECT | FD_CLOSE);
  }
}

/**
 * Address: 0x004835F0 (FUN_004835F0)
 *
 * What it does:
 * Returns currently selected socket-event handle for this connector.
 */
HANDLE CNetTCPConnector::GetSelectedEventHandle() const noexcept
{
  return mHandle;
}

/**
 * Address: 0x00483620 (FUN_00483620)
 * Address: 0x1007D410 (sub_1007D410)
 *
 * What it does:
 * Returns empty stamp snapshot for legacy TCP path.
 */
SSendStampView CNetTCPConnector::SnapshotSendStamps(const int32_t /*since*/)
{
  return SSendStampView{0, 0};
}

/**
 * Address: 0x00484AB0 (FUN_00484AB0)
 *
 * What it does:
 * Initializes TCP connector around already-open listening socket.
 */
CNetTCPConnector::CNetTCPConnector(const SOCKET socket) noexcept
  : INetConnector()
  , WeakObject() // 0x00484AB2: the weak-reference head is zeroed first
  , mSocket(socket)
  , mConnections()
  , mPartials()
  , mHandle(nullptr)
{}

/**
 * Address: 0x004853D0 (FUN_004853D0)
 *
 * What it does:
 * Takes over a partial connection's socket and buffered stream: an answering
 * connection for the same endpoint adopts the socket and starts
 * establishing, otherwise a new pending connection is made for it. The
 * connection's input then gets a `LOBMSG_ConnMade` followed by everything the
 * partial had buffered.
 */
void CNetTCPConnector::ReadFromStream(
  const SOCKET socket, const u_long address, const u_short port, gpg::PipeStream& stream
)
{
  CNetTCPConnection* connection = nullptr;
  for (CNetTCPConnection* const current : mConnections) {
    if (current->GetAddr() == address && current->GetPort() == port && current->mState == kNetStateAnswering) {
      connection = current;
      connection->AdoptSocketAndSetEstablishing(socket);
      break;
    }
  }

  if (!connection) {
    connection = new CNetTCPConnection(this, socket, address, port, kNetStatePending);
  }

  CMessage connMade{ELobbyMsg::LOBMSG_ConnMade};
  connection->mInputStream.Write(connMade.mBuff);

  stream.Close(gpg::Stream::ModeSend);
  char buffer[kNetTcpIoChunkSize];
  while (!stream.Empty()) {
    const size_t count = stream.Read(buffer, sizeof(buffer));
    connection->mInputStream.Write(buffer, count);
  }
}
