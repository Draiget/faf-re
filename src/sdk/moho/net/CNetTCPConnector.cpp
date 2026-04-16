#include "CNetTCPConnector.h"

#include <cstddef>
#include <cstring>
#include <new>

#include "CMessageStream.h"
#include "CNetTCPConnection.h"
#include "Common.h"
#include "ELobbyMsg.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

namespace moho
{
  /**
    * Alias of FUN_00484660 (non-canonical helper lane).
   *
   * What it does:
   * Tracks an accepted socket until first TCP connect payload is decoded.
   */
  struct STcpPartialConnection : TDatListItem<STcpPartialConnection, void>
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
    STcpPartialConnection(CNetTCPConnector* connector, const SOCKET socket, const u_long address, const u_short port)
      : TDatListItem<STcpPartialConnection, void>()
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
    ~STcpPartialConnection()
    {
      if (mSocket != INVALID_SOCKET) {
        ::closesocket(mSocket);
        mSocket = INVALID_SOCKET;
      }
      ListUnlink();
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
  static_assert(offsetof(STcpPartialConnection, mConnector) == 0x08, "STcpPartialConnection::mConnector must be +0x08");
  static_assert(offsetof(STcpPartialConnection, mSocket) == 0x0C, "STcpPartialConnection::mSocket must be +0x0C");
  static_assert(offsetof(STcpPartialConnection, mAddr) == 0x10, "STcpPartialConnection::mAddr must be +0x10");
  static_assert(offsetof(STcpPartialConnection, mPort) == 0x14, "STcpPartialConnection::mPort must be +0x14");
  static_assert(offsetof(STcpPartialConnection, mStream) == 0x18, "STcpPartialConnection::mStream must be +0x18");
  static_assert(offsetof(STcpPartialConnection, mMessage) == 0x60, "STcpPartialConnection::mMessage must be +0x60");
  static_assert(offsetof(STcpPartialConnection, mPad0xB4) == 0xB4, "STcpPartialConnection::mPad0xB4 must be +0xB4");
  static_assert(sizeof(STcpPartialConnection) == 0xB8, "STcpPartialConnection size must be 0xB8");

  /**
   * Active per-call work-link node shape used by `CNetTCPConnection::Pull`
   * and `CNetTCPConnector::Pull` while connected into `mWorkingList`.
   */
  struct STcpConnWorkFrame
  {
    STcpConnWorkList* owner{nullptr};
    STcpConnWorkFrame* next{nullptr};
  };
  static_assert(sizeof(STcpConnWorkFrame) == 0x8, "STcpConnWorkFrame size must be 0x8");

  STcpConnWorkFrame* AsWorkFrame(STcpConnWorkList* const link) noexcept
  {
    return reinterpret_cast<STcpConnWorkFrame*>(link);
  }

  STcpConnWorkList* AsWorkListLink(STcpConnWorkFrame* const frame) noexcept
  {
    return reinterpret_cast<STcpConnWorkList*>(frame);
  }

  /**
   * Address: 0x00485830 (FUN_00485830)
   *
   * What it does:
   * Reports whether a pull work frame is still linked to a live connector
   * owner chain.
   */
  bool HasLinkedOwner(const STcpConnWorkFrame& frame) noexcept
  {
    return frame.owner != nullptr;
  }

  /**
   * Address: 0x00485810 (FUN_00485810, helper inside connector pull flow)
   *
   * What it does:
   * Registers an in-flight stack frame in connector work-chain to allow
   * asynchronous cleanup code to null out active frames safely.
   */
  void LinkWorkFrame(STcpConnWorkList& owner, STcpConnWorkFrame& frame) noexcept
  {
    frame.owner = &owner;
    frame.next = AsWorkFrame(owner.next);
    owner.next = AsWorkListLink(&frame);
  }

  /**
    * Alias of FUN_00485810 (non-canonical helper lane).
   *
   * What it does:
   * Unlinks an in-flight frame from connector work-chain if still active.
   */
  void UnlinkWorkFrame(STcpConnWorkFrame& frame) noexcept
  {
    STcpConnWorkList* const owner = frame.owner;
    if (!owner) {
      return;
    }

    STcpConnWorkFrame* prev = nullptr;
    STcpConnWorkFrame* cur = AsWorkFrame(owner->next);
    while (cur) {
      if (cur == &frame) {
        if (prev) {
          prev->next = cur->next;
        } else {
          owner->next = AsWorkListLink(cur->next);
        }
        frame.owner = nullptr;
        frame.next = nullptr;
        return;
      }
      prev = cur;
      cur = cur->next;
    }

    frame.owner = nullptr;
    frame.next = nullptr;
  }

  class ScopedTcpWorkFrame
  {
  public:
    explicit ScopedTcpWorkFrame(STcpConnWorkList& owner) noexcept
    {
      LinkWorkFrame(owner, mFrame);
    }

    ~ScopedTcpWorkFrame()
    {
      UnlinkWorkFrame(mFrame);
    }

    [[nodiscard]] bool IsAlive() const noexcept
    {
      return HasLinkedOwner(mFrame);
    }

  private:
    STcpConnWorkFrame mFrame{};
  };

  /**
   * Address: 0x00484B00 (FUN_00484B00)
   *
   * What it does:
   * Unlinks the partial-list head from any current neighbors and resets it
   * to a self-linked empty intrusive list sentinel.
   */
  void ResetPartialListHead(TDatListItem<STcpPartialConnection, void>* const head)
  {
    head->ListUnlink();
  }

  /**
   * Address: 0x00484B20 (FUN_00484B20)
   *
   * What it does:
   * Unlinks the connection-list head from any current neighbors and resets it
   * to a self-linked empty intrusive list sentinel.
   */
  void ResetConnectionListHead(TDatListItem<CNetTCPConnection, void>* const head)
  {
    head->ListUnlink();
  }
} // namespace moho

/**
 * Address: 0x00484AE0 (FUN_00484AE0)
 * Address: 0x1007E6E0 (sub_1007E6E0)
 *
 * What it does:
 * Deletes all TCP connections/partials and closes listening socket.
 */
CNetTCPConnector::~CNetTCPConnector()
{
  CleanupConnectionsAndPartials();
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
  for (auto* node = mConnections.mNext; node != &mConnections; node = node->mNext) {
    auto* const connection = static_cast<CNetTCPConnection*>(node);
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

  for (auto* node = mConnections.mNext; node != &mConnections; node = node->mNext) {
    auto* const connection = static_cast<CNetTCPConnection*>(node);
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

  for (auto* node = mConnections.mNext; node != &mConnections; node = node->mNext) {
    auto* const connection = static_cast<CNetTCPConnection*>(node);
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

    auto* const partial = new (std::nothrow) STcpPartialConnection(this, accepted, hostAddress, hostPort);
    if (partial) {
      mPartials.push_front(partial);
    } else {
      ::closesocket(accepted);
    }
  }

  ScopedTcpWorkFrame workFrame{mWorkingList};

  auto* const partialHead = static_cast<TDatListItem<STcpPartialConnection, void>*>(&mPartials);
  for (auto* node = partialHead->mNext; node != partialHead;) {
    auto* const current = static_cast<STcpPartialConnection*>(node);
    node = node->mNext;
    current->Pull();
  }

  auto* const connectionHead = static_cast<TDatListItem<CNetTCPConnection, void>*>(&mConnections);
  for (auto* node = connectionHead->mNext; node != connectionHead;) {
    auto* const current = static_cast<CNetTCPConnection*>(node);
    node = node->mNext;
    current->Pull();
    if (!workFrame.IsAlive()) {
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

  for (auto* node = mConnections.mNext; node != &mConnections; node = node->mNext) {
    auto* const connection = static_cast<CNetTCPConnection*>(node);
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
  : mWorkingList{nullptr}
  , mSocket(socket)
  , mConnections()
  , mPartials()
  , mHandle(nullptr)
{}

/**
 * Address: 0x004853D0 (FUN_004853D0)
 *
 * What it does:
 * Binds accepted partial socket stream to a TCP connection.
 */
void CNetTCPConnector::ReadFromStream(
  const SOCKET socket, const u_long address, const u_short port, gpg::PipeStream& stream
)
{
  CNetTCPConnection* connection = nullptr;
  for (auto* node = mConnections.mNext; node != &mConnections; node = node->mNext) {
    auto* const current = static_cast<CNetTCPConnection*>(node);
    if (current->GetAddr() == address && current->GetPort() == port && current->mState == kNetStateAnswering) {
      connection = current;
      connection->AdoptSocketAndSetEstablishing(socket);
      break;
    }
  }

  if (!connection) {
    connection = new (std::nothrow) CNetTCPConnection(this, socket, address, port, kNetStatePending);
    if (!connection) {
      ::closesocket(socket);
      return;
    }
  }
  connection->AdoptIncomingStream(socket, stream);
}

/**
 * Address: 0x00484B40 (FUN_00484B40)
 *
 * What it does:
 * Runs connector cleanup body: deletes connection objects, closes listener,
 * resets intrusive heads, and clears active work-link frames.
 */
void CNetTCPConnector::CleanupConnectionsAndPartials()
{
  while (!mConnections.empty()) {
    auto* const node = mConnections.pop_front();
    delete static_cast<CNetTCPConnection*>(node);
  }

  if (mSocket != INVALID_SOCKET) {
    ::closesocket(mSocket);
    mSocket = INVALID_SOCKET;
  }

  auto* const partialHead = static_cast<TDatListItem<STcpPartialConnection, void>*>(&mPartials);
  auto* const connectionHead = static_cast<TDatListItem<CNetTCPConnection, void>*>(&mConnections);
  ResetPartialListHead(partialHead);
  ResetConnectionListHead(connectionHead);

  auto* work = reinterpret_cast<STcpConnWorkFrame*>(mWorkingList.next);
  while (work != nullptr) {
    auto* const next = work->next;
    mWorkingList.next = reinterpret_cast<STcpConnWorkList*>(next);
    work->owner = nullptr;
    work->next = nullptr;
    work = next;
  }
}
