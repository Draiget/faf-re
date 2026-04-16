#include "CNetUDPConnector.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <new>

#include "boost/thread.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "INetNATTraversalProvider.h"
#include "moho/containers/TDatList.h"
#include "moho/core/Thread.h"
#include "NetConVars.h"
using namespace moho;

namespace
{
  /**
   * Address: 0x00481D70 (FUN_00481D70, func_NatTravProvPtr)
   *
   * What it does:
   * Copies NAT traversal provider weak pointer only when the provider still has
   * a live strong-reference count.
   */
  boost::weak_ptr<INetNATTraversalProvider>
  CopyLiveNatTraversalProviderWeakPtr(const boost::weak_ptr<INetNATTraversalProvider>& provider)
  {
    if (provider.expired()) {
      return boost::weak_ptr<INetNATTraversalProvider>{};
    }
    return provider;
  }
} // namespace

/**
 * Address: 0x00485CA0 (FUN_00485CA0)
 * Address: 0x1007F750 (sub_1007F750)
 *
 * What it does:
 * Returns UDP transport protocol tag for this connector implementation.
 */
ENetProtocolType CNetUDPConnector::GetProtocol()
{
  return ENetProtocolType::kUdp;
}

/**
 * Address: 0x00485C10 (FUN_00485C10)
 *
 * What it does:
 * Signals this connector's socket wake event.
 */
bool CNetUDPConnector::SignalSocketEvent() noexcept
{
#if defined(_WIN32)
  return ::WSASetEvent(event_) != FALSE;
#else
  return false;
#endif
}

/**
 * Address: 0x00485C20 (FUN_00485C20)
 *
 * What it does:
 * Relinks a connection's intrusive node to the front of connector list.
 */
CNetUDPConnection& CNetUDPConnector::RelinkConnectionToFront(CNetUDPConnection& connection) noexcept
{
  auto* const connectionNode = static_cast<TDatListItem<CNetUDPConnection, void>*>(&connection);
  auto* const listHead = static_cast<TDatListItem<CNetUDPConnection, void>*>(&mConnections);
  connectionNode->moho::TDatListItem<CNetUDPConnection, void>::ListLinkAfter(listHead);
  return connection;
}

/**
 * Address: 0x004899E0 (FUN_004899E0, deleting wrapper)
 * Address: 0x00489BC0 (FUN_00489BC0)
 * Address: 0x10083420 (sub_10083420, deleting wrapper)
 * Address: 0x10083600 (sub_10083600, non-deleting destructor)
 *
 * What it does:
 * Releases connector-owned queues, packet pool, diagnostics stream, and
 * network/socket resources.
 */
CNetUDPConnector::~CNetUDPConnector()
{
  // Drain packet free-list.
  while (mPacketList.mNext != &mPacketList) {
    if (auto* n = mPacketList.mNext) {
      // Unlink from intrusive list and free
      delete n->ListUnlink();
    }
  }

#if defined(_WIN32)
  if (socket_ != INVALID_SOCKET)
    closesocket(socket_);
#endif

  if (mPacketLogFile) {
    fclose(mPacketLogFile);
  }

  // SendStamp buffer cleanup (original sub_47D990)
  mSendStampBuffer.Reset();

  // Clear receive queues (original sub_48C580 on both)
  mInboundTraversalPackets.clear();
  mOutboundPackets.clear();

  // Normalize intrusive lists (both to self-sentinel)
  mPacketList.ListUnlink();
  mConnections.ListUnlink();

  // Release weak_ptr to NAT traversal provider
  mNatTraversalProvider.reset();
}

/**
 * Address: 0x004896F0 (FUN_004896F0)
 *
 * What it does:
 * Initializes UDP connector runtime state, arms socket events, starts worker
 * thread (`Entry`), and registers NAT traversal handler with provider.
 */
CNetUDPConnector::CNetUDPConnector(SOCKET sock, boost::weak_ptr<INetNATTraversalProvider>& prov)
  : lock_{}
  , socket_{sock}
  , event_{::WSACreateEvent()}
  , mNatTraversalProvider{prov}
  , mConnections{}
  , mPacketList{}
  , mPacketPoolSize{0}
  , mTimeBaseUs{0}
  , mTimer{}
  , mCurrentTimeUs{0}
  , mClosed{false}
  , mIsPulling{false}
  , mOutboundPackets{}
  , mInboundTraversalPackets{}
  , mSelectedEvent{nullptr}
  , mSendStampBuffer{}
  , mPacketLogFile{nullptr}
  , mTailPadding{0}
{
  FILETIME systemTime{};
  ::GetSystemTimeAsFileTime(&systemTime);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = systemTime.dwLowDateTime;
  ticks.HighPart = systemTime.dwHighDateTime;
  mTimeBaseUs = static_cast<int64_t>(ticks.QuadPart / 10ULL);

  // Keep one aliasing shared_ptr alive in worker thread so provider weak_ptr
  // remains lockable during connector lifetime.
  auto selfOwner = boost::shared_ptr<CNetUDPConnector>(this, [](CNetUDPConnector*) {});
  {
    boost::recursive_mutex::scoped_lock lock{lock_};

    if (event_ != WSA_INVALID_EVENT) {
      ::WSAEventSelect(socket_, event_, FD_READ | FD_WRITE);
    }

    boost::thread([selfOwner]() {
      selfOwner->Entry();
    });
  }

  const auto natProviderWeak = CopyLiveNatTraversalProviderWeakPtr(mNatTraversalProvider);
  if (const auto natProvider = natProviderWeak.lock()) {
    boost::shared_ptr<INetNATTraversalHandler> natHandler =
      boost::static_pointer_cast<INetNATTraversalHandler>(selfOwner);
    const int port = GetLocalPort();
    natProvider->SetTraversalHandler(port, &natHandler);
  }
}

/**
 * Address: 0x00489D20 (FUN_00489D20)
 * Address: 0x10083760 (sub_10083760)
 *
 * What it does:
 * Clears NAT provider handler, schedules all connections for destroy, and
 * signals connector worker loop to stop.
 */
void CNetUDPConnector::Destroy()
{
  const auto natProviderWeak = CopyLiveNatTraversalProviderWeakPtr(mNatTraversalProvider);
  if (const auto natProvider = natProviderWeak.lock()) {
    boost::shared_ptr<INetNATTraversalHandler> nullHandler{};
    const int port = GetLocalPort();
    natProvider->SetTraversalHandler(port, &nullHandler);
  }

  boost::recursive_mutex::scoped_lock lock{lock_};
  mNatTraversalProvider.reset();
  for (auto* conn : mConnections.owners()) {
    conn->ScheduleDestroy();
  }

  mClosed = true;
#if defined(_WIN32)
  SignalSocketEvent();
#endif
}

/**
 * Address: 0x0048B250 (FUN_0048B250)
 * Address: 0x10084C10 (sub_10084C10)
 *
 * What it does:
 * Returns local UDP socket port in host byte-order.
 */
u_short CNetUDPConnector::GetLocalPort()
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  sockaddr_in sa{};
  int nameLen = sizeof(sa);
  getsockname(socket_, reinterpret_cast<sockaddr*>(&sa), &nameLen);
  return ntohs(sa.sin_port);
}

/**
 * Address: 0x0048B2B0 (FUN_0048B2B0)
 * Address: 0x10084C70 (sub_10084C70)
 *
 * What it does:
 * Finds/updates existing connection state for a remote endpoint or allocates a
 * new outgoing connection in connecting state.
 */
CNetUDPConnection* CNetUDPConnector::Connect(const u_long address, const u_short port)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
#if defined(_WIN32)
  SignalSocketEvent();
#endif

  for (auto* conn : mConnections.owners()) {
    // Match by address/port
    if (conn->GetAddr() != address || conn->GetPort() != port) {
      continue;
    }

    switch (conn->mState) {
    case kNetStatePending: // 0 -> 2
      conn->mState = kNetStateAnswering;
      return conn;

    case kNetStateConnecting:   // 1 -> 5
    case kNetStateAnswering:    // 2 -> 5
    case kNetStateEstablishing: // 3 -> 5
      conn->mState = kNetStateErrored;
      break;

    case kNetStateErrored: // 5 -> keep scanning
      break;

    case kNetStateTimedOut:
    default:
      GPG_UNREACHABLE()
      break;
    }
  }

  auto* const conn = new (std::nothrow) CNetUDPConnection(*this, address, port, kNetStateConnecting);
  return conn;
}

/**
 * Address: 0x0048B410 (FUN_0048B410)
 * Address: 0x10084DD0 (sub_10084DD0)
 *
 * What it does:
 * Finds first pending, non-destroy-scheduled endpoint for accept/reject flow.
 */
bool CNetUDPConnector::FindNextAddress(u_long& outAddress, u_short& outPort)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  for (auto* connection : mConnections.owners()) {
    if (connection->GetConnectionState() == kNetStatePending && !connection->IsDestroyScheduled()) {
      outAddress = connection->GetAddr();
      outPort = connection->GetPort();
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x0048B4F0 (FUN_0048B4F0)
 * Address: 0x10084EB0 (sub_10084EB0)
 *
 * What it does:
 * Thin wrapper around `Connect(address,port)` used by accept flow.
 */
INetConnection* CNetUDPConnector::Accept(const u_long address, const u_short port)
{
  return Connect(address, port);
}

/**
 * Address: 0x0048B500 (FUN_0048B500)
 * Address: 0x10084EC0 (sub_10084EC0)
 *
 * What it does:
 * Marks matching pending connection for destroy.
 */
void CNetUDPConnector::Reject(const u_long address, const u_short port)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  for (auto* connection : mConnections.owners()) {
    if (
      connection->GetAddr() == address && connection->GetPort() == port &&
      connection->GetConnectionState() == kNetStatePending && !connection->IsDestroyScheduled()
    ) {
      connection->ScheduleDestroy();
    }
  }
}

/**
 * Address: 0x0048B5C0 (FUN_0048B5C0)
 * Address: 0x10084F80 (sub_10084F80)
 *
 * What it does:
 * Drains queued NAT-traversal packets to provider callbacks, flushes connector
 * input queues, then dispatches connection input events.
 */
void CNetUDPConnector::Pull()
{
  {
    boost::recursive_mutex::scoped_lock lock{lock_};
    mIsPulling = true;

    if (!mInboundTraversalPackets.empty()) {
      const auto natProvider = CopyLiveNatTraversalProviderWeakPtr(mNatTraversalProvider).lock();

      while (!mInboundTraversalPackets.empty()) {
        const auto [packet, address, port] = mInboundTraversalPackets.front();
        mInboundTraversalPackets.pop_front();

        if (natProvider) {
          const auto* payload = static_cast<const char*>(packet->GetPayload());
          const int payloadBytes = (packet->mSize > 0) ? (packet->mSize - 1) : 0;
          lock.unlock();
          natProvider->ReceivePacket(address, port, payload + 1, payloadBytes);
          lock.lock();
        }

        DisposePacket(packet);
      }
    }

    // FA snapshots `next` before potential delete in this loop body.
    for (auto* connection : mConnections.owners_safe()) {
      if (connection->IsDestroyedFlagSet()) {
        delete (connection);
      } else {
        connection->FlushInput();
      }
    }
  }

  for (auto* conn : mConnections.owners()) {
    conn->DispatchFromInput();
  }

  mIsPulling = false;
  if (mClosed) {
#if defined(_WIN32)
    SignalSocketEvent();
#endif
  }
}

/**
  * Alias of FUN_0048B7F0 (non-canonical helper lane).
 * Address: 0x100851A0 (sub_100851A0)
 *
 * What it does:
 * Flushes per-connection output and signals connector event if any data became
 * send-ready.
 */
void CNetUDPConnector::Push()
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  bool didFlush = false;
  for (auto* conn : mConnections.owners()) {
    if (conn->FlushOutput()) {
      didFlush = true;
    }
  }

  if (didFlush) {
#if defined(_WIN32)
    SignalSocketEvent();
#endif
  }
}

/**
 * Address: 0x0048B9A0 (FUN_0048B9A0)
 * Address: 0x10085340 (sub_10085340)
 *
 * What it does:
 * Installs optional external wake event and pokes connector event loop.
 */
void CNetUDPConnector::SelectEvent(const HANDLE ev)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  mSelectedEvent = ev;
#if defined(_WIN32)
  SignalSocketEvent();
#endif
}

/**
 * Address: 0x0048B8E0 (FUN_0048B8E0)
 * Address: 0x10085280 (sub_10085280)
 *
 * What it does:
 * Logs connector-level diagnostics and emits per-connection debug state.
 */
void CNetUDPConnector::Debug()
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  gpg::Logf("CNetUDPConnector 0x%08x:", this);
  gpg::Logf("  local port=%d", GetLocalPort());
  gpg::Logf("  packet pool size=%d", mPacketPoolSize);
  for (auto* connection : mConnections.owners()) {
    connection->Debug();
  }
}

/**
 * Address: 0x0048B9E0 (FUN_0048B9E0)
 * Address: 0x10085380 (sub_10085380)
 *
 * What it does:
 * Returns a snapshot view of send/recv stamps from `since` milliseconds up to current connector time.
 */
SSendStampView CNetUDPConnector::SnapshotSendStamps(const int32_t since)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  const uint64_t endTimeUs = static_cast<uint64_t>(GetTime());
  const uint64_t startTimeUs = static_cast<uint64_t>(1000LL * since);
  return mSendStampBuffer.GetBetween(endTimeUs, startTimeUs);
}

/**
 * Address: 0x00489F30 (FUN_00489F30)
 *
 * What it does:
 * Returns monotonic microsecond timestamp anchored to ctor FILETIME baseline.
 */
int64_t CNetUDPConnector::GetTime()
{
  const auto cur = mTimer.ElapsedMicroseconds();
  const auto add = mTimeBaseUs + cur;
  if (add > mCurrentTimeUs) {
    mCurrentTimeUs = add;
  } else {
    ++mCurrentTimeUs;
  }
  return mCurrentTimeUs;
}

/**
 * Address: 0x00488150 (FUN_00488150)
 *
 * What it does:
 * Chooses lower non-`-1` timeout, treating `-1` as infinity.
 */
int32_t CNetUDPConnector::ChooseTimeout(const int32_t current, const int32_t choice)
{
  if (current == -1 || choice != -1 && choice < current) {
    return choice;
  }
  return current;
}

/**
 * Address: 0x0048A280 (FUN_0048A280)
 * Address: 0x0048A288 (SEH-prologue label inside FUN_0048A280)
 *
 * What it does:
 * Drains readable UDP datagrams, validates packet framing, dispatches packet
 * handlers by type, and recycles unconsumed packet storage into pool.
 */
void CNetUDPConnector::ReceiveData()
{
  TDatList<SNetPacket, void> acquiredPackets{};

  while (true) {
    SNetPacket* packet = NewPacket();
    if (!packet) {
      break;
    }

    packet->ListLinkBefore(&acquiredPackets);

    sockaddr_in from{};
    int fromLen = sizeof(from);
    const int n =
      recvfrom(socket_, static_cast<char*>(packet->GetPayload()), 512, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);

    if (n < 0) {
#if defined(_WIN32)
      const int lastErr = WSAGetLastError();
      if (lastErr != WSAEWOULDBLOCK && net_DebugLevel) {
        const char* es = NET_GetWinsockErrorString();
        gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): recvfrom() failed: %s", GetLocalPort(), es);
      }
#else
      if (errno != EWOULDBLOCK && errno != EAGAIN && net_DebugLevel) {
        gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): recvfrom() failed: errno=%d", GetLocalPort(), errno);
      }
#endif
      break;
    }

    packet->mSize = n;
    const int64_t timeNow = GetTime();
    packet->mSentTime = timeNow;
    mSendStampBuffer.Push(1, timeNow, n);

    const uint32_t addrHost = ntohl(static_cast<uint32_t>(from.sin_addr.s_addr));
    const uint16_t portHost = ntohs(from.sin_port);

    if (net_LogPackets) {
      LogPacket(1, timeNow, addrHost, portHost, &packet->header.mType, n);
    }

    if (net_DebugLevel >= 2) {
      const msvc8::string packetString = packet->ToString();
      const msvc8::string hostString = NET_GetHostName(addrHost);
      const msvc8::string timeString = gpg::FileTimeToString(timeNow);
      gpg::Debugf(
        "%s:                     recv %s:%hu, %s",
        timeString.c_str(),
        hostString.c_str(),
        portHost,
        packetString.c_str()
      );
    }

    if (n > 0 && packet->header.mType == PT_NATTraversal) {
      if (CopyLiveNatTraversalProviderWeakPtr(mNatTraversalProvider).lock()) {
        packet->ListUnlink();
        mInboundTraversalPackets.push_back({packet, addrHost, portHost});
#if defined(_WIN32)
        if (mSelectedEvent) {
          SetEvent(mSelectedEvent);
        }
#endif
      }
      continue;
    }

    if (static_cast<unsigned>(n) < 15U) {
      if (net_DebugLevel) {
        const msvc8::string host = NET_GetHostName(addrHost);
        gpg::Logf(
          "CNetUDPConnector<%hu>::ReceiveData(): ignoring short (%d bytes) packet from %s:%hu",
          GetLocalPort(),
          n,
          host.c_str(),
          portHost
        );
      }
      continue;
    }

    if (packet->header.mType < PT_NumTypes) {
      const int expected = static_cast<int>(packet->header.mPayloadLength) + kNetPacketHeaderSize;
      if (n != expected) {
        if (net_DebugLevel) {
          const msvc8::string host = NET_GetHostName(addrHost);
          gpg::Logf(
            "CNetUDPConnector<%hu>::ReceiveData(): ignoring packet with payload length mismatch "
            "(got %d, header says %d) from %s:%hu",
            GetLocalPort(),
            n,
            packet->header.mPayloadLength,
            host.c_str(),
            portHost
          );
        }
        continue;
      }

      if (packet->header.mType == PT_Connect) {
        ProcessConnect(packet, addrHost, portHost);
        continue;
      }

      CNetUDPConnection* target = nullptr;
      for (auto* connection : mConnections.owners()) {
        if (
          connection->GetAddr() == addrHost && connection->GetPort() == portHost && connection->IsBeforeErroredState()
        ) {
          target = connection;
          break;
        }
      }

      if (!target) {
        if (net_DebugLevel) {
          const msvc8::string host = NET_GetHostName(addrHost);
          gpg::Logf(
            "CNetUDPConnector<%hu>::ReceiveData(): ignoring packet of type %d from unknown host %s:%hu",
            GetLocalPort(),
            packet->header.mType,
            host.c_str(),
            portHost
          );
        }
        continue;
      }

      switch (packet->header.mType) {
      case PT_Answer:
        target->ProcessAnswer(packet);
        break;
      case PT_Data:
        target->ProcessData(packet);
        break;
      case PT_Ack:
        target->ProcessAck(packet);
        break;
      case PT_KeepAlive:
        target->ProcessKeepAlive(packet);
        break;
      case PT_Goodbye:
        target->ProcessGoodbye(packet);
        break;
      default:
        if (net_DebugLevel) {
          const msvc8::string host = NET_GetHostName(addrHost);
          gpg::Logf(
            "CNetUDPConnector<%hu>::ReceiveData(): ignoring unimplemented packet of type %d from %s:%hu",
            GetLocalPort(),
            packet->header.mType,
            host.c_str(),
            portHost
          );
        }
        break;
      }
    } else {
      if (net_DebugLevel) {
        const msvc8::string host = NET_GetHostName(addrHost);
        gpg::Logf(
          "CNetUDPConnector<%hu>::ReceiveData(): ignoring unknown packet type (%d) from %s:%hu",
          GetLocalPort(),
          packet->header.mType,
          host.c_str(),
          portHost
        );
      }
    }
  }

  while (!acquiredPackets.empty()) {
    SNetPacket* packet = acquiredPackets.ListGetNext();
    packet->ListUnlink();
    DisposePacket(packet);
  }
}

/**
 * Address: 0x0048AA40 (FUN_0048AA40)
 *
 * What it does:
 * Validates incoming CONNECT packet, routes it to an existing candidate
 * connection, or creates a new pending connection when needed.
 */
void CNetUDPConnector::ProcessConnect(const SNetPacket* packet, const u_long address, const u_short port)
{
  if (packet->mSize != kNetPacketHeaderSize + sizeof(SPacketBodyConnect)) {
    if (net_DebugLevel) {
      const auto host = NET_GetHostName(address);
      gpg::Logf(
        "CNetUDPConnector<%hu>::ProcessConnect(): ignoring wrong length CONNECT (got %d bytes, required %d) from %s:%d",
        GetLocalPort(),
        packet->mSize,
        60,
        host.c_str(),
        port
      );
    }
    return;
  }

  const auto& connectPacket = packet->As<SPacketBodyConnect>();

  if (connectPacket.protocol != ENetProtocolType::kUdp) {
    if (net_DebugLevel) {
      const auto host = NET_GetHostName(address);
      gpg::Logf(
        "CNetUDPConnector<%hu>::ProcessConnect(): ignoring connect with wrong protocol (got %d, required %d) from "
        "%s:%d",
        GetLocalPort(),
        connectPacket.protocol,
        2,
        host.c_str(),
        port
      );
    }
    return;
  }

  for (auto* connection : mConnections.owners()) {
    if (
      connection->GetAddr() == address && connection->GetPort() == port && connection->IsBeforeErroredState() &&
      connection->ProcessConnect(packet)
    ) {
      return;
    }
  }

  if (mClosed) {
    return;
  }

  auto* const newConnection = new (std::nothrow) CNetUDPConnection(*this, address, port, kNetStatePending);
  if (!newConnection) {
    return;
  }

  newConnection->ProcessConnect(packet);
#if defined(_WIN32)
  if (mSelectedEvent) {
    SetEvent(mSelectedEvent);
  }
#endif
}

/**
 * Address: 0x0048B040 (FUN_0048B040)
 *
 * What it does:
 * Appends packet-log records (`.pktlog`) with lazy file-open, 16-byte record
 * headers, and optional incoming/outgoing direction flag.
 */
void CNetUDPConnector::LogPacket(
  const int direction,
  const std::int64_t timestampUs,
  const std::uint32_t addressHost,
  const std::uint16_t portHost,
  const void* payload,
  const int payloadLen
)
{
  if (!net_LogPackets) {
    return;
  }

  // Lazy open
  if (!mPacketLogFile) {
    char* temp = nullptr;
    size_t tempLen = 0;
    if (_dupenv_s(&temp, &tempLen, "TEMP") != 0 || temp == nullptr) {
      net_LogPackets = 0;
      gpg::Logf("NET: Can't find a place for the packet log -- %%TEMP%% not set!");
      return;
    }

    char host[260] = {};
    if (gethostname(host, sizeof(host) - 1) == -1) {
      free(temp);
      net_LogPackets = 0;
      gpg::Logf("NET: Can't figure out a name for the packet log -- gethostname failed.");
      return;
    }

    const unsigned localPort = GetLocalPort();
    const msvc8::string path = gpg::STR_Printf("%s\\%s-%u.pktlog", temp, host, localPort);

    const errno_t openError = fopen_s(&mPacketLogFile, path.c_str(), "ab");
    if (openError != 0 || !mPacketLogFile) {
      free(temp);
      net_LogPackets = 0;
      gpg::Logf("NET: can't open packet log \"%s\" for writing.", path.c_str());
      return;
    }
    free(temp);

    gpg::Logf("NET: Packet log \"%s\" opened.", path.c_str());

    // Write 16-byte "start" record: {timestamp_us, time64(0), 0, 0}
    PacketLogRecord start;
    start.timestamp_us = timestampUs;
    start.addr = static_cast<std::uint32_t>(_time64(nullptr)); // time64(0)
    start.len_flags = 0;
    start.port = 0;
    std::fwrite(&start, sizeof(start), 1, mPacketLogFile);
  }

  // Record header
  PacketLogRecord rec;
  rec.timestamp_us = timestampUs;
  rec.addr = addressHost;
  rec.len_flags = static_cast<std::uint16_t>(payloadLen & 0x7FFF);
  if (direction == 1) {
    rec.len_flags |= 0x8000; // incoming flag
  }
  rec.port = portHost;

  // Write header + payload
  std::fwrite(&rec, sizeof(rec), 1, mPacketLogFile);
  std::fwrite(payload, 1, static_cast<size_t>(payloadLen), mPacketLogFile);
}

/**
 * Address: 0x00489ED0 (FUN_00489ED0)
 *
 * What it does:
 * Returns packet storage to pool (cap 20) or frees it when the pool is full.
 */
void CNetUDPConnector::DisposePacket(SNetPacket* packet)
{
  if (!packet) {
    return;
  }

  if (mPacketPoolSize >= kReceiveUdpPacketPoolSize) {
    packet->ListUnlink();
    operator delete(packet);
  } else {
    packet->ListLinkBefore(&mPacketList);
    ++mPacketPoolSize;
  }
}

/**
 * Address: 0x0048BA80 (FUN_0048BA80)
 * Address: 0x10085450 (sub_10085450)
 *
 * What it does:
 * Resets message payload buffer and writes NAT traversal packet-type byte (8).
 */
void CNetUDPConnector::PrepareTraversalMessage(CMessage* msg)
{
  msg->mBuff.Clear();
  // FastVectorN::Append signature is legacy non-const `T&`.
  char marker = static_cast<char>(PT_NATTraversal);
  msg->mBuff.Append(marker);
}

/**
 * Address: 0x0048BAE0 (FUN_0048BAE0)
 * Address: 0x100854B0 (sub_100854B0)
 *
 * What it does:
 * Queues NAT traversal payload for UDP send, reusing packet-pool storage when
 * available, then signals connector event.
 */
void CNetUDPConnector::ReceivePacket(const u_long address, const u_short port, const char* dat, size_t size)
{
  boost::recursive_mutex::scoped_lock lock{lock_};
  if (size > kPacketMaxSize) {
    gpg::Logf("Truncating NAT traversal packet from %d to %d bytes", size, kPacketMaxSize);
    size = kPacketMaxSize;
  }

  SNetPacket* const packet = NewPacket();
  memcpy(&packet->header, dat, size);
  packet->mSize = static_cast<int32_t>(size);
  const SReceivePacket r{packet, address, port};
  mOutboundPackets.push_back(r);

#if defined(_WIN32)
  SignalSocketEvent();
#endif
}

/**
 * Address: 0x00489E80 (FUN_00489E80)
 *
 * What it does:
 * Acquires a packet from connector pool or allocates a new packet.
 */
SNetPacket* CNetUDPConnector::NewPacket()
{
  if (mPacketList.empty()) {
    return new (std::nothrow) SNetPacket{};
  }

  --mPacketPoolSize;
  SNetPacket* packet = mPacketList.ListGetNext();
  packet->ListUnlink();
  return packet;
}

/**
 * Address: 0x00489F90 (FUN_00489F90)
 * Address: 0x0128C620 (FUN_0128C620, patch_Moho::CNetUDPConnector::Entry)
 *
 * What it does:
 * Connector worker loop: receives inbound data, sends outbound data, handles
 * shutdown, and sleeps on socket event with computed timeout.
 */
void CNetUDPConnector::Entry()
{
  const msvc8::string name = gpg::STR_Printf("CNetUDPConnector for port %d", GetLocalPort());
  gpg::SetThreadName(0xFFFFFFFF, name.c_str());
  THREAD_SetAffinity(false);
#if defined(_WIN32)
  ::SetThreadPriority(::GetCurrentThread(), 2);
#endif
  boost::recursive_mutex::scoped_lock lock{lock_};
  while (true) {
    if (!net_LogPackets && mPacketLogFile != nullptr) {
      ::fclose(mPacketLogFile);
      mPacketLogFile = nullptr;
    }
    ReceiveData();
    const LONGLONG timeout = SendData();
    if (mClosed && !mIsPulling) {
      for (const auto* connection : mConnections.owners()) {
        if (connection->IsDestroyedFlagSet()) {
          delete connection;
        }
      }
      if (mConnections.empty()) {
        break;
      }
    }
    lock.unlock();
    if (net_DebugCrash) {
      *static_cast<int*>(0) = 0;
    }

    LONGLONG startTime = 0;
    if (net_DebugLevel >= 3) {
      startTime = GetTime();
      const auto timeStr = gpg::FileTimeToString(startTime);
      gpg::Debugf("%s: waiting, timeout=%dms", timeStr.c_str(), timeout);
    }
    ::WSAWaitForMultipleEvents(1, &event_, false, static_cast<DWORD>(timeout), true);

    if (startTime != 0) {
      const auto time = GetTime();
      const auto timeStr = gpg::FileTimeToString(time);
      gpg::Debugf("%s: wait finished, elapsed=%dms", timeStr.c_str(), (time - startTime) / 1000);
    }
    lock.lock();
    ::WSAResetEvent(event_);
  }
}

/**
  * Alias of FUN_0048AC40 (non-canonical helper lane).
 *
 * What it does:
 * Flushes connector outbound packet queue, then computes next wake timeout
 * from per-connection send/backlog state.
 */
int32_t CNetUDPConnector::SendData()
{
  int timeout = -1;
  int64_t curTime = GetTime();

  while (!mOutboundPackets.empty()) {
    const SReceivePacket packet = mOutboundPackets.front();
    mOutboundPackets.pop_front();

    sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = ::htons(packet.mPort);
    name.sin_addr.S_un.S_addr = ::htonl(packet.mAddr);

    const auto payload = packet.mPacket->GetPayload();
    const auto payloadSize = packet.mPacket->GetPayloadSize();

    ::sendto(
      socket_,
      static_cast<const char*>(payload),
      static_cast<int32_t>(payloadSize),
      0,
      reinterpret_cast<SOCKADDR*>(&name),
      16
    );

    if (net_LogPackets) {
      LogPacket(0, curTime, packet.mAddr, packet.mPort, payload, packet.mPacket->mSize);
    }

    mSendStampBuffer.Add(0, curTime, packet.mPacket->mSize);
    if (net_DebugLevel >= 2) {
      msvc8::string packStr = packet.mPacket->ToString();
      msvc8::string hostStr = NET_GetHostName(packet.mAddr);
      curTime = GetTime();
      msvc8::string timeStr = gpg::FileTimeToString(curTime);
      gpg::Debugf("%s: send %s:%d, %s", timeStr.c_str(), hostStr.c_str(), packet.mPort, packStr.c_str());
    }
    DisposePacket(packet.mPacket);
  }

  for (auto* conn : mConnections.owners()) {
    int conTimeout = 0;
    while (true) {
      int backlogTimeout = 0;
      if (!conn->GetBacklogTimeout(curTime, backlogTimeout)) {
        conTimeout = backlogTimeout;
        break;
      }

      conTimeout = static_cast<int32_t>(conn->SendData());
      if (conTimeout != 0) {
        break;
      }
    }
    timeout = ChooseTimeout(timeout, conTimeout);
  }

  return timeout;
}

/**
 * Helper alias used by recovered connection codepaths.
 *
 * Binary behavior maps to `DisposePacket` (FA `0x00489ED0`).
 */
void CNetUDPConnector::AddPacket(SNetPacket* packet)
{
  DisposePacket(packet);
}
