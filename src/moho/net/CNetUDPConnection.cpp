// ReSharper disable CppTooWideScope
#include "CNetUDPConnection.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>

#include "CLobby.h"
#include "CNetUDPConnector.h"
#include "ELobbyMsg.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "NetConVars.h"
#include "NetMessageRanges.h"
using namespace moho;

namespace
{
  // Received bytes waiting for the game thread to dispatch them. The window
  // bounds what a peer has in flight, not what deflate expands it to, nor how
  // far ahead of a stalled dispatcher it may run; real traffic stays far below.
  constexpr std::size_t kMaxBufferedInputBytes = 16u * 1024u * 1024u;

  // "No receiver for message type" warnings logged per connection.
  constexpr std::uint32_t kMaxUnroutedMessageWarnings = 8;
} // namespace

/**
 * Address: 0x00485BE0 (FUN_00485BE0)
 *
 * What it does:
 * Returns remote IPv4 host address in host byte order.
 */
u_long CNetUDPConnection::GetAddr()
{
  return mAddr;
}

/**
 * Address: 0x00485BF0 (FUN_00485BF0)
 *
 * What it does:
 * Returns remote UDP port in host byte order.
 */
uint16_t CNetUDPConnection::GetPort()
{
  return mPort;
}

/**
 * Address: 0x00485BA0 (FUN_00485BA0)
 *
 * What it does:
 * Returns the current UDP connection state lane.
 */
ENetConnectionState CNetUDPConnection::GetConnectionState() const noexcept
{
  return mState;
}

/**
 * Address: 0x00485BB0 (FUN_00485BB0)
 *
 * What it does:
 * Returns whether state is still before errored lane (`< kNetStateErrored`).
 */
bool CNetUDPConnection::IsBeforeErroredState() const noexcept
{
  return static_cast<int>(mState) < static_cast<int>(kNetStateErrored);
}

/**
 * Address: 0x00485BD0 (FUN_00485BD0)
 *
 * What it does:
 * Returns whether destroy was already requested.
 */
bool CNetUDPConnection::IsDestroyScheduled() const noexcept
{
  return mScheduleDestroy;
}

/**
 * Address: 0x00485BC0 (FUN_00485BC0)
 *
 * What it does:
 * Returns whether this connection has already been fully destroyed.
 */
bool CNetUDPConnection::IsDestroyedFlagSet() const noexcept
{
  return mDestroyed;
}

/**
 * Address: 0x00489550 (FUN_00489550)
 * Address: 0x10082F50 (sub_10082F50)
 *
 * What it does:
 * Returns filtered ping in milliseconds under connector lock.
 */
float CNetUDPConnection::GetPing()
{
  boost::recursive_mutex::scoped_lock lock{mConnector->lock_};
  return mPingTime;
}

/**
 * Address: 0x00489590 (FUN_00489590)
 * Address: 0x10082F90 (sub_10082F90)
 *
 * What it does:
 * Returns milliseconds elapsed since last received packet, or -1 when no packet was seen.
 */
float CNetUDPConnection::GetTime()
{
  boost::recursive_mutex::scoped_lock lock{mConnector->lock_};
  if (!mLastRecv) {
    return -1.0;
  }

  const std::int64_t now = mConnector->GetTime();
  return static_cast<float>(now - mLastRecv) * 0.001f;
}

/**
 * Address: 0x00489130 (FUN_00489130)
 * Address: 0x10082B30 (sub_10082B30)
 *
 * What it does:
 * Queues bytes from NetDataSpan [start, end) into the pending output stream/filter,
 * schedules send deadline, updates queued-byte MD5/counters, and signals socket event.
 */
void CNetUDPConnection::Write(NetDataSpan* data)
{
  const uint8_t* begin = data->start;
  const uint8_t* end = data->end;
  const size_t len = static_cast<size_t>(end - begin);
  boost::recursive_mutex::scoped_lock lock{mConnector->lock_};

  if (auto* target = mOutputFilterStream) {
    target->VirtWrite(reinterpret_cast<const char*>(begin), len);
  } else {
    mPendingOutputData.VirtWrite(reinterpret_cast<const char*>(begin), len);
  }

  // Schedule earliest send time once:
  // mSendBy = now + net_SendDelay * 1000 (ms > us ticks in bin)
  if (mSendBy.mTime == 0) {
    const std::int64_t now = mConnector->GetTime();
    mSendBy.mTime = now + static_cast<std::int64_t>(net_SendDelay) * 1000;
  }

  // Mark output stream as having pending post-filter bytes.
  mOutputFlushPending = true;

  // Update counters and MD5 of total queued bytes
  mTotalBytesQueued += static_cast<std::uint64_t>(len);
  mTotalBytesQueuedMD5.Update(begin, len);

  // Verbose debug (net_DebugLevel >= 3)
  if (net_DebugLevel >= 3) {
    const auto dig = mTotalBytesQueuedMD5.Digest();
    const auto ts = gpg::FileTimeToString(mConnector->GetTime());

    const unsigned msgType = len ? begin[0] : 0;
    gpg::Debugf(
      "%s: %s: msg type %u queued [%zu bytes, total now %llu, md5 %s]",
      ts.c_str(),
      ToString().c_str(),
      msgType,
      len,
      static_cast<unsigned long long>(mTotalBytesQueued),
      dig.ToString().c_str()
    );
  }

#if defined(_WIN32)
  mConnector->SignalSocketEvent();
#endif
}

/**
 * Address: 0x004893F0 (FUN_004893F0)
 *
 * What it does:
 * Closes outbound stream/filter state once, marks output shutdown, and wakes the
 * connector worker event.
 */
void CNetUDPConnection::Close()
{
  boost::recursive_mutex::scoped_lock lock{mConnector->lock_};
  if (mOutputShutdown) {
    return;
  }

  if (mOutputFilterStream) {
    mOutputFilterStream->VirtClose(gpg::Stream::ModeBoth);
    auto* const oldFilter = mOutputFilterStream;
    mOutputFilterStream = nullptr;
    delete oldFilter;
  }

  mPendingOutputData.VirtClose(gpg::Stream::ModeBoth);
  mOutputShutdown = true;
  mOutputFlushPending = false;

#if defined(_WIN32)
  mConnector->SignalSocketEvent();
#endif
}

/**
 * Address: 0x004894C0 (FUN_004894C0)
 *
 * What it does:
 * Formats the remote endpoint as "host:port".
 */
msvc8::string CNetUDPConnection::ToString()
{
  const auto host = NET_GetHostName(mAddr);
  return gpg::STR_Printf("%s:%d", host.c_str(), static_cast<int>(mPort));
}

/**
 * Address: 0x00489660 (FUN_00489660)
 *
 * What it does:
 * Requests connection teardown, closes output path, and wakes the connector.
 */
void CNetUDPConnection::ScheduleDestroy()
{
  boost::recursive_mutex::scoped_lock lock{mConnector->lock_};
  Close();
  mScheduleDestroy = true;

#if defined(_WIN32)
  mConnector->SignalSocketEvent();
#endif
}

/**
 * Address: 0x00485D30 (FUN_00485D30)
 * Address: 0x1007F7E0 (sub_1007F7E0)
 *
 * What it does:
 * Initializes UDP connection transport state, inserts the connection into the
 * connector list, and configures send compression/filtering.
 */
CNetUDPConnection::CNetUDPConnection(
  CNetUDPConnector& connector,
  const u_long address,
  const u_short port,
  const ENetConnectionState state
)
  : mConnector(&connector)
  , // [esi+0x418]
  mAddr(address)
  , // [esi+0x41C]
  mPort(port)
  , // [esi+0x420]
  mOurCompressionMethod(static_cast<ENetCompressionMethod>(net_CompressionMethod))
  , // [esi+0x424]
  mState(state)
  , mUnAckedPayloads()
  , mEarlyPackets()
  , // [esi+0x42C]
  mMessage()
{
  // Binary initializes these timer slots to zero, not "now".
  mLastSend.mTime = 0;
  mSendTime = 0;
  mLastRecv = 0;
  mLastKeepAlive = 0;

  // Init small scratch buffers
  std::memset(mNonceA, 0, sizeof(mNonceA));
  std::memset(mNonceB, 0, sizeof(mNonceB));
  mReserved494 = 0;
  mHandshakeTime = 0;
  mNextSerialNumber = 1;
  mInResponseTo = 0;

  // Initialize MD5 accumulators
  mTotalBytesQueuedMD5.Reset();
  mTotalBytesSentMD5.Reset();
  mTotalBytesReceivedMD5.Reset();
  mTotalBytesDispatchedMD5.Reset();

  // Streams: output first (at +0x4B8)
  // ctor call observed in ASM
  // NOTE: mOutputData default-constructs; ensure default ctor matches
  // the in-game PipeStream behavior (no pending buffers, etc.)
  // Then clear filter & flags (ASM stores 0 to [0x500],[0x508],[0x50C],[0x50D])
  mOutputFilterStream = nullptr;
  mFlushedOutputData = 0;
  mOutputShutdown = false;
  mSentShutdown = false;

  // Streams: input (at +0x0D98)
  // ctor call observed in ASM
  // Set ring pointers/layout around [0x0DE8..0x0DF4] - wrap:
  {
    // Clear filter and EoI flags (matches writes at +0xDE0, +0xDE4, +0xDE5)
    mFilterStream = nullptr;
    mReceivedEndOfInput = false;
    mDispatchedEndOfInput = false;
    // Nothing else to do: PipeStream() ctor already allocated a buffer
    // and set [mReadHead==mReadEnd==begin(), mWriteHead==mWriteStart==begin(), mWriteEnd==end()].
  }

  mSendBy.mTime = 0;

  // Link this connection into connector's intrusive list
  // ASM: uses node at +0x410; do the same in Attach().
  connector.RelinkConnectionToFront(*this);

  // Whoever sends a CONNECT creates a pending connection, on the connector
  // thread with its lock held. Naming it by reverse DNS would let the sender's
  // address stall that thread, and the game thread waiting on the lock.
  const msvc8::string peerName = state == kNetStatePending
    ? gpg::STR_Printf("%s:%d", NET_GetDottedOctetFromUInt32(address).c_str(), static_cast<int>(port))
    : CNetUDPConnection::ToString();

  // Select SEND compression (controlled by Moho::net_CompressionMethod)
  switch (mOurCompressionMethod) {
  case NETCOMP_None:
    gpg::Logf("NET: using no compression for sends to %s.", peerName.c_str());
    break;
  case NETCOMP_Deflate: {
    gpg::Logf("NET: using deflate compression for sends to %s.", peerName.c_str());

    // Allocate filter (operator new 0x460 seen in asm).
    // Construct zlib filter for deflate (send path).
    const auto filterStream = new gpg::ZLibOutputFilterStream(&mPendingOutputData, gpg::FLOP_Deflate);
    if (filterStream) {
      auto* const oldFilter = mOutputFilterStream;
      mOutputFilterStream = filterStream;
      if (oldFilter) {
        delete oldFilter;
      }
    } else {
      gpg::Warnf("NET: failed to allocate ZLibOutputFilterStream, falling back to no compression");
      mOurCompressionMethod = NETCOMP_None;
    }
    break;
  }
  default:
    gpg::Warnf("Unknown compression method %d, assuming none.", static_cast<int>(mOurCompressionMethod));
    mOurCompressionMethod = NETCOMP_None;
    break;
  }

  // Initialize pings structure and ping time
  std::memset(&mPings, 0, sizeof(mPings));
  mPingTime = 0.0f;
}

/**
 * Address: 0x00486150 (FUN_00486150)
 * Address: 0x1007FC10 (sub_1007FC10)
 *
 * What it does:
 * Recycles queued packet nodes, tears down optional filter streams, and unlinks
 * this connection from the connector intrusive list.
 */
CNetUDPConnection::~CNetUDPConnection()
{
  constexpr int poolCap = 0x14u;

  auto recyclePacket = [this](SNetPacket* p) noexcept {
    if (!p) {
      return;
    }
    if (mConnector->mPacketPoolSize >= poolCap) {
      operator delete(p);
    } else {
      mConnector->mPacketList.push_back(p);
      ++mConnector->mPacketPoolSize;
    }
  };

  // Un-acked
  for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end();) {
    auto* n = it.node();
    auto* p = static_cast<SNetPacket*>(n);
    it = mUnAckedPayloads.erase(it);
    recyclePacket(p);
  }

  // Early
  for (auto it = mEarlyPackets.begin(); it != mEarlyPackets.end();) {
    auto* n = it.node();
    auto* p = static_cast<SNetPacket*>(n);
    it = mEarlyPackets.erase(it);
    recyclePacket(p);
  }

  if (mFilterStream) {
    delete mFilterStream;
    mFilterStream = nullptr;
  }

  if (mOutputFilterStream) {
    delete mOutputFilterStream;
    mOutputFilterStream = nullptr;
  }

  // The ctor links this node into CNetUDPConnector::mConnections; the
  // `gpg::DListItem` base's destructor takes it out (0x00486110 is that
  // destructor's unwind copy).
}

/**
 * Address: 0x00486910 (FUN_00486910)
 *
 * What it does:
 * Transitions to established state, injects ConnMade marker into input stream,
 * and configures inbound decompression filter.
 */
void CNetUDPConnection::CreateFilterStream()
{
  mState = kNetStateEstablishing;

  CMessage msg(ELobbyMsg::LOBMSG_ConnMade);
  mInputBuffer.Write(msg.mBuff.Data(), msg.mBuff.Size());

  if (mReceivedCompressionMethod == NETCOMP_None) {
    gpg::Logf("NET: using no compression for receives from %s", ToString().c_str());
    return;
  }

  if (mReceivedCompressionMethod != NETCOMP_Deflate) {
    GPG_UNREACHABLE()
  }

  gpg::Logf("NET: using deflate compression for receives from %s", ToString().c_str());

  // 0x00486A6A pushes 0 (inflate); the send-side filter in the ctor pushes 1.
  const auto* const old = mFilterStream;
  mFilterStream = new gpg::ZLibOutputFilterStream(&mInputBuffer, gpg::FLOP_Inflate);
  delete old;
}

/**
 * Address: 0x00486380 (FUN_00486380)
 *
 * What it does:
 * Validates CONNECT handshake packets, updates nonce/compression handshake
 * state, and handles invalid state transitions.
 */
bool CNetUDPConnection::ProcessConnect(const SNetPacket* packet)
{
  const auto& pConnect = *reinterpret_cast<const SPacketBodyConnect*>(packet->data);

  // Obsolete CONNECT: ignore
  if (pConnect.time <= mHandshakeTime) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring obsolete CONNECT",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return true;
  }

  // Fresh packet: record last-recv wall clock from peer
  mLastRecv = packet->mSentTime;

  // Unknown compression method
  if (pConnect.comp >= NETCOMP_Deflate + 1) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring connect w/ unknown compression method (%u)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(pConnect.comp)
      );
    }
    return true;
  }

  switch (mState) {
  case kNetStatePending:   // 0
  case kNetStateAnswering: // 2
  {
    // Copy remote nonce and adopt compression.
    std::copy_n(pConnect.senderNonce, 32, mNonceB);
    mHandshakeTime = pConnect.time;
    mReceivedCompressionMethod = pConnect.comp;

    // Binary rebinds/repurposes packet memory to this connection.
    AdoptPacket(packet);
    return true;
  }
  case kNetStateConnecting: // 1 (Connecting)
  {
    // Crypto nonce blob copy (opaque 32-byte handshake field).
    std::copy_n(pConnect.senderNonce, 32, mNonceB);
    mHandshakeTime = pConnect.time;
    mReceivedCompressionMethod = pConnect.comp;

    AdoptPacket(packet);

    // Transition to Answering
    mState = kNetStateAnswering;
    return true;
  }
  case kNetStateEstablishing: // 3
  case kNetStateTimedOut:     // 4
  {
    mState = kNetStateErrored;
    mReceivedEndOfInput = true;

    // Close input side (ModeBoth per binary)
    mInputBuffer.Close(gpg::Stream::ModeBoth);

    if (mConnector->mSelectedEvent) {
#if defined(_WIN32)
      SetEvent(mConnector->mSelectedEvent);
#endif
    }
    return false;
  }
  default:
    GPG_UNREACHABLE()
    return false;
  }
}

/**
 * Address: 0x004865E0 (FUN_004865E0)
 *
 * What it does:
 * Validates ANSWER handshake packets and completes negotiated receive setup.
 */
void CNetUDPConnection::ProcessAnswer(const SNetPacket* packet)
{
  const auto& pAnswer = *reinterpret_cast<const SPacketBodyAnswer*>(packet->data);

  // Strict size check: expected 92 bytes
  if (packet->mSize != 92) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring wrong length ANSWER (got %d bytes, required %d)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        packet->mSize,
        92
      );
    }
    return;
  }

  // Obsolete ANSWER
  if (pAnswer.time <= mHandshakeTime) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring obsolete ANSWER",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return;
  }

  // Receiver nonce must match what we sent earlier
  if (ReceiverNonceDiffers32(mNonceA, pAnswer.receiverNonce)) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER with wrong receiver nonce",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return;
  }

  // Unknown compression method
  if (pAnswer.comp >= 2u) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring answer w/ unknown compression method (%u)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(pAnswer.comp)
      );
    }
    return;
  }

  // Must be in Connecting (1) or Answering (2)
  if (mState == kNetStatePending) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on pending connection",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return;
  }

  if (!(mState == kNetStateConnecting || mState == kNetStateAnswering)) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on established connection",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return;
  }

  // Update remote timing/window from header.
  UpdatePingInfoFromPacket(*packet);

  // Refresh peer time and negotiated params.
  mLastRecv = packet->mSentTime;
  // Crypto nonce blob copy (opaque 32-byte handshake field).
  std::copy_n(pAnswer.senderNonce, 32, mNonceB);
  mHandshakeTime = pAnswer.time;
  mReceivedCompressionMethod = pAnswer.comp;

  // Enable RX filter according to negotiated compression.
  CreateFilterStream();

  // Binary rebinds/repurposes packet memory to this connection.
  AdoptPacket(packet);

#if defined(_WIN32)
  if (mConnector->mSelectedEvent) {
    SetEvent(mConnector->mSelectedEvent);
  }
#endif
}

/**
 * Address: 0x00486B10 (FUN_00486B10)
 *
 * What it does:
 * Validates peer ACK window, updates ping timing, releases acknowledged
 * reliable packets, and advances remote expected sequence tracker.
 */
bool CNetUDPConnection::ProcessAckInternal(const SNetPacket* packet)
{
  switch (mState) {
  case kNetStatePending: { // 0
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Pending connection.",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return false;
  }
  case kNetStateConnecting: { // 1
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Connecting connection.",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return false;
  }
  case kNetStateAnswering: // 2
    // First ACK on Active path turns on RX filter if not set.
    CreateFilterStream();
  case kNetStateEstablishing: // 3
    break;                    // proceed
  case kNetStateTimedOut:     // 4
    // Transition per binary: Error -> Closing before handling.
    mState = kNetStateEstablishing;
    break;
  case kNetStateErrored: { // 5
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Errored connection.",
        mConnector->GetLocalPort(),
        ToString().c_str()
      );
    }
    return false;
  }
  default:
    GPG_UNREACHABLE()
    return false;
  }

  // Validate that remote's ExpectedSeq isn't ahead of what we've sent.
  const uint16_t expected = packet->header.mExpectedSequenceNumber;
  if (static_cast<int16_t>(mNextSequenceNumber - expected) < 0) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessHeader(): ignoring acknowledgement of data we haven't sent (packet=%u, "
        "next=%u)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(expected),
        static_cast<unsigned>(mNextSequenceNumber)
      );
    }
    return false;
  }

  // Fold in timing/window accounting first.
  UpdatePingInfoFromPacket(*packet);

  // Ack window: ack everything older than 'expected', and also bits in early mask for last 32.
  const uint32_t earlyMask = packet->header.mEarlyMask;

  // Iterate intrusive list and prefetch next before AddPacket(), because AddPacket unlinks nodes.
  using PacketNode = TDatListItem<SNetPacket, void>;
  PacketNode* const end = static_cast<PacketNode*>(&mUnAckedPayloads);
  for (PacketNode* node = end->mNext; node != end;) {
    auto* p = static_cast<SNetPacket*>(node);
    node = node->mNext;

    const int16_t d = static_cast<int16_t>(p->header.mSequenceNumber - expected);
    bool ack = false;
    if (d < 0) {
      ack = true;
    } else {
      const uint16_t idx = static_cast<uint16_t>(d - 1);
      if (idx <= 0x1F) {
        ack = ((earlyMask >> idx) & 1u) != 0;
      }
    }

    if (ack && mConnector) {
      mConnector->AddPacket(p);
    }
  }

  // Track far end's window head if it advanced.
  if (static_cast<int16_t>(expected - mRemoteExpectedSequenceNumber) > 0) {
    mRemoteExpectedSequenceNumber = expected;
  }

  return true;
}

/**
 * Address: 0x00486DB0 (FUN_00486DB0)
 *
 * What it does:
 * Applies ACK processing, inserts/filters incoming DATA by sequence window,
 * drains in-order payloads into input stream, and rebuilds early ACK mask.
 */
void CNetUDPConnection::ProcessData(SNetPacket* packet)
{
  if (!ProcessAckInternal(packet)) {
    return;
  }

  AdoptPacket(packet);

  // Compute delta = seq - expected
  const uint16_t seq = packet->header.mSequenceNumber;
  const int16_t delta = static_cast<int16_t>(seq - mExpectedSequenceNumber);

  if (delta < 0) {
    // Repeat of old DATA
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessData(): ignoring repeat of old DATA (seqno=%d, expected=%d)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(seq),
        static_cast<unsigned>(mExpectedSequenceNumber)
      );
    }
    return;
  }

  if (delta > 32) {
    // Too far in the future
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessData(): ignoring DATA from too far in the future (seqno=%d, expected=%d, "
        "delta=%d)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(seq),
        static_cast<unsigned>(mExpectedSequenceNumber),
        static_cast<int>(delta)
      );
    }
    return;
  }

  // Queue packet into early set (sorted, unique). A duplicate stays in the
  // connector's receive batch, which recycles it.
  const bool inserted = InsertEarlySorted(packet);

  if (!inserted) {
    if (net_DebugLevel) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>::ProcessData(): ignoring repeat of future DATA (seqno=%d, expected=%d)",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(seq),
        static_cast<unsigned>(mExpectedSequenceNumber)
      );
    }
    return;
  }

  // 0x00486F50: only an inserted packet refreshes the receive time.
  mLastRecv = packet->mSentTime;

  // Drain in-order packets from the head
  bool progressed = false;
  while (true) {
    if (mEarlyPackets.empty()) {
      break;
    }

    // End-of-stream guard
    if (mReceivedEndOfInput) {
      if (net_DebugLevel) {
        gpg::Logf(
          "CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring DATA after end-of-stream",
          mConnector->GetLocalPort(),
          ToString().c_str()
        );
      }

      SNetPacket* drop = EarlyPopFront();
      if (drop && mConnector) {
        mConnector->AddPacket(drop);
      }
      continue;
    }

    // Peek head; stop if not the expected sequence
    auto* n = mEarlyPackets.begin().node();
    auto* headPacket = static_cast<SNetPacket*>(n);
    if (headPacket->header.mSequenceNumber != mExpectedSequenceNumber) {
      break;
    }

    // Consume this packet
    ConsumePacketHeaderData(headPacket);
    progressed = true;
  }

  // Rebuild ACK mask from remaining early packets
  EarlyRebuildAckMask(mExpectedSequenceNumber, mMask);

  // Signal connector event if progressed (matches SetEvent path in asm)
#if defined(_WIN32)
  if (progressed && mConnector && mConnector->mSelectedEvent) {
    SetEvent(mConnector->mSelectedEvent);
  }
#endif
}

/**
 * Address: 0x00487310 (FUN_00487310)
 *
 * What it does:
 * ACK wrapper that refreshes last receive timestamp on successful ACK handling.
 */
bool CNetUDPConnection::ProcessAck(const SNetPacket* packet)
{
  if (!ProcessAckInternal(packet)) {
    return false;
  }

  mLastRecv = packet->mSentTime;
  return true;
}

/**
 * Address: 0x00487340 (FUN_00487340)
 *
 * What it does:
 * KEEPALIVE wrapper that applies ACK handling and updates response tracking.
 */
bool CNetUDPConnection::ProcessKeepAlive(const SNetPacket* packet)
{
  if (!ProcessAckInternal(packet)) {
    return false;
  }

  mLastRecv = packet->mSentTime;
  AdoptPacket(packet); // SPacket::SPacket(pkt, this)
  return true;
}

/**
 * Address: 0x00487370 (FUN_00487370)
 *
 * What it does:
 * Processes remote GOODBYE by closing receive side and transitioning to errored
 * end-of-input state when needed.
 */
bool CNetUDPConnection::ProcessGoodbye(const SNetPacket* packet)
{
  if (!ProcessAckInternal(packet)) {
    return false;
  }

  mLastRecv = packet->mSentTime;

  if (!mReceivedEndOfInput) {
    mState = kNetStateErrored;
    mReceivedEndOfInput = true;

    if (mFilterStream) {
      try {
        mFilterStream->Close(gpg::Stream::ModeBoth); // VirtClose(2)
      } catch (const std::exception& e) {
        // 0x00487401: a GOODBYE before the deflate stream ended.
        gpg::Logf("Error decompressing data from %s: %s", ToString().c_str(), e.what());
        mState = kNetStateErrored;
      }
      const auto* z = mFilterStream;
      mFilterStream = nullptr;
      delete z; // vtable dtr in asm
    }

    mInputBuffer.Close(gpg::Stream::ModeBoth);
#if defined(_WIN32)
    if (mConnector && mConnector->mSelectedEvent) {
      SetEvent(mConnector->mSelectedEvent);
    }
#endif
  }

  return true;
}

/**
 * Address: 0x00488170 (FUN_00488170)
 *
 * What it does:
 * Calculates exponential resend delay (microseconds) clamped by net resend CVars.
 */
int64_t CNetUDPConnection::CalcResendDelay(const SNetPacket* packet) const
{
  const float baseMs = mPingTime * net_ResendPingMultiplier + static_cast<float>(net_ResendDelayBias);

  int rc = packet->mResendCount;
  if (rc > 3) {
    rc = 3;
  }

  int delayMs = static_cast<int>((1 << rc) * baseMs);
  if (delayMs > net_MaxResendDelay) {
    delayMs = net_MaxResendDelay;
  }
  if (delayMs < net_MinResendDelay) {
    delayMs = net_MinResendDelay;
  }

  return static_cast<int64_t>(delayMs) * 1000LL;
}

/**
 * Address: 0x00488260 (Moho::CNetUDPConnection::GetSentTime)
 *
 * What it does:
 * Returns remaining send backlog budget in bytes (rate-shaped by net_MaxSendRate),
 * or 0 and clears mSendTime when the budget has expired.
 */
int CNetUDPConnection::GetSentTime(const int64_t time)
{
  if (mSendTime != 0) {
    const int result = mSendTime - (time - mLastSend.mTime) * net_MaxSendRate * 0.000001;
    if (result > 0) {
      return result;
    }
    mSendTime = 0;
  }
  return 0;
}

/**
 * Address: 0x004882C0 (FUN_004882C0, inlined/chunk helper lane)
 * Address: 0x0048AC40 (inlined helper inside FUN_0048AC40)
 *
 * What it does:
 * Helper used by connector send loop to convert per-connection backlog into
 * timeout ms against net_MaxBacklog.
 *
 * Binary note:
 * In FA this logic is inlined in CNetUDPConnector::SendData (0x0048AC40),
 * not a standalone method symbol.
 */
int CNetUDPConnection::GetBacklogTimeout(const int64_t time, int32_t& timeout)
{
  const int backlog = GetSentTime(time);
  if (backlog > net_MaxBacklog) {
    timeout = 1000 * (backlog - net_MaxBacklog) / net_MaxSendRate;
    return false;
  }

  timeout = 0;
  return true;
}

/**
 * Address: 0x004881F0 (FUN_004881F0)
 *
 * What it does:
 * Returns non-negative milliseconds until `time` relative to connector clock.
 */
int CNetUDPConnection::TimeSince(const int64_t time) const
{
  const int64_t since = (time - mConnector->GetTime()) / 1000;
  if (since < 0) {
    return 0;
  }
  return static_cast<int>(since);
}

/**
 * Address: 0x00488300 (FUN_00488300)
 *
 * What it does:
 * Main per-connection send scheduler: emits control/data frames, retries
 * unacked payloads, handles timeouts, and returns next wake timeout (ms).
 */
int CNetUDPConnection::SendData()
{
  if (mDestroyed) {
    return -1;
  }

  switch (mState) {
  case kNetStatePending:
  case kNetStateErrored:
    if (mScheduleDestroy) {
      mDestroyed = true;
      return -1;
    }
    return -1;

  case kNetStateConnecting: {
    if (mScheduleDestroy) {
      mDestroyed = true;
      return -1;
    }

    if (mInResponseTo != 0 || mConnector->GetTime() - mLastSend.mTime > 1'000'000) {
      SendPacket(NewConnectPacket());
    }

    return TimeSince(mLastSend.mTime + 1'000'000);
  }

  case kNetStateAnswering: {
    if (mScheduleDestroy) {
      mDestroyed = true;
      return -1;
    }

    if (mInResponseTo != 0 || mConnector->GetTime() - mLastSend.mTime > 1'000'000) {
      SendPacket(NewAnswerPacket());
    }

    return TimeSince(mLastSend.mTime + 1'000'000);
  }

  case kNetStateEstablishing: {
    const int64_t curTime = mConnector->GetTime();
    const int64_t idle = curTime - mLastRecv;

    if (curTime - mLastRecv > 10'000'000) {
      if (net_DebugLevel) {
        gpg::Logf(
          "CNetUDPConnection<%u,%s>::SendData(): connection timed out.",
          mConnector->GetLocalPort(),
          ToString().c_str()
        );
      }
      mState = kNetStateTimedOut;
    } else {
      SNetPacket* packet = nullptr;
      if (!mUnAckedPayloads.empty() && curTime >= mUnAckedPayloads.ListGetNext()->mSentTime) {
        packet = mUnAckedPayloads.ListGetNext();
        packet->ListUnlink();
      } else if (HasPacketWaiting(curTime)) {
        packet = ReadPacket();
      } else if (mScheduleDestroy && mSentShutdown && mUnAckedPayloads.empty()) {
        packet = NewGoodbyePacket();
        mDestroyed = true;
      } else if (curTime >= mLastKeepAlive + mKeepAliveFreqUs) {
        packet = NewPacket(true, 0, PT_KeepAlive);
      } else if (mInResponseTo != 0 && curTime >= mSendBy.mTime) {
        // 0x004885D9: a bare ACK only while a received packet is owed one.
        packet = NewPacket(true, 0, PT_Ack);
      }

      if (packet) {
        SendPacket(packet);
      }

      // Zero asks the connector to call again at once. With nothing sent,
      // flushed data is waiting on a full window: calling again changes
      // nothing until a timer below is due, and the binary (0x00488610) spun
      // here holding the connector lock -- the game thread with it -- for as
      // long as the peer withheld its ACKs. Sleep to the next timer instead;
      // the peer's ACK wakes the connector through the socket event.
      if (packet && (mFlushedOutputData || mPendingOutputData.GetLength() > 0x1F1)) {
        return 0;
      }

      auto since = TimeSince(mLastKeepAlive + mKeepAliveFreqUs);
      if (!mUnAckedPayloads.empty()) {
        const auto sentTime = mUnAckedPayloads.ListGetNext()->mSentTime;
        since = ChooseTimeout(since, TimeSince(sentTime));
      }
      // Pending data only waits on the send deadline while the window can take
      // it (`HasPacketWaiting`); behind a full window that deadline is no
      // reason to wake, and an expired one would spin the same way.
      const bool windowOpen = static_cast<int16_t>(mNextSequenceNumber - mRemoteExpectedSequenceNumber) <= 32;
      if (mSendBy.mTime != 0 &&
          (mInResponseTo != 0 || (windowOpen && (mPendingOutputData.GetLength() != 0 || mOutputFlushPending)))) {
        since = ChooseTimeout(since, TimeSince(mSendBy.mTime));
      }
      return since;
    }
  }
  case kNetStateTimedOut: {
    if (mScheduleDestroy) {
      mDestroyed = true;
      return -1;
    }

    if (mConnector->GetTime() - mLastKeepAlive > mKeepAliveFreqUs) {
      SendPacket(NewPacket(true, 0, PT_KeepAlive));
    }
    return TimeSince(mLastKeepAlive + mKeepAliveFreqUs);
  }

  default:
    GPG_UNREACHABLE()
    return -1;
  }
}

/**
 * Address: 0x00488730 (FUN_00488730)
 *
 * What it does:
 * Determines whether payload/EOF packet emission is due given send windows and
 * output flush state.
 */
bool CNetUDPConnection::HasPacketWaiting(const int64_t nowUs)
{
  // Window check (16-bit arithmetic in asm)
  if (static_cast<int16_t>(mNextSequenceNumber - mRemoteExpectedSequenceNumber) > 32) {
    return false;
  }

  gpg::PipeStream* out = &mPendingOutputData;

  // End-of-stream pending? (read head == read end && AtEnd && !mSentShutdown)
  if (mPendingOutputData.mReadHead == mPendingOutputData.mReadEnd && out->VirtAtEnd() && !mSentShutdown) {
    return true;
  }

  // Hold-off sending small chunks until mSendBy or keepalive kick-in
  if (nowUs <= mSendBy.mTime && !mFlushedOutputData && nowUs < (mLastKeepAlive + mKeepAliveFreqUs)) {
    // 497 bytes threshold from asm
    return mPendingOutputData.GetLength() >= kNetPacketMaxPayload;
  }

  // Pending flush request?
  if (mOutputFlushPending) {
    if (mOutputFilterStream) {
      mOutputFilterStream->VirtFlush();
    }
    out->VirtFlush();
    mOutputFlushPending = false;
  }

  // Any bytes available?
  return mPendingOutputData.GetLength() != 0;
}

/**
 * Address: 0x00488980 (FUN_00488980)
 *
 * What it does:
 * Builds next DATA packet from pending output stream and updates send counters.
 */
SNetPacket* CNetUDPConnection::ReadPacket()
{
  // clamp payload to wire limit
  unsigned int len = mPendingOutputData.GetLength();
  if (len >= static_cast<unsigned int>(kNetPacketMaxPayload)) {
    len = kNetPacketMaxPayload;
  }

  // allocate with header inheritance (seq/expected/mask)
  SNetPacket* packet = NewPacket(true, static_cast<int>(len), PT_Data);
  if (!packet) {
    return nullptr;
  }

  // copy payload
  if (len != 0) {
    const auto dst = reinterpret_cast<char*>(&packet->data[0]);

    // fast path if contiguous
    if (len <= static_cast<unsigned int>(mPendingOutputData.mReadEnd - mPendingOutputData.mReadHead)) {
      // Raw pending-output stream blob copy.
      std::copy_n(mPendingOutputData.mReadHead, len, dst);
      mPendingOutputData.mReadHead += len;
    } else {
      mPendingOutputData.Read(dst, len); // virtual read
    }

    // adjust "flushed output" debt
    if (len >= mFlushedOutputData) {
      mFlushedOutputData = 0;
    } else {
      mFlushedOutputData -= len;
    }

    // stats + md5
    mTotalBytesSent += len;
    mTotalBytesSentMD5.Update(dst, len);

    // advance local sequence
    ++mNextSequenceNumber;
    return packet;
  }

  // zero-length DATA > EOF marker;
  // flag shutdown and advance seq
  ++mNextSequenceNumber;
  mSentShutdown = true;
  return packet;
}

/**
 * Address: 0x00488810 (FUN_00488810)
 *
 * What it does:
 * Builds a CONNECT control packet with current nonce/time/compression.
 */
SNetPacket* CNetUDPConnection::NewConnectPacket() const
{
  constexpr auto payloadSize = sizeof(SPacketBodyConnect);

  // allocate with no header inheritance (seq/expected/mask all zero)
  SNetPacket* packet = NewPacket(false, payloadSize, PT_Connect);
  if (!packet) {
    return nullptr;
  }

  auto& connectPacket = packet->As<SPacketBodyConnect>();

  connectPacket.protocol = ENetProtocolType::kUdp;
  connectPacket.time = mConnector->GetTime();
  connectPacket.comp = mOurCompressionMethod;

  // Crypto nonce blob copy (opaque 32-byte handshake field).
  std::copy_n(mNonceA, 32, connectPacket.senderNonce);
  return packet;
}

/**
 * Address: 0x004888C0 (FUN_004888C0)
 *
 * What it does:
 * Builds an ANSWER control packet with local/remote nonce fields.
 */
SNetPacket* CNetUDPConnection::NewAnswerPacket() const
{
  constexpr auto payloadSize = sizeof(SPacketBodyAnswer);

  // allocate with no header inheritance (seq/expected/mask all zero)
  SNetPacket* packet = NewPacket(false, payloadSize, PT_Answer);
  if (!packet) {
    return nullptr;
  }

  auto& answerPacket = packet->As<SPacketBodyAnswer>();

  answerPacket.protocol = ENetProtocolType::kUdp;
  answerPacket.time = mConnector->GetTime();
  answerPacket.comp = mOurCompressionMethod;

  // Crypto nonce blob copy (opaque 32-byte handshake field).
  std::copy_n(mNonceA, 32, answerPacket.senderNonce);
  // Crypto nonce blob copy (opaque 32-byte handshake field).
  std::copy_n(mNonceB, 32, answerPacket.receiverNonce);
  return packet;
}

/**
 * Address: 0x00488AA0 (FUN_00488AA0)
 *
 * What it does:
 * Builds a GOODBYE control packet (empty payload).
 */
SNetPacket* CNetUDPConnection::NewGoodbyePacket() const
{
  SNetPacket* packet = NewPacket(false, 0, PT_Goodbye);
  if (!packet) {
    return nullptr;
  }

  return packet;
}

/**
 * Address: 0x00488B20 (FUN_00488B20)
 *
 * What it does:
 * Allocates/reuses a packet node, resets metadata, and fills transport header
 * fields with optional sequence inheritance.
 */
SNetPacket* CNetUDPConnection::NewPacket(const bool inherit, const int size, const EPacketType state) const
{
  // take from connector's pool or allocate
  SNetPacket* pkt;
  if (mConnector->mPacketList.mNext != &mConnector->mPacketList) {
    --mConnector->mPacketPoolSize;
    pkt = reinterpret_cast<SNetPacket*>(mConnector->mPacketList.mNext);
    // unlink from pool
    pkt->ListUnlink();
  } else {
    // 536 bytes (0x218 from asm)
    pkt = new SNetPacket();
    if (!pkt) {
      return nullptr;
    }
  }
  // reset intrusive node
  pkt->mNext = pkt;
  pkt->mPrev = pkt;

  // zero resend counter and set wire sizes/state
  pkt->mResendCount = 0;
  pkt->mSize = static_cast<int32_t>(size) + kNetPacketHeaderSize;
  pkt->header.mType = state;

  // sequence/ack header inheritance
  pkt->header.mSequenceNumber = inherit ? mNextSequenceNumber : 0;
  pkt->header.mExpectedSequenceNumber = inherit ? mExpectedSequenceNumber : 0;
  pkt->header.mEarlyMask = inherit ? mMask : 0u;

  // payload length always set in header (even for control packets)
  pkt->header.mPayloadLength = static_cast<std::uint16_t>(size);

  return pkt;
}

/**
 * Address: 0x00488D80 (FUN_00488D80)
 *
 * What it does:
 * Emits a packet to socket, updates resend/sequence/keepalive bookkeeping, and
 * records send diagnostics.
 */
void CNetUDPConnection::SendPacket(SNetPacket* packet)
{
  packet->header.mSerialNumber = mNextSerialNumber;
  packet->header.mInResponseTo = mInResponseTo;

#if defined(_WIN32)
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_port = htons(mPort);
  to.sin_addr.s_addr = htonl(mAddr);
#else
#error "Implement me on non-Windows platform!"
#endif

  const auto payloadLen = static_cast<int>(packet->GetPayloadSize());
  const auto payload = static_cast<const char*>(packet->GetPayload());
  sendto(mConnector->socket_, payload, payloadLen, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));

  const int64_t nowUs = mConnector->GetTime();
  mConnector->LogPacket(0, nowUs, mAddr, mPort, payload, payloadLen);
  mConnector->mSendStampBuffer.Add(0, nowUs, payloadLen);

  if (packet->header.mType == PT_Data) {
    ++packet->mResendCount;
    packet->mSentTime = nowUs + CalcResendDelay(packet); // microseconds
    InsertUnAckedSorted(packet);
  } else {
    // Return to connector pool immediately for any other:
    // CONNECT, ANSWER, RESETSERIAL, SERIALRESET, ACK, KEEPALIVE, GOODBYE, NATTRAVERSAL
    mConnector->AddPacket(packet);
  }

  if (net_DebugLevel >= 2) {
    const auto pktStr = packet->ToString();
    const auto connStr = ToString();
    const auto timeStr = gpg::FileTimeToString(nowUs);
    gpg::Debugf("%s: send %s, %s", timeStr.c_str(), connStr.c_str(), pktStr.c_str());
  }

  ++mNextSerialNumber;
  mInResponseTo = 0;

  if (mPendingOutputData.GetLength()) {
    // time in us
    mSendBy.mTime = nowUs + 1000LL * net_SendDelay;
  } else {
    mSendBy.mTime = 0;
  }

  mTimings[packet->header.mSerialNumber & 0x7F].mSource = packet->header.mSerialNumber;
  mTimings[packet->header.mSerialNumber & 0x8000007F].mTime.Reset();

  mSendTime = packet->mSize + GetSentTime(nowUs);
  mLastSend.mTime = nowUs;

  if (packet->header.mType != PT_Ack) {
    mLastKeepAlive = nowUs;
  }

  if (packet->header.mType == PT_KeepAlive) {
    mKeepAliveFreqUs = 2'000'000; // 2s
  }
}

/**
 * Address: 0x00487590 (FUN_00487590)
 * Address: 0x10080FD0 (sub_10080FD0)
 *
 * What it does:
 * Flushes receive filter/input stream while input is still open.
 */
void CNetUDPConnection::FlushInput()
{
  if (!mScheduleDestroy && !mReceivedEndOfInput) {
    if (mFilterStream != nullptr) {
      try {
        mFilterStream->VirtFlush();
      } catch (const std::exception& e) {
        // 0x004875F8: the peer's deflate data is corrupt.
        gpg::Logf("Error decompressing data from %s: %s", ToString().c_str(), e.what());
        mInputBuffer.Close(gpg::Stream::ModeBoth);
        mState = kNetStateErrored;
        mReceivedEndOfInput = true;
        // The binary went on to flush the input stream it had just closed,
        // which throws; stop here instead.
        return;
      }
    }
    mInputBuffer.VirtFlush();
  }
}

/**
 * Address: 0x004879E0 (FUN_004879E0, inlined/chunk helper lane)
 * Address: 0x0048B7F0 (inlined helper inside FUN_0048B7F0)
 *
 * What it does:
 * Flushes pending output/filter streams and snapshots currently flushed bytes.
 *
 * Binary note:
 * In FA this logic is inlined in CNetUDPConnector::Push (0x0048B7F0),
 * not a standalone CNetUDPConnection symbol.
 */
bool CNetUDPConnection::FlushOutput()
{
  if (!mOutputShutdown) {
    if (mOutputFilterStream != nullptr) {
      mOutputFilterStream->VirtFlush();
    }
    mPendingOutputData.VirtFlush();
    mFlushedOutputData = mPendingOutputData.GetLength();
  }
  return mFlushedOutputData != 0;
}

/**
 * Address: 0x004876A0 (FUN_004876A0)
 * Address: 0x100810D0 (sub_100810D0)
 * Address: 0x100813A0 (sub_100810D0, alias/chunk export)
 *
 * What it does:
 * Drains framed messages from input stream, updates dispatch stats, forwards to
 * per-type receiver, and emits EOF/errored disconnect notifications.
 */
void CNetUDPConnection::DispatchFromInput()
{
  if (mDispatchedEndOfInput || mScheduleDestroy) {
    return;
  }

  while (mMessage.Read(&mInputBuffer)) {
    const ELobbyMsg streamMsg = mMessage.GetType();
    const auto msgType = static_cast<uint8_t>(streamMsg);

    // Types 200..209 are connection events this side makes up; no peer sends
    // them. The only genuine one in the stream is the ConnMade that
    // `CreateFilterStream` writes ahead of the peer's first byte.
    if (msgType >= MSGTYPE_LobbyBase && msgType < MSGTYPE_LobbyEnd) {
      if (streamMsg != ELobbyMsg::LOBMSG_ConnMade || mDispatchedConnMade) {
        mMessage.mBuff.Clear();
        mMessage.mPos = 0;
        continue;
      }
      mDispatchedConnMade = true;
    }
    if (streamMsg != ELobbyMsg::LOBMSG_ConnMade) {
      const size_t len = mMessage.mBuff.Size();
      mTotalBytesDispatched += len;
      mTotalBytesDispatchedMD5.Update(&mMessage.mBuff[0], len);
    }

    if (net_DebugLevel >= 3) {
      msvc8::string digStr = mTotalBytesDispatchedMD5.Digest().ToString();
      msvc8::string thisStr = ToString();
      msvc8::string timeStr = gpg::FileTimeToString(mConnector->GetTime());
      gpg::Debugf(
        "%s: %s: msg type %d dispatched [%d bytes, total now %lld, md5 %s]",
        timeStr.c_str(),
        thisStr.c_str(),
        static_cast<unsigned>(msgType),
        static_cast<int>(mMessage.mBuff.Size()),
        mTotalBytesDispatched,
        digStr.c_str()
      );
    }

    const auto receiver = mReceivers[msgType];
    if (receiver == nullptr) {
      // A peer can send any type byte; warn about the first few only.
      if (mUnroutedMessageCount < kMaxUnroutedMessageWarnings) {
        ++mUnroutedMessageCount;
        msvc8::string host = NET_GetHostName(mAddr);
        gpg::Warnf(
          "No receiver for message type %d received from %s:%d.", static_cast<unsigned>(msgType), host.c_str(), mPort
        );
        if (mUnroutedMessageCount == kMaxUnroutedMessageWarnings) {
          gpg::Warnf("Further messages without a receiver from %s:%d will not be reported.", host.c_str(), mPort);
        }
      }
    } else {
      receiver->ReceiveMessage(&mMessage, this);
    }
    mMessage.mBuff.Clear();
    mMessage.mPos = 0;
    if (mScheduleDestroy) {
      return;
    }
  }

  // A header claiming under 3 bytes stops `Read` for good: nothing after it
  // can be framed, and the input would pile up behind it unread.
  if (mMessage.HasInvalidLength()) {
    gpg::Logf(
      "CNetUDPConnection<%u,%s>::DispatchFromInput(): corrupt message (type %u, size %u), dropping input.",
      mConnector->GetLocalPort(),
      ToString().c_str(),
      static_cast<unsigned>(mMessage.GetType().raw()),
      static_cast<unsigned>(mMessage.GetSize())
    );
    {
      boost::recursive_mutex::scoped_lock lock{mConnector->lock_};
      AbortInput();
    }
    mMessage.mBuff.Clear();
    mMessage.mPos = 0;
    mDispatchedEndOfInput = true;
    CMessage lost{ELobbyMsg::LOBMSG_ConnLostErrored};
    Dispatch(&lost);
    return;
  }

  if (!mInputBuffer.CanRead() && mInputBuffer.VirtAtEnd()) {
    mDispatchedEndOfInput = true;
    // 0x00487971: the notice lives on the stack; nothing keeps it.
    CMessage lost{mState == kNetStateErrored ? ELobbyMsg::LOBMSG_ConnLostErrored : ELobbyMsg::LOBMSG_ConnLostEof};
    Dispatch(&lost);
  }
}

/**
 * Address: 0x00487B90 (FUN_00487B90)
 * Address: 0x10081570 (sub_10081570)
 *
 * What it does:
 * Dumps detailed per-connection transport/queue/timing/hash diagnostics.
 */
void CNetUDPConnection::Debug()
{
  const auto time = mConnector->GetTime();
  gpg::Logf("  CNetUDPConnection %p:", static_cast<const void*>(this));
  const msvc8::string address = NET_GetDottedOctetFromUInt32(mAddr);
  const msvc8::string hostname = NET_GetHostName(mAddr);
  gpg::Logf("    remote addr: %s[%s]:%d", hostname.c_str(), address.c_str(), mPort);
  const char* state;
  msvc8::string stateBuffer;
  if (mState > kNetStateErrored) {
    stateBuffer = gpg::STR_Printf("??? (%d)", mState);
    state = stateBuffer.c_str();
  } else {
    state = NetConnectionStateToStr(mState);
  }
  gpg::Logf("    State: %s", state);
  gpg::Logf("    Last Send: %7dusec ago", time - mLastSend.mTime);
  gpg::Logf("    Last Recv: %7dusec ago", time - mLastRecv);
  gpg::Logf("    Last KeepAlive: %7dusec ago", time - mLastKeepAlive);
  gpg::Logf("    KeepAlive Freq: %d", mKeepAliveFreqUs);
  gpg::Logf("    Next Serial Number: %d", mNextSerialNumber);
  gpg::Logf("    In Response To: %d", mInResponseTo);
  if (mSendBy.mTime != 0) {
    gpg::Logf("    Send By: %7dusec from now", mSendBy.mTime - time);
  } else {
    gpg::Logf("    Send By: NA");
  }
  const LONGLONG sentTime = GetSentTime(time);
  gpg::Logf("    Backlog: %d bytes", sentTime);
  gpg::Logf("    Next Sequence Number: %d", mNextSequenceNumber);
  gpg::Logf("    Remote Expected Sequence Number: %d", mRemoteExpectedSequenceNumber);
  gpg::Logf("    Expected Sequence Number: %d", mExpectedSequenceNumber);
  gpg::Logf("    Pending Output Data: %d", mPendingOutputData.GetLength());
  gpg::Logf("    Flushed Output Data: %d", mFlushedOutputData);
  gpg::Logf("    Output Shutdown: %s", mOutputShutdown ? "true" : "false");
  gpg::Logf("    Sent Shutdown: %s", mSentShutdown ? "true" : "false");
  gpg::Logf("    Unacked Payloads:");
  for (const auto* packet : mUnAckedPayloads.owners()) {
    packet->LogPacket("Sent", time);
  }
  gpg::Logf("    Ping Time=%f", mPingTime);
  gpg::Logf("    Early Packets:");
  for (const auto* packet : mEarlyPackets.owners()) {
    packet->LogPacket("Received", time);
  }
  gpg::Logf("    Buffered Input Data: %d bytes", mInputBuffer.GetLength());
  gpg::Logf("    Received End of Input: %s", mReceivedEndOfInput ? "true" : "false");
  gpg::Logf("    Dispatched End of Input: %s", mDispatchedEndOfInput ? "true" : "false");
  gpg::Logf("    Closed: %s", mScheduleDestroy ? "true" : "false");
  gpg::Logf("    Total bytes queued: %llu [%s]", mTotalBytesQueued, mTotalBytesQueuedMD5.Digest().ToString().c_str());
  gpg::Logf("    Total bytes sent: %llu [%s]", mTotalBytesSent, mTotalBytesSentMD5.Digest().ToString().c_str());
  gpg::Logf(
    "    Total bytes received: %llu [%s]", mTotalBytesReceived, mTotalBytesReceivedMD5.Digest().ToString().c_str()
  );
  gpg::Logf(
    "    Total bytes dispatched: %llu [%s]", mTotalBytesDispatched, mTotalBytesDispatchedMD5.Digest().ToString().c_str()
  );
}

/**
 * Address: 0x00488220 (FUN_00488220)
 *
 * What it does:
 * Adopts peer serial as response target and schedules ACK deadline if idle.
 */
void CNetUDPConnection::AdoptPacket(const SNetPacket* packet)
{
  mInResponseTo = packet->header.mSerialNumber;

  if (mSendBy.mTime == 0) {
    // net_AckDelay (ms) -> us
    const int64_t ackDelayUs = static_cast<int64_t>(net_AckDelay) * 1000LL;
    mSendBy.mTime = packet->mSentTime + ackDelayUs;
  }
}

/**
 * Address: <synthetic helper; inlined in the binary's decompression error
 *   handler at 0x0048710B>
 *
 * What it does:
 * Drops the inflate filter, closes the input stream and marks the connection
 * errored: DATA after this is discarded, and dispatch reports
 * `LOBMSG_ConnLostErrored` once the buffered messages are delivered.
 */
void CNetUDPConnection::AbortInput()
{
  if (mFilterStream) {
    const auto* z = mFilterStream;
    mFilterStream = nullptr;
    delete z;
  }
  mInputBuffer.Close(gpg::Stream::ModeBoth);
  mState = kNetStateErrored;
  mReceivedEndOfInput = true;
}

/**
 * Address: 0x004874C0 (FUN_004874C0)
 *
 * What it does:
 * Updates rolling ping/jitter statistics from packet response serial timing.
 */
void CNetUDPConnection::UpdatePingInfoFromPacket(const SNetPacket& packet)
{
  if (!packet.header.mInResponseTo) {
    return;
  }

  const uint16_t src = packet.header.mInResponseTo;
  const uint32_t index = (src & 0x7F); // 128-entry ring

  if (mTimings[index].mSource == src) {
    // Elapsed time in ms since we timestamped that serial
    const float rawMs = mTimings[index].mTime.ElapsedMilliseconds();

    // Update running stats (median/jitter)
    mPings.Append(rawMs);
    const float filtered = mPings.Median();
    mPingTime = filtered;
    const float jit = mPings.Jitter(filtered);

    if (net_DebugLevel) {
      gpg::Logf("Ping time: raw=%7.3fms filtered=%7.3fms, jitter=%7.3f", rawMs, mPingTime, jit);
    }

    // Reset keep-alive cadence to 2s (microseconds)
    mKeepAliveFreqUs = 2'000'000;
  }
}

/**
  * Alias of FUN_00486DB0 (non-canonical helper lane).
 *
 * What it does:
 * Inserts DATA packet into future-queue sorted by sequence and rejects duplicates.
 */
bool CNetUDPConnection::InsertEarlySorted(SNetPacket* packet)
{
  // Walk list to find insertion point (first element with seq > p->seq).
  // 0x00486F0B scans before it unlinks: a duplicate must stay linked in the
  // connector's receive batch, or nothing ever frees it.
  SNetPacket* insertBefore = nullptr;
  for (auto* cur : mEarlyPackets.owners()) {
    if (cur->header.mSequenceNumber == packet->header.mSequenceNumber) {
      // Duplicate of a future DATA - ignore insertion
      return false;
    }

    if (static_cast<int16_t>(cur->header.mSequenceNumber - packet->header.mSequenceNumber) > 0) {
      insertBefore = cur;
      break;
    }
  }

  // Detach from the receive batch. ListUnlink() (not used here) returns the
  // OLD mNext -- some other node entirely, not packet itself -- so using its
  // return value here spliced whatever packet used to point to into
  // mEarlyPackets instead of packet. ListUnlinkSelf() returns `this`.
  const auto node = packet->ListUnlinkSelf();
  if (insertBefore != nullptr) {
    node->ListLinkBefore(insertBefore);
  } else {
    // Insert at tail (before end sentinel)
    node->ListLinkBefore(mEarlyPackets.end().node());
  }
  return true;
}

/**
  * Alias of FUN_00486DB0 (non-canonical helper lane).
 *
 * What it does:
 * Pops the oldest packet from the early/future queue.
 */
SNetPacket* CNetUDPConnection::EarlyPopFront()
{
  // mEarlyPackets.ListUnlink() (not used here) unlinks the SENTINEL itself
  // from the ring -- it returns the front element (correct value), but also
  // splices the sentinel out, leaving any remaining queued packets linked to
  // each other but unreachable from mEarlyPackets. pop_front() unlinks the
  // front element instead, which is what this needs.
  auto* const node = mEarlyPackets.pop_front();
  return static_cast<SNetPacket*>(node);
}

/**
  * Alias of FUN_00486DB0 (non-canonical helper lane).
 *
 * What it does:
 * Recomputes ACK early-mask bits from queued future packet sequences.
 */
void CNetUDPConnection::EarlyRebuildAckMask(const uint16_t expected, uint32_t& mask)
{
  mask = 0;
  for (const auto* cur : mEarlyPackets.owners()) {
    const int16_t d = static_cast<int16_t>(cur->header.mSequenceNumber - expected);
    if (d >= 1 && d <= 32) {
      mask |= (1u << (d - 1));
    }
  }
}

/**
  * Alias of FUN_00486DB0 (non-canonical helper lane).
 *
 * What it does:
 * Consumes one in-order DATA packet payload into input pipeline and advances
 * expected sequence/input-end state.
 */
void CNetUDPConnection::ConsumePacketHeaderData(SNetPacket* packet)
{
  const uint16_t payloadLen = packet->header.mPayloadLength;

  if (payloadLen != 0) {
    const auto payload = reinterpret_cast<const char*>(&packet->data[0]);

    // Stats
    mTotalBytesReceived += payloadLen;
    mTotalBytesReceivedMD5.Update(payload, payloadLen);

    // Write through filter if present
    try {
      if (mFilterStream) {
        mFilterStream->Write(payload, payloadLen);
      } else {
        mInputBuffer.Write(payload, payloadLen);
      }
    } catch (const std::exception& e) {
      // 0x0048710B: the peer's deflate data is corrupt.
      gpg::Logf("Error decompressing data from %s: %s", ToString().c_str(), e.what());
      AbortInput();
    }

    // The game thread has fallen this far behind, or a small deflate stream
    // has expanded this far: either way the peer is not playing.
    if (!mReceivedEndOfInput && mInputBuffer.GetLength() > kMaxBufferedInputBytes) {
      gpg::Logf(
        "CNetUDPConnection<%u,%s>: over %u bytes received and not yet dispatched, dropping input.",
        mConnector->GetLocalPort(),
        ToString().c_str(),
        static_cast<unsigned>(kMaxBufferedInputBytes)
      );
      AbortInput();
    }
  } else {
    // End-of-input marker
    if (mFilterStream) {
      try {
        mFilterStream->Close(gpg::Stream::ModeBoth);
      } catch (const std::exception& e) {
        // 0x004871E9: end of input before the deflate stream ended.
        gpg::Logf("Error decompressing data from %s: %s", ToString().c_str(), e.what());
        mState = kNetStateErrored;
      }
      const auto* z = mFilterStream;
      mFilterStream = nullptr;
      delete z;
    }
    mInputBuffer.Close(gpg::Stream::ModeBoth);
    mReceivedEndOfInput = true;
  }

  // Advance expected sequence
  ++mExpectedSequenceNumber;

  // Return packet to pool
  if (mConnector) {
    mConnector->AddPacket(packet);
  }
}

/**
 * Address: 0x00485AA0 (FUN_00485AA0)
 *
 * What it does:
 * Compares expected and received 32-byte nonce lanes.
 */
bool CNetUDPConnection::ReceiverNonceDiffers32(const char (&expected)[32], const char (&received)[32]) noexcept
{
  return ByteArrayDiffers(expected, received);
}


/**
  * Alias of FUN_00488D80 (non-canonical helper lane).
 *
 * What it does:
 * Inserts outbound DATA packet into resend queue ordered by scheduled send time.
 */
void CNetUDPConnection::InsertUnAckedSorted(SNetPacket* packet)
{
  // See InsertEarlySorted's comment: ListUnlinkSelf() returns `this`
  // (packet), not the OLD mNext ListUnlink() would return.
  const auto node = packet->ListUnlinkSelf();

  for (auto* cur : mUnAckedPayloads.owners()) {
    if (packet->mSentTime < cur->mSentTime) {
      node->ListLinkBefore(cur);
      return;
    }
  }
  // append at tail
  node->ListLinkBefore(mUnAckedPayloads.end().node());
}

