#include "NetGameChannel.h"

#include "CNetUDPConnection.h"
#include "CNetUDPConnector.h"
#include "NetConVars.h"
#include "NetPeerTransport.h"
#include "SNetPacket.h"
#include "gpg/core/utils/Logging.h"
#include "remote/net/DatagramCipher.h"
#include "remote/net/NetChannel.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace moho
{
  namespace
  {
    namespace rn = faf::remote::net;

    // The first byte of each reliable message on the channel.
    constexpr std::uint8_t kStreamBytes = 1; // then stream bytes
    constexpr std::uint8_t kStreamEnd = 2;   // the sender closed its stream

    // How often SendData wakes while the channel has something in flight or an ack is owed (ms): the channel's ack
    // delay is 10 ms and its repeat interval 30 ms.
    constexpr int kBusyWakeMs = 5;
    constexpr int kIdleWakeMs = 100;

    struct GameChannel
    {
      explicit GameChannel(
        const rn::ChannelConfig& config
      )
        : channel(config)
      {}

      rn::NetChannel channel;
      std::uint64_t datagramsSent = 0;
    };

    // Keyed by connection. Every use but the destructor's holds the connector lock; the destructor may run on the
    // connector's thread after it let go of a connection, so the table has its own lock too.
    struct Table
    {
      std::mutex lock;
      std::unordered_map<const CNetUDPConnection*, std::unique_ptr<GameChannel>> channels;
    };

    Table& Channels()
    {
      static Table* const table = new Table(); // used by connector threads until they end; never destroyed
      return *table;
    }

    GameChannel* Find(
      const CNetUDPConnection* connection
    )
    {
      Table& t = Channels();
      std::scoped_lock lock(t.lock);
      const auto it = t.channels.find(connection);
      return it == t.channels.end() ? nullptr : it->second.get();
    }

    rn::ChannelConfig GameChannelConfig()
    {
      rn::ChannelConfig config;
      config.reliableRepeats = static_cast<std::uint32_t>(std::clamp(net_GameChannelRepeats, 0, 8));
      config.redundancy = 0;
      // No lane messages here, so the lane's repeat interval is the reliable repeats' first gap alone.
      config.redundantRepeatUs = static_cast<std::uint64_t>(std::clamp(net_GameChannelRepeatMs, 5, 1000)) * 1000;
      // The connection has its own liveness check (10 s without a datagram); the channel never times out by itself.
      config.timeoutUs = 24ull * 3600 * 1000 * 1000;
      // A keepalive at least every 250 ms, so only an outage leaves resendAfterSilenceUs without a datagram.
      config.keepaliveIntervalUs = 250'000;
      // A few datagrams per call, each counted against net_MaxSendRate as a shipped packet is (SendPacket), so the
      // connector's backlog check paces bulk data (a large order, a rejoin's save) as it always has.
      config.maxDatagramsPerPoll = 8;
      // net_GameChannelRepeatHoldMs: repeats only while the link loses; 0 (default), always (the measurements:
      // at most 11 % fewer bytes, but on a 0.5 % loss link more than twice the order delay needed).
      config.reliableRepeatHoldUs = static_cast<std::uint64_t>(std::max(net_GameChannelRepeatHoldMs, 0)) * 1000;
      // After an outage the first datagram from the peer sends everything in flight again at once.
      config.resendAfterSilenceUs = 500'000;
      return config;
    }
  } // namespace

  void NET_ForgetGameChannel(
    const CNetUDPConnection* const connection
  )
  {
    Table& t = Channels();
    std::scoped_lock lock(t.lock);
    t.channels.erase(connection);
  }

  bool CNetUDPConnection::InGameChannel() const
  {
    return Find(this) != nullptr;
  }

  bool CNetUDPConnection::StartGameChannel()
  {
    if (Find(this) != nullptr) {
      return true;
    }
    if (net_GameChannel == 0) {
      return false;
    }
    rn::ChannelKeys keys;
    bool keyed = false;
    if (!NET_PeerTransportOffersGameChannel(mConnector, GetAddr(), GetPort(), keys, keyed)) {
      return false;
    }
    auto channel = std::make_unique<GameChannel>(GameChannelConfig());
    if (keyed) {
      keyed = channel->channel.SetKeys(keys);
    }
    rn::WipeKey(keys.send);
    rn::WipeKey(keys.receive);
    {
      Table& t = Channels();
      std::scoped_lock lock(t.lock);
      t.channels[this] = std::move(channel);
    }
    gpg::Logf(
      "NET: %s carries its stream on the game channel (%s)", ToString().c_str(), keyed ? "encrypted" : "not encrypted"
    );
    return true;
  }

  int CNetUDPConnection::GameChannelSendData(
    const std::int64_t nowUs
  )
  {
    GameChannel* const gc = Find(this);
    rn::NetChannel& channel = gc->channel;
    const auto now = static_cast<std::uint64_t>(nowUs);

    // The stream: held, as DATA packets are, until it is flushed, net_SendDelay has passed or a packet's worth waits
    // (HasPacketWaiting); then all of it goes into the channel at once.
    const bool hold = nowUs <= mSendBy.mTime && mFlushedOutputData == 0 &&
      mPendingOutputData.GetLength() < static_cast<unsigned int>(kNetPacketMaxPayload);
    if (!hold) {
      if (mOutputFlushPending) {
        if (mOutputFilterStream) {
          mOutputFilterStream->VirtFlush();
        }
        mPendingOutputData.VirtFlush();
        mOutputFlushPending = false;
      }
      const unsigned int length = mPendingOutputData.GetLength();
      if (length != 0) {
        std::vector<std::uint8_t> message(1 + static_cast<std::size_t>(length));
        message[0] = kStreamBytes;
        mPendingOutputData.Read(reinterpret_cast<char*>(message.data() + 1), length);
        mTotalBytesSent += length;
        mTotalBytesSentMD5.Update(message.data() + 1, length);
        (void)channel.SendReliable(message.data(), message.size());
      }
      mFlushedOutputData = 0;
      if (!mOutputFlushPending) {
        mSendBy.mTime = 0;
      }
    }
    // Close(): the end of the stream, once everything before it went in.
    if (
      !mSentShutdown && mPendingOutputData.mReadHead == mPendingOutputData.mReadEnd && mPendingOutputData.VirtAtEnd()
    ) {
      const std::uint8_t end = kStreamEnd;
      (void)channel.SendReliable(&end, 1);
      mSentShutdown = true;
    }

    // An ACK still owed for a shipped packet (the handshake's ANSWER), so the peer's side completes as shipped.
    if (mInResponseTo != 0 && nowUs >= mSendBy.mTime) {
      SendPacket(NewPacket(true, 0, PT_Ack));
    }

    std::vector<std::vector<std::uint8_t>> datagrams;
    channel.Poll(now, datagrams);
    for (const std::vector<std::uint8_t>& d : datagrams) {
      mSendTime = static_cast<int>(d.size()) + GetSentTime(nowUs);
      mLastSend.mTime = nowUs;
      if (NET_SendThroughPeerTransport(mConnector, GetAddr(), GetPort(), d.data(), d.size())) {
        ++gc->datagramsSent;
        gNetTraffic.packets.fetch_add(1, std::memory_order_relaxed);
        gNetTraffic.bytes.fetch_add(static_cast<std::int64_t>(d.size()), std::memory_order_relaxed);
      }
    }
    const rn::ChannelStats& stats = channel.Stats();
    if (stats.rttSamples > 0) {
      mPingTime = static_cast<float>(stats.rttSmoothedUs) / 1000.0f;
    }
    // Retail keepalive bookkeeping: the channel keeps the link alive.
    mLastKeepAlive = nowUs;

    // Goodbye as shipped, once the stream's end is acked.
    if (mScheduleDestroy && mSentShutdown && channel.ReliableUnacked() == 0) {
      SNetPacket* const goodbye = NewGoodbyePacket();
      mDestroyed = true;
      SendPacket(goodbye);
      return -1;
    }

    // A full batch: call again at once (the connector's backlog check decides whether it may send now).
    if (datagrams.size() >= GameChannelConfig().maxDatagramsPerPoll) {
      return 0;
    }
    const bool busy = channel.ReliableUnacked() != 0 || stats.redundantUnacked != 0 || !datagrams.empty();
    int wake = busy ? kBusyWakeMs : kIdleWakeMs;
    if (mSendBy.mTime != 0) {
      wake = std::min(wake, TimeSince(mSendBy.mTime));
    }
    return wake;
  }

  void CNetUDPConnection::ProcessGameChannelDatagram(
    const std::uint8_t* const data,
    const std::size_t size
  )
  {
    // The peer finished its handshake first and went to the channel: its datagrams complete ours, as its ACK would.
    if (Find(this) == nullptr && (mState != kNetStateAnswering || !StartGameChannel())) {
      return;
    }
    if (mState == kNetStateAnswering) {
      CreateFilterStream();
    } else if (mState == kNetStateTimedOut) {
      mState = kNetStateEstablishing;
    }
    if (mState != kNetStateEstablishing) {
      return;
    }
    GameChannel* const gc = Find(this);
    if (gc == nullptr) {
      return;
    }
    const std::int64_t nowUs = mConnector->GetTime();
    if (gc->channel.Receive(data, size, static_cast<std::uint64_t>(nowUs)) != rn::ReceiveResult::Accepted) {
      return;
    }
    mLastRecv = nowUs;
    std::vector<std::uint8_t> message;
    bool progressed = false;
    while (gc->channel.TakeReliable(message)) {
      if (message.empty() || mReceivedEndOfInput) {
        continue;
      }
      if (message[0] == kStreamBytes && message.size() > 1) {
        ConsumeInputBytes(reinterpret_cast<const char*>(message.data() + 1), message.size() - 1);
      } else if (message[0] == kStreamEnd) {
        ConsumeEndOfInput();
      }
      progressed = true;
    }
    if (progressed && mConnector->mSelectedEvent) {
      SetEvent(mConnector->mSelectedEvent);
    }
  }
} // namespace moho
