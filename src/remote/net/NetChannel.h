#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

#include "remote/net/Datagram.h"
#include "remote/net/DatagramCipher.h"
#include "remote/net/ReliableStream.h"

// Engine addition, net channel (plan §7.1, D1; WP10.2, WP10.3, WP10.6, WP10.8): one end of a
// link to one peer. It does no I/O and reads no clock: the owner hands it each datagram that
// arrives with the time, calls Poll() with the time to collect the datagrams to send, and
// moves them over whatever carries them (a UDP socket for the server, the game's link for
// peers). Every time is in microseconds on one monotonic clock of the owner's choosing.
//
// What goes over it:
//   - reliable messages, in order, of any size up to ChannelConfig::maxMessageSize
//     (ReliableStream.h);
//   - unreliable messages: one datagram each, delivered at most once, never resent:
//       [2] chunk type 2, varint length, the bytes
//
// Redundant messages (issue #240): unreliable messages that ride again in the
// next datagrams until one carrying them is acked, at most `redundancy` more
// times each, so one lost datagram costs no wait:
//       [4] chunk type 4, varint lane sequence (1, 2, ...), varint length, the bytes
// The receiver hands each lane sequence out once (TakeUnreliable) and drops
// repeats. With nothing new to send, Poll repeats unacked ones at most every
// redundantRepeatUs.
//
// Acks: the header acks the newest datagram and the 32 before it. When more than that
// arrived since the last datagram out (a burst), an ack chunk covers the rest, up to 16
// blocks of 32 below the header's range:
//       [3] chunk type 3, varint block count, per block: varint (header ack - block top),
//           4 bytes of bits, bit i set when sequence (block top - i) was received
// An ack goes out at once after a gap, a late arrival or 4 unanswered datagrams.
//
// What it keeps (WP10.8): an ack-only datagram goes out within ackDelayUs of an arrival
// when nothing else does; a keepalive goes out when nothing was sent for
// keepaliveIntervalUs (ack-only datagrams do not count), so an idle link keeps measuring its
// RTT; RTT and its variation are smoothed as RFC 6298 does, from the newest acked datagram
// less the delay the peer reports, and the retransmission timeout adds maxAckDelayUs;
// a datagram counts as lost once one sent lossThreshold later is acked, or once it is older
// than 9/8 RTT behind an acked one, or older than the retransmission timeout; a late ack
// takes a loss back, and raises the reordering allowance (the count to what was seen, the
// time by 1/8 RTT, to 2 RTT) so a path that reorders stops causing resends; and the
// channel times out when nothing arrives for timeoutUs, which the server's disconnect
// handling (WP3.5) reads from State().

namespace faf::remote::net
{
  struct ChannelConfig
  {
    std::size_t maxDatagramSize = kMaxDatagramSize;
    /** Reliable bytes sent past the peer's acked prefix at most. */
    std::size_t maxReliableInFlight = 256 * 1024;
    /** Out-of-order reliable bytes the receiver holds at most; later ones come back. */
    std::size_t receiveWindow = 1024 * 1024;
    std::size_t maxMessageSize = 16 * 1024 * 1024;
    /** Unreliable messages waiting either way at most; past it they are dropped. */
    std::size_t maxUnreliableQueued = 1024;
    std::size_t maxDatagramsPerPoll = 64;
    /** The first sequence number sent (1 in use; tests start near the end). */
    std::uint32_t firstSequence = 1;
    /** SendRedundant: how many later datagrams repeat each message (0: none). */
    std::uint32_t redundancy = 2;
    /** With nothing new to send, unacked redundant messages go again this often. */
    std::uint64_t redundantRepeatUs = 30'000;
    std::uint64_t ackDelayUs = 10'000;
    /** The most ack delay a peer's report may take off an RTT sample; added to the RTO. */
    std::uint64_t maxAckDelayUs = 25'000;
    std::uint64_t keepaliveIntervalUs = 250'000;
    std::uint64_t timeoutUs = 10'000'000;
    std::uint32_t lossThreshold = 3;
    std::uint64_t initialRttUs = 100'000;
    std::uint64_t minRtoUs = 50'000;
    std::uint64_t maxRtoUs = 2'000'000;
    /**
     * Plan WP10.7: keep a congestion window on the reliable stream (AIMD as TCP Reno, RFC 5681): it starts at
     * initialWindowDatagrams, grows by the bytes acked until the first loss and by about a datagram an RTT after,
     * halves on a loss (once for whatever was sent before the cut), never under minWindowDatagrams or over
     * maxReliableInFlight. Off by default: the lockstep game links keep their behaviour; the server's player channels
     * turn it on.
     */
    bool congestionControl = false;
    std::uint32_t initialWindowDatagrams = 16;
    std::uint32_t minWindowDatagrams = 4;
  };

  enum class ChannelState
  {
    /** Nothing received yet. */
    Connecting,
    Connected,
    /** Nothing arrived for timeoutUs. */
    TimedOut,
    /** The peer broke the protocol, or the sequence ran out. */
    Failed,
  };

  enum class ReceiveResult
  {
    Accepted,
    /** Seen before: a duplicate on the path or a replay. */
    Duplicate,
    /** Behind the receive window. */
    TooOld,
    Malformed,
    /** Keys are set and the tag does not match, or the datagram is not sealed. */
    Unauthenticated,
    /** The channel has timed out or failed. */
    Closed,
  };

  struct ChannelStats
  {
    std::uint64_t datagramsSent = 0;
    std::uint64_t bytesSent = 0;
    std::uint64_t ackOnlySent = 0;
    std::uint64_t keepalivesSent = 0;
    std::uint64_t datagramsReceived = 0;
    std::uint64_t bytesReceived = 0;
    std::uint64_t duplicatesDropped = 0;
    std::uint64_t tooOldDropped = 0;
    std::uint64_t malformedDropped = 0;
    std::uint64_t unauthenticatedDropped = 0;
    std::uint64_t unreliableDropped = 0;

    /** Ack-eliciting datagrams the peer acked, and those counted lost. */
    std::uint64_t datagramsAcked = 0;
    std::uint64_t datagramsLost = 0;
    /** Counted lost, then acked after all: moved from datagramsLost to datagramsAcked. */
    std::uint64_t spuriousLosses = 0;
    /** The reordering allowance now: datagrams, and eighths of an RTT. */
    std::uint32_t reorderThreshold = 0;
    std::uint32_t reorderTimeEighths = 9;

    /** Redundant lane: messages sent, repeats sent, messages that ran out of
     * repeats before an ack, and on the receiving side repeats dropped. */
    std::uint64_t redundantSent = 0;
    std::uint64_t redundantRepeats = 0;
    std::uint64_t redundantUnacked = 0;
    std::uint64_t redundantReceived = 0;
    std::uint64_t redundantDuplicates = 0;
    std::uint64_t reliableBytesResent = 0;
    /** Lost share of the last 256 ack-eliciting datagrams resolved (acked or counted lost;
     * a later spurious ack does not change it). */
    double lossRecent = 0.0;
    /** Peer sequences skipped and not (yet) filled by a late arrival: inbound loss. */
    std::uint64_t inboundMissing = 0;
    std::uint64_t inboundReordered = 0;

    std::uint64_t rttLatestUs = 0;
    std::uint64_t rttSmoothedUs = 0;
    std::uint64_t rttVarUs = 0;
    std::uint64_t rttMinUs = 0;
    std::uint64_t rttSamples = 0;
    std::uint64_t rtoUs = 0;
    /** Plan WP10.7: the congestion window now (bytes; 0 without congestion control) and its cuts. */
    std::uint64_t congestionWindow = 0;
    std::uint64_t congestionCuts = 0;
  };

  class NetChannel
  {
  public:
    explicit NetChannel(const ChannelConfig& config = {});
    ~NetChannel();
    NetChannel(const NetChannel&) = delete;
    NetChannel& operator=(const NetChannel&) = delete;

    /**
     * From now on every datagram out is sealed and every datagram in must be (WP10.6).
     * Called once, when the handshake has made the keys; the sequence numbers go on from
     * where they are, so no nonce repeats within this channel. The keys must be new for
     * this channel: a reconnect makes a new channel and new keys, since a new channel
     * starts again at sequence 1. False, changing nothing, when keys are already set.
     */
    bool SetKeys(const ChannelKeys& keys);

    /** False when larger than maxMessageSize, or the channel is closed. */
    bool SendReliable(const void* data, std::size_t size);
    /** False when it does not fit one datagram, the queue is full, or the channel is closed. */
    bool SendUnreliable(const void* data, std::size_t size);
    /**
     * An unreliable message that later datagrams repeat until one carrying it is
     * acked (ChannelConfig::redundancy). Arrives through TakeUnreliable, at most
     * once. False when it does not fit one datagram or the channel is closed.
     */
    bool SendRedundant(const void* data, std::size_t size);
    /** The largest unreliable message one datagram carries. */
    [[nodiscard]] std::size_t MaxUnreliableSize() const noexcept;

    ReceiveResult Receive(const void* data, std::size_t size, std::uint64_t nowUs);
    /** Appends the datagrams to send now to `out`. */
    void Poll(std::uint64_t nowUs, std::vector<std::vector<std::uint8_t>>& out);

    bool TakeReliable(std::vector<std::uint8_t>& out) { return mReceiver.Take(out); }
    bool TakeUnreliable(std::vector<std::uint8_t>& out);

    [[nodiscard]] ChannelState State() const noexcept { return mState; }
    [[nodiscard]] const ChannelStats& Stats() const noexcept { return mStats; }
    /** Time since the last datagram accepted (or since the first Poll before any). */
    [[nodiscard]] std::uint64_t SinceLastReceivedUs(std::uint64_t nowUs) const noexcept;
    /** Reliable bytes queued and not yet acked by the peer. */
    [[nodiscard]] std::uint64_t ReliableUnacked() const noexcept { return mSender.Unacked(); }
    [[nodiscard]] std::size_t ReliableHeld() const noexcept { return mReceiver.Held(); }

  private:
    struct SentDatagram
    {
      std::uint32_t sequence = 0;
      std::uint64_t sentUs = 0;
      bool acked = false;
      bool lost = false;  // kept a while: a late ack takes the loss back
      bool lostByTime = false;
      std::uint32_t lostBehind = 0;  // how far behind the largest acked it was counted lost
      std::vector<StreamRange> reliable;
      std::uint64_t reliableBytes = 0;       // plan WP10.7: the reliable bytes it carried, in flight until resolved
      std::vector<std::uint32_t> redundant;  // lane sequences it carried
    };

    struct AckBlock
    {
      std::uint32_t top = 0;
      std::uint32_t bits = 0;
    };

    struct LaneMessage
    {
      std::uint32_t sequence = 0;
      std::vector<std::uint8_t> bytes;
      std::uint32_t repeatsLeft = 0;
      bool sent = false;
    };

    // Appends lane chunks to `out` within `budget`: new messages, then repeats
    // of unacked ones (newest first) unless `newOnly`.
    void WriteLane(ByteWriter& out, std::size_t budget, bool newOnly, std::vector<std::uint32_t>& carried);
    [[nodiscard]] bool HasLaneRepeats() const noexcept;
    void LaneAcked(const std::vector<std::uint32_t>& sequences);

    struct ParsedChunk
    {
      std::uint8_t type = 0;
      std::uint64_t offset = 0;
      const std::uint8_t* data = nullptr;
      std::size_t size = 0;
    };

    [[nodiscard]] bool ParsePayload(
      const DatagramHeader& header,
      const std::uint8_t* data,
      std::size_t size,
      std::vector<ParsedChunk>& out,
      std::vector<AckBlock>& acks
    ) const;
    void ProcessAcks(const DatagramHeader& header, const std::vector<AckBlock>& blocks, std::uint64_t nowUs);
    /** Acks every sequence top - i with bit i set in `bits` (i < span). */
    bool AckDown(std::uint32_t top, std::uint64_t bits, std::uint32_t span, const DatagramHeader& header, std::uint64_t nowUs);
    void WriteAckChunk(std::vector<std::uint8_t>& out) const;
    void Resolve(SentDatagram& sent, bool acked);
    void DropSettled(std::uint64_t nowUs);
    void DetectLoss(std::uint64_t nowUs);
    void SampleRtt(std::uint64_t latestUs, std::uint64_t adjustedUs);
    [[nodiscard]] std::uint64_t Rto() const noexcept;
    void Emit(
      std::uint8_t flags,
      const std::vector<std::uint8_t>& payload,
      std::vector<StreamRange>&& reliable,
      std::vector<std::uint32_t>&& redundant,
      std::uint64_t nowUs,
      std::vector<std::vector<std::uint8_t>>& out
    );
    [[nodiscard]] std::size_t PayloadBudget() const noexcept;

    ChannelConfig mConfig;
    ChannelState mState = ChannelState::Connecting;
    ChannelStats mStats;
    std::optional<ChannelKeys> mKeys;

    // Sending.
    std::uint32_t mNextSequence = 1;
    std::deque<SentDatagram> mSent;  // ack-eliciting datagrams not yet acked, by sequence
    std::uint32_t mLargestAcked = 0;
    std::uint32_t mBackoff = 0;  // retransmission timeouts in a row
    // Plan WP10.7 (`ChannelConfig::congestionControl`): the window, the slow-start threshold, and when the last cut
    // was made (a loss of a datagram sent before it makes no second cut).
    double mCongestionBytes = 0.0;
    std::uint64_t mOutstanding = 0; // reliable bytes in datagrams neither acked nor counted lost (the window's measure)
    double mSlowStartEnd = 1.0e18;
    std::uint64_t mLastCutUs = 0;
    std::uint64_t mLastElicitingSentUs = 0;
    bool mSentAny = false;
    ReliableSender mSender;
    std::deque<std::vector<std::uint8_t>> mUnreliableOut;
    std::vector<bool> mRecentOutcomes;  // ring of the last 256 resolutions, true = lost
    std::size_t mRecentNext = 0;
    std::size_t mRecentCount = 0;
    std::size_t mRecentLost = 0;
    std::deque<LaneMessage> mLaneOut;  // by lane sequence
    std::uint32_t mNextLaneSequence = 1;
    std::uint64_t mLastLaneRepeatUs = 0;

    // Receiving.
    ReceiveWindow mWindow;
    std::uint64_t mNewestReceivedUs = 0;
    std::uint64_t mLastReceivedUs = 0;
    std::uint64_t mStartUs = 0;
    bool mStarted = false;
    bool mAckPending = false;
    std::uint64_t mAckDueUs = 0;
    std::uint32_t mUnanswered = 0;   // ack-eliciting datagrams since the last datagram out
    std::uint32_t mReportFrom = 0;   // lowest sequence received since then, 0 = none
    ReliableReceiver mReceiver;
    std::deque<std::vector<std::uint8_t>> mUnreliableIn;
    ReceiveWindow mLaneIn;
  };
} // namespace faf::remote::net
