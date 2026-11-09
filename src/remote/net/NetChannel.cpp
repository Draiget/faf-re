#include "remote/net/NetChannel.h"

#include <algorithm>
#include <cstring>

namespace faf::remote::net
{
  namespace
  {
    constexpr std::size_t kRecentWindow = 256;
    constexpr std::uint32_t kMaxAckBlocks = 16;
    constexpr std::uint32_t kAckAfterUnanswered = 4;
    constexpr std::uint32_t kMaxReorderThreshold = 64;
    constexpr std::uint32_t kMaxReorderTimeEighths = 16;
    // Redundant messages kept for repeats at most; older ones are given up.
    constexpr std::size_t kMaxLaneMessages = 512;
    // Consecutive timeouts double the retransmission timeout up to 2^this.
    constexpr std::uint32_t kMaxBackoff = 6;
  } // namespace

  NetChannel::NetChannel(const ChannelConfig& config)
    : mConfig(config)
    , mSender(config.maxReliableInFlight, config.maxMessageSize)
    , mRecentOutcomes(kRecentWindow, false)
    , mReceiver(config.receiveWindow, config.maxMessageSize)
  {
    // Until the first sample, RFC 6298's starting point from the configured guess.
    mStats.rttSmoothedUs = mConfig.initialRttUs;
    mStats.rttVarUs = mConfig.initialRttUs / 2;
    mStats.rtoUs = Rto();
    mStats.reorderThreshold = mConfig.lossThreshold;
    mNextSequence = std::max<std::uint32_t>(mConfig.firstSequence, 1);
  }

  NetChannel::~NetChannel()
  {
    if (mKeys) {
      WipeKey(mKeys->send);
      WipeKey(mKeys->receive);
    }
  }

  bool NetChannel::SetKeys(const ChannelKeys& keys)
  {
    if (mKeys) {
      return false;
    }
    mKeys = keys;
    return true;
  }

  std::size_t NetChannel::PayloadBudget() const noexcept
  {
    return mConfig.maxDatagramSize - kHeaderSize - (mKeys ? kTagSize : 0);
  }

  std::size_t NetChannel::MaxUnreliableSize() const noexcept
  {
    const std::size_t budget = PayloadBudget();
    return budget - 1 - VarintSize(budget);
  }

  bool NetChannel::SendReliable(const void* const data, const std::size_t size)
  {
    if (mState == ChannelState::TimedOut || mState == ChannelState::Failed) {
      return false;
    }
    return mSender.Queue(static_cast<const std::uint8_t*>(data), size);
  }

  bool NetChannel::SendUnreliable(const void* const data, const std::size_t size)
  {
    if (mState == ChannelState::TimedOut || mState == ChannelState::Failed || size > MaxUnreliableSize() ||
        mUnreliableOut.size() >= mConfig.maxUnreliableQueued) {
      return false;
    }
    const auto* const bytes = static_cast<const std::uint8_t*>(data);
    mUnreliableOut.emplace_back(bytes, bytes + size);
    return true;
  }

  bool NetChannel::SendRedundant(const void* const data, const std::size_t size)
  {
    if (mState == ChannelState::TimedOut || mState == ChannelState::Failed || size > MaxUnreliableSize() ||
        mNextLaneSequence == UINT32_MAX) {
      return false;
    }
    if (mLaneOut.size() >= kMaxLaneMessages) {
      if (!mLaneOut.front().sent) {
        return false; // nothing has gone out for a while: the caller is far ahead of Poll
      }
      mLaneOut.pop_front();
      ++mStats.redundantUnacked;
    }
    const auto* const bytes = static_cast<const std::uint8_t*>(data);
    LaneMessage& m = mLaneOut.emplace_back();
    m.sequence = mNextLaneSequence++;
    m.bytes.assign(bytes, bytes + size);
    m.repeatsLeft = mConfig.redundancy;
    return true;
  }

  void NetChannel::LaneAcked(const std::vector<std::uint32_t>& sequences)
  {
    for (const std::uint32_t s : sequences) {
      const auto it = std::lower_bound(mLaneOut.begin(), mLaneOut.end(), s, [](const LaneMessage& m, std::uint32_t v) {
        return m.sequence < v;
      });
      if (it != mLaneOut.end() && it->sequence == s) {
        mLaneOut.erase(it);
      }
    }
  }

  bool NetChannel::HasLaneRepeats() const noexcept
  {
    return std::any_of(mLaneOut.begin(), mLaneOut.end(), [](const LaneMessage& m) {
      return m.sent && m.repeatsLeft > 0;
    });
  }

  void NetChannel::WriteLane(
    ByteWriter& out, const std::size_t budget, const bool newOnly, std::vector<std::uint32_t>& carried
  )
  {
    const std::size_t start = out.Size();
    const auto fits = [&](const LaneMessage& m) {
      const std::size_t need = 1 + VarintSize(m.sequence) + VarintSize(m.bytes.size()) + m.bytes.size();
      return out.Size() - start + need <= budget;
    };
    const auto write = [&](const LaneMessage& m) {
      out.Byte(kChunkRedundant);
      out.Varint(m.sequence);
      out.Varint(m.bytes.size());
      out.Bytes(m.bytes.data(), m.bytes.size());
      carried.push_back(m.sequence);
    };
    const std::size_t fresh = carried.size();
    for (LaneMessage& m : mLaneOut) {
      if (m.sent) {
        continue;
      }
      if (!fits(m)) {
        break;
      }
      write(m);
      m.sent = true;
      ++mStats.redundantSent;
    }
    if (!newOnly) {
      const auto writtenNow = [&](const std::uint32_t s) {
        return std::find(carried.begin() + static_cast<std::ptrdiff_t>(fresh), carried.end(), s) != carried.end();
      };
      for (auto it = mLaneOut.rbegin(); it != mLaneOut.rend(); ++it) {
        if (!it->sent || it->repeatsLeft == 0 || writtenNow(it->sequence) || !fits(*it)) {
          continue;
        }
        write(*it);
        --it->repeatsLeft;
        ++mStats.redundantRepeats;
      }
    }
    while (!mLaneOut.empty() && mLaneOut.front().sent && mLaneOut.front().repeatsLeft == 0) {
      mLaneOut.pop_front();
      ++mStats.redundantUnacked;
    }
  }

  bool NetChannel::TakeUnreliable(std::vector<std::uint8_t>& out)
  {
    if (mUnreliableIn.empty()) {
      return false;
    }
    out = std::move(mUnreliableIn.front());
    mUnreliableIn.pop_front();
    return true;
  }

  std::uint64_t NetChannel::SinceLastReceivedUs(const std::uint64_t nowUs) const noexcept
  {
    const std::uint64_t since = mStats.datagramsReceived != 0 ? mLastReceivedUs : mStartUs;
    return nowUs > since ? nowUs - since : 0;
  }

  // --- Receiving ------------------------------------------------------------------------

  bool NetChannel::ParsePayload(
    const DatagramHeader& header,
    const std::uint8_t* const data,
    const std::size_t size,
    std::vector<ParsedChunk>& out,
    std::vector<AckBlock>& acks
  ) const
  {
    ByteReader in(data, size);
    while (in.Ok() && !in.AtEnd()) {
      ParsedChunk chunk;
      chunk.type = in.Byte();
      if (chunk.type == kChunkAcks) {
        const std::uint64_t count = in.Varint();
        if (count == 0 || count > kMaxAckBlocks || !acks.empty()) {
          return false;
        }
        for (std::uint64_t i = 0; i < count; ++i) {
          const std::uint64_t below = in.Varint();
          const std::uint8_t* const bits = in.Bytes(4);
          if (!in.Ok() || below == 0 || below >= header.ack) {
            return false;
          }
          acks.push_back({static_cast<std::uint32_t>(header.ack - below),
                          static_cast<std::uint32_t>(bits[0] | (bits[1] << 8) | (bits[2] << 16)) |
                            (static_cast<std::uint32_t>(bits[3]) << 24)});
        }
        continue;
      }
      if (chunk.type == kChunkReliable || chunk.type == kChunkRedundant) {
        chunk.offset = in.Varint(); // the lane sequence for a redundant message
        if (chunk.type == kChunkRedundant && (chunk.offset == 0 || chunk.offset > UINT32_MAX)) {
          return false;
        }
      } else if (chunk.type != kChunkUnreliable) {
        return false;
      }
      const std::uint64_t length = in.Varint();
      if (!in.Ok() || length > size || (chunk.type == kChunkReliable && length == 0)) {
        return false;
      }
      chunk.size = static_cast<std::size_t>(length);
      chunk.data = in.Bytes(chunk.size);
      out.push_back(chunk);
    }
    return in.Ok();
  }

  ReceiveResult NetChannel::Receive(const void* const data, const std::size_t size, const std::uint64_t nowUs)
  {
    if (!mStarted) {
      mStarted = true;
      mStartUs = nowUs;
    }
    if (mState == ChannelState::TimedOut || mState == ChannelState::Failed) {
      return ReceiveResult::Closed;
    }

    const auto* const bytes = static_cast<const std::uint8_t*>(data);
    DatagramHeader header;
    if (!ReadHeader(bytes, size, header)) {
      ++mStats.malformedDropped;
      return ReceiveResult::Malformed;
    }

    // Authenticate before anything else looks at it, so forged datagrams change nothing.
    std::vector<std::uint8_t> plain;
    const std::uint8_t* payload = bytes + kHeaderSize;
    std::size_t payloadSize = size - kHeaderSize;
    const bool sealed = (header.flags & kFlagEncrypted) != 0;
    if (mKeys) {
      if (!sealed || size < kHeaderSize + kTagSize) {
        ++mStats.unauthenticatedDropped;
        return ReceiveResult::Unauthenticated;
      }
      payloadSize = size - kHeaderSize - kTagSize;
      plain.resize(payloadSize);
      if (!OpenDatagram(mKeys->receive, header.sequence, bytes, size, plain.data())) {
        ++mStats.unauthenticatedDropped;
        return ReceiveResult::Unauthenticated;
      }
      payload = plain.data();
    } else if (sealed) {
      ++mStats.unauthenticatedDropped;
      return ReceiveResult::Unauthenticated;
    }

    switch (mWindow.Check(header.sequence)) {
    case ReceiveWindow::Verdict::Duplicate:
      ++mStats.duplicatesDropped;
      return ReceiveResult::Duplicate;
    case ReceiveWindow::Verdict::TooOld:
      ++mStats.tooOldDropped;
      return ReceiveResult::TooOld;
    case ReceiveWindow::Verdict::New:
      break;
    }

    std::vector<ParsedChunk> chunks;
    std::vector<AckBlock> ackBlocks;
    if (header.ack >= mNextSequence || !ParsePayload(header, payload, payloadSize, chunks, ackBlocks)) {
      ++mStats.malformedDropped;
      return ReceiveResult::Malformed;
    }

    const std::uint32_t previousNewest = mWindow.Newest();
    mWindow.Accept(header.sequence);
    if (mReportFrom == 0 || header.sequence < mReportFrom) {
      mReportFrom = header.sequence;
    }
    if (header.sequence > previousNewest) {
      mStats.inboundMissing += header.sequence - previousNewest - 1;
      mNewestReceivedUs = nowUs;
    } else {
      ++mStats.inboundReordered;
      if (mStats.inboundMissing > 0) {
        --mStats.inboundMissing;
      }
    }
    mLastReceivedUs = nowUs;
    ++mStats.datagramsReceived;
    mStats.bytesReceived += size;
    if (mState == ChannelState::Connecting) {
      mState = ChannelState::Connected;
    }

    ProcessAcks(header, ackBlocks, nowUs);

    for (const ParsedChunk& chunk : chunks) {
      if (chunk.type == kChunkReliable) {
        if (!mReceiver.OnFragment(chunk.offset, chunk.data, chunk.size)) {
          mState = ChannelState::Failed;
          return ReceiveResult::Malformed;
        }
      } else if (chunk.type == kChunkRedundant) {
        const auto sequence = static_cast<std::uint32_t>(chunk.offset);
        if (mLaneIn.Check(sequence) != ReceiveWindow::Verdict::New) {
          ++mStats.redundantDuplicates;
          continue;
        }
        mLaneIn.Accept(sequence);
        ++mStats.redundantReceived;
        if (mUnreliableIn.size() < mConfig.maxUnreliableQueued) {
          mUnreliableIn.emplace_back(chunk.data, chunk.data + chunk.size);
        } else {
          ++mStats.unreliableDropped;
        }
      } else if (mUnreliableIn.size() < mConfig.maxUnreliableQueued) {
        mUnreliableIn.emplace_back(chunk.data, chunk.data + chunk.size);
      } else {
        ++mStats.unreliableDropped;
      }
    }

    if ((header.flags & kFlagAckOnly) == 0) {
      if (!mAckPending) {
        mAckPending = true;
        mAckDueUs = nowUs + mConfig.ackDelayUs;
      }
      if (header.sequence != previousNewest + 1 || ++mUnanswered >= kAckAfterUnanswered) {
        mAckDueUs = nowUs;  // a gap, a late one, or a run of them: tell the peer at once
      }
    }
    return ReceiveResult::Accepted;
  }

  void NetChannel::ProcessAcks(
    const DatagramHeader& header, const std::vector<AckBlock>& blocks, const std::uint64_t nowUs
  )
  {
    if (header.ack == 0) {
      return;
    }
    // The header: the newest and the 32 before it.
    bool acked = AckDown(header.ack, 1ull | (static_cast<std::uint64_t>(header.ackBits) << 1), 33, header, nowUs);
    for (const AckBlock& block : blocks) {
      acked = AckDown(block.top, block.bits, 32, header, nowUs) || acked;
    }
    mLargestAcked = std::max(mLargestAcked, header.ack);
    if (acked) {
      mBackoff = 0;
    }
    DropSettled(nowUs);
  }

  void NetChannel::DropSettled(const std::uint64_t nowUs)
  {
    // A lost datagram stays while the peer could still ack it: within the ack chunk's reach
    // below the newest acked, and for a few retransmission timeouts.
    const std::uint64_t keepUs = 4 * Rto();
    while (!mSent.empty()) {
      const SentDatagram& front = mSent.front();
      const bool settled = front.acked ||
                           (front.lost && (mLargestAcked - front.sequence > 33 + 32 * kMaxAckBlocks ||
                                           nowUs - front.sentUs > keepUs));
      if (!settled) {
        break;
      }
      mSent.pop_front();
    }
  }

  bool NetChannel::AckDown(
    const std::uint32_t top,
    const std::uint64_t bits,
    const std::uint32_t span,
    const DatagramHeader& header,
    const std::uint64_t nowUs
  )
  {
    const std::uint32_t lowest = top >= span ? top - span + 1 : 1;
    auto it = std::lower_bound(mSent.begin(), mSent.end(), lowest, [](const SentDatagram& sent, std::uint32_t s) {
      return sent.sequence < s;
    });
    bool acked = false;
    for (; it != mSent.end() && it->sequence <= top; ++it) {
      if (it->acked || ((bits >> (top - it->sequence)) & 1u) == 0) {
        continue;
      }
      if (it->lost) {
        // Counted lost too early (reordering, a delayed ack): its bytes did arrive.
        it->acked = true;
        mSender.OnAcked(it->reliable);
        LaneAcked(it->redundant);
        ++mStats.spuriousLosses;
        --mStats.datagramsLost;
        ++mStats.datagramsAcked;
        if (it->lostByTime) {
          mStats.reorderTimeEighths = std::min(mStats.reorderTimeEighths + 1, kMaxReorderTimeEighths);
        } else if (it->lostBehind != 0) {
          mStats.reorderThreshold = std::clamp(it->lostBehind + 1, mStats.reorderThreshold, kMaxReorderThreshold);
        }
        acked = true;
        continue;
      }
      if (it->sequence == header.ack) {
        // RFC 9002 5.3: the peer's reported delay comes off, up to the most it may delay.
        const std::uint64_t latest = nowUs - it->sentUs;
        const std::uint64_t delay = std::min<std::uint64_t>(header.ackDelay * 100ull, mConfig.maxAckDelayUs);
        SampleRtt(latest, latest >= delay + 1000 ? latest - delay : latest);
      }
      Resolve(*it, true);
      acked = true;
    }
    return acked;
  }

  void NetChannel::WriteAckChunk(std::vector<std::uint8_t>& out) const
  {
    // Blocks of 32 below the header's range, down to the lowest sequence received since the
    // last datagram out; blocks with nothing received are left out.
    const std::uint32_t newest = mWindow.Newest();
    if (mReportFrom == 0 || newest <= 33 || mReportFrom + 32 >= newest) {
      return;
    }
    std::vector<AckBlock> blocks;
    for (std::uint32_t top = newest - 33; blocks.size() < kMaxAckBlocks && top >= mReportFrom; top -= 32) {
      if (newest - top >= ReceiveWindow::kSize) {
        break;
      }
      if (const std::uint32_t bits = mWindow.BitsDownFrom(top); bits != 0) {
        blocks.push_back({top, bits});
      }
      if (top <= 32) {
        break;
      }
    }
    if (blocks.empty()) {
      return;
    }
    ByteWriter writer(out);
    writer.Byte(kChunkAcks);
    writer.Varint(blocks.size());
    for (const AckBlock& block : blocks) {
      writer.Varint(newest - block.top);
      for (int shift = 0; shift < 32; shift += 8) {
        writer.Byte(static_cast<std::uint8_t>(block.bits >> shift));
      }
    }
  }

  void NetChannel::SampleRtt(const std::uint64_t latestUs, const std::uint64_t adjustedUs)
  {
    // RFC 6298 2.2 and 2.3.
    if (mStats.rttSamples == 0) {
      mStats.rttMinUs = latestUs;
      mStats.rttSmoothedUs = adjustedUs;
      mStats.rttVarUs = adjustedUs / 2;
    } else {
      mStats.rttMinUs = std::min(mStats.rttMinUs, latestUs);
      const std::uint64_t error = mStats.rttSmoothedUs > adjustedUs ? mStats.rttSmoothedUs - adjustedUs
                                                                    : adjustedUs - mStats.rttSmoothedUs;
      mStats.rttVarUs = (3 * mStats.rttVarUs + error) / 4;
      mStats.rttSmoothedUs = (7 * mStats.rttSmoothedUs + adjustedUs) / 8;
    }
    mStats.rttLatestUs = adjustedUs;
    ++mStats.rttSamples;
    mStats.rtoUs = Rto();
  }

  std::uint64_t NetChannel::Rto() const noexcept
  {
    const std::uint64_t rto =
      mStats.rttSmoothedUs + std::max<std::uint64_t>(4 * mStats.rttVarUs, 1000) + mConfig.maxAckDelayUs;
    return std::clamp(rto, mConfig.minRtoUs, mConfig.maxRtoUs);
  }

  void NetChannel::DetectLoss(const std::uint64_t nowUs)
  {
    const std::uint64_t rto = std::min(mConfig.maxRtoUs, Rto() << mBackoff);
    const std::uint64_t reorderDelay = std::max<std::uint64_t>(
      mStats.reorderTimeEighths * std::max(mStats.rttSmoothedUs, mStats.rttLatestUs) / 8, 1000
    );
    bool timedOut = false;
    for (SentDatagram& sent : mSent) {
      if (sent.acked || sent.lost) {
        continue;
      }
      const std::uint64_t age = nowUs - sent.sentUs;
      const bool behindAcked = sent.sequence < mLargestAcked;
      const std::uint32_t behind = behindAcked ? mLargestAcked - sent.sequence : 0;
      if (behindAcked && behind >= mStats.reorderThreshold) {
        sent.lostBehind = behind;
        Resolve(sent, false);
      } else if (behindAcked && age >= reorderDelay) {
        sent.lostByTime = true;
        Resolve(sent, false);
      } else if (age >= rto) {
        Resolve(sent, false);
        timedOut = true;
      }
    }
    if (timedOut && mBackoff < kMaxBackoff) {
      ++mBackoff;
    }
    DropSettled(nowUs);
  }

  // --- Sending --------------------------------------------------------------------------

  void NetChannel::Poll(const std::uint64_t nowUs, std::vector<std::vector<std::uint8_t>>& out)
  {
    if (!mStarted) {
      mStarted = true;
      mStartUs = nowUs;
    }
    if (mState == ChannelState::TimedOut || mState == ChannelState::Failed) {
      return;
    }
    if (SinceLastReceivedUs(nowUs) >= mConfig.timeoutUs) {
      mState = ChannelState::TimedOut;
      return;
    }

    DetectLoss(nowUs);

    const std::size_t budget = PayloadBudget();
    std::vector<std::uint8_t> payload;
    std::size_t produced = 0;
    while (produced < mConfig.maxDatagramsPerPoll && mState != ChannelState::Failed) {
      const bool laneNew = std::any_of(mLaneOut.begin(), mLaneOut.end(), [](const LaneMessage& m) { return !m.sent; });
      const bool fresh = laneNew || !mUnreliableOut.empty() || mSender.HasPending();
      const bool repeatDue = HasLaneRepeats() && nowUs - mLastLaneRepeatUs >= mConfig.redundantRepeatUs;
      if (!fresh && !(repeatDue && produced == 0)) {
        break;
      }
      payload.clear();
      WriteAckChunk(payload);
      const std::size_t dataStart = payload.size();
      ByteWriter writer(payload);
      // Issue #240: the redundant lane first; repeats of unacked messages ride
      // along with new data, or go alone once the repeat interval has passed.
      std::vector<std::uint32_t> lane;
      const std::uint64_t repeatsBefore = mStats.redundantRepeats;
      WriteLane(writer, budget, false, lane);
      if (mStats.redundantRepeats != repeatsBefore) {
        mLastLaneRepeatUs = nowUs;
      }
      while (!mUnreliableOut.empty()) {
        const std::vector<std::uint8_t>& message = mUnreliableOut.front();
        if (1 + VarintSize(message.size()) + message.size() > budget - writer.Size()) {
          if (writer.Size() == dataStart) {
            // Queued before SetKeys took the tag's 16 bytes: it fits no datagram now.
            mUnreliableOut.pop_front();
            ++mStats.unreliableDropped;
            continue;
          }
          break;
        }
        writer.Byte(kChunkUnreliable);
        writer.Varint(message.size());
        writer.Bytes(message.data(), message.size());
        mUnreliableOut.pop_front();
      }
      std::vector<StreamRange> reliable;
      if (budget > writer.Size()) {
        mSender.Write(writer, budget - writer.Size(), reliable);
      }
      if (payload.size() == dataStart) {
        break;
      }
      Emit(0, payload, std::move(reliable), std::move(lane), nowUs, out);
      ++produced;
      if (!fresh) {
        break; // one repeat-only datagram per interval
      }
    }

    if (produced == 0 && mState != ChannelState::Failed) {
      payload.clear();
      WriteAckChunk(payload);
      if (mAckPending && nowUs >= mAckDueUs) {
        Emit(kFlagAckOnly, payload, {}, {}, nowUs, out);
        ++mStats.ackOnlySent;
      } else if (!mSentAny || nowUs - mLastElicitingSentUs >= mConfig.keepaliveIntervalUs) {
        Emit(0, payload, {}, {}, nowUs, out);
        ++mStats.keepalivesSent;
      }
    }
    mStats.reliableBytesResent = mSender.BytesResent();
  }

  void NetChannel::Emit(
    const std::uint8_t flags,
    const std::vector<std::uint8_t>& payload,
    std::vector<StreamRange>&& reliable,
    std::vector<std::uint32_t>&& redundant,
    const std::uint64_t nowUs,
    std::vector<std::vector<std::uint8_t>>& out
  )
  {
    if (mNextSequence == UINT32_MAX) {
      mState = ChannelState::Failed;
      return;
    }
    DatagramHeader header;
    header.flags = static_cast<std::uint8_t>(flags | (mKeys ? kFlagEncrypted : 0));
    header.sequence = mNextSequence++;
    header.ack = mWindow.Newest();
    header.ackBits = mWindow.AckBits();
    if (header.ack != 0) {
      header.ackDelay = static_cast<std::uint16_t>(std::min<std::uint64_t>((nowUs - mNewestReceivedUs) / 100, 0xFFFF));
    }

    std::vector<std::uint8_t> datagram(kHeaderSize + payload.size() + (mKeys ? kTagSize : 0));
    WriteHeader(header, datagram.data());
    if (!payload.empty()) {
      std::memcpy(datagram.data() + kHeaderSize, payload.data(), payload.size());
    }
    if (mKeys) {
      SealDatagram(mKeys->send, header.sequence, datagram.data(), payload.size());
    }

    ++mStats.datagramsSent;
    mStats.bytesSent += datagram.size();
    mAckPending = false;
    mUnanswered = 0;
    mReportFrom = 0;
    if ((flags & kFlagAckOnly) == 0) {
      mSentAny = true;
      mLastElicitingSentUs = nowUs;
      SentDatagram& sent = mSent.emplace_back();
      sent.sequence = header.sequence;
      sent.sentUs = nowUs;
      sent.reliable = std::move(reliable);
      sent.redundant = std::move(redundant);
    }
    out.push_back(std::move(datagram));
  }

  void NetChannel::Resolve(SentDatagram& sent, const bool acked)
  {
    if (acked) {
      sent.acked = true;
      mSender.OnAcked(sent.reliable);
      LaneAcked(sent.redundant);
      ++mStats.datagramsAcked;
    } else {
      sent.lost = true;
      mSender.OnLost(sent.reliable);
      ++mStats.datagramsLost;
    }

    if (mRecentCount == kRecentWindow) {
      if (mRecentOutcomes[mRecentNext]) {
        --mRecentLost;
      }
    } else {
      ++mRecentCount;
    }
    mRecentOutcomes[mRecentNext] = !acked;
    if (!acked) {
      ++mRecentLost;
    }
    mRecentNext = (mRecentNext + 1) % kRecentWindow;
    mStats.lossRecent = static_cast<double>(mRecentLost) / static_cast<double>(mRecentCount);
    mStats.reliableBytesResent = mSender.BytesResent();
  }
} // namespace faf::remote::net
