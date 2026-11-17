#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <vector>

#include "remote/net/Datagram.h"

// Engine addition, net channel (plan WP10.3, issue #142): the reliable stream. Messages are
// laid end to end in one byte stream per direction, each as a varint length and its bytes.
// The stream travels in fragments, "reliable" chunks inside datagrams:
//
//   [1] chunk type 1, varint stream offset, varint length (1 or more), the bytes
//
// so a message of any size spans as many datagrams as it needs and a resend can cut the
// stream differently from the first send. The sender keeps every byte until a datagram
// carrying it is acked; the channel tells it which datagrams were acked or lost (from the
// header's ack fields), and a lost datagram's ranges go back on the send queue minus
// whatever another datagram already delivered. The receiver puts fragments back in stream
// order, drops what it already has, and hands out whole messages in order.

namespace faf::remote::net
{
  inline constexpr std::uint8_t kChunkReliable = 1;
  inline constexpr std::uint8_t kChunkUnreliable = 2;
  inline constexpr std::uint8_t kChunkAcks = 3;
  inline constexpr std::uint8_t kChunkRedundant = 4;

  /** Stream bytes [begin, end). */
  struct StreamRange
  {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
  };

  /** A set of stream offsets kept as merged, non-touching ranges. */
  class RangeSet
  {
  public:
    void Add(std::uint64_t begin, std::uint64_t end);
    void Remove(std::uint64_t begin, std::uint64_t end);
    /** The parts of [begin, end) the set does not hold, in order. */
    void Missing(std::uint64_t begin, std::uint64_t end, std::vector<StreamRange>& out) const;
    /** End of the range that starts at 0, or 0. */
    [[nodiscard]] std::uint64_t PrefixEnd() const noexcept;
    [[nodiscard]] bool Empty() const noexcept
    {
      return mRanges.empty();
    }
    [[nodiscard]] StreamRange First() const noexcept;
    [[nodiscard]] std::size_t RangeCount() const noexcept
    {
      return mRanges.size();
    }

  private:
    std::map<std::uint64_t, std::uint64_t> mRanges; // begin -> end
  };

  class ReliableSender
  {
  public:
    ReliableSender(
      std::size_t maxInFlight,
      std::size_t maxMessage
    ) noexcept
      : mMaxInFlight(maxInFlight)
      , mMaxMessage(maxMessage)
    {}

    /** False when the message is larger than the channel's limit. */
    bool Queue(const std::uint8_t* data, std::size_t size);

    /**
     * Appends reliable chunks to `out` until `budget` bytes are used or nothing is left:
     * lost ranges first, then bytes never sent while the bytes past the acked prefix stay
     * within the in-flight limit. `sent` receives the ranges written.
     */
    void Write(ByteWriter& out, std::size_t budget, std::vector<StreamRange>& sent);

    /** Something to write now (lost ranges, or new bytes the in-flight limit allows). */
    [[nodiscard]] bool HasPending() const noexcept;
    void OnAcked(const std::vector<StreamRange>& ranges);
    void OnLost(const std::vector<StreamRange>& ranges);

    /** Bytes sent past the acked prefix (acked ranges above it included). */
    [[nodiscard]] std::uint64_t InFlight() const noexcept
    {
      return mNextNew - mAcked.PrefixEnd();
    }
    /** Plan WP10.7: unacked bytes past the acked prefix at most, under maxInFlight (the channel's congestion window).
     */
    void SetWindow(
      const std::uint64_t bytes
    ) noexcept
    {
      mCongestionWindow = bytes;
    }
    /** Queued bytes not yet acked. */
    [[nodiscard]] std::uint64_t Unacked() const noexcept
    {
      return mEnd - mAcked.PrefixEnd();
    }
    [[nodiscard]] std::uint64_t BytesResent() const noexcept
    {
      return mBytesResent;
    }

    /**
     * Repeats (game links between players): each range Write sends for the first time goes out again while some of it
     * is unacked, `firstGapUs` after it was sent, then after twice that, four times and so on, `count` times at most,
     * so a lost datagram's bytes arrive within a gap instead of after loss detection, and a burst that swallows the
     * first repeats still meets a later one. 0 (the default) repeats nothing. Only while at most `maxInFlight`
     * reliable bytes are in flight: a beat is tens of bytes, a large order or a save is left to loss detection.
     */
    void SetRepeats(
      const std::uint32_t count,
      const std::uint64_t firstGapUs,
      const std::uint64_t maxInFlight
    ) noexcept
    {
      mRepeats = count;
      mRepeatFirstGapUs = firstGapUs;
      mRepeatMaxInFlight = maxInFlight;
    }
    /** Repeats on or off for now (ChannelConfig::reliableRepeatHoldUs); off forgets the ranges waiting for one. */
    void SetRepeatsActive(
      const bool active
    ) noexcept
    {
      mRepeatsActive = active;
      if (!active) {
        mRepeatQueue.clear();
      }
    }
    /** The time Write stamps on new ranges (the channel's Poll sets it first). */
    void SetNow(
      const std::uint64_t nowUs
    ) noexcept
    {
      mNowUs = nowUs;
    }
    /** Some range is due for a repeat at `nowUs`. */
    [[nodiscard]] bool RepeatDue(std::uint64_t nowUs) const noexcept;
    /** Appends the repeats due at `nowUs`, oldest first, until `budget` is used; `sent` receives the ranges written. */
    void WriteRepeats(ByteWriter& out, std::size_t budget, std::vector<StreamRange>& sent, std::uint64_t nowUs);
    [[nodiscard]] std::uint64_t BytesRepeated() const noexcept
    {
      return mBytesRepeated;
    }

  private:
    void Compact();

    struct Repeat
    {
      std::uint64_t begin = 0;
      std::uint64_t end = 0;
      std::uint32_t left = 0;
      std::uint64_t dueUs = 0;
      std::uint64_t gapUs = 0;
    };
    std::uint32_t mRepeats = 0;
    std::uint64_t mRepeatFirstGapUs = 30'000;
    std::uint64_t mNowUs = 0;
    bool mRepeatsActive = true;
    // Repeats only while this little is in flight: game beats are tens of bytes; a large order or a save would be
    // sent several times over on an uplink it already fills.
    std::uint64_t mRepeatMaxInFlight = 0;
    std::deque<Repeat> mRepeatQueue;
    std::uint64_t mBytesRepeated = 0;

    std::size_t mMaxInFlight;
    std::uint64_t mCongestionWindow =
      ~std::uint64_t{0}; // plan WP10.7: the congestion window, when the channel keeps one
    std::size_t mMaxMessage;
    std::vector<std::uint8_t> mBuffer; // stream bytes from mBase to mEnd
    std::uint64_t mBase = 0;
    std::uint64_t mEnd = 0;
    std::uint64_t mNextNew = 0;
    RangeSet mAcked;
    RangeSet mLost;
    std::uint64_t mBytesResent = 0;
  };

  class ReliableReceiver
  {
  public:
    ReliableReceiver(
      std::size_t window,
      std::size_t maxMessage
    ) noexcept
      : mWindow(window)
      , mMaxMessage(maxMessage)
    {}

    /**
     * Takes one fragment. Bytes already received are dropped; a fragment reaching past the
     * window (bytes not yet delivered in order plus `window`) is dropped whole and comes back
     * on a resend. False when a message announces more than the channel's limit: the peer
     * broke the protocol.
     */
    [[nodiscard]] bool OnFragment(std::uint64_t offset, const std::uint8_t* data, std::size_t size);

    /** The next whole message in order, if any. */
    bool Take(std::vector<std::uint8_t>& out);

    /** Out-of-order bytes held back for a gap. */
    [[nodiscard]] std::size_t Held() const noexcept
    {
      return mHeldBytes;
    }
    [[nodiscard]] std::uint64_t Delivered() const noexcept
    {
      return mDelivered;
    }

  private:
    [[nodiscard]] bool Append(const std::uint8_t* data, std::size_t size);
    [[nodiscard]] bool ParseMessages();

    std::size_t mWindow;
    std::size_t mMaxMessage;
    std::uint64_t mDelivered = 0;                             // every byte below this arrived and went to mAssembly
    std::map<std::uint64_t, std::vector<std::uint8_t>> mHeld; // non-overlapping fragments
    std::size_t mHeldBytes = 0;
    std::vector<std::uint8_t> mAssembly; // contiguous bytes not yet cut into messages
    std::size_t mAssemblyPos = 0;
    std::deque<std::vector<std::uint8_t>> mMessages;
  };
} // namespace faf::remote::net
