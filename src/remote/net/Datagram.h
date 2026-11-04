#pragma once

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>

// Engine addition, net channel (plan WP10.2, issue #141): the datagram header every channel
// datagram starts with, the receive window that turns arriving sequence numbers into the
// ack fields, and the byte helpers the payload is written with. Little-endian throughout.
//
// Header, 16 bytes (plan §7.1):
//   [0]      kDatagramTag; a datagram starting with anything else is not the channel's
//   [1]      flags (DatagramFlag)
//   [2..5]   sequence: 1, 2, 3, ... per direction; 0 is never sent
//   [6..9]   ack: the newest sequence received from the peer, 0 before the first one
//   [10..13] ack bits: bit i set when sequence ack - 1 - i was received
//   [14..15] ack delay: time from receiving `ack` to sending this datagram, 100 us units
//
// A 32-bit sequence lasts 497 days at 100 datagrams a second; a channel that reaches the
// end fails instead of wrapping.

namespace faf::remote::net
{
  inline constexpr std::uint8_t kDatagramTag = 0xFC;
  inline constexpr std::size_t kHeaderSize = 16;
  /** The UDP payload limit (plan §7.1): header, chunks and the AEAD tag together. */
  inline constexpr std::size_t kMaxDatagramSize = 1200;

  enum DatagramFlag : std::uint8_t
  {
    /** The payload is sealed and a 16-byte tag follows it (WP10.6). */
    kFlagEncrypted = 1u << 0,
    /** Carries only acks: the receiver does not ack it back. */
    kFlagAckOnly = 1u << 1,
  };
  inline constexpr std::uint8_t kKnownFlags = kFlagEncrypted | kFlagAckOnly;

  struct DatagramHeader
  {
    std::uint8_t flags = 0;
    std::uint32_t sequence = 0;
    std::uint32_t ack = 0;
    std::uint32_t ackBits = 0;
    std::uint16_t ackDelay = 0;
  };

  void WriteHeader(const DatagramHeader& header, std::uint8_t* out) noexcept;
  /** False when `size` is below the header, the tag is not ours, a flag is unknown or the
   * sequence is 0. */
  [[nodiscard]] bool ReadHeader(const std::uint8_t* data, std::size_t size, DatagramHeader& out) noexcept;

  /**
   * The sequence numbers received from the peer: which are new, which repeat (a duplicate
   * or a replay, dropped), and the ack fields for the next datagram out. Check() changes
   * nothing, so a datagram is authenticated and parsed before Accept() records it.
   */
  class ReceiveWindow
  {
  public:
    /** Sequences older than this behind the newest are refused as too old. */
    static constexpr std::uint32_t kSize = 1024;

    enum class Verdict
    {
      New,
      Duplicate,
      TooOld,
    };

    [[nodiscard]] Verdict Check(std::uint32_t sequence) const noexcept;
    void Accept(std::uint32_t sequence) noexcept;

    [[nodiscard]] std::uint32_t Newest() const noexcept { return mNewest; }
    [[nodiscard]] std::uint32_t AckBits() const noexcept;
    /** Bit i set when sequence top - i was received (i < 32, inside the window). */
    [[nodiscard]] std::uint32_t BitsDownFrom(std::uint32_t top) const noexcept;

  private:
    std::uint32_t mNewest = 0;
    std::bitset<kSize> mSeen;
  };

  // --- Payload bytes --------------------------------------------------------------------

  /** Bytes a LEB128 varint of `value` takes (1 to 10). */
  [[nodiscard]] std::size_t VarintSize(std::uint64_t value) noexcept;

  class ByteWriter
  {
  public:
    explicit ByteWriter(std::vector<std::uint8_t>& out) noexcept
      : mOut(out)
    {}

    void Byte(std::uint8_t value) { mOut.push_back(value); }
    void Varint(std::uint64_t value);
    void Bytes(const std::uint8_t* data, std::size_t size) { mOut.insert(mOut.end(), data, data + size); }
    [[nodiscard]] std::size_t Size() const noexcept { return mOut.size(); }

  private:
    std::vector<std::uint8_t>& mOut;
  };

  /** Never reads past its buffer; once it runs out it stays failed. */
  class ByteReader
  {
  public:
    ByteReader(const std::uint8_t* data, std::size_t size) noexcept
      : mData(data)
      , mSize(size)
    {}

    [[nodiscard]] std::uint8_t Byte() noexcept;
    /** Fails on an 11th byte or a 10th byte above 1. */
    [[nodiscard]] std::uint64_t Varint() noexcept;
    /** `size` bytes in place, or null and failed when fewer are left. */
    [[nodiscard]] const std::uint8_t* Bytes(std::size_t size) noexcept;

    [[nodiscard]] bool Ok() const noexcept { return !mFailed; }
    [[nodiscard]] bool AtEnd() const noexcept { return mPos == mSize; }

  private:
    const std::uint8_t* mData;
    std::size_t mSize;
    std::size_t mPos = 0;
    bool mFailed = false;
  };
} // namespace faf::remote::net
