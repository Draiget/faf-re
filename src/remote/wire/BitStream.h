#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// Engine addition, server mode: the bit-level writer and reader every server-mode wire
// record is built with (plan §7.2). Little-endian bit order: the first bit written is bit 0
// of byte 0. The reader never reads past its buffer and never allocates; once it runs out it
// returns zeros and stays failed, so a decoder checks `Ok()` once at the end.

namespace faf::remote::wire
{
  class BitWriter
  {
  public:
    /** Appends the low `bitCount` bits of `value` (0 to 32 bits). */
    void WriteBits(std::uint32_t value, int bitCount);
    void WriteBool(bool value) { WriteBits(value ? 1u : 0u, 1); }
    /** 7 data bits per group, high bit set while more groups follow (1 to 5 groups). */
    void WriteVarUint(std::uint32_t value);
    /** The float's exact bit pattern: for values the UI shows as numbers (§7.2). */
    void WriteFloatExact(float value);

    [[nodiscard]] std::size_t BitCount() const noexcept { return mBitCount; }
    [[nodiscard]] std::span<const std::uint8_t> Bytes() const noexcept { return mBytes; }

  private:
    std::vector<std::uint8_t> mBytes;
    std::size_t mBitCount = 0;
  };

  class BitReader
  {
  public:
    explicit BitReader(std::span<const std::uint8_t> bytes) noexcept
      : mBytes(bytes)
    {}

    /** The next `bitCount` bits (0 to 32); 0 and failed once the buffer is exhausted. */
    [[nodiscard]] std::uint32_t ReadBits(int bitCount) noexcept;
    [[nodiscard]] bool ReadBool() noexcept { return ReadBits(1) != 0u; }
    /** Fails on a sixth group or a fifth group carrying more than 4 data bits. */
    [[nodiscard]] std::uint32_t ReadVarUint() noexcept;
    [[nodiscard]] float ReadFloatExact() noexcept;

    /** Marks the stream failed (a decoder found the data inconsistent). */
    void Fail() noexcept { mFailed = true; }
    [[nodiscard]] bool Ok() const noexcept { return !mFailed; }
    [[nodiscard]] std::size_t BitsLeft() const noexcept
    {
      return mFailed ? 0u : mBytes.size() * 8u - mBitPos;
    }

  private:
    std::span<const std::uint8_t> mBytes;
    std::size_t mBitPos = 0;
    bool mFailed = false;
  };
} // namespace faf::remote::wire
