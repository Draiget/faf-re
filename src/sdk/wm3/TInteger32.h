#pragma once

#include <cstddef>
#include <cstdint>

namespace Wm3
{
  /**
   * Fixed-precision integer type using 64 blocks of 16 bits (1024-bit integer).
   * Binary name: Wm3::TInteger32
   *
   * The internal representation is an array of 64 signed 16-bit words stored in
   * little-endian block order (least-significant block first).
   */
  class TInteger32
  {
  public:
    static constexpr int kNumBlocks = 64;

    /**
     * Address: 0x00A5A360 (FUN_00A5A360)
     * Mangled: ?GetTrailingBlock@TInteger32@Wm3@@QAEHH@Z
     *
     * IDA signature:
     * int __userpurge Wm3::TInteger32::GetTrailingBlock@<eax>(
     *   Wm3::TInteger32 *this@<ecx>, unsigned int blockIndex);
     *
     * What it does:
     * Returns the index (0..15) of the lowest set bit within the 16-bit block
     * at `blockIndex`. Returns -1 if the block index is out of range.
     */
    [[nodiscard]] int GetTrailingBlock(unsigned int blockIndex);

    /**
     * Address: 0x00A5AB30 (FUN_00A5AB30)
     * Mangled: ?GetTrailingBit@TInteger32@Wm3@@QAEPAFH@Z
     *
     * IDA signature:
     * __int16 *__userpurge Wm3::TInteger32::GetTrailingBit@<eax>(
     *   Wm3::TInteger32 *this@<ecx>, int bitCount);
     *
     * What it does:
     * Right-shifts the integer value by `bitCount` bits in place, sign-extending
     * the most significant blocks. Returns a pointer to the internal buffer.
     */
    std::int16_t* GetTrailingBit(int bitCount);

  public:
    std::int16_t m_asBuffer[kNumBlocks]; // +0x00, 128 bytes total
  };

  static_assert(sizeof(TInteger32) == 0x80, "TInteger32 size must be 0x80");
} // namespace Wm3
