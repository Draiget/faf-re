#pragma once

#include <cstddef>
#include <cstdint>

namespace Wm3
{
  /**
   * Fixed-precision integer type using 128 blocks of 16 bits (2048-bit integer).
   * Binary name: Wm3::TInteger64
   *
   * The internal representation is an array of 128 signed 16-bit words stored in
   * little-endian block order (least-significant block first).
   */
  class TInteger64
  {
  public:
    static constexpr int kNumBlocks = 128;

    /**
     * Address: 0x00A5B2E0 (FUN_00A5B2E0)
     * Mangled: ?GetTrailingBlock@TInteger64@Wm3@@QAEHH@Z
     *
     * IDA signature:
     * int __userpurge Wm3::TInteger64::GetTrailingBlock@<eax>(
     *   Wm3::TInteger64 *this@<ecx>, unsigned int blockIndex);
     *
     * What it does:
     * Returns the index (0..15) of the lowest set bit within the 16-bit block
     * at `blockIndex`. Returns -1 if the block index is out of range.
     */
    [[nodiscard]] int GetTrailingBlock(unsigned int blockIndex);

    /**
     * Address: 0x00A5BAC0 (FUN_00A5BAC0)
     * Mangled: ?GetTrailingBit@TInteger64@Wm3@@QAEPAFH@Z
     *
     * IDA signature:
     * __int16 *__userpurge Wm3::TInteger64::GetTrailingBit@<eax>(
     *   Wm3::TInteger64 *this@<ecx>, int bitCount);
     *
     * What it does:
     * Right-shifts the integer value by `bitCount` bits in place, sign-extending
     * the most significant blocks. Returns a pointer to the internal buffer.
     */
    std::int16_t* GetTrailingBit(int bitCount);

  public:
    std::int16_t m_asBuffer[kNumBlocks]; // +0x00, 256 bytes total
  };

  static_assert(sizeof(TInteger64) == 0x100, "TInteger64 size must be 0x100");
} // namespace Wm3
