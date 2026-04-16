#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  /**
   * Packed bit storage using 32-bit words.
   *
   * Layout matches multiple binary-facing containers that store:
   * - bit count
   * - reserved base-word metadata
   * - begin/end/capacity word pointers
   */
  struct SBitStorage32
  {
    std::uint32_t mBitCount;          // +0x00
    std::uint32_t mReservedWordBase;  // +0x04
    std::uint32_t* mWords;            // +0x08
    std::uint32_t* mWordsEnd;         // +0x0C
    std::uint32_t* mWordsCapacityEnd; // +0x10

    /**
      * Alias of FUN_00440030 (non-canonical helper lane).
     * Address: 0x00443110 (FUN_00443110, storage-reset lane preserving base-word metadata)
     * Address: 0x00443144 (FUN_00443144, capacity-tail clear lane)
     *
     * What it does:
     * Releases word storage and clears all metadata lanes.
     */
    void Reset();

    /**
     * Address: 0x00443150/FUN_00443150 behavior-equivalent shape
     * Address: 0x00443950 (FUN_00443950, word-window allocation helper lane)
     *
     * std::uint32_t,bool
     *
     * What it does:
     * Resizes packed storage for `bitCount` bits and initializes payload words.
     */
    void Resize(std::uint32_t bitCount, bool setBits);

    /**
     * Address: 0x00642140/FUN_00642140 behavior-equivalent
     * Address: 0x00443860 (FUN_00443860, bit-cursor test lane)
     *
     * std::uint32_t
     *
     * What it does:
     * Returns whether one bit is set.
     */
    [[nodiscard]]
    bool TestBit(std::uint32_t bitIndex) const;

    /**
     * Address: 0x0063EF20/FUN_0063EF20 behavior-equivalent
     * Address: 0x00443830 (FUN_00443830, bit-cursor set/clear lane)
     *
     * std::uint32_t,bool
     *
     * What it does:
     * Sets or clears one bit.
     */
    void SetBit(std::uint32_t bitIndex, bool enabled);
  };

  static_assert(offsetof(SBitStorage32, mBitCount) == 0x00, "SBitStorage32::mBitCount offset must be 0x00");
  static_assert(
    offsetof(SBitStorage32, mReservedWordBase) == 0x04,
    "SBitStorage32::mReservedWordBase offset must be 0x04"
  );
  static_assert(offsetof(SBitStorage32, mWords) == 0x08, "SBitStorage32::mWords offset must be 0x08");
  static_assert(offsetof(SBitStorage32, mWordsEnd) == 0x0C, "SBitStorage32::mWordsEnd offset must be 0x0C");
  static_assert(
    offsetof(SBitStorage32, mWordsCapacityEnd) == 0x10,
    "SBitStorage32::mWordsCapacityEnd offset must be 0x10"
  );
  static_assert(sizeof(SBitStorage32) == 0x14, "SBitStorage32 size must be 0x14");
} // namespace moho
