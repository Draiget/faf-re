#include <cstdint>
#include <cstring>

extern "C"
{
  std::int32_t mpabdr_init_count = 0;
  std::uint8_t mpabdr_bref_table[0x4001]{};
  std::uint16_t mpabdr_mask16_table[0x101]{};
  std::uint32_t mpabdr_mask32_table[0x401]{};

  /**
   * Address: 0x00B297B0 (_mpabdr_Init)
   *
   * What it does:
   * Builds MPA bit-reader lookup/mask tables on first init.
   */
  int mpabdr_Init()
  {
    if (++mpabdr_init_count == 1) {
      std::uint32_t sourceByte = 0;
      std::uint8_t* brefWrite = &mpabdr_bref_table[1];
      do {
        for (std::uint32_t bitOffset = 0; bitOffset <= 7; ++bitOffset) {
          for (std::uint32_t bitCount = 0; bitCount < 8; ++bitCount) {
            const std::uint32_t shift = 7 - bitCount - bitOffset;
            const std::uint32_t mask = (0xFFu >> (7 - bitCount)) << shift;
            *brefWrite++ = static_cast<std::uint8_t>((sourceByte & mask) >> shift);
          }
        }
        ++sourceByte;
      } while (sourceByte <= 0xFFu);

      std::uint32_t startBit16 = 0;
      auto* mask16Write = &mpabdr_mask16_table[1];
      do {
        for (std::uint32_t bitCount = 0; bitCount < 16; ++bitCount) {
          const std::uint32_t shift = 15 - bitCount - startBit16;
          const std::uint32_t mask = (0xFFFFu >> (15 - bitCount)) << shift;
          *mask16Write++ = static_cast<std::uint16_t>(mask);
        }
        ++startBit16;
      } while (startBit16 <= 0x0Fu);

      std::uint32_t startBit32 = 0;
      auto* mask32Write = &mpabdr_mask32_table[1];
      do {
        for (std::uint32_t bitCount = 0; bitCount < 32; ++bitCount) {
          const std::uint32_t shift = 31 - bitCount - startBit32;
          const std::uint32_t mask = (0xFFFFFFFFu >> (31 - bitCount)) << shift;
          *mask32Write++ = mask;
        }
        ++startBit32;
      } while (startBit32 <= 0x1Fu);
    }

    return 0;
  }

  /**
   * Address: 0x00B298A0 (_mpabdr_Finish)
   *
   * What it does:
   * Clears MPA bit-reader tables when init refcount drops to zero.
   */
  int mpabdr_Finish()
  {
    if (--mpabdr_init_count == 0) {
      std::memset(&mpabdr_mask32_table[1], 0, 0x1000u);
      std::memset(&mpabdr_mask16_table[1], 0, 0x200u);
      std::memset(&mpabdr_bref_table[1], 0, 0x4000u);
    }

    return 0;
  }

  /**
   * Address: 0x00B298E0 (_mpabdr_GetBitVal8)
   *
   * What it does:
   * Reads one 8-bit source lane bitfield using prebuilt byte lookup table.
   */
  int __cdecl mpabdr_GetBitVal8(
    std::uint8_t sourceByte,
    int bitOffset,
    int bitCount,
    int* outValue
  )
  {
    *outValue = mpabdr_bref_table[
      64 * static_cast<int>(sourceByte) + (8 * bitOffset) + bitCount
    ];
    return 0;
  }

  /**
   * Address: 0x00B29910 (_mpabdr_GetBitVal16)
   *
   * What it does:
   * Reads one 16-bit big-endian source lane bitfield using mask table.
   */
  int __cdecl mpabdr_GetBitVal16(
    const std::uint8_t* sourceBytes,
    int bitOffset,
    int bitCount,
    int* outValue
  )
  {
    const std::uint32_t sourceWord =
      static_cast<std::uint32_t>(sourceBytes[1]) |
      (static_cast<std::uint32_t>(sourceBytes[0]) << 8);
    const std::uint32_t mask =
      mpabdr_mask16_table[(16 * bitOffset) + bitCount];

    *outValue = static_cast<int>(
      (mask & sourceWord) >> (16 - bitCount - bitOffset)
    );
    return 0;
  }

  /**
   * Address: 0x00B29960 (_mpabdr_GetBitVal32)
   *
   * What it does:
   * Reads one 32-bit big-endian source lane bitfield using mask table.
   */
  int __cdecl mpabdr_GetBitVal32(
    const std::uint8_t* sourceBytes,
    int bitOffset,
    int bitCount,
    std::uint32_t* outValue
  )
  {
    const std::uint32_t sourceDword =
      static_cast<std::uint32_t>(sourceBytes[3]) |
      (static_cast<std::uint32_t>(sourceBytes[2]) << 8) |
      (static_cast<std::uint32_t>(sourceBytes[1]) << 16) |
      (static_cast<std::uint32_t>(sourceBytes[0]) << 24);
    const std::uint32_t mask =
      mpabdr_mask32_table[(32 * bitOffset) + bitCount];

    *outValue = (mask & sourceDword) >> (32 - bitCount - bitOffset);
    return 0;
  }
}
