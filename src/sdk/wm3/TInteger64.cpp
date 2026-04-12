#include "wm3/TInteger64.h"

#include <cstring>

namespace Wm3
{
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
  int TInteger64::GetTrailingBlock(const unsigned int blockIndex)
  {
    if (blockIndex > 127)
    {
      return -1;
    }

    const std::int16_t block = m_asBuffer[blockIndex];
    const auto lowByte = static_cast<std::uint8_t>(block);

    if (lowByte != 0)
    {
      if ((lowByte & 0x0F) != 0)
      {
        if ((lowByte & 0x03) != 0)
        {
          return static_cast<std::uint8_t>(~lowByte) & 1;
        }
        else
        {
          return (static_cast<std::uint8_t>(~lowByte) & 4u | 8u) >> 2;
        }
      }
      else
      {
        if ((lowByte & 0x30) != 0)
        {
          return (static_cast<std::uint8_t>(~lowByte) & 0x10u | 0x40u) >> 4;
        }
        else
        {
          return (static_cast<std::uint8_t>(~lowByte) & 0x40u | 0x180u) >> 6;
        }
      }
    }
    else
    {
      const auto highBits = static_cast<std::uint16_t>(block);

      if ((highBits & 0x0F00) != 0)
      {
        if ((highBits & 0x0300) != 0)
        {
          return ((highBits & 0x0100) == 0 ? 1 : 0) | 8;
        }
        else
        {
          return ((highBits & 0x0400) == 0 ? 1 : 0) | 0x0A;
        }
      }
      else if ((highBits & 0x3000) != 0)
      {
        return ((highBits & 0x1000) == 0 ? 1 : 0) | 0x0C;
      }
      else
      {
        return ((highBits & 0x4000) == 0 ? 1 : 0) | 0x0E;
      }
    }
  }

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
  std::int16_t* TInteger64::GetTrailingBit(const int bitCount)
  {
    if (bitCount <= 0)
    {
      return m_asBuffer;
    }

    const int blockShift = bitCount / 16;
    if (blockShift > 127)
    {
      return m_asBuffer;
    }

    // Phase 1: Shift whole blocks
    if (blockShift > 0)
    {
      int destIdx = 0;
      const std::int16_t* src = &m_asBuffer[blockShift];
      int remaining = kNumBlocks - blockShift;
      do
      {
        m_asBuffer[destIdx++] = *src++;
        --remaining;
      } while (remaining);

      // Sign-extend the vacated high blocks
      const int signValue = (m_asBuffer[kNumBlocks - 1] < 0) ? -1 : 0;

      if (destIdx <= 127)
      {
        const auto fillCount = static_cast<unsigned int>(kNumBlocks - destIdx) >> 1;
        std::int16_t* fillPtr = &m_asBuffer[destIdx];
        std::memset(fillPtr, (signValue == -1) ? 0xFF : 0x00, fillCount * sizeof(std::int32_t));
        auto* tail = reinterpret_cast<char*>(&fillPtr[2 * fillCount]);
        for (int i = (kNumBlocks - static_cast<std::uint8_t>(destIdx)) & 1; i > 0; --i)
        {
          *reinterpret_cast<std::int16_t*>(tail) = static_cast<std::int16_t>(signValue);
          tail += 2;
        }
      }
    }

    // Phase 2: Shift remaining bits within blocks
    const int bitRemainder = bitCount % 16;
    if (bitRemainder > 0)
    {
      auto* ptr = reinterpret_cast<std::uint16_t*>(m_asBuffer);
      int iterations = kNumBlocks - 1;
      do
      {
        const auto cur = static_cast<std::uint32_t>(ptr[0]);
        const auto next = static_cast<std::uint32_t>(ptr[1]);
        const std::uint32_t combined = cur | (next << 16);
        ptr[0] = static_cast<std::uint16_t>(combined >> bitRemainder);
        ++ptr;
        --iterations;
      } while (iterations);

      // Handle the last block with sign extension
      auto lastWord = static_cast<std::uint32_t>(static_cast<std::uint16_t>(m_asBuffer[kNumBlocks - 1]));
      if (m_asBuffer[kNumBlocks - 1] < 0)
      {
        lastWord |= 0xFFFF0000u;
      }
      m_asBuffer[kNumBlocks - 1] = static_cast<std::int16_t>(lastWord >> bitRemainder);
    }

    return m_asBuffer;
  }
} // namespace Wm3
