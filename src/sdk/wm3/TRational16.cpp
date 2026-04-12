#include "wm3/TRational16.h"

#include <cstring>

#include "wm3/System.h"

namespace Wm3
{
  /**
   * Address: 0x00A78410 (FUN_00A78410)
   * Mangled: ?EliminatePowersOfTwo@TRational16@Wm3@@QAEXXZ
   *
   * IDA signature:
   * void __thiscall Wm3::TRational16::EliminatePowersOfTwo(
   *   Wm3::TRational16 *this);
   *
   * What it does:
   * Reduces the rational by removing shared powers of two from numerator and
   * denominator. If the numerator is zero, sets the denominator to 1.
   */
  void TRational16::EliminatePowersOfTwo()
  {
    // Both numerator and denominator must be even for there to be shared powers of two.
    if ((m_kNumer.m_asBuffer[0] & 1) != 0)
    {
      return;
    }

    if ((m_kDenom.m_asBuffer[0] & 1) != 0)
    {
      return;
    }

    // Find the first non-zero block in the numerator.
    int numerFirstNonZero = 0;
    while (m_kNumer.m_asBuffer[numerFirstNonZero] == 0)
    {
      if (++numerFirstNonZero > 31)
      {
        break;
      }
    }

    // If the numerator is entirely zero, set denominator to 1 and return.
    if (numerFirstNonZero > 31 || numerFirstNonZero == -1)
    {
      TInteger16 one{};
      std::memset(&one, 0, sizeof(one));
      int oneValue = 1;
      System::Memcpy(&one, 4u, &oneValue, 4u);
      System::Memcpy(&m_kDenom, sizeof(TInteger16), &one, sizeof(TInteger16));
      return;
    }

    // Find the first non-zero block in the denominator.
    int denomFirstNonZero = 0;
    {
      const std::int16_t* denomPtr = m_kDenom.m_asBuffer;
      while (*denomPtr == 0)
      {
        ++denomFirstNonZero;
        ++denomPtr;
        if (denomFirstNonZero > 31)
        {
          denomFirstNonZero = -1;
          break;
        }
      }
    }

    // Take the minimum number of completely zero blocks.
    int minZeroBlocks = numerFirstNonZero;
    if (numerFirstNonZero >= denomFirstNonZero)
    {
      minZeroBlocks = denomFirstNonZero;
    }

    // Count trailing zero bits within the first non-zero blocks.
    const int numerTrailingBits = m_kNumer.GetTrailingBlock(numerFirstNonZero);
    const int denomTrailingBits = m_kDenom.GetTrailingBlock(denomFirstNonZero);

    // Take the minimum of the two trailing-bit counts.
    int minTrailingBits = denomTrailingBits;
    if (numerTrailingBits < denomTrailingBits)
    {
      minTrailingBits = numerTrailingBits;
    }

    // Total shared trailing zero bits = (whole blocks * 16) + sub-block bits.
    const int totalShift = minTrailingBits + 16 * minZeroBlocks;

    // Right-shift both numerator and denominator to eliminate the shared factor.
    m_kNumer.GetTrailingBit(totalShift);
    m_kDenom.GetTrailingBit(totalShift);
  }
} // namespace Wm3
