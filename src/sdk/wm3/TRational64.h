#pragma once

#include <cstddef>

#include "wm3/TInteger64.h"

namespace Wm3
{
  /**
   * Fixed-precision rational number (numerator / denominator) using TInteger64.
   * Binary name: Wm3::TRational64
   */
  class TRational64
  {
  public:
    /**
     * Address: 0x00A5BE50 (FUN_00A5BE50)
     * Mangled: ?EliminatePowersOfTwo@TRational64@Wm3@@QAEXXZ
     *
     * IDA signature:
     * void __thiscall Wm3::TRational64::EliminatePowersOfTwo(
     *   Wm3::TRational64 *this);
     *
     * What it does:
     * Reduces the rational by removing shared powers of two from numerator and
     * denominator. If the numerator is zero, sets the denominator to 1.
     */
    void EliminatePowersOfTwo();

  public:
    TInteger64 m_kNumer; // +0x00
    TInteger64 m_kDenom; // +0x100
  };

  static_assert(offsetof(TRational64, m_kNumer) == 0x00, "TRational64::m_kNumer offset must be 0x00");
  static_assert(offsetof(TRational64, m_kDenom) == 0x100, "TRational64::m_kDenom offset must be 0x100");
  static_assert(sizeof(TRational64) == 0x200, "TRational64 size must be 0x200");
} // namespace Wm3
