#pragma once

#include <cstddef>

#include "wm3/TInteger16.h"

namespace Wm3
{
  /**
   * Fixed-precision rational number (numerator / denominator) using TInteger16.
   * Binary name: Wm3::TRational16
   */
  class TRational16
  {
  public:
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
    void EliminatePowersOfTwo();

  public:
    TInteger16 m_kNumer; // +0x00
    TInteger16 m_kDenom; // +0x40
  };

  static_assert(offsetof(TRational16, m_kNumer) == 0x00, "TRational16::m_kNumer offset must be 0x00");
  static_assert(offsetof(TRational16, m_kDenom) == 0x40, "TRational16::m_kDenom offset must be 0x40");
  static_assert(sizeof(TRational16) == 0x80, "TRational16 size must be 0x80");
} // namespace Wm3
