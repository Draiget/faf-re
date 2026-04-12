#pragma once

#include <cstddef>

#include "wm3/TInteger32.h"

namespace Wm3
{
  /**
   * Fixed-precision rational number (numerator / denominator) using TInteger32.
   * Binary name: Wm3::TRational32
   */
  class TRational32
  {
  public:
    /**
     * Address: 0x00A5AEE0 (FUN_00A5AEE0)
     * Mangled: ?EliminatePowersOfTwo@TRational32@Wm3@@QAEXXZ
     *
     * IDA signature:
     * void __thiscall Wm3::TRational32::EliminatePowersOfTwo(
     *   Wm3::TRational32 *this);
     *
     * What it does:
     * Reduces the rational by removing shared powers of two from numerator and
     * denominator. If the numerator is zero, sets the denominator to 1.
     */
    void EliminatePowersOfTwo();

  public:
    TInteger32 m_kNumer; // +0x00
    TInteger32 m_kDenom; // +0x80
  };

  static_assert(offsetof(TRational32, m_kNumer) == 0x00, "TRational32::m_kNumer offset must be 0x00");
  static_assert(offsetof(TRational32, m_kDenom) == 0x80, "TRational32::m_kDenom offset must be 0x80");
  static_assert(sizeof(TRational32) == 0x100, "TRational32 size must be 0x100");
} // namespace Wm3
