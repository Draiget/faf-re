#pragma once

#include "PlatformDefines.h"

#include <cstdint>

#if FAFRE_ARCH_X86 || FAFRE_ARCH_X64
#include <xmmintrin.h>
#endif

/**
 * Engine addition: the floating-point control registers simulation threads run under, per
 * processor, for the code that copies or checks them (the worker pools' SFpuControlState, the
 * desync recorder, legacy/math's CRT lane gate).
 *
 *   x86, x86-64   MXCSR: rounding, flush-to-zero, denormals-are-zero, exception masks. Every
 *                 thread of the Windows x64 game runs at 0x1F80 (round to nearest, exceptions
 *                 masked, no FTZ/DAZ). The x87 control word is x86's alone (platform/X87Precision.h).
 *   ARM64         FPCR: rounding (RMode), flush-to-zero (FZ), default NaN (DN), alternate
 *                 handling (AH), trap enables. The simulation runs at 0: round to nearest, IEEE
 *                 denormals, NaN propagation, no traps - the arm64 counterpart of 0x1F80. A new
 *                 thread starts at 0 on Linux and macOS (the kernel's default, not the creator's
 *                 value), and nothing in the engine changes it.
 */
namespace platform
{
#if FAFRE_ARCH_X86 || FAFRE_ARCH_X64
  /// MXCSR's control bits (rounding, FTZ, DAZ, exception masks); the low six are sticky flags.
  inline constexpr std::uint32_t kMxcsrControlMask = 0xFFC0u;
  /// The Windows x64 game threads' MXCSR.
  inline constexpr std::uint32_t kSimMxcsr = 0x1F80u;

  [[nodiscard]] inline std::uint32_t ReadMxcsr() noexcept
  {
    return _mm_getcsr();
  }

  inline void WriteMxcsr(
    const std::uint32_t value
  ) noexcept
  {
    _mm_setcsr(value);
  }
#endif

#if FAFRE_ARCH_ARM64
  /// The simulation's FPCR: round to nearest, no flush-to-zero, no default NaN, no traps.
  inline constexpr std::uint64_t kSimFpcr = 0;

  [[nodiscard]] inline std::uint64_t ReadFpcr() noexcept
  {
    return __builtin_arm_rsr64("fpcr");
  }

  inline void WriteFpcr(
    const std::uint64_t value
  ) noexcept
  {
    __builtin_arm_wsr64("fpcr", value);
  }
#endif

  /**
   * Loads the simulation's floating-point control state on the calling thread where the
   * processor has one register for it: FPCR on ARM64. x86's MXCSR is already the game's on
   * every thread, and x86's x87 precision goes through SetX87PrecisionControl.
   */
  inline void LoadSimFloatingPointControl() noexcept
  {
#if FAFRE_ARCH_ARM64
    WriteFpcr(kSimFpcr);
#endif
  }
} // namespace platform
