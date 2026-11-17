#pragma once

#include "../PlatformDefines.h"

// Engine addition (dedicated-server plan WPL.9): the POSIX threads' floating-point
// environment, pinned to the Windows x64 build's (platform/posix/FpEnvPosix.cpp).

#if !FAFRE_PLATFORM_WINDOWS

#include <cstdint>

namespace platform::posix
{
#if FAFRE_ARCH_X64
  /// The Windows x64 threads' x87 control word (WPL.8): 53-bit precision, round to nearest,
  /// exceptions masked.
  inline constexpr std::uint16_t kSimX87ControlWord = 0x027F;
  /// The Windows x64 threads' MXCSR (WPL.8): round to nearest, exceptions masked, no FTZ/DAZ.
  inline constexpr std::uint32_t kSimMxcsr = 0x1F80;
#endif

  struct FloatingPointState
  {
    std::uint32_t x87ControlWord; // x86-64
    std::uint32_t mxcsr;          // x86-64
    std::uint64_t fpcr;           // ARM64
  };

  /// Loads the simulation's floating-point control state on the calling thread: the x87 control
  /// word and MXCSR on x86-64, FPCR on ARM64 (platform/FpControl.h).
  void SetSimFloatingPointEnvironment() noexcept;

  /// The calling thread's floating-point control state.
  [[nodiscard]] FloatingPointState ReadFloatingPointEnvironment() noexcept;
} // namespace platform::posix

#endif
