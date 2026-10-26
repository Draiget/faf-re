#pragma once

// Engine addition (dedicated-server plan WPL.9): the Linux threads' floating-point
// environment, pinned to the Windows x64 build's (platform/posix/FpEnvPosix.cpp).

#if !defined(_WIN32)

#include <cstdint>

namespace platform::posix
{
  /// The Windows x64 threads' x87 control word (WPL.8): 53-bit precision, round to nearest,
  /// exceptions masked.
  inline constexpr std::uint16_t kSimX87ControlWord = 0x027F;
  /// The Windows x64 threads' MXCSR (WPL.8): round to nearest, exceptions masked, no FTZ/DAZ.
  inline constexpr std::uint32_t kSimMxcsr = 0x1F80;

  struct FloatingPointState
  {
    std::uint32_t x87ControlWord;
    std::uint32_t mxcsr;
  };

  /// Loads kSimX87ControlWord and kSimMxcsr on the calling thread.
  void SetSimFloatingPointEnvironment() noexcept;

  /// The calling thread's x87 control word and MXCSR.
  [[nodiscard]] FloatingPointState ReadFloatingPointEnvironment() noexcept;
} // namespace platform::posix

#endif
