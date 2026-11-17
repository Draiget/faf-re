#pragma once

#include "PlatformDefines.h"

#if FAFRE_ARCH_X86 || FAFRE_ARCH_X64
#include <immintrin.h>
#endif

namespace platform
{
  /**
   * Engine addition: the pause inside a spin-wait loop, which tells the core it is waiting so it
   * yields resources to the other hardware thread and saves power.
   *
   *   x86, x86-64   `pause`
   *   ARM64         `isb sy`: `yield` is close to a no-op on Apple's and most other cores, while an
   *                 instruction barrier stalls for a few dozen cycles like x86's `pause`.
   */
  inline void SpinPause() noexcept
  {
#if FAFRE_ARCH_X86 || FAFRE_ARCH_X64
    _mm_pause();
#elif FAFRE_ARCH_ARM64
    __builtin_arm_isb(15);
#endif
  }
} // namespace platform
