#pragma once

#include "FpControl.h"
#include "PlatformDefines.h"

#include <float.h>

namespace platform
{
  /**
   * The binary sets the x87 precision-control field with
   * `_controlfp(_PC_24, _MCW_PC)` on every thread that runs simulation or
   * frame code. x64 code generation never uses the x87 unit for arithmetic,
   * and the x64 CRT rejects the precision mask (the debug CRT asserts in
   * ieee.c, the release CRT ignores it), so on x64 this does nothing.
   *
   * ARM64 has no x87 unit (legacy/math's x87 routines are software there, at
   * the precision each asm routine sets itself). The same threads load the
   * simulation's FPCR here instead (platform/FpControl.h), so every thread that
   * runs simulation code starts from a known floating-point state.
   */
  inline void SetX87PrecisionControl(
    const unsigned int precision
  ) noexcept
  {
#if FAFRE_ARCH_X86
    (void)::_controlfp(precision, _MCW_PC);
#else
    (void)precision;
    LoadSimFloatingPointControl();
#endif
  }
} // namespace platform
