#pragma once

#include <float.h>

namespace platform
{
  /**
   * The binary sets the x87 precision-control field with
   * `_controlfp(_PC_24, _MCW_PC)` on every thread that runs simulation or
   * frame code. x64 code generation never uses the x87 unit for arithmetic,
   * and the x64 CRT rejects the precision mask (the debug CRT asserts in
   * ieee.c, the release CRT ignores it), so on x64 this does nothing.
   */
  inline void SetX87PrecisionControl(const unsigned int precision) noexcept
  {
#if defined(_M_IX86)
    (void)::_controlfp(precision, _MCW_PC);
#else
    (void)precision;
#endif
  }
} // namespace platform
