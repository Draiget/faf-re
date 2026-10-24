#pragma once

#include <math.h>

/**
 * Force-included into every x86 engine translation unit (src/CMakeLists.txt).
 *
 * The simulation runs with the x87 precision-control field at `_PC_24`
 * (platform::SetX87PrecisionControl). Under that control word the CRT's
 * `sqrt` - the call Debug makes, and the `fsqrt` the original x87 binary
 * executed - rounds its result to 24 bits. /O2 implies /Oi, and with /Oi
 * MSVC replaces `sqrt(double)` by `__libm_sse2_sqrt_precise`, an SSE2
 * `sqrtsd` that ignores the x87 control word, so the two configurations
 * produced different doubles for the same input (every one of 2,000,000
 * sampled inputs differed under `_PC_24`; none did under `_PC_53`).
 *
 * `#pragma function` keeps `sqrt` a call to the CRT function while leaving
 * every other /Oi intrinsic in place. With it, sqrt, sin, cos, tan, asin,
 * acos, atan, atan2, exp, log, log10, pow, fmod and floor - double and float
 * forms - are bit-identical between a /Od translation unit and an /O2 one
 * under both precision settings. Dropping /Oi instead (`/Oi-`) is worse: the
 * optimizer then keeps call results on the x87 stack and rounds follow-on
 * arithmetic to 24 bits, which broke log/log10 parity in the same test.
 */
#if defined(_M_IX86)
#pragma function(sqrt)
#endif
