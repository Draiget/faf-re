#pragma once

namespace msvc8::libm
{
  /**
   * Engine addition (dedicated-server plan WPL.11), not in the binary: the double `exp`, `log`
   * and `asin` the simulation's float lanes (`msvc8::expf`, `logf`, `asinf`) round to float,
   * in the engine instead of the host's libm, so Windows and Linux run the same code. Ports of
   * musl 1.2.5 (`exp` and `log` from Arm's optimized-routines, `asin` from fdlibm), SSE2 double
   * arithmetic with no contraction on every target. `(float)f((double)x)` equals the Windows
   * x64 UCRT's for every float (faf_sim_math_tests --sweep against the UCRT sweep of WPL.12).
   * Floating-point exception flags are not raised as the C library would; nothing reads them.
   */
  [[nodiscard]] double exp(double x) noexcept;
  [[nodiscard]] double log(double x) noexcept;
  [[nodiscard]] double asin(double x) noexcept;
} // namespace msvc8::libm
