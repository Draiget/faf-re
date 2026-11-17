#pragma once

#include <cstdint>

/**
 * Engine addition (#262): the x87 instruction sequences of legacy/math/X87Routines.h in software,
 * bit for bit what the x87 unit stores, for targets without one (ARM64). The functions here have
 * the routines' signatures; X87Soft.cpp also defines the routines' C names (msvc8_x87_*) when the
 * build takes the software (FAF_SOFT_X87), and a test can link both these and the assembly on
 * x86-64 to compare them on real hardware (tools/x87-oracle).
 *
 * Model of the hardware:
 *   - Arithmetic (fadd, fsub, fmul, fdiv, fsqrt and their forms) rounds the exact result once to
 *     the precision-control width (24 bits at _PC_24) to nearest-even, keeping the extended
 *     exponent range: nothing overflows at FLT_MAX or turns denormal below FLT_MIN until the store.
 *   - fld, fild, fldl2e/fldln2/fldlg2/fld1, fchs, fabs, fxch: exact. frndint and fscale: exact
 *     (round to nearest-even integer; exponent add).
 *   - fstp m32 / m64: one rounding to binary32 / binary64, with denormals and overflow to infinity.
 *     fistp m32: round to nearest-even, the integer indefinite 0x80000000 outside int32 or for NaN.
 *   - fsin, fcos, fptan: the argument reduced exactly by Intel's 66-bit pi (|x| >= 2^63 left
 *     unchanged, out of range), then the function rounded to a 64-bit significand. fpatan, fyl2x,
 *     f2xm1: the function rounded to a 64-bit significand. The hardware is accurate to under one
 *     unit in the 64th bit; this model rounds correctly, so the two can differ only where the
 *     hardware's own error crosses a rounding boundary of what is stored after it - at most about
 *     2^-39 of inputs for a float result.
 *   - NaNs: an invalid operation gives the real indefinite (negative quiet NaN, 0xFFC00000 as a
 *     float); a NaN operand propagates quieted; of two NaNs the one with the larger significand.
 */
namespace fa::x87
{
  [[nodiscard]] float Sinf(float x) noexcept;
  [[nodiscard]] float Cosf(float x) noexcept;
  [[nodiscard]] float Tanf(float x) noexcept;
  [[nodiscard]] float Atan2f(float y, float x) noexcept;
  [[nodiscard]] double Acos(double x) noexcept;
  [[nodiscard]] double Asin(double x) noexcept;
  [[nodiscard]] double Pow(double x, double y) noexcept;
  [[nodiscard]] unsigned int ControlWord() noexcept;
  [[nodiscard]] float Atan2Difference(float firstY, float firstX, float secondY, float secondX) noexcept;
  [[nodiscard]] float Atan2Plus(float y, float x, float addend) noexcept;
  [[nodiscard]] float SinTimesCos(float sinArg, float cosArg) noexcept;
  [[nodiscard]] float SinOfProductTimes(float a, float b, float factor) noexcept;
  [[nodiscard]] float TwisterWordInRange(float lower, float upper, std::uint32_t word) noexcept;
  void SlerpSphericalBlend(
    float* outLanes,
    const float* q1Lanes,
    const float* rhsLanes,
    float angle,
    float oneMinusT,
    float t
  ) noexcept;
  [[nodiscard]] float IntrinsicExp(float x) noexcept;
  [[nodiscard]] float IntrinsicLn(float x) noexcept;
  [[nodiscard]] float IntrinsicLog10(float x) noexcept;
  [[nodiscard]] float IntrinsicLnQuotient(float x, double base) noexcept;
  [[nodiscard]] float ScaledLnQuotient(float numerator, float denominator, float scale) noexcept;
  [[nodiscard]] float CosTimesCos(float firstArg, float secondArg) noexcept;
  [[nodiscard]] float BilinearHeight(float h00, float h01, float h10, float h11, float fracX, float fracZ) noexcept;
  [[nodiscard]] float
  SubtractBilinearHeight(float top, float h00, float h01, float h10, float h11, float fracX, float fracZ) noexcept;
  [[nodiscard]] std::int32_t RoundToInt(float value) noexcept;
  void ScaleVectorMaxLength(float* x, float* y, float* z, float maxLength, float lengthSq) noexcept;
  void ScaleVectorToLength(float* destLanes, const float* sourceLanes, float lengthSq, float length) noexcept;
  void ScaleVector(float* destLanes, const float* sourceLanes, float scale) noexcept;
  [[nodiscard]] float BoxRadiusOnAxis(const float* boxLanes, const float* axisLanes) noexcept;
  void ScaleVectorToLengthOf(
    float* destLanes,
    const float* sourceLanes,
    const float* targetLanes,
    float sourceLengthSq
  ) noexcept;
  [[nodiscard]] float VectorLengthZYX(const float* lanes) noexcept;

  namespace testing
  {
    /**
     * The hot arithmetic routines on the exact model only, without the double fast path, so a
     * test can check the two agree (the fast path must be bit-identical wherever it is taken).
     */
    [[nodiscard]] float SinfExact(float x) noexcept;
    [[nodiscard]] float CosfExact(float x) noexcept;
    [[nodiscard]] float
    BilinearHeightExact(float h00, float h01, float h10, float h11, float fracX, float fracZ) noexcept;
    [[nodiscard]] float BoxRadiusOnAxisExact(const float* boxLanes, const float* axisLanes) noexcept;
    [[nodiscard]] float VectorLengthZYXExact(const float* lanes) noexcept;
    void ScaleVectorToLengthOfExact(
      float* destLanes,
      const float* sourceLanes,
      const float* targetLanes,
      float sourceLengthSq
    ) noexcept;
    [[nodiscard]] float TwisterWordInRangeExact(float lower, float upper, std::uint32_t word) noexcept;
  } // namespace testing
} // namespace fa::x87
