#pragma once

#include "platform/PlatformDefines.h"

#include <cstdint>

/**
 * The x87 instruction sequences legacy/math/X87Math.cpp runs on 64-bit targets, which have no
 * inline x87 assembly: each is a retail code block at the x87 precision it sets itself (most at
 * _PC_24), with the caller's arguments in and the stored result out. 32-bit x86 inlines the same
 * blocks in X87Math.cpp.
 *
 *   x86-64 Windows   legacy/math/X87Math64.asm (MASM, Windows x64 calling convention)
 *   x86-64 Linux     legacy/math/X87Math64.S (System V)
 *   ARM64            legacy/math/X87Soft.cpp: software, bit for bit what the x87 unit stores
 *                    (#262). FAF_SOFT_X87 builds it on x86-64 in their place, to compare.
 */
#if FAFRE_ARCH_64BIT
extern "C" float __cdecl msvc8_x87_sinf(float x);
extern "C" float __cdecl msvc8_x87_cosf(float x);
extern "C" float __cdecl msvc8_x87_tanf(float x);
extern "C" float __cdecl msvc8_x87_atan2f(float y, float x);
extern "C" double __cdecl msvc8_x87_acos(double x);
extern "C" double __cdecl msvc8_x87_asin(double x);
extern "C" double __cdecl msvc8_x87_pow(double x, double y);
extern "C" unsigned int __cdecl msvc8_x87_control_word();
extern "C" float __cdecl msvc8_x87_atan2_difference(float firstY, float firstX, float secondY, float secondX);
extern "C" float __cdecl msvc8_x87_atan2_plus(float y, float x, float addend);
extern "C" float __cdecl msvc8_x87_sin_times_cos(float sinArg, float cosArg);
extern "C" float __cdecl msvc8_x87_sin_of_product_times(float a, float b, float factor);
extern "C" float __cdecl msvc8_x87_twister_word_in_range(float lower, float upper, std::uint32_t word);
extern "C" void __cdecl msvc8_x87_slerp_spherical_blend(
  float* outLanes,
  const float* q1Lanes,
  const float* rhsLanes,
  float angle,
  float oneMinusT,
  float t
);
extern "C" float __cdecl msvc8_x87_intrinsic_exp(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_ln(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_log10(float x);
extern "C" float __cdecl msvc8_x87_intrinsic_ln_quotient(float x, double base);
extern "C" float __cdecl msvc8_x87_scaled_ln_quotient(float numerator, float denominator, float scale);
extern "C" float __cdecl msvc8_x87_cos_times_cos(float firstArg, float secondArg);
extern "C" float __cdecl
msvc8_x87_bilinear_height(float h00, float h01, float h10, float h11, float fracX, float fracZ);
extern "C" float __cdecl
msvc8_x87_subtract_bilinear_height(float top, float h00, float h01, float h10, float h11, float fracX, float fracZ);
extern "C" std::int32_t __cdecl msvc8_x87_round_to_int(float value);
extern "C" void __cdecl
msvc8_x87_scale_vector_max_length(float* x, float* y, float* z, float maxLength, float lengthSq);
extern "C" void __cdecl
msvc8_x87_scale_vector_to_length(float* destLanes, const float* sourceLanes, float lengthSq, float length);
extern "C" void __cdecl msvc8_x87_scale_vector(float* destLanes, const float* sourceLanes, float scale);
extern "C" float __cdecl msvc8_x87_box_radius_on_axis(const float* boxLanes, const float* axisLanes);
extern "C" void __cdecl msvc8_x87_scale_vector_to_length_of(
  float* destLanes,
  const float* sourceLanes,
  const float* targetLanes,
  float sourceLengthSq
);
extern "C" float __cdecl msvc8_x87_vector_length_zyx(const float* lanes);
#endif
