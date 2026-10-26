// Engine addition (dedicated-server plan WPL.10): the System V x86-64 port of
// X87Math64.asm, instruction for instruction (legacy/math/X87Math.cpp).
//
// The x87 sequences are the MASM file's. What differs is the calling
// convention: System V passes float and double arguments in xmm0..xmm7 in
// order and pointers in rdi, rsi, rdx, rcx (Windows x64 passes the n-th
// argument in the n-th register of either kind, and the fifth and sixth on the
// stack), and the scratch slots are in the 128-byte red zone below rsp instead
// of the caller's home area above it. Every routine is a leaf, so rsp never
// moves. tests/sim_math checks the results bit for bit against the Windows x64
// build.

    .intel_syntax noprefix
    .text

// Saves the control word at [rsp-8] and loads it with the precision field
// cleared (24-bit) from [rsp-6]; RESTORE_CW puts the caller's back.
.macro SET_PC24
    fnstcw  word ptr [rsp-8]
    movzx   eax, word ptr [rsp-8]
    and     eax, 0xfffffcff
    mov     word ptr [rsp-6], ax
    fldcw   word ptr [rsp-6]
.endm

.macro RESTORE_CW
    fldcw   word ptr [rsp-8]
.endm

.macro FUNC name
    .globl  \name
    .type   \name, @function
    .p2align 4
\name:
.endm

.macro ENDF name
    .size   \name, . - \name
.endm

// int32_t msvc8_x87_round_to_int(float value)
FUNC msvc8_x87_round_to_int
    movss   dword ptr [rsp-16], xmm0
    fld     dword ptr [rsp-16]
    fistp   dword ptr [rsp-16]
    mov     eax, dword ptr [rsp-16]
    ret
ENDF msvc8_x87_round_to_int

// float msvc8_x87_bilinear_height(h00, h01, h10, h11, fracX, fracZ): xmm0..xmm5.
FUNC msvc8_x87_bilinear_height
    movss   dword ptr [rsp-32], xmm0    // h00
    movss   dword ptr [rsp-28], xmm1    // h01
    movss   dword ptr [rsp-24], xmm2    // h10
    movss   dword ptr [rsp-20], xmm3    // h11
    movss   dword ptr [rsp-16], xmm4    // fracX
    movss   dword ptr [rsp-12], xmm5    // fracZ
    SET_PC24
    fld     dword ptr [rsp-28]
    fld     dword ptr [rsp-32]
    fsub    st(1), st(0)
    fld     dword ptr [rsp-12]
    fmul    st(2), st(0)
    fxch    st(2)
    faddp   st(1), st(0)
    fld     dword ptr [rsp-20]
    fld     dword ptr [rsp-24]
    fsub    st(1), st(0)
    fxch    st(1)
    fmulp   st(3), st(0)
    faddp   st(2), st(0)
    fsub    st(1), st(0)
    fxch    st(1)
    fmul    dword ptr [rsp-16]
    faddp   st(1), st(0)
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_bilinear_height

// float msvc8_x87_sinf(float x)
FUNC msvc8_x87_sinf
    movss   dword ptr [rsp-16], xmm0
    fld     dword ptr [rsp-16]
    fsin
    fstp    dword ptr [rsp-16]
    movss   xmm0, dword ptr [rsp-16]
    ret
ENDF msvc8_x87_sinf

// float msvc8_x87_cosf(float x)
FUNC msvc8_x87_cosf
    movss   dword ptr [rsp-16], xmm0
    fld     dword ptr [rsp-16]
    fcos
    fstp    dword ptr [rsp-16]
    movss   xmm0, dword ptr [rsp-16]
    ret
ENDF msvc8_x87_cosf

// float msvc8_x87_tanf(float x)
FUNC msvc8_x87_tanf
    movss   dword ptr [rsp-16], xmm0
    fld     dword ptr [rsp-16]
    fptan                               // tan(x), then 1.0
    fstp    st(0)                       // drop the 1.0
    fstp    dword ptr [rsp-16]
    movss   xmm0, dword ptr [rsp-16]
    ret
ENDF msvc8_x87_tanf

// float msvc8_x87_atan2f(float y, float x)
FUNC msvc8_x87_atan2f
    movss   dword ptr [rsp-16], xmm0    // y
    movss   dword ptr [rsp-12], xmm1    // x
    fld     dword ptr [rsp-16]
    fld     dword ptr [rsp-12]
    fpatan                              // atan(y / x) with the quadrant of (x, y)
    fstp    dword ptr [rsp-16]
    movss   xmm0, dword ptr [rsp-16]
    ret
ENDF msvc8_x87_atan2f

// unsigned msvc8_x87_control_word()
FUNC msvc8_x87_control_word
    fnstcw  word ptr [rsp-16]
    movzx   eax, word ptr [rsp-16]
    ret
ENDF msvc8_x87_control_word

// double msvc8_x87_acos(double x), the simulation's original PC24 CRT lane.
FUNC msvc8_x87_acos
    movsd   qword ptr [rsp-24], xmm0
    SET_PC24
    fld     qword ptr [rsp-24]
    fld1
    fadd    st(0), st(1)
    fld1
    fsub    st(0), st(2)
    fmulp   st(1), st(0)
    fsqrt
    fxch    st(1)
    fpatan
    fstp    qword ptr [rsp-24]
    RESTORE_CW
    movsd   xmm0, qword ptr [rsp-24]
    ret
ENDF msvc8_x87_acos

// double msvc8_x87_asin(double x): atan2(x, sqrt((1 + x) * (1 - x))) at PC24.
FUNC msvc8_x87_asin
    movsd   qword ptr [rsp-24], xmm0
    SET_PC24
    fld     qword ptr [rsp-24]
    fld1
    fadd    st(0), st(1)
    fld1
    fsub    st(0), st(2)
    fmulp   st(1), st(0)
    fsqrt
    fpatan
    fstp    qword ptr [rsp-24]
    RESTORE_CW
    movsd   xmm0, qword ptr [rsp-24]
    ret
ENDF msvc8_x87_asin

// double msvc8_x87_pow(double x, double y): fyl2x, then frndint/f2xm1/fscale, at PC24.
FUNC msvc8_x87_pow
    movsd   qword ptr [rsp-24], xmm0    // x
    movsd   qword ptr [rsp-32], xmm1    // y
    SET_PC24
    fld     qword ptr [rsp-32]
    fld     qword ptr [rsp-24]
    fyl2x
    fld     st(0)
    frndint
    fsubr   st(1), st(0)
    fxch    st(1)
    fchs
    f2xm1
    fld1
    faddp   st(1), st(0)
    fscale
    fstp    st(1)
    fstp    qword ptr [rsp-24]
    RESTORE_CW
    movsd   xmm0, qword ptr [rsp-24]
    ret
ENDF msvc8_x87_pow

// float msvc8_x87_atan2_difference(firstY, firstX, secondY, secondX): xmm0..xmm3.
FUNC msvc8_x87_atan2_difference
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    movss   dword ptr [rsp-24], xmm2
    movss   dword ptr [rsp-20], xmm3
    SET_PC24
    fld     dword ptr [rsp-32]
    fld     dword ptr [rsp-28]
    fpatan
    fstp    dword ptr [rsp-32]
    fld     dword ptr [rsp-24]
    fld     dword ptr [rsp-20]
    fpatan
    fsubr   dword ptr [rsp-32]
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_atan2_difference

// float msvc8_x87_atan2_plus(float y, float x, float addend)
FUNC msvc8_x87_atan2_plus
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    movss   dword ptr [rsp-24], xmm2
    SET_PC24
    fld     dword ptr [rsp-32]
    fld     dword ptr [rsp-28]
    fpatan
    fadd    dword ptr [rsp-24]
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_atan2_plus

// float msvc8_x87_sin_times_cos(float sinArg, float cosArg)
FUNC msvc8_x87_sin_times_cos
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    SET_PC24
    fld     dword ptr [rsp-28]
    fcos
    fld     dword ptr [rsp-32]
    fsin
    fmulp   st(1), st(0)
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_sin_times_cos

// float msvc8_x87_sin_times(float sinArg, float factor)
FUNC msvc8_x87_sin_times
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    SET_PC24
    fld     dword ptr [rsp-32]
    fsin
    fmul    dword ptr [rsp-28]
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_sin_times

// void msvc8_x87_slerp_spherical_blend(float* out, const float* q1, const float* rhs,
//                                      float angle, float oneMinusT, float t)
// rdi=out, rsi=q1, rdx=rhs, xmm0=angle, xmm1=oneMinusT, xmm2=t.
FUNC msvc8_x87_slerp_spherical_blend
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    movss   dword ptr [rsp-24], xmm2
    SET_PC24
    fld     dword ptr [rsp-32]
    fld     st(0)
    fsin
    fld1
    fdivrp  st(1), st(0)
    fld     st(1)
    fmul    dword ptr [rsp-28]
    fsin
    fmul    st(0), st(1)
    fld     dword ptr [rsp-24]
    fmulp   st(3), st(0)
    fxch    st(2)
    fsin
    fmulp   st(1), st(0)
    fld     dword ptr [rsi]
    fmul    st(0), st(2)
    fld     dword ptr [rdx]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rdi]
    fld     dword ptr [rsi+4]
    fmul    st(0), st(2)
    fld     dword ptr [rdx+4]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rdi+4]
    fld     dword ptr [rsi+8]
    fmul    st(0), st(2)
    fld     dword ptr [rdx+8]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rdi+8]
    fld     dword ptr [rsi+12]
    fmulp   st(2), st(0)
    fmul    dword ptr [rdx+12]
    faddp   st(1), st(0)
    fstp    dword ptr [rdi+12]
    RESTORE_CW
    ret
ENDF msvc8_x87_slerp_spherical_blend

// float msvc8_x87_intrinsic_exp(float x): MSVC8's /Oi exp expansion at PC24.
FUNC msvc8_x87_intrinsic_exp
    movss   dword ptr [rsp-32], xmm0
    SET_PC24
    fld     dword ptr [rsp-32]
    fldl2e
    fmulp   st(1), st(0)
    fld     st(0)
    frndint
    fxch    st(1)
    fsub    st(0), st(1)
    f2xm1
    fld1
    faddp   st(1), st(0)
    fscale
    fstp    st(1)
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_intrinsic_exp

// float msvc8_x87_intrinsic_ln(float x)
FUNC msvc8_x87_intrinsic_ln
    movss   dword ptr [rsp-32], xmm0
    SET_PC24
    fld     dword ptr [rsp-32]
    fldln2
    fxch    st(1)
    fyl2x
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_intrinsic_ln

// float msvc8_x87_intrinsic_ln_quotient(float x, double base): xmm0, xmm1.
FUNC msvc8_x87_intrinsic_ln_quotient
    movss   dword ptr [rsp-32], xmm0
    movsd   qword ptr [rsp-24], xmm1
    SET_PC24
    fld     dword ptr [rsp-32]
    fldln2
    fxch    st(1)
    fyl2x
    fld     qword ptr [rsp-24]
    fldln2
    fxch    st(1)
    fyl2x
    fdivp   st(1), st(0)
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_intrinsic_ln_quotient

// float msvc8_x87_scaled_ln_quotient(float numerator, float denominator, float scale)
FUNC msvc8_x87_scaled_ln_quotient
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    movss   dword ptr [rsp-24], xmm2
    SET_PC24
    fld     dword ptr [rsp-32]
    fdiv    dword ptr [rsp-28]
    fldln2
    fxch    st(1)
    fyl2x
    fmul    dword ptr [rsp-24]
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_scaled_ln_quotient

// float msvc8_x87_intrinsic_log10(float x)
FUNC msvc8_x87_intrinsic_log10
    movss   dword ptr [rsp-32], xmm0
    SET_PC24
    fld     dword ptr [rsp-32]
    fldlg2
    fxch    st(1)
    fyl2x
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_intrinsic_log10

// float msvc8_x87_cos_times_cos(float firstArg, float secondArg)
FUNC msvc8_x87_cos_times_cos
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    SET_PC24
    fld     dword ptr [rsp-28]
    fcos
    fld     dword ptr [rsp-32]
    fcos
    fmulp   st(1), st(0)
    fstp    dword ptr [rsp-32]
    RESTORE_CW
    movss   xmm0, dword ptr [rsp-32]
    ret
ENDF msvc8_x87_cos_times_cos

// void msvc8_x87_scale_vector_max_length(float* x, float* y, float* z, float maxLength, float lengthSq)
// rdi=x, rsi=y, rdx=z, xmm0=maxLength, xmm1=lengthSq (the caller's float).
FUNC msvc8_x87_scale_vector_max_length
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    SET_PC24
    fld     dword ptr [rsp-28]
    fsqrt
    fdivr   dword ptr [rsp-32]
    fld     dword ptr [rdi]
    fmul    st(0), st(1)
    fstp    dword ptr [rdi]
    fld     dword ptr [rsi]
    fmul    st(0), st(1)
    fstp    dword ptr [rsi]
    fmul    dword ptr [rdx]
    fstp    dword ptr [rdx]
    RESTORE_CW
    ret
ENDF msvc8_x87_scale_vector_max_length

// void msvc8_x87_scale_vector_to_length(float* dest, const float* source, float lengthSq, float length)
// rdi=dest, rsi=source, xmm0=lengthSq, xmm1=length.
FUNC msvc8_x87_scale_vector_to_length
    movss   dword ptr [rsp-32], xmm0
    movss   dword ptr [rsp-28], xmm1
    SET_PC24
    fld     dword ptr [rsp-32]
    fsqrt
    fdivr   dword ptr [rsp-28]
    fld     dword ptr [rsi]
    fmul    st(0), st(1)
    fstp    dword ptr [rdi]
    fld     st(0)
    fmul    dword ptr [rsi+4]
    fstp    dword ptr [rdi+4]
    fmul    dword ptr [rsi+8]
    fstp    dword ptr [rdi+8]
    RESTORE_CW
    ret
ENDF msvc8_x87_scale_vector_to_length

// void msvc8_x87_scale_vector(float* dest, const float* source, float scale)
// rdi=dest, rsi=source, xmm0=scale.
FUNC msvc8_x87_scale_vector
    movss   dword ptr [rsp-32], xmm0
    SET_PC24
    fld     dword ptr [rsp-32]
    fld     dword ptr [rsi]
    fmul    st(0), st(1)
    fstp    dword ptr [rdi]
    fld     dword ptr [rsi+4]
    fmul    st(0), st(1)
    fstp    dword ptr [rdi+4]
    fmul    dword ptr [rsi+8]
    fstp    dword ptr [rdi+8]
    RESTORE_CW
    ret
ENDF msvc8_x87_scale_vector

// void msvc8_x87_scale_vector_to_length_of(float* dest, const float* source,
//                                          const float* target, float sourceLengthSq)
// rdi=dest, rsi=source, rdx=target, xmm0=sourceLengthSq.
FUNC msvc8_x87_scale_vector_to_length_of
    movss   dword ptr [rsp-32], xmm0
    SET_PC24
    fld     dword ptr [rdx]
    fmul    st(0), st(0)
    fld     dword ptr [rdx+4]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fld     dword ptr [rdx+8]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fdiv    dword ptr [rsp-32]
    fsqrt
    fld     dword ptr [rsi]
    fmul    st(0), st(1)
    fstp    dword ptr [rdi]
    fld     st(0)
    fmul    dword ptr [rsi+4]
    fstp    dword ptr [rdi+4]
    fmul    dword ptr [rsi+8]
    fstp    dword ptr [rdi+8]
    RESTORE_CW
    ret
ENDF msvc8_x87_scale_vector_to_length_of

// float msvc8_x87_box_radius_on_axis(const float* box, const float* axis)
// rdi=box (center, axis0..2, extent), rsi=axis.
FUNC msvc8_x87_box_radius_on_axis
    SET_PC24
    fld     dword ptr [rdi+0x28]
    fld     dword ptr [rsi+4]
    fmul    st(1), st(0)
    fld     dword ptr [rdi+0x2C]
    fld     dword ptr [rsi+8]
    fmul    st(1), st(0)
    fxch    st(3)
    faddp   st(1), st(0)
    fld     dword ptr [rdi+0x24]
    fld     dword ptr [rsi]
    fmul    st(1), st(0)
    fxch    st(2)
    faddp   st(1), st(0)
    fabs
    fmul    dword ptr [rdi+0x38]
    fld     dword ptr [rdi+0x1C]
    fmul    st(0), st(3)
    fld     dword ptr [rdi+0x20]
    fmul    st(0), st(5)
    faddp   st(1), st(0)
    fld     dword ptr [rdi+0x18]
    fmul    st(0), st(3)
    faddp   st(1), st(0)
    fabs
    fmul    dword ptr [rdi+0x34]
    faddp   st(1), st(0)
    fld     dword ptr [rdi+0x10]
    fmulp   st(3), st(0)
    fld     dword ptr [rdi+0x14]
    fmulp   st(4), st(0)
    fxch    st(2)
    faddp   st(3), st(0)
    fmul    dword ptr [rdi+0x0C]
    faddp   st(2), st(0)
    fxch    st(1)
    fabs
    fmul    dword ptr [rdi+0x30]
    faddp   st(1), st(0)
    fstp    dword ptr [rsp-32]
    movss   xmm0, dword ptr [rsp-32]
    RESTORE_CW
    ret
ENDF msvc8_x87_box_radius_on_axis

// float msvc8_x87_vector_length_zyx(const float* lanes): rdi=lanes.
FUNC msvc8_x87_vector_length_zyx
    SET_PC24
    fld     dword ptr [rdi+8]
    fmul    st(0), st(0)
    fld     dword ptr [rdi+4]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fld     dword ptr [rdi]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fsqrt
    fstp    dword ptr [rsp-32]
    movss   xmm0, dword ptr [rsp-32]
    RESTORE_CW
    ret
ENDF msvc8_x87_vector_length_zyx

    .section .note.GNU-stack,"",@progbits
