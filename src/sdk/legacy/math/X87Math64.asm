; x87 transcendental instructions for 64-bit code (legacy/math/X87Math.cpp).
;
; MSVC has no inline assembly on x64, but the x87 unit works in long mode and
; gives the same bits as the x86 build's inline sequences. Each routine is a
; leaf: the caller's 32-byte home area at [rsp+8] is the scratch slot, so rsp
; never moves and no unwind data is needed. Arguments and results travel in
; xmm0/xmm1 (Windows x64 calling convention).

.code
; int32_t msvc8_x87_round_to_int(float value)
msvc8_x87_round_to_int PROC
    movss   dword ptr [rsp+8], xmm0
    fld     dword ptr [rsp+8]
    fistp   dword ptr [rsp+8]
    mov     eax, dword ptr [rsp+8]
    ret
msvc8_x87_round_to_int ENDP


; Terrain's inlined interpolation block, under simulation PC24.
; The fifth and sixth float arguments occupy stack slots beyond the home area.
msvc8_x87_bilinear_height PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    movss   dword ptr [rsp+16], xmm2
    movss   dword ptr [rsp+20], xmm3
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+12]
    fld     dword ptr [rsp+8]
    fsub    st(1), st(0)
    fld     dword ptr [rsp+48]
    fmul    st(2), st(0)
    fxch    st(2)
    faddp   st(1), st(0)
    fld     dword ptr [rsp+20]
    fld     dword ptr [rsp+16]
    fsub    st(1), st(0)
    fxch    st(1)
    fmulp   st(3), st(0)
    faddp   st(2), st(0)
    fsub    st(1), st(0)
    fxch    st(1)
    fmul    dword ptr [rsp+40]
    faddp   st(1), st(0)
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_bilinear_height ENDP

; float msvc8_x87_sinf(float x)
msvc8_x87_sinf PROC
    movss   dword ptr [rsp+8], xmm0
    fld     dword ptr [rsp+8]
    fsin
    fstp    dword ptr [rsp+8]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_sinf ENDP

; float msvc8_x87_cosf(float x)
msvc8_x87_cosf PROC
    movss   dword ptr [rsp+8], xmm0
    fld     dword ptr [rsp+8]
    fcos
    fstp    dword ptr [rsp+8]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_cosf ENDP

; float msvc8_x87_tanf(float x)
msvc8_x87_tanf PROC
    movss   dword ptr [rsp+8], xmm0
    fld     dword ptr [rsp+8]
    fptan                               ; tan(x), then 1.0
    fstp    st(0)                       ; drop the 1.0
    fstp    dword ptr [rsp+8]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_tanf ENDP

; float msvc8_x87_atan2f(float y, float x)
msvc8_x87_atan2f PROC
    movss   dword ptr [rsp+8], xmm0     ; y
    movss   dword ptr [rsp+16], xmm1    ; x
    fld     dword ptr [rsp+8]
    fld     dword ptr [rsp+16]
    fpatan                              ; atan(y / x) with the quadrant of (x, y)
    fstp    dword ptr [rsp+8]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_atan2f ENDP

; unsigned msvc8_x87_control_word()
msvc8_x87_control_word PROC
    fnstcw  word ptr [rsp+8]
    movzx   eax, word ptr [rsp+8]
    ret
msvc8_x87_control_word ENDP

; double msvc8_x87_acos(double x), simulation's original PC24 CRT lane.
msvc8_x87_acos PROC
    movsd   qword ptr [rsp+8], xmm0
    fnstcw  word ptr [rsp+16]
    movzx   eax, word ptr [rsp+16]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+18], ax
    fldcw   word ptr [rsp+18]
    fld     qword ptr [rsp+8]
    fld1
    fadd    st(0), st(1)
    fld1
    fsub    st(0), st(2)
    fmulp   st(1), st(0)
    fsqrt
    fxch    st(1)
    fpatan
    fstp    qword ptr [rsp+8]
    fldcw   word ptr [rsp+16]
    movsd   xmm0, qword ptr [rsp+8]
    ret
msvc8_x87_acos ENDP

; double msvc8_x87_pow(double x, double y), the CRT's x87 pow body (0x00A8E18A
; fyl2x, then the 0x00AA7BC0 frndint/f2xm1/fscale exp2) at PC24 like the
; other simulation lanes here.
msvc8_x87_pow PROC
    movsd   qword ptr [rsp+8], xmm0
    movsd   qword ptr [rsp+16], xmm1
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     qword ptr [rsp+16]
    fld     qword ptr [rsp+8]
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
    fstp    qword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movsd   xmm0, qword ptr [rsp+8]
    ret
msvc8_x87_pow ENDP

; float msvc8_x87_atan2_difference(float firstY, float firstX,
;                                float secondY, float secondX)
msvc8_x87_atan2_difference PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    movss   dword ptr [rsp+16], xmm2
    movss   dword ptr [rsp+20], xmm3
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fld     dword ptr [rsp+12]
    fpatan
    fstp    dword ptr [rsp+8]
    fld     dword ptr [rsp+16]
    fld     dword ptr [rsp+20]
    fpatan
    fsubr   dword ptr [rsp+8]
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_atan2_difference ENDP


; float msvc8_x87_atan2_plus(float y, float x, float addend)
; fpatan result added before rounding, under PC24 (FUN_006309F0 heading lane).
msvc8_x87_atan2_plus PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    movss   dword ptr [rsp+16], xmm2
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fld     dword ptr [rsp+12]
    fpatan
    fadd    dword ptr [rsp+16]
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_atan2_plus ENDP


; float msvc8_x87_sin_times_cos(float sinArg, float cosArg)
; fsin/fcos stay unrounded; the product rounds once under PC24 (FUN_00695180).
msvc8_x87_sin_times_cos PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+12]
    fcos
    fld     dword ptr [rsp+8]
    fsin
    fmulp   st(1), st(0)
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_sin_times_cos ENDP


; float msvc8_x87_sin_times(float sinArg, float factor)
; fsin stays unrounded; the product rounds once under PC24 (FUN_006C3220).
msvc8_x87_sin_times PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fsin
    fmul    dword ptr [rsp+12]
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_sin_times ENDP


; void msvc8_x87_slerp_spherical_blend(float* out, const float* q1, const float* rhs,
;                                      float angle, float oneMinusT, float t)
; Moho::SLERP 0x004EBD95..0x004EBDF2: weights and lane products stay on the
; x87 stack under PC24. rcx=out, rdx=q1, r8=rhs, xmm3=angle; oneMinusT and t
; are the fifth and sixth arguments at [rsp+40] / [rsp+48].
msvc8_x87_slerp_spherical_blend PROC
    movss   dword ptr [rsp+32], xmm3
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+32]
    fld     st(0)
    fsin
    fld1
    fdivrp  st(1), st(0)
    fld     st(1)
    fmul    dword ptr [rsp+40]
    fsin
    fmul    st(0), st(1)
    fld     dword ptr [rsp+48]
    fmulp   st(3), st(0)
    fxch    st(2)
    fsin
    fmulp   st(1), st(0)
    fld     dword ptr [rdx]
    fmul    st(0), st(2)
    fld     dword ptr [r8]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rcx]
    fld     dword ptr [rdx+4]
    fmul    st(0), st(2)
    fld     dword ptr [r8+4]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rcx+4]
    fld     dword ptr [rdx+8]
    fmul    st(0), st(2)
    fld     dword ptr [r8+8]
    fmul    st(0), st(2)
    faddp   st(1), st(0)
    fstp    dword ptr [rcx+8]
    fld     dword ptr [rdx+12]
    fmulp   st(2), st(0)
    fmul    dword ptr [r8+12]
    faddp   st(1), st(0)
    fstp    dword ptr [rcx+12]
    fldcw   word ptr [rsp+24]
    ret
msvc8_x87_slerp_spherical_blend ENDP


; float msvc8_x87_intrinsic_exp(float x)
; MSVC8 /Oi exp expansion (math_exp 0x00919D5D); fmul/fadd round under PC24.
msvc8_x87_intrinsic_exp PROC
    movss   dword ptr [rsp+8], xmm0
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
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
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_intrinsic_exp ENDP


; float msvc8_x87_intrinsic_ln(float x)
msvc8_x87_intrinsic_ln PROC
    movss   dword ptr [rsp+8], xmm0
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fldln2
    fxch    st(1)
    fyl2x
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_intrinsic_ln ENDP


; float msvc8_x87_intrinsic_ln_quotient(float x, double base)
; ln(x) / ln(base) with both logs kept on the x87 stack; only the quotient
; rounds to float.
msvc8_x87_intrinsic_ln_quotient PROC
    movss   dword ptr [rsp+8], xmm0
    movsd   qword ptr [rsp+16], xmm1
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fldln2
    fxch    st(1)
    fyl2x
    fld     qword ptr [rsp+16]
    fldln2
    fxch    st(1)
    fyl2x
    fdivp   st(1), st(0)
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_intrinsic_ln_quotient ENDP


; float msvc8_x87_intrinsic_log10(float x)
msvc8_x87_intrinsic_log10 PROC
    movss   dword ptr [rsp+8], xmm0
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+8]
    fldlg2
    fxch    st(1)
    fyl2x
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_intrinsic_log10 ENDP


; float msvc8_x87_cos_times_cos(float firstArg, float secondArg)
msvc8_x87_cos_times_cos PROC
    movss   dword ptr [rsp+8], xmm0
    movss   dword ptr [rsp+12], xmm1
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+12]
    fcos
    fld     dword ptr [rsp+8]
    fcos
    fmulp   st(1), st(0)
    fstp    dword ptr [rsp+8]
    fldcw   word ptr [rsp+24]
    movss   xmm0, dword ptr [rsp+8]
    ret
msvc8_x87_cos_times_cos ENDP


; void msvc8_x87_scale_vector_max_length(float* x, float* y, float* z, float maxLength)
; The scale stays in extended precision across all three component multiplies
; (FUN_005D1E70). rcx=x, rdx=y, r8=z; maxLength arrives on the stack at
; [rsp+40] (fifth slot counting the home area).
msvc8_x87_scale_vector_max_length PROC
    fld     dword ptr [rcx]
    fmul    st(0), st(0)
    fld     dword ptr [rdx]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fld     dword ptr [r8]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fsqrt
    fdivr   dword ptr [rsp+40]
    fld     dword ptr [rcx]
    fmul    st(0), st(1)
    fstp    dword ptr [rcx]
    fld     dword ptr [rdx]
    fmul    st(0), st(1)
    fstp    dword ptr [rdx]
    fmul    dword ptr [r8]
    fstp    dword ptr [r8]
    ret
msvc8_x87_scale_vector_max_length ENDP


; void msvc8_x87_scale_vector_to_length(float* dest, const float* source,
;                                       float lengthSq, float length)
; func_VecSetLengthS 0x005B1CCF..0x005B1CF7: fsqrt, fdivr length, the scale
; stays on the x87 stack across the three multiplies. rcx=dest, rdx=source,
; xmm2=lengthSq, xmm3=length; runs under PC24 like the simulation thread.
msvc8_x87_scale_vector_to_length PROC
    movss   dword ptr [rsp+32], xmm2
    movss   dword ptr [rsp+36], xmm3
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+32]
    fsqrt
    fdivr   dword ptr [rsp+36]
    fld     dword ptr [rdx]
    fmul    st(0), st(1)
    fstp    dword ptr [rcx]
    fld     st(0)
    fmul    dword ptr [rdx+4]
    fstp    dword ptr [rcx+4]
    fmul    dword ptr [rdx+8]
    fstp    dword ptr [rcx+8]
    fldcw   word ptr [rsp+24]
    ret
msvc8_x87_scale_vector_to_length ENDP


; void msvc8_x87_scale_vector(float* dest, const float* source, float scale)
; dest[i] = source[i] * scale, each product formed on the x87 stack under PC24
; and stored once. rcx=dest, rdx=source, xmm2=scale.
msvc8_x87_scale_vector PROC
    movss   dword ptr [rsp+32], xmm2
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [rsp+32]
    fld     dword ptr [rdx]
    fmul    st(0), st(1)
    fstp    dword ptr [rcx]
    fld     dword ptr [rdx+4]
    fmul    st(0), st(1)
    fstp    dword ptr [rcx+4]
    fmul    dword ptr [rdx+8]
    fstp    dword ptr [rcx+8]
    fldcw   word ptr [rsp+24]
    ret
msvc8_x87_scale_vector ENDP


; void msvc8_x87_scale_vector_to_length_of(float* dest, const float* source,
;                                          const float* target, float sourceLengthSq)
; func_VecSetLengthTo 0x0069A3A5..0x0069A3D3. rcx=dest, rdx=source,
; r8=target, xmm3=sourceLengthSq; runs under PC24 like the simulation thread.
msvc8_x87_scale_vector_to_length_of PROC
    movss   dword ptr [rsp+32], xmm3
    fnstcw  word ptr [rsp+24]
    movzx   eax, word ptr [rsp+24]
    and     eax, 0fffffcffh
    mov     word ptr [rsp+26], ax
    fldcw   word ptr [rsp+26]
    fld     dword ptr [r8]
    fmul    st(0), st(0)
    fld     dword ptr [r8+4]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fld     dword ptr [r8+8]
    fmul    st(0), st(0)
    faddp   st(1), st(0)
    fdiv    dword ptr [rsp+32]
    fsqrt
    fld     dword ptr [rdx]
    fmul    st(0), st(1)
    fstp    dword ptr [rcx]
    fld     st(0)
    fmul    dword ptr [rdx+4]
    fstp    dword ptr [rcx+4]
    fmul    dword ptr [rdx+8]
    fstp    dword ptr [rcx+8]
    fldcw   word ptr [rsp+24]
    ret
msvc8_x87_scale_vector_to_length_of ENDP

END
