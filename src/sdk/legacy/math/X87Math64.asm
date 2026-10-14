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

END
