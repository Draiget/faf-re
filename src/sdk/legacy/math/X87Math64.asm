; x87 transcendental instructions for 64-bit code (legacy/math/X87Math.cpp).
;
; MSVC has no inline assembly on x64, but the x87 unit works in long mode and
; gives the same bits as the x86 build's inline sequences. Each routine is a
; leaf: the caller's 32-byte home area at [rsp+8] is the scratch slot, so rsp
; never moves and no unwind data is needed. Arguments and results travel in
; xmm0/xmm1 (Windows x64 calling convention).

.code

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

END
