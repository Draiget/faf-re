#include "retail_thunks.h"

// See retail_thunks.h. Every thunk below has the same frame:
//
//   push ebx / push esi / push edi / push ebp      ; 16 bytes
//   -> the first __cdecl argument is at [esp+20], the second at [esp+24], ...
//
// and restores those four registers before `ret`, so retail code may clobber
// any of them. Absolute call targets go through a register the retail
// function does not take as input.


namespace retail
{
  // ---- plain __cdecl leaves -----------------------------------------------

  __declspec(naked) float __cdecl Sqrtf(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x00452FC0
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) float __cdecl SqrtfB(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x0040EAF0
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) float __cdecl Fabsf(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x0040DAB0
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) float __cdecl Sinf(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x005734E0
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) float __cdecl Cosf(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x005734D0
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004E9DF0: `fld [ebp+8]; fld [ebp+0Ch]; fpatan` -> atan2(arg0, arg1).
  __declspec(naked) float __cdecl Atan2f(float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 24]
      push dword ptr [esp + 24]
      mov eax, 0x004E9DF0
      call eax
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00A8DCD0 (_CIacos): operand in st(0), result in st(0). Dispatches on
  // `global_mode_sse2` (0x01107030) + MXCSR/x87-CW defaults to the SSE2 body
  // at 0x00AA7430 or the x87 one.
  __declspec(naked) double __cdecl Acos(double)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld qword ptr [esp + 20]
      mov eax, 0x00A8DCD0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00A8E06A (_CIfmod): `fld x; fld y; call` -> fmod(x, y) in st(0)
  // (NormalizeAngleSignedRadians, 0x0062FB59..0x0062FB62).
  __declspec(naked) double __cdecl Fmod(double, double)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld qword ptr [esp + 20]
      fld qword ptr [esp + 28]
      mov eax, 0x00A8E06A
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00A8E0E0 (_CIpow), called by Lua math.pow at 0x00919CD3 with both
  // operands loaded from floats and the result stored straight to a float.
  __declspec(naked) void __cdecl PowF(float, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld dword ptr [esp + 20]
      fld dword ptr [esp + 24]
      mov eax, 0x00A8E0E0
      call eax
      mov eax, dword ptr [esp + 28]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- Lua math library (0x00919930..0x0091A110) ---------------------------

  // A `float __cdecl f(float)` leaf whose result is left in st(0):
  // 0x00919A40 (fptan), 0x00919980 (fldlg2; fyl2x), 0x009199D0 (the /Oi exp
  // expansion), 0x0040EAD0 (fldln2; fyl2x).
  __declspec(naked) float __cdecl UnaryFloatLeaf(unsigned, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      push dword ptr [esp + 24]
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // A CRT `_CI*` entry with its operand on the x87 stack, as math_asin
  // (0x00919B20) and math_acos (0x00919B50) call it: the float from
  // luaL_checknumber in st(0), the result stored with `fstp dword`.
  __declspec(naked) void __cdecl CrtStackUnaryF(unsigned, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld dword ptr [esp + 24]
      mov eax, [esp + 20]
      call eax
      mov eax, [esp + 28]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // A two-operand `_CI*` entry (st(1) = x, st(0) = y), as math_mod
  // (0x00919C63) calls `_CIfmod`.
  __declspec(naked) void __cdecl CrtStackBinaryF(unsigned, float, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld dword ptr [esp + 24]
      fld dword ptr [esp + 28]
      mov eax, [esp + 20]
      call eax
      mov eax, [esp + 32]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // A cdecl `double f(double)` CRT entry fed a widened float and stored back
  // to float, as math_ceil (0x00919BF0) and math_floor (0x00919C20) call
  // ceil 0x00A840A0 / floor 0x00A8DF30.
  __declspec(naked) void __cdecl CrtDoubleArgF(unsigned, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld dword ptr [esp + 24]
      sub esp, 8
      fstp qword ptr [esp]
      mov eax, [esp + 28]
      call eax
      add esp, 8
      mov eax, [esp + 28]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_frexp 0x00919E01..0x00919E14: frexp 0x00A8DA05(double, int*).
  __declspec(naked) void __cdecl FrexpF(float, float*, int*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 28]
      sub esp, 8
      fld dword ptr [esp + 32]
      fstp qword ptr [esp]
      mov eax, 0x00A8DA05
      call eax
      add esp, 12
      mov eax, [esp + 24]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_ldexp 0x00919E4E..0x00919E6F: _ftol2 0x00A89CC0 on the exponent,
  // then ldexp 0x00A8DADF(double, int).
  __declspec(naked) void __cdecl LdexpF(float, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fld dword ptr [esp + 24]
      mov eax, 0x00A89CC0
      call eax
      push eax
      sub esp, 8
      fld dword ptr [esp + 32]
      fstp qword ptr [esp]
      mov eax, 0x00A8DADF
      call eax
      add esp, 12
      mov eax, [esp + 28]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_deg 0x00919D9D / math_rad 0x00919DCD: `fmul dword ptr [const]` on
  // the float argument; the constant is read from the mapped image.
  __declspec(naked) float __cdecl MulImageConstant(float, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 24]
      fld dword ptr [esp + 20]
      fmul dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_random 0x00919F99..0x00919FB2: `rand() % 0x7FFF`, cvtsi2ss, mulss
  // by the scale at 0x00D46378.
  __declspec(naked) float __cdecl RandomSample(int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      cdq
      mov ecx, 0x7FFF
      idiv ecx
      cvtsi2ss xmm0, edx
      mov eax, 0x00D46378
      mulss xmm0, dword ptr [eax]
      sub esp, 4
      movss dword ptr [esp], xmm0
      fld dword ptr [esp]
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_random's one-argument lane 0x0091A089..0x0091A0AC: fild upper,
  // fmul sample, floor 0x00A8DF30, fadd 1.0f (0x00D41424), fstp dword.
  __declspec(naked) void __cdecl RandomPickUpTo(int, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fild dword ptr [esp + 20]
      sub esp, 8
      fmul dword ptr [esp + 32]
      fstp qword ptr [esp]
      mov eax, 0x00A8DF30
      call eax
      mov eax, 0x00D41424
      fadd dword ptr [eax]
      add esp, 8
      mov eax, [esp + 28]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_random's two-argument lane 0x0091A02E..0x0091A048: fild count,
  // fmul sample, floor 0x00A8DF30, fiadd lower, fstp dword.
  __declspec(naked) void __cdecl RandomPickRange(int, float, int, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      fild dword ptr [esp + 20]
      sub esp, 8
      fmul dword ptr [esp + 32]
      fstp qword ptr [esp]
      mov eax, 0x00A8DF30
      call eax
      fiadd dword ptr [esp + 36]
      add esp, 8
      mov eax, [esp + 32]
      fstp dword ptr [eax]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // math_randomseed 0x0091A0DF..0x0091A0FE: truncating `fistp qword` under
  // a temporary round-toward-zero control word; the low dword is the seed.
  __declspec(naked) unsigned __cdecl RandomSeedWord(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      sub esp, 12
      fld dword ptr [esp + 32]
      fnstcw word ptr [esp + 2]
      movzx eax, word ptr [esp + 2]
      or eax, 0x0C00
      mov dword ptr [esp + 4], eax
      fldcw word ptr [esp + 4]
      fistp qword ptr [esp + 4]
      mov eax, dword ptr [esp + 4]
      fldcw word ptr [esp + 2]
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) void __cdecl RunStaticInit(unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- custom register conventions ----------------------------------------

  // 0x00452AF0: `mov esi, ecx` - the vector is `this` in ecx; length in st0.
  __declspec(naked) float __cdecl Wm3Normalize(void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov eax, 0x00452AF0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0044F7E0: reads [edi], writes [esi], `mov eax, esi`.
  __declspec(naked) void* __cdecl NormalizeVectorInto(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov edi, [esp + 24]
      mov eax, 0x0044F7E0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0044F880: ebx = dest, edi = fallback axis, then v1 (3 floats at
  // [esp+4]) and v2 (3 floats at [esp+10h]) by value; plain `ret`.
  __declspec(naked) void* __cdecl QuatCrossAdd(void*, const void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ebx, [esp + 20]
      mov edi, [esp + 32]
      mov eax, [esp + 28]
      push dword ptr [eax + 8]
      push dword ptr [eax + 4]
      push dword ptr [eax]
      mov eax, [esp + 36]
      push dword ptr [eax + 8]
      push dword ptr [eax + 4]
      push dword ptr [eax]
      mov eax, 0x0044F880
      call eax
      add esp, 24
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0069AA50: ecx = reference axis; [esp+4] = quat, [esp+8] = rads.
  __declspec(naked) void __cdecl QuatFromVecRot(void*, const void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 24]
      push dword ptr [esp + 28]
      push dword ptr [esp + 24]
      mov eax, 0x0069AA50
      call eax
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EB740: esi = quat, [esp+4] = rads, result in al.
  __declspec(naked) int __cdecl RotateQuatByAngle(void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      push dword ptr [esp + 24]
      mov eax, 0x004EB740
      call eax
      add esp, 4
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EBC00: eax = q2, ecx = q1, ebx = out, [esp+4] = t.
  __declspec(naked) void* __cdecl Slerp(const void*, const void*, void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov ebx, [esp + 28]
      push dword ptr [esp + 32]
      mov edx, 0x004EBC00
      call edx
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EBA80: eax = q1, ecx = q2, ebx = out, [esp+4] = t.
  __declspec(naked) void* __cdecl QuatLerp(const void*, const void*, void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov ebx, [esp + 28]
      push dword ptr [esp + 32]
      mov edx, 0x004EBA80
      call edx
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00452D40: ebx = dest, esi = vec, ecx = quat (forwarded untouched to
  // QuatToMatrix as `this`).
  __declspec(naked) void* __cdecl MultQuadVec(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ebx, [esp + 20]
      mov esi, [esp + 24]
      mov ecx, [esp + 28]
      mov eax, 0x00452D40
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00452FD0: __thiscall - ecx = quat, [esp+4] = out rows, `ret 4`.
  __declspec(naked) void* __cdecl QuatToMatrix(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 24]
      mov eax, 0x00452FD0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0069A360: eax = dest, edx = target-length vector, ecx = source.
  __declspec(naked) void* __cdecl VecSetLengthTo(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edx, [esp + 24]
      mov ecx, [esp + 28]
      mov ebx, 0x0069A360
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005B1C90: esi = vector, [esp+4] = target length, result in al.
  __declspec(naked) int __cdecl VecSetLength(void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      push dword ptr [esp + 24]
      mov eax, 0x005B1C90
      call eax
      add esp, 4
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EDAA0: esi = quat.
  __declspec(naked) void __cdecl NormalizeQuatInPlace(void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov eax, 0x004EDAA0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EDED0: edi = lhs, esi = rhs, eax = 0/1.
  __declspec(naked) int __cdecl QuatsNearEqual(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edi, [esp + 20]
      mov esi, [esp + 24]
      mov eax, 0x004EDED0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- second wave ----------------------------------------------------------

  // 0x004CC960: eax = from, ecx = to; the float comes back in xmm0 (an
  // MSVC8 /arch:SSE2 internal-linkage convention), moved to st0 here.
  __declspec(naked) float __cdecl DistanceSquared3D(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, 0x004CC960
      call edx
      sub esp, 4
      movss dword ptr [esp], xmm0
      fld dword ptr [esp]
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0069A230: eax = dest, edx = incident, ecx = normal.
  __declspec(naked) void* __cdecl ReflectAcrossNormal(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edx, [esp + 24]
      mov ecx, [esp + 28]
      mov ebx, 0x0069A230
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0069A1D0: eax = vector, eax = 0/1.
  __declspec(naked) int __cdecl IsUnitLength(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ebx, 0x0069A1D0
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005382E0: ecx = vector, eax = axis index.
  __declspec(naked) int __cdecl LargestAxis(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov eax, 0x005382E0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004ED810: __thiscall - ecx = vector, [esp+4] = divisor, `ret 4`.
  __declspec(naked) void* __cdecl ScaleByReciprocalOrSetMax(void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 24]
      mov eax, 0x004ED810
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00565A10: eax = vector, result in st0.
  __declspec(naked) float __cdecl HeadingFromXZ(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ebx, 0x00565A10
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00694AF0: eax = out, ecx = quat.
  __declspec(naked) void* __cdecl ExtractYAxisColumn(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov ebx, 0x00694AF0
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0062FBA0: eax = quat lanes, ecx = out, esi = source vector (passed
  // straight through to MultQuadVec).
  __declspec(naked) void* __cdecl RotateByConjugate(const void*, void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov esi, [esp + 28]
      mov edx, 0x0062FBA0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00697360: esi = quat out, axis-angle vector by value at [esp+4].
  __declspec(naked) void* __cdecl QuatFromAxisAngleVector(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov eax, [esp + 24]
      push dword ptr [eax + 8]
      push dword ptr [eax + 4]
      push dword ptr [eax]
      mov eax, 0x00697360
      call eax
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00570750: edi = axis, esi = out, [esp+4] = roll, `ret 4`.
  __declspec(naked) void* __cdecl EulerRollToQuat(const void*, void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edi, [esp + 20]
      mov esi, [esp + 24]
      push dword ptr [esp + 28]
      mov eax, 0x00570750
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005D1E70: eax = vector, [esp+4] = max length, al.
  __declspec(naked) int __cdecl VecLimitLengthTo(void*, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      push dword ptr [esp + 24]
      mov edx, 0x005D1E70
      call edx
      add esp, 4
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EB3F0: eax = matrix rows, esi = out quaternion.
  __declspec(naked) void __cdecl MatrixToQuat(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov esi, [esp + 24]
      mov edx, 0x004EB3F0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004F0CB0: __thiscall - ecx = out quaternion, [esp+4] = rows, `ret 4`.
  __declspec(naked) void __cdecl MatrixRowsToQuatCanonical(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 24]
      push dword ptr [esp + 20]
      mov eax, 0x004F0CB0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x006C1070: esi = quat, edi = axis out, ebx = angle out.
  __declspec(naked) void __cdecl QuatToAxisAndAngle(const void*, void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov edi, [esp + 24]
      mov ebx, [esp + 28]
      mov eax, 0x006C1070
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0050CB50: eax = target normal, edi = out delta, esi = current up.
  __declspec(naked) void* __cdecl TiltShortestArcDelta(const void*, void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edi, [esp + 24]
      mov esi, [esp + 28]
      mov edx, 0x0050CB50
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0062FB50: __cdecl float(float), result in xmm0.
  __declspec(naked) float __cdecl NormalizeAngle(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x0062FB50
      call eax
      movss dword ptr [esp], xmm0
      fld dword ptr [esp]
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x006D2680: eax = result, [esp+4] = a (lhs), [esp+8] = b, `ret 8`.
  __declspec(naked) void* __cdecl Multiply3x3(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov edx, 0x006D2680
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x006D1E30: esi = out rows, [esp+4] heading, [+8] pitch, [+0Ch] roll,
  // `ret 0Ch`.
  __declspec(naked) void* __cdecl EulerHPRToMatrix(void*, float, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov eax, 0x006D1E30
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EB830: ebx = goal, edi = out, [esp+4] = current, [+8] = step,
  // [+0Ch] = bool* no-step flag; plain `ret`.
  __declspec(naked) void* __cdecl BlendOrientation(const void*, const void*, float, void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ebx, [esp + 20]
      mov edi, [esp + 36]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov eax, 0x004EB830
      call eax
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- third wave: manipulator angle lanes ---------------------------------

  // 0x00630CB0 CAimManipulator::SetFiringArc and 0x00636490
  // CBuilderArmManipulator::SetAimingArc: esi = this, six floats on the
  // stack (min/max heading, heading slew, min/max pitch, pitch slew), `ret 18h`.
  // Each `push [esp+44]` takes the next argument down, since the push itself
  // moves esp by the argument stride.
  __declspec(naked) void __cdecl SetFiringArc(void*, float, float, float, float, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      mov eax, 0x00630CB0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) void __cdecl SetAimingArc(void*, float, float, float, float, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      mov eax, 0x00636490
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00636220 CBuilderArmManipulator::UpdateTrackingAxis: eax = target
  // direction, ecx = watch bone (read only without the world-space flag, so
  // passed as null), [esp+4] = this, then center, half arc, slew, flags;
  // `ret 14h`, result in eax.
  __declspec(naked) int __cdecl BuilderArmUpdateTrackingAxis(void*, const void*, float, float, float, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 36]
      mov eax, [esp + 44]
      xor ecx, ecx
      mov edx, 0x00636220
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x006309F0 CAimManipulator::CheckTracking: eax = target direction, ecx =
  // watch bone (null, as above), [esp+4] = this, then center, half range,
  // slew, tolerance, flags; `ret 18h`, result in eax.
  __declspec(naked) int __cdecl AimCheckTracking(void*, const void*, float, float, float, float, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 44]
      push dword ptr [esp + 40]
      mov eax, [esp + 48]
      xor ecx, ecx
      mov edx, 0x006309F0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00422940 WrapPositiveModulo: cdecl (value, range), result in xmm0.
  __declspec(naked) float __cdecl WrapPositiveModulo(float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 24]
      push dword ptr [esp + 24]
      mov eax, 0x00422940
      call eax
      movss dword ptr [esp], xmm0
      fld dword ptr [esp]
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // --- fourth wave: callers of the inline X87Math helpers -------------------

  // 0x0055AE10 RATE_GameRateToSpeed: cdecl (rate), int in eax.
  __declspec(naked) int __cdecl RateGameRateToSpeed(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x0055AE10
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0092D8B0 HaStar::Cluster::QuantizeEdgeCost: cdecl (a, b), the bucket
  // `fild`ed into st0.
  __declspec(naked) float __cdecl QuantizeEdgeCost(float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 24]
      push dword ptr [esp + 24]
      mov eax, 0x0092D8B0
      call eax
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0050AFA0 COORDS_ToGridRect: eax = result, ecx = centerXZ, edi = sizeX,
  // esi = sizeZ, no stack arguments; returns eax.
  __declspec(naked) void* __cdecl CoordsToGridRect(void*, const void*, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edi, [esp + 28]
      mov esi, [esp + 32]
      mov edx, 0x0050AFA0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00475550 (CColPrimitiveBase ProjectBoxOntoAxis): eax = box, ecx = axis,
  // [esp+4] = outMin, [esp+8] = outMax, caller pops.
  __declspec(naked) void __cdecl ProjectBoxOntoAxis(const void*, const void*, float*, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov edx, 0x00475550
      call edx
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004F0AE0 MatrixColumnsToQuatCanonical: ecx = out, [esp+4] = columns,
  // `ret 4`; returns what 0x004F0CB0 returns (eax = out).
  __declspec(naked) void* __cdecl MatrixColumnsToQuat(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 24]
      push dword ptr [esp + 20]
      mov eax, 0x004F0AE0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005657F0 Moho::IsValid_Vector3f: esi = v, eax = 1 when no lane is NaN.
  __declspec(naked) int __cdecl IsValidVector3f(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov eax, 0x005657F0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EC590 VAxes3::VAxes3(const Quaternionf&): eax = this (9 floats),
  // ecx = quat, no stack arguments.
  __declspec(naked) void* __cdecl VAxes3FromQuat(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, 0x004EC590
      call edx
      mov eax, [esp + 20]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0066D1D0 FloorSecondsToTicks: seconds in xmm0, ticks in eax.
  __declspec(naked) int __cdecl FloorSecondsToTicks(float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      movss xmm0, dword ptr [esp + 20]
      mov eax, 0x0066D1D0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00506E20 GridPos::GridPos(Vec3f* wldPos, int gridSize): ecx = this,
  // esi = wldPos, [esp+4] = gridSize, caller pops; returns eax = this.
  __declspec(naked) void* __cdecl GridPosFromWorld(void*, const void*, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov esi, [esp + 24]
      push dword ptr [esp + 28]
      mov eax, 0x00506E20
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004FE130 Segment3f(start, end): esi = this, ecx = start, eax = end;
  // returns eax = this.
  __declspec(naked) void* __cdecl SegmentFromEndpoints(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov ecx, [esp + 24]
      mov eax, [esp + 28]
      mov edx, 0x004FE130
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004FE2D0 AxisAlignedBox3f(const Box3f&): esi = this (Min[3], Max[3]),
  // ecx = box (handed to Box3f::ComputeVertices 0x004FFF00); returns eax.
  __declspec(naked) void* __cdecl AlignedBoundsFromBox(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov ecx, [esp + 24]
      mov eax, 0x004FE2D0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EE980 VMatrix4::Set(quat, vec): eax = this (16 floats), ecx = quat,
  // edx = vec, no stack arguments.
  __declspec(naked) void __cdecl VMatrix4Set(void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, [esp + 28]
      mov ebx, 0x004EE980
      call ebx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // CColPrimitive<Box3f/Sphere3f> virtuals: __thiscall, ecx = this, stack
  // arguments popped by the callee (`ret 4/8/0Ch`), bool in al. After the
  // four saves the k-th argument is at [esp+28+4k]; each push moves the next
  // one to the same offset.
  __declspec(naked) int __cdecl ThisCallBool1(unsigned, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      push dword ptr [esp + 28]
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) int __cdecl ThisCallBool2(unsigned, const void*, const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) int __cdecl ThisCallBool3(unsigned, const void*, const void*, const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // Wild Magic query members (IntrBox2Box2<float>::Test 0x00A47D40,
  // DistVector3Segment3<float>::GetSquared 0x00A484F0): ecx = this, no
  // arguments.
  __declspec(naked) int __cdecl ThisCallBool0(unsigned, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  __declspec(naked) float __cdecl ThisCallFloat0(unsigned, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- sixth wave: the terrain, the random stream, the transform inverse,
  // Vector2f, the ray slab clip and the bone rotation -----------------------

  // 0x0044FB90 CHeightField::GetElevation(x, z): ecx = field {data, width,
  // height}, [x z], ret 8, float in st0.
  __declspec(naked) float __cdecl HeightFieldElevation(const void*, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov eax, 0x0044FB90
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0051B5C0 CRandomStream::FRand(lower, upper): edx = stream (IRand
  // 0x0040E9F0 reads the twister through it; the callers set edx, not ecx),
  // [lower upper], ret 8, float in st0.
  __declspec(naked) float __cdecl RandomStreamFRand(void*, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edx, [esp + 20]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov eax, 0x0051B5C0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0046FBF0 VTransform::Inverse: eax = this, edi = out; calls MultQuadVec
  // (0x00452D40) for the translation, returns out in eax.
  __declspec(naked) void* __cdecl VTransformInverse(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edi, [esp + 20]
      mov eax, [esp + 24]
      mov edx, 0x0046FBF0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004CC8F0 Distance2D: eax = from, ecx = to, the sqrt leaf's st0.
  __declspec(naked) float __cdecl Distance2D(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, 0x004CC8F0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004CC930 DistanceSquared2D: eax = from, ecx = to, ret xmm0.
  __declspec(naked) float __cdecl DistanceSquared2D(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, 0x004CC930
      call edx
      sub esp, 4
      movss dword ptr [esp], xmm0
      fld dword ptr [esp]
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005657B0 IsValid_Vector2f: esi = v, eax.
  __declspec(naked) int __cdecl IsValidVector2f(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov eax, 0x005657B0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00473DF0 RayBoxSlabClip: ecx = ray state (narrowed in place), edx =
  // box, eax.
  __declspec(naked) int __cdecl RayBoxSlabClip(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov edx, [esp + 24]
      mov eax, 0x00473DF0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0054BC00 CAniPoseBone::Rotate: eax = bone (orientation at +20h), ecx =
  // rotation; ends in CAniPose::MarkBoneDirty (0x0054B990) with ecx =
  // [bone+3Ch], esi = [bone+40h].
  __declspec(naked) void __cdecl AniPoseBoneRotate(void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      mov edx, 0x0054BC00
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // ---- inlined sites: the call site's own instructions ----------------------

  // MotorFallDown::Update 0x006952A9..0x006953B1: the fall axis from the
  // direction and the elevation angle, both trig results unrounded until
  // their product (or, for y, the negation) is stored.
  __declspec(naked) void __cdecl FallAxis(float, float, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 28]
      fld dword ptr [esp + 20]
      fld dword ptr [esp + 24]
      fld st(0)
      fcos
      fld st(2)
      fsin
      fmul st, st(1)
      fstp dword ptr [eax]
      fxch st(1)
      fsin
      fchs
      fstp dword ptr [eax + 4]
      fxch st(1)
      fcos
      fmulp st(1), st
      fstp dword ptr [eax + 8]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // CUnitMotion::CalcWingedOrientation 0x006BDAF2..0x006BDB31: two calls to
  // the float atan2 leaf (0x004E9DF0, cdecl y, x), the first stored as float,
  // the second subtracted from it unrounded (`fsubr`), st0.
  __declspec(naked) float __cdecl Atan2DifferenceSite(float, float, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      sub esp, 12
      mov eax, [esp + 32]
      mov [esp], eax
      mov eax, [esp + 36]
      mov [esp + 4], eax
      mov eax, 0x004E9DF0
      call eax
      fstp dword ptr [esp + 8]
      mov eax, [esp + 40]
      mov [esp], eax
      mov eax, [esp + 44]
      mov [esp + 4], eax
      mov eax, 0x004E9DF0
      call eax
      fsubr dword ptr [esp + 8]
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // CUnitMotion::HandleDivingAndSurfacing 0x006C336C..0x006C3380: `fld
  // phase; fmul pi (0x00DFF088); fsin; fmul base`, st0.
  __declspec(naked) float __cdecl DiveCurveSpeed(float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, 0x00DFF088
      fld dword ptr [esp + 20]
      fmul dword ptr [eax]
      fsin
      fmul dword ptr [esp + 24]
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // cfunc_ProjectileGetCurrentSpeedL 0x006A2846..0x006A2861: (z*z + y*y) +
  // x*x and the fsqrt on the x87 stack, st0.
  __declspec(naked) float __cdecl VelocityLength(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      fld dword ptr [eax + 8]
      fmul st, st(0)
      fld dword ptr [eax + 4]
      fmul st, st(0)
      faddp st(1), st
      fld dword ptr [eax]
      fmul st, st(0)
      faddp st(1), st
      fsqrt
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // The Lua table code's number keys (lua_getn 0x0090AD62, sub_907380
  // 0x009073A6, LuaObject::GetInteger 0x0090795A): one `cvttss2si`.
  __declspec(naked) int __cdecl TruncateFloatKey(float)
  {
    __asm {
      cvttss2si eax, dword ptr [esp + 4]
      ret
    }
  }

  // --- seventh wave: integer floor and ceil sites (plan WPL.25) -------------

  // 0x00425110 the inlined float ceil as a function: cdecl (value), int in eax.
  __declspec(naked) int __cdecl CeilFloatToInt(float)
  {
    __asm {
      push dword ptr [esp + 4]
      mov eax, 0x00425110
      call eax
      add esp, 4
      ret
    }
  }

  // ---- engine objects (targets_sim.cpp) -------------------------------------

  // 0x00957A60 operator delete (jmp to free 0x00958C40, redirected).
  __declspec(naked) void __cdecl OperatorDelete(void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 20]
      mov eax, 0x00957A60
      call eax
      add esp, 4
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00476090 CHeightField::CHeightField(width, height): __stdcall with this
  // first, ret 0Ch, eax = this (0x00476202..0x00476214).
  __declspec(naked) void* __cdecl HeightFieldConstruct(void*, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov eax, 0x00476090
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00476BB0 CHeightField::UpdateBounds(gpg::Rect2i): __stdcall, this then
  // the rect by value (x0 z0 x1 z1), ret 14h.
  __declspec(naked) void __cdecl HeightFieldUpdateBounds(void*, int, int, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      mov eax, 0x00476BB0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00476F30 CHeightField::Intersection(line, res): eax = this, esi = line,
  // ebx = the result vector, [res], ret 4 (0x00476F55..0x00476FC4).
  __declspec(naked) void* __cdecl HeightFieldIntersection(const void*, const void*, void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov esi, [esp + 24]
      mov ebx, [esp + 28]
      push dword ptr [esp + 32]
      mov ecx, 0x00476F30
      call ecx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00564DF0 STIMap::OccupancyCapsOfFootprintAt(pos, footprint): ecx = map,
  // eax = the SOCellPos (two shorts, 0x00564DF7/0x00564DFB), [footprint] on
  // the stack (read at 0x00564EC1 after five dwords pushed), plain ret
  // (caller pops), al = the caps.
  __declspec(naked) unsigned __cdecl MapOccupancyCaps(const void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov eax, [esp + 24]
      push dword ptr [esp + 28]
      mov edx, 0x00564DF0
      call edx
      add esp, 4
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00720920 OCCUPY_Filter: ecx = footprint (0x0072092E), esi = grid
  // (0x00720932), [pos] then [caps] on the stack (0x00720920, 0x00720929),
  // ret 8 (0x007209CE), al = the caps.
  __declspec(naked) unsigned __cdecl OccupyFilter(const void*, const void*, const void*, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov esi, [esp + 24]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov edx, 0x00720920
      call edx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00564AB0 OCCUPY_MobileCheck: ecx = pos (0x00564AB3), [footprint]
  // (0x00564ABD) then [map] (0x00564AF3) on the stack, caller-popped (the
  // add esp, 8 at 0x00720A24), eax = the caps.
  __declspec(naked) unsigned __cdecl OccupyMobileCheck(const void*, const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov edx, 0x00564AB0
      call edx
      add esp, 8
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x007209E0 OCCUPY_FootprintFits: eax = grid (0x007209EA), edi = pos
  // (0x00720A3C), [footprint] (0x007209E2) then [caps] (0x007209F9), ret 8
  // (0x00720A09), al = the caps.
  __declspec(naked) unsigned __cdecl OccupyFootprintFits(const void*, const void*, const void*, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edi, [esp + 24]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov edx, 0x007209E0
      call edx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0062CA60 STIMap::IsWithin: eax = map (0x0062CA9E), edx = pos
  // (0x0062CA6E), [border] (0x0062CA72) then [wholeMap] (0x0062CA61),
  // caller-popped, al = inside.
  __declspec(naked) unsigned __cdecl MapIsWithin(const void*, const void*, float, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edx, [esp + 24]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov ecx, 0x0062CA60
      call ecx
      add esp, 8
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005AA860 CAiPathFinder::ShouldSearchRect(rect): thiscall, ecx =
  // finder (0x005AA86B), rect at [esp+0x18] after the frame (0x005AA866),
  // ret 4 (0x005AA8D2), al.
  __declspec(naked) unsigned __cdecl PathFinderShouldSearchRect(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 24]
      mov edx, 0x005AA860
      call edx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005A9D60 ComputeOctileDistanceCore(a, b): cdecl ([ebp+8], [ebp+0xC]),
  // st0 (0x005A9D7C).
  float __cdecl OctileDistanceCore(const float a, const float b)
  {
    return reinterpret_cast<float(__cdecl*)(float, float)>(0x005A9D60u)(a, b);
  }

  // 0x00927090 computesizes(ntotal, narray, nhash): nums in eax
  // (0x00927096), the rest cdecl on the stack (0x00927091, 0x009270E1,
  // 0x009270EC).
  __declspec(naked) void __cdecl LuaComputeSizes(const int*, int, int*, int*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov edx, 0x00927090
      call edx
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004FCBE0 func_AABoxToRect: eax = box (0x004FCBE5), ebx = out
  // (0x004FCCBC), eax = out.
  __declspec(naked) void __cdecl AABoxToRect(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ebx, [esp + 24]
      mov edx, 0x004FCBE0
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0050B0F0 COORDS_ToWorldPos: eax = cell (0x0050B0F0), edi = map
  // (0x0050B10F), esi = out (0x0050B140), [layer] [sizeX] [sizeZ] on the
  // stack (0x0050B151, 0x0050B0F3, 0x0050B105), plain ret, caller-popped.
  __declspec(naked) void __cdecl CoordsToWorldPos(const void*, const void*, void*, unsigned, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edi, [esp + 24]
      mov esi, [esp + 28]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      mov edx, 0x0050B0F0
      call edx
      add esp, 12
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005BE210 CIntelGrid::IsVisible(rect, bool): eax = grid (0x005BE215),
  // ecx = rect (0x005BE21B); the bool slot is never read; plain ret, al.
  __declspec(naked) unsigned __cdecl IntelGridIsVisibleRect(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, [esp + 24]
      push 0
      mov edx, 0x005BE210
      call edx
      add esp, 4
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0062D7E0 CalculateMapWaterRatio(map): ecx = map (0x0062D7E4), ret,
  // the ratio in xmm0 (divss at 0x0062DA41), returned here as its bits.
  __declspec(naked) unsigned __cdecl MapWaterRatio(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov edx, 0x0062D7E0
      call edx
      movd eax, xmm0
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x005AA680 CAiPathFinder::IsInBounds(from, to, cost): thiscall, ecx =
  // finder, to read at [esp+0xC] after one push (0x005AA68D), ret 0xC
  // (0x005AA6FA), al = 0 or 1.
  __declspec(naked) unsigned __cdecl PathFinderIsInBounds(const void*, const void*, const void*, float*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      push dword ptr [esp + 32]
      mov edx, 0x005AA680
      call edx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00577F20 STIMap::IsBlockingTerrain(z, x): ecx = map, esi = x, edi = z
  // (0x00577F28, 0x00577F32), ret, al = the blocking byte (0x00577F49) or 1
  // out of bounds (0x00577F51).
  __declspec(naked) unsigned __cdecl MapIsBlockingTerrain(const void*, unsigned, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov esi, [esp + 24]
      mov edi, [esp + 28]
      mov eax, 0x00577F20
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0040D860 InitGridTraversalLine(line, step, xEnd, xStart, zStart, zEnd):
  // ecx = line, eax = step (0x0040D869), xmm1 = xEnd, xmm2 = xStart
  // (0x0040D86D), [zStart zEnd] on the stack (0x0040D8A1/0x0040D8A7), ret 8.
  __declspec(naked) void __cdecl GridLineInit(void*, int, float, float, float, float)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov eax, [esp + 24]
      movss xmm1, dword ptr [esp + 28]
      movss xmm2, dword ptr [esp + 32]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      mov edx, 0x0040D860
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00475FD0 AdvanceGridTraversalEdge(line): eax = line, ret.
  __declspec(naked) void __cdecl GridLineAdvance(void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, 0x00475FD0
      call ecx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00476050 GetGridTraversalCell(line, x, z): ecx = line, eax = the two
  // ints (x at +0, z at +4), ret.
  __declspec(naked) void __cdecl GridLineCell(const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      mov eax, [esp + 24]
      mov edx, 0x00476050
      call edx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00476070 IsGridTraversalBeyondEnd(line): eax = line, ret, eax = 0 or 1.
  __declspec(naked) int __cdecl GridLineBeyondEnd(const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, 0x00476070
      call ecx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0091A510 luaO_log2(x) and 0x0091A4E0 luaO_int2fb(x): plain cdecl, the
  // argument at [esp+4] (0x0091A510, 0x0091A4E0), the result in eax.
  unsigned __cdecl LuaLog2(const unsigned x)
  {
    return reinterpret_cast<unsigned(__cdecl*)(unsigned)>(0x0091A510u)(x);
  }
  unsigned __cdecl LuaInt2Fb(const unsigned x)
  {
    return reinterpret_cast<unsigned(__cdecl*)(unsigned)>(0x0091A4E0u)(x);
  }
  // The three table lookups are plain cdecl, result in eax (0x00927508,
  // 0x0092746A, 0x0092755C).
  unsigned __cdecl LuaHGetStr(const void* const table, const void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*)>(0x009274D0u)(table, key);
  }
  unsigned __cdecl LuaHGetNum(const void* const table, const int key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, int)>(0x00927450u)(table, key);
  }
  unsigned __cdecl LuaHGet(const void* const table, const void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*)>(0x00927510u)(table, key);
  }
  // luaH_mainposition: cdecl, key at [esp+8] (0x00926F70), table at [esp+0xC]
  // after two pushes (0x00926FA4), eax = the node.
  unsigned __cdecl LuaHMainPosition(const void* const table, const void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*)>(0x00926F70u)(table, key);
  }
  // luaV_equalval(L, l, r): cdecl, l at [esp+0x10] after two pushes
  // (0x00929812), r at [esp+0x1C] after four (0x00929835), eax = 0 or 1.
  unsigned __cdecl LuaVEqualVal(const void* const state, const void* const left, const void* const right)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*, const void*)>(0x00929810u)(state, left, right);
  }
  // The stack API: cdecl, L at [esp+4] and idx at [esp+8] (0x0090C3D0,
  // 0x0090C340, 0x0090C740, 0x0090C5A0, 0x0090C6E0, 0x0090C590).
  unsigned __cdecl LuaAIndex(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090C3D0u)(state, idx);
  }
  unsigned __cdecl LuaNegIndex(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090C340u)(state, idx);
  }
  unsigned __cdecl LuaType(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090C740u)(state, idx);
  }
  unsigned __cdecl LuaGetTop(void* const state)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*)>(0x0090C590u)(state);
  }
  void __cdecl LuaSetTop(void* const state, const int idx)
  {
    reinterpret_cast<void(__cdecl*)(void*, int)>(0x0090C5A0u)(state, idx);
  }
  void __cdecl LuaPushValue(void* const state, const int idx)
  {
    reinterpret_cast<void(__cdecl*)(void*, int)>(0x0090C6E0u)(state, idx);
  }
  // lua_tonumber returns in st0 (fld at 0x0090CA39); lua_pushnumber takes a
  // 4-byte float (movss [esp+8], 0x0090CD40); lua_rawgeti's n at [esp+0x10]
  // after one push (0x0090D0C0).
  float __cdecl LuaToNumber(void* const state, const int idx)
  {
    return reinterpret_cast<float(__cdecl*)(void*, int)>(0x0090C9F0u)(state, idx);
  }
  void __cdecl LuaRawGetI(void* const state, const int idx, const int n)
  {
    reinterpret_cast<void(__cdecl*)(void*, int, int)>(0x0090D0A0u)(state, idx, n);
  }
  void __cdecl LuaPushNumber(void* const state, const float n)
  {
    reinterpret_cast<void(__cdecl*)(void*, float)>(0x0090CD40u)(state, n);
  }
  unsigned __cdecl LuaNextApi(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090D6D0u)(state, idx);
  }
  // luaT_gettm(events, event, ename): cdecl, ename at [esp+0xC] (0x00928420),
  // events at [esp+8] after one push, event at [esp+0xC] after it (0x00928438).
  unsigned __cdecl LuaTGetTm(void* const events, const int event, const void* const ename)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int, const void*)>(0x00928420u)(events, event, ename);
  }
  // lua_toboolean, lua_isnumber, lua_pushnil, lua_pushboolean, lua_rawget,
  // lua_rawseti, lua_rawset: cdecl, L at [esp+4] (0x0090CA40, 0x0090C7A0,
  // 0x0090CD01, 0x0090CF87, 0x0090D057, 0x0090D2F7, 0x0090D2A7).
  unsigned __cdecl LuaToBoolean(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090CA40u)(state, idx);
  }
  unsigned __cdecl LuaIsNumber(void* const state, const int idx)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, int)>(0x0090C7A0u)(state, idx);
  }
  void __cdecl LuaPushNil(void* const state)
  {
    reinterpret_cast<void(__cdecl*)(void*)>(0x0090CD00u)(state);
  }
  void __cdecl LuaPushBoolean(void* const state, const int b)
  {
    reinterpret_cast<void(__cdecl*)(void*, int)>(0x0090CF80u)(state, b);
  }
  void __cdecl LuaRawGet(void* const state, const int idx)
  {
    reinterpret_cast<void(__cdecl*)(void*, int)>(0x0090D050u)(state, idx);
  }
  void __cdecl LuaRawSetI(void* const state, const int idx, const int n)
  {
    reinterpret_cast<void(__cdecl*)(void*, int, int)>(0x0090D2F0u)(state, idx, n);
  }
  void __cdecl LuaRawSet(void* const state, const int idx)
  {
    reinterpret_cast<void(__cdecl*)(void*, int)>(0x0090D2A0u)(state, idx);
  }
  // luaV_gettable / luaV_index (L, t, key, loop): cdecl (0x009293E9 L,
  // 0x009293FE t, 0x0092940B key, 0x009293E1 loop), eax = the slot.
  unsigned __cdecl LuaVGetTable(void* const state, const void* const t, const void* const key, const int loop)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, const void*, const void*, int)>(0x009293E0u)(state, t, key, loop);
  }
  unsigned __cdecl LuaVIndex(void* const state, const void* const t, const void* const key, const int loop)
  {
    return reinterpret_cast<unsigned(__cdecl*)(void*, const void*, const void*, int)>(0x00929BF0u)(state, t, key, loop);
  }
  // luaV_settable(L, t, key, val): cdecl; 0x00929450 jumps to FAF's body at
  // 0x0128C4F4 (L at 0x0128C4FF, t at 0x0128C4FB, key at 0x0128C513).
  void __cdecl LuaVSetTable(void* const state, const void* const t, void* const key, void* const val)
  {
    reinterpret_cast<void(__cdecl*)(void*, const void*, void*, void*)>(0x00929450u)(state, t, key, val);
  }
  // luaV_lessthan(L, l, r): cdecl, r at [esp+0x10] after one push
  // (0x009296F1), l at [esp+0x10] after two (0x009296F8), eax = 0 or 1.
  unsigned __cdecl LuaVLessThan(const void* const state, const void* const left, const void* const right)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*, const void*)>(0x009296F0u)(state, left, right);
  }
  // luaH_index(L, t, key) and luaH_next(L, t, key): cdecl, key at [esp+0xC]
  // (0x00927610, 0x009276A5), eax = the index / 0 or 1.
  unsigned __cdecl LuaHIndex(const void* const state, const void* const table, const void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*, const void*)>(0x00927610u)(state, table, key);
  }
  unsigned __cdecl LuaHNext(const void* const state, const void* const table, void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, const void*, void*)>(0x009276A0u)(state, table, key);
  }
  // luaH_set(L, t, key): cdecl, table at [esp+0x10] after two pushes and key
  // at [esp+0x14] (0x00927575, 0x00927562), eax = the slot.
  unsigned __cdecl LuaHSet(const void* const state, void* const table, const void* const key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, void*, const void*)>(0x00927560u)(state, table, key);
  }
  // luaH_setnum(L, t, key): cdecl, key at [esp+0x18] after the 8-byte frame
  // and one push (0x00927AC4), table at [esp+0x18] after one more push
  // (0x00927AC9), eax = the slot.
  unsigned __cdecl LuaHSetNum(const void* const state, void* const table, const int key)
  {
    return reinterpret_cast<unsigned(__cdecl*)(const void*, void*, int)>(0x00927AC0u)(state, table, key);
  }

  // 0x004ECBD0 VEC_LookAt(up, forward, axes): edx = up (0x004ECC65), ecx =
  // forward (0x004ECBD9), ebx = the 9-float VAxes3 (0x004ECDAA..0x004ECE01),
  // ret.
  __declspec(naked) void __cdecl VecLookAt(const void*, const void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edx, [esp + 20]
      mov ecx, [esp + 24]
      mov ebx, [esp + 28]
      mov eax, 0x004ECBD0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004EE710 VEC_Mul4x3(lhs, out, rhs): eax = lhs, ecx = rhs (row 0 read at
  // 0x004EE71D/0x004EE727), edx = out (x/y/z of each row, 0x004EE7EA..
  // 0x004EE974), ret.
  __declspec(naked) void __cdecl VecMul4x3(const void*, void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edx, [esp + 24]
      mov ecx, [esp + 28]
      mov esi, 0x004EE710
      call esi
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00715750 InfluenceGrid::GetThreat(type, army): eax = this, edx = the
  // threat type, ecx = the army (0x00715750..0x00715767), result in xmm0,
  // ret. The bits come back in eax so a NaN keeps its payload.
  __declspec(naked) unsigned __cdecl InfluenceGetThreatBits(const void*, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov edx, [esp + 24]
      mov ecx, [esp + 28]
      mov ebx, 0x00715750
      call ebx
      movd eax, xmm0
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00715130 InfluenceGrid::DecayInfluence(): eax = this, ret.
  __declspec(naked) void __cdecl InfluenceDecay(void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 20]
      mov ecx, 0x00715130
      call ecx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00475DA0 CHeightField::GetTierBounds(x, z, tier): edx = this, esi =
  // the result pair, eax = z, [x tier], ret 8 (0x00475DA0..0x00475DE1).
  __declspec(naked) void* __cdecl HeightFieldTierBounds(const void*, int, int, int, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edx, [esp + 20]
      mov eax, [esp + 28]
      mov esi, [esp + 36]
      push dword ptr [esp + 32]
      push dword ptr [esp + 28]
      mov ecx, 0x00475DA0
      call ecx
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x004776E0 CHeightField::ClipSegmentToWorld(pos, dir, min, max): ebx =
  // pos, edi = dir, esi = this, [min max] (0x004776E3, 0x004776FE), ret 8,
  // result in al (0x004778CB, 0x004778D7, 0x004778E0).
  __declspec(naked) int __cdecl HeightFieldClipSegment(const void*, const void*, const void*, void*, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov esi, [esp + 20]
      mov ebx, [esp + 24]
      mov edi, [esp + 28]
      push dword ptr [esp + 36]
      push dword ptr [esp + 36]
      mov ecx, 0x004776E0
      call ecx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x0069A620 CHeightField::GetNormal(x, z): edi = this, esi = the result
  // vector, [x z], ret 8, eax = esi.
  __declspec(naked) void* __cdecl HeightFieldNormal(const void*, float, float, void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov edi, [esp + 20]
      mov esi, [esp + 32]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov eax, 0x0069A620
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x008D82F0 gpg::BitArray2D::BitArray2D(width, height): ecx = this, ret 8.
  __declspec(naked) void __cdecl BitArrayConstruct(void*, unsigned, unsigned)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 28]
      push dword ptr [esp + 28]
      mov eax, 0x008D82F0
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x008D8370 gpg::BitArray2D::FillRect(x0, z0, w, h, fill): ecx = this,
  // ret 14h.
  __declspec(naked) void __cdecl BitArrayFillRect(void*, int, int, int, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      mov eax, 0x008D8370
      call eax
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x008D8460 gpg::BitArray2D::GetRectOr(x0, z0, w, h, disallowNegative):
  // ecx = this, ret 14h, bool in al.
  __declspec(naked) int __cdecl BitArrayGetRectOr(const void*, int, int, int, int, int)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov ecx, [esp + 20]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      push dword ptr [esp + 40]
      mov eax, 0x008D8460
      call eax
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }

  // 0x00720580 gpg::BitArray2D::GetRectNeg(rect): eax = rect, [this], ret 4,
  // bool in al.
  __declspec(naked) int __cdecl BitArrayGetRectNeg(const void*, const void*)
  {
    __asm {
      push ebx
      push esi
      push edi
      push ebp
      mov eax, [esp + 24]
      push dword ptr [esp + 20]
      mov ecx, 0x00720580
      call ecx
      movzx eax, al
      pop ebp
      pop edi
      pop esi
      pop ebx
      ret
    }
  }
} // namespace retail
