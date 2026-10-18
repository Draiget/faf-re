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
} // namespace retail
