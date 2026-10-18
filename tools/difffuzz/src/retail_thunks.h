#pragma once

#include <cstdint>

// Retail entry points, wrapped as plain __cdecl functions.
//
// Each wrapper is a __declspec(naked) thunk that saves every callee-saved
// register, loads the retail function's inputs into the registers/stack slots
// its asm reads, calls the absolute VA inside the mapped retail image, and
// restores. Register conventions come from the FUN_*.asm export, not from IDA
// prototypes: e.g. NormalizeVectorInto reads the source through edi and the
// destination through esi.
//
// Float returns stay in st(0) exactly as the retail function left them; the
// C++ caller stores them to float, which is what every engine caller does.
// `bool` (al) returns are widened to int with movzx.
namespace retail
{
  // --- plain __cdecl leaves (callable through typed pointers too) ---------
  float __cdecl Sqrtf(float x);              // 0x00452FC0  fld; fsqrt
  float __cdecl SqrtfB(float x);             // 0x0040EAF0  fld; fsqrt (second copy)
  float __cdecl Fabsf(float x);              // 0x0040DAB0  fld; fabs
  float __cdecl Sinf(float x);               // 0x005734E0  fld; fsin
  float __cdecl Cosf(float x);               // 0x005734D0  fld; fcos
  float __cdecl Atan2f(float y, float x);    // 0x004E9DF0  fld y; fld x; fpatan
  double __cdecl Acos(double x);             // 0x00A8DCD0  _CIacos: arg and result in st(0)
  double __cdecl Fmod(double x, double y);   // 0x00A8E06A  _CIfmod: st(1)=x, st(0)=y, result in st(0)
  void __cdecl RunStaticInit(unsigned va);   // call a retail void(void) C-init entry (e.g. 0x00BEDC30)

  // --- custom register conventions ----------------------------------------
  float __cdecl Wm3Normalize(void* v);                                     // 0x00452AF0 ecx=v, ret st0
  void* __cdecl NormalizeVectorInto(void* dest, const void* src);          // 0x0044F7E0 esi=dest edi=src
  void* __cdecl QuatCrossAdd(void* dest, const void* v1, const void* v2, const void* fallback);
                                                                           // 0x0044F880 ebx=dest edi=fallback, v1,v2 by value
  void __cdecl QuatFromVecRot(void* quat, const void* refAxis, float rads); // 0x0069AA50 ecx=refAxis, [quat, rads]
  int __cdecl RotateQuatByAngle(void* quat, float rads);                   // 0x004EB740 esi=quat, [rads], al
  void* __cdecl Slerp(const void* q2, const void* q1, void* out, float t); // 0x004EBC00 eax=q2 ecx=q1 ebx=out, [t]
  void* __cdecl QuatLerp(const void* q1, const void* q2, void* out, float t); // 0x004EBA80 eax=q1 ecx=q2 ebx=out, [t]
  void* __cdecl MultQuadVec(void* dest, const void* vec, const void* quat); // 0x00452D40 ebx=dest esi=vec ecx=quat
  void* __cdecl QuatToMatrix(const void* quat, void* outRows);             // 0x00452FD0 ecx=quat, [out], ret 4
  void* __cdecl VecSetLengthTo(void* dest, const void* target, const void* src); // 0x0069A360 eax=dest edx=target ecx=src
  int __cdecl VecSetLength(void* vec, float length);                       // 0x005B1C90 esi=vec, [len], al
  void __cdecl NormalizeQuatInPlace(void* quat);                           // 0x004EDAA0 esi=quat
  int __cdecl QuatsNearEqual(const void* a, const void* b);                // 0x004EDED0 edi=a esi=b, eax

  // --- second wave: the remaining leaves of QuaternionMath.cpp / Vector3f.cpp
  float __cdecl DistanceSquared3D(const void* from, const void* to);       // 0x004CC960 eax=from ecx=to, ret xmm0
  void* __cdecl ReflectAcrossNormal(void* dest, const void* incident, const void* normal); // 0x0069A230 eax edx ecx
  int __cdecl IsUnitLength(const void* v);                                 // 0x0069A1D0 eax=v, eax
  int __cdecl LargestAxis(const void* v);                                  // 0x005382E0 ecx=v, eax
  void* __cdecl ScaleByReciprocalOrSetMax(void* v, float divisor);         // 0x004ED810 __thiscall, ret 4
  float __cdecl HeadingFromXZ(const void* v);                              // 0x00565A10 eax=v, ret st0
  void* __cdecl ExtractYAxisColumn(void* out, const void* quat);           // 0x00694AF0 eax=out ecx=quat
  void* __cdecl RotateByConjugate(const void* quatLanes, void* out, const void* src); // 0x0062FBA0 eax ecx esi
  void* __cdecl QuatFromAxisAngleVector(void* quat, const void* axisAngle); // 0x00697360 esi=quat, vec by value
  void* __cdecl EulerRollToQuat(const void* axis, void* out, float roll);  // 0x00570750 edi=axis esi=out, [roll], ret 4
  int __cdecl VecLimitLengthTo(void* v, float maxLength);                  // 0x005D1E70 eax=v, [max], al
  void __cdecl MatrixToQuat(const void* rows, void* out);                  // 0x004EB3F0 eax=rows esi=out
  void __cdecl MatrixRowsToQuatCanonical(const void* rows, void* out);     // 0x004F0CB0 ecx=out, [rows], ret 4
  void __cdecl QuatToAxisAndAngle(const void* quat, void* axis, void* angle); // 0x006C1070 esi edi ebx
  void* __cdecl TiltShortestArcDelta(const void* targetNormal, void* out, const void* currentUp); // 0x0050CB50 eax edi esi
  float __cdecl NormalizeAngle(float rads);                                // 0x0062FB50 cdecl, ret xmm0
  void* __cdecl Multiply3x3(void* result, const void* a, const void* b);   // 0x006D2680 eax=result, [a, b], ret 8
  void* __cdecl EulerHPRToMatrix(void* out, float h, float p, float r);    // 0x006D1E30 esi=out, [h p r], ret 0Ch
  void* __cdecl BlendOrientation(const void* goal, const void* current, float step, void* outNoStep, void* out);
                                                                           // 0x004EB830 ebx=goal edi=out, [cur step flag]

  // --- third wave: manipulator angle lanes ----------------------------------
  void __cdecl SetFiringArc(void* self, float minH, float maxH, float hSlew, float minP, float maxP, float pSlew);
                                                                           // 0x00630CB0 esi=this, [6 floats], ret 18h
  void __cdecl SetAimingArc(void* self, float minH, float maxH, float hSlew, float minP, float maxP, float pSlew);
                                                                           // 0x00636490 esi=this, [6 floats], ret 18h
  int __cdecl BuilderArmUpdateTrackingAxis(void* self, const void* target, float center, float halfArc, float slew, int flags);
                                                                           // 0x00636220 eax=target ecx=bone, [this ...], ret 14h
  int __cdecl AimCheckTracking(void* self, const void* target, float center, float halfRange, float slew, float tolerance, int flags);
                                                                           // 0x006309F0 eax=target ecx=bone, [this ...], ret 18h
  float __cdecl WrapPositiveModulo(float value, float range);              // 0x00422940 cdecl, ret xmm0
} // namespace retail
