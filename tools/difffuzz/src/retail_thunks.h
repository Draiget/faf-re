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
  double __cdecl Fmod(double x, double y);
  void __cdecl PowF(float x, float y, float* out); // 0x00A8E0E0 _CIpow as math.pow (0x00919CD3) uses it: st(1)=x, st(0)=y, fstp dword   // 0x00A8E06A  _CIfmod: st(1)=x, st(0)=y, result in st(0)
  void __cdecl RunStaticInit(unsigned va);   // call a retail void(void) C-init entry (e.g. 0x00BEDC30)

  // --- Lua math library (0x00919930..0x0091A110) -----------------------------
  float __cdecl UnaryFloatLeaf(unsigned va, float x);                   // cdecl float(float) leaf, ret st0
  void __cdecl CrtStackUnaryF(unsigned va, float x, float* out);        // _CI* entry: fld dword; call; fstp dword
  void __cdecl CrtStackBinaryF(unsigned va, float x, float y, float* out); // _CI* entry: st1=x st0=y; fstp dword
  void __cdecl CrtDoubleArgF(unsigned va, float x, float* out);         // cdecl double(double) CRT entry; fstp dword
  void __cdecl FrexpF(float x, float* mantissa, int* exponent);         // frexp 0x00A8DA05 as math_frexp calls it
  void __cdecl LdexpF(float x, float exponent, float* out);             // _ftol2 0x00A89CC0 + ldexp 0x00A8DADF
  float __cdecl MulImageConstant(float x, unsigned constantVa);         // `fld x; fmul dword [va]` (math_deg/rad)
  float __cdecl RandomSample(int randValue);                            // math_random's [0,1) sample
  void __cdecl RandomPickUpTo(int upper, float sample, float* out);     // math_random(u) arithmetic
  void __cdecl RandomPickRange(int count, float sample, int lower, float* out); // math_random(l, u) arithmetic
  unsigned __cdecl RandomSeedWord(float seed);                          // math_randomseed's fistp low dword

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

  // --- fourth wave: callers of the inline X87Math helpers (plan WPR.21) -----
  int __cdecl RateGameRateToSpeed(float rate);                             // 0x0055AE10 cdecl, eax
  float __cdecl QuantizeEdgeCost(float a, float b);                        // 0x0092D8B0 cdecl, ret st0
  void* __cdecl CoordsToGridRect(void* result, const void* centerXZ, int sizeX, int sizeZ);
                                                                           // 0x0050AFA0 eax ecx edi esi, ret eax
  void __cdecl ProjectBoxOntoAxis(const void* box, const void* axis, float* outMin, float* outMax);
                                                                           // 0x00475550 eax=box ecx=axis, [min max]
  void* __cdecl MatrixColumnsToQuat(const void* columns, void* out);       // 0x004F0AE0 ecx=out, [columns], ret 4
  int __cdecl IsValidVector3f(const void* v);                              // 0x005657F0 esi=v, eax
  void* __cdecl VAxes3FromQuat(void* out, const void* quat);               // 0x004EC590 eax=out ecx=quat
  int __cdecl FloorSecondsToTicks(float seconds);                          // 0x0066D1D0 xmm0, eax
  void* __cdecl GridPosFromWorld(void* out, const void* worldPos, int gridSize); // 0x00506E20 ecx esi, [size]
  void* __cdecl SegmentFromEndpoints(void* out, const void* start, const void* end); // 0x004FE130 esi ecx eax
  void* __cdecl AlignedBoundsFromBox(void* out, const void* box);          // 0x004FE2D0 esi=out ecx=box
  void __cdecl VMatrix4Set(void* out, const void* quat, const void* pos);  // 0x004EE980 eax=out ecx=quat edx=pos

  // --- fifth wave: the collision primitives' virtuals (Wild Magic queries) ---
  // __thiscall at `va` with ecx = self and 1..3 stack arguments the callee
  // pops; the bool in al, widened.
  int __cdecl ThisCallBool1(unsigned va, const void* self, const void* a);
  int __cdecl ThisCallBool2(unsigned va, const void* self, const void* a, void* b);
  int __cdecl ThisCallBool3(unsigned va, const void* self, const void* a, const void* b, void* c);
  // The Wild Magic query objects' members: __thiscall, no stack arguments.
  int __cdecl ThisCallBool0(unsigned va, void* self);     // bool in al, widened
  float __cdecl ThisCallFloat0(unsigned va, void* self);  // float in st0

  // --- sixth wave: terrain, random stream, transform inverse, Vector2f ------
  float __cdecl HeightFieldElevation(const void* field, float x, float z); // 0x0044FB90 ecx=field, [x z], ret 8, st0
  float __cdecl RandomStreamFRand(void* stream, float lower, float upper); // 0x0051B5C0 edx=stream, [lower upper], ret 8, st0
  void* __cdecl VTransformInverse(void* out, const void* self);            // 0x0046FBF0 edi=out eax=this
  float __cdecl Distance2D(const void* from, const void* to);              // 0x004CC8F0 eax=from ecx=to, st0
  float __cdecl DistanceSquared2D(const void* from, const void* to);       // 0x004CC930 eax=from ecx=to, xmm0
  int __cdecl IsValidVector2f(const void* v);                              // 0x005657B0 esi=v, eax
  int __cdecl RayBoxSlabClip(void* state, const void* box);                // 0x00473DF0 ecx=state edx=box, eax
  void __cdecl AniPoseBoneRotate(void* bone, const void* rotation);        // 0x0054BC00 eax=bone ecx=rotation

  // Inlined sites: the thunk runs the site's own instructions (and calls the
  // retail leaves it calls), not a retail function.
  void __cdecl FallAxis(float direction, float elevation, float* outAxis); // MotorFallDown 0x006952A9..0x006953B1
  float __cdecl Atan2DifferenceSite(float y1, float x1, float y2, float x2); // 0x006BDAF2..0x006BDB31 via leaf 0x004E9DF0
  float __cdecl DiveCurveSpeed(float phase, float base);                   // 0x006C336C..0x006C3380
  float __cdecl VelocityLength(const void* v);                             // 0x006A2846..0x006A2861
  int __cdecl TruncateFloatKey(float key);                                 // cvttss2si (0x0090AD62)
  int __cdecl CeilFloatToInt(float value);                                 // 0x00425110 [value], eax

  // --- engine objects (targets_sim.cpp): built and freed by retail's own code
  // through the redirected allocator (main.cpp, kRetailHeapEntries) ----------
  void __cdecl OperatorDelete(void* p);                                    // 0x00957A60 [p]
  void* __cdecl HeightFieldConstruct(void* self, int width, int height);   // 0x00476090 [self width height], ret 0Ch
  void __cdecl HeightFieldUpdateBounds(void* self, int x0, int z0, int x1, int z1); // 0x00476BB0 [self rect], ret 14h
  void* __cdecl HeightFieldIntersection(const void* self, const void* line, void* out, void* res); // 0x00476F30 eax=self esi=line ebx=out, [res], ret 4
  unsigned __cdecl MapOccupancyCaps(const void* map, const void* pos, const void* footprint); // 0x00564DF0 ecx=map eax=pos, [fp], ret, al
  unsigned __cdecl OccupyFilter(const void* footprint, const void* grid, const void* pos, unsigned caps); // 0x00720920 ecx=fp esi=grid, [pos][caps], ret 8, al
  unsigned __cdecl PathFinderIsInBounds(const void* finder, const void* from, const void* to, float* cost); // 0x005AA680 thiscall, ret 0xC, al
  unsigned __cdecl MapWaterRatio(const void* map); // 0x0062D7E0 ecx = map, ret, xmm0 (returned as bits)
  unsigned __cdecl PathFinderShouldSearchRect(const void* finder, const void* rect); // 0x005AA860 thiscall, ret 4, al
  float __cdecl OctileDistanceCore(float a, float b);                         // 0x005A9D60 cdecl, st0
  void __cdecl LuaComputeSizes(const int* nums, int ntotal, int* narray, int* nhash); // 0x00927090 eax = nums, cdecl
  void __cdecl AABoxToRect(const void* box, void* out);                        // 0x004FCBE0 eax = box, ebx = out
  void __cdecl CoordsToWorldPos(const void* cell, const void* map, void* out, unsigned layer, int sizeX, int sizeZ); // 0x0050B0F0 eax edi esi, [layer][sx][sz]
  unsigned __cdecl IntelGridIsVisibleRect(const void* grid, const void* rect); // 0x005BE210 eax = grid, ecx = rect, al
  unsigned __cdecl OccupyMobileCheck(const void* pos, const void* footprint, const void* map); // 0x00564AB0 ecx=pos, [fp][map], eax
  unsigned __cdecl OccupyFootprintFits(const void* grid, const void* pos, const void* footprint, unsigned caps); // 0x007209E0 eax=grid edi=pos, [fp][caps], ret 8, al
  unsigned __cdecl MapIsWithin(const void* map, const void* pos, float border, unsigned wholeMap); // 0x0062CA60 eax=map edx=pos, [border][whole], al
  unsigned __cdecl MapIsBlockingTerrain(const void* map, unsigned x, unsigned z); // 0x00577F20 ecx=map esi=x edi=z, ret, al
  void __cdecl GridLineInit(void* line, int step, float xEnd, float xStart, float zStart, float zEnd); // 0x0040D860 ecx=line eax=step xmm1/xmm2, [zStart zEnd], ret 8
  void __cdecl GridLineAdvance(void* line);                         // 0x00475FD0 eax=line, ret
  void __cdecl GridLineCell(const void* line, void* xz);            // 0x00476050 ecx=line eax=out, ret
  int __cdecl GridLineBeyondEnd(const void* line);                  // 0x00476070 eax=line, ret, eax
  unsigned __cdecl LuaLog2(unsigned x);   // 0x0091A510 luaO_log2, cdecl [x], eax
  unsigned __cdecl LuaInt2Fb(unsigned x); // 0x0091A4E0 luaO_int2fb, cdecl [x], eax
  unsigned __cdecl LuaHGetStr(const void* table, const void* key); // 0x009274D0 luaH_getstr, cdecl, eax = value slot
  unsigned __cdecl LuaHGetNum(const void* table, int key);         // 0x00927450 luaH_getnum, cdecl, eax = value slot
  unsigned __cdecl LuaHGet(const void* table, const void* key);    // 0x00927510 luaH_get, cdecl, eax = value slot
  unsigned __cdecl LuaHMainPosition(const void* table, const void* key); // 0x00926F70 luaH_mainposition, cdecl, eax = node
  unsigned __cdecl LuaVEqualVal(const void* state, const void* left, const void* right); // 0x00929810 luaV_equalval, cdecl, eax
  unsigned __cdecl LuaHIndex(const void* state, const void* table, const void* key); // 0x00927610 luaH_index, cdecl, eax
  unsigned __cdecl LuaHNext(const void* state, const void* table, void* key);        // 0x009276A0 luaH_next, cdecl, eax; writes key[0..1]
  unsigned __cdecl LuaHSet(const void* state, void* table, const void* key);         // 0x00927560 luaH_set, cdecl, eax = slot; clears flags
  unsigned __cdecl LuaHSetNum(const void* state, void* table, int key);              // 0x00927AC0 luaH_setnum, cdecl, eax = slot
  unsigned __cdecl LuaVLessThan(const void* state, const void* left, const void* right); // 0x009296F0 luaV_lessthan, cdecl, eax
  unsigned __cdecl LuaAIndex(void* state, int idx);   // 0x0090C3D0 luaA_index, cdecl, eax = slot
  unsigned __cdecl LuaNegIndex(void* state, int idx); // 0x0090C340 negindex, cdecl, eax = slot or 0
  unsigned __cdecl LuaType(void* state, int idx);     // 0x0090C740 lua_type, cdecl, eax
  unsigned __cdecl LuaGetTop(void* state);            // 0x0090C590 lua_gettop, cdecl, eax
  void __cdecl LuaSetTop(void* state, int idx);       // 0x0090C5A0 lua_settop, cdecl
  void __cdecl LuaPushValue(void* state, int idx);    // 0x0090C6E0 lua_pushvalue, cdecl
  float __cdecl LuaToNumber(void* state, int idx);    // 0x0090C9F0 lua_tonumber, cdecl, st0
  void __cdecl LuaRawGetI(void* state, int idx, int n); // 0x0090D0A0 lua_rawgeti, cdecl
  void __cdecl LuaPushNumber(void* state, float n);   // 0x0090CD40 lua_pushnumber, cdecl
  unsigned __cdecl LuaNextApi(void* state, int idx);  // 0x0090D6D0 lua_next, cdecl, eax
  unsigned __cdecl LuaTGetTm(void* events, int event, const void* ename); // 0x00928420 luaT_gettm, cdecl, eax = slot or 0
  unsigned __cdecl LuaVGetTable(void* state, const void* t, const void* key, int loop); // 0x009293E0 luaV_gettable, cdecl, eax
  unsigned __cdecl LuaVIndex(void* state, const void* t, const void* key, int loop);    // 0x00929BF0 luaV_index, cdecl, eax
  void __cdecl LuaVSetTable(void* state, const void* t, void* key, void* val);         // 0x00929450 luaV_settable (FAF body 0x0128C4F4), cdecl
  unsigned __cdecl LuaToBoolean(void* state, int idx);  // 0x0090CA40 lua_toboolean, cdecl, eax
  unsigned __cdecl LuaIsNumber(void* state, int idx);   // 0x0090C7A0 lua_isnumber, cdecl, eax
  void __cdecl LuaPushNil(void* state);                 // 0x0090CD00 lua_pushnil, cdecl
  void __cdecl LuaPushBoolean(void* state, int b);      // 0x0090CF80 lua_pushboolean, cdecl
  void __cdecl LuaRawGet(void* state, int idx);         // 0x0090D050 lua_rawget, cdecl
  void __cdecl LuaRawSetI(void* state, int idx, int n); // 0x0090D2F0 lua_rawseti, cdecl
  void __cdecl LuaRawSet(void* state, int idx);         // 0x0090D2A0 lua_rawset, cdecl
  void __cdecl VecLookAt(const void* up, const void* forward, void* axes);       // 0x004ECBD0 edx=up ecx=forward ebx=axes, ret
  void __cdecl VecMul4x3(const void* lhs, void* out, const void* rhs);          // 0x004EE710 eax=lhs edx=out ecx=rhs, ret
  unsigned __cdecl InfluenceGetThreatBits(const void* self, int type, int army); // 0x00715750 eax=self edx=type ecx=army, ret, xmm0 -> bits
  void __cdecl InfluenceDecay(void* self);                                       // 0x00715130 eax=self, ret
  void* __cdecl HeightFieldTierBounds(const void* self, int x, int z, int tier, void* out); // 0x00475DA0 edx=self esi=out eax=z, [x tier], ret 8
  int __cdecl HeightFieldClipSegment(const void* self, const void* pos, const void* dir, void* min, void* max); // 0x004776E0 esi=self ebx=pos edi=dir, [min max], ret 8, al
  void* __cdecl HeightFieldNormal(const void* self, float x, float z, void* out); // 0x0069A620 edi=self esi=out, [x z], ret 8
  void __cdecl BitArrayConstruct(void* self, unsigned width, unsigned height); // 0x008D82F0 ecx=self, [width height], ret 8
  void __cdecl BitArrayFillRect(void* self, int x0, int z0, int w, int h, int fill); // 0x008D8370 ecx=self, [x0 z0 w h fill], ret 14h
  int __cdecl BitArrayGetRectOr(const void* self, int x0, int z0, int w, int h, int disallowNegative); // 0x008D8460 ecx=self, [..], ret 14h, al
  int __cdecl BitArrayGetRectNeg(const void* self, const void* rect);         // 0x00720580 eax=rect, [self], ret 4, al
} // namespace retail
