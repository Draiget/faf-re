// The retail:: thunks for builds that have no retail image (faf_math_dump,
// plan WPR.21): the targets' retail functions still link, and reaching one
// aborts. dump_main.cpp only calls the targets' gen and ours functions.
// Keep the list in step with retail_thunks.h.

#include "retail_thunks.h"

#include <cstdio>
#include <cstdlib>

namespace
{
  [[noreturn]] void NoRetailImage(const char* const name)
  {
    std::fprintf(stderr, "faf_math_dump: retail::%s called, but this build has no retail image\n", name);
    std::abort();
  }
} // namespace

namespace retail
{
  float __cdecl Sqrtf(float) { NoRetailImage("Sqrtf"); }
  float __cdecl SqrtfB(float) { NoRetailImage("SqrtfB"); }
  float __cdecl Fabsf(float) { NoRetailImage("Fabsf"); }
  float __cdecl Sinf(float) { NoRetailImage("Sinf"); }
  float __cdecl Cosf(float) { NoRetailImage("Cosf"); }
  float __cdecl Atan2f(float, float) { NoRetailImage("Atan2f"); }
  double __cdecl Acos(double) { NoRetailImage("Acos"); }
  double __cdecl Fmod(double, double) { NoRetailImage("Fmod"); }
  void __cdecl PowF(float, float, float*) { NoRetailImage("PowF"); }
  void __cdecl RunStaticInit(unsigned) { NoRetailImage("RunStaticInit"); }

  float __cdecl UnaryFloatLeaf(unsigned, float) { NoRetailImage("UnaryFloatLeaf"); }
  void __cdecl CrtStackUnaryF(unsigned, float, float*) { NoRetailImage("CrtStackUnaryF"); }
  void __cdecl CrtStackBinaryF(unsigned, float, float, float*) { NoRetailImage("CrtStackBinaryF"); }
  void __cdecl CrtDoubleArgF(unsigned, float, float*) { NoRetailImage("CrtDoubleArgF"); }
  void __cdecl FrexpF(float, float*, int*) { NoRetailImage("FrexpF"); }
  void __cdecl LdexpF(float, float, float*) { NoRetailImage("LdexpF"); }
  float __cdecl MulImageConstant(float, unsigned) { NoRetailImage("MulImageConstant"); }
  float __cdecl RandomSample(int) { NoRetailImage("RandomSample"); }
  void __cdecl RandomPickUpTo(int, float, float*) { NoRetailImage("RandomPickUpTo"); }
  void __cdecl RandomPickRange(int, float, int, float*) { NoRetailImage("RandomPickRange"); }
  unsigned __cdecl RandomSeedWord(float) { NoRetailImage("RandomSeedWord"); }

  float __cdecl Wm3Normalize(void*) { NoRetailImage("Wm3Normalize"); }
  void* __cdecl NormalizeVectorInto(void*, const void*) { NoRetailImage("NormalizeVectorInto"); }
  void* __cdecl QuatCrossAdd(void*, const void*, const void*, const void*) { NoRetailImage("QuatCrossAdd"); }
  void __cdecl QuatFromVecRot(void*, const void*, float) { NoRetailImage("QuatFromVecRot"); }
  int __cdecl RotateQuatByAngle(void*, float) { NoRetailImage("RotateQuatByAngle"); }
  void* __cdecl Slerp(const void*, const void*, void*, float) { NoRetailImage("Slerp"); }
  void* __cdecl QuatLerp(const void*, const void*, void*, float) { NoRetailImage("QuatLerp"); }
  void* __cdecl MultQuadVec(void*, const void*, const void*) { NoRetailImage("MultQuadVec"); }
  void* __cdecl QuatToMatrix(const void*, void*) { NoRetailImage("QuatToMatrix"); }
  void* __cdecl VecSetLengthTo(void*, const void*, const void*) { NoRetailImage("VecSetLengthTo"); }
  int __cdecl VecSetLength(void*, float) { NoRetailImage("VecSetLength"); }
  void __cdecl NormalizeQuatInPlace(void*) { NoRetailImage("NormalizeQuatInPlace"); }
  int __cdecl QuatsNearEqual(const void*, const void*) { NoRetailImage("QuatsNearEqual"); }

  float __cdecl DistanceSquared3D(const void*, const void*) { NoRetailImage("DistanceSquared3D"); }
  void* __cdecl ReflectAcrossNormal(void*, const void*, const void*) { NoRetailImage("ReflectAcrossNormal"); }
  int __cdecl IsUnitLength(const void*) { NoRetailImage("IsUnitLength"); }
  int __cdecl LargestAxis(const void*) { NoRetailImage("LargestAxis"); }
  void* __cdecl ScaleByReciprocalOrSetMax(void*, float) { NoRetailImage("ScaleByReciprocalOrSetMax"); }
  float __cdecl HeadingFromXZ(const void*) { NoRetailImage("HeadingFromXZ"); }
  void* __cdecl ExtractYAxisColumn(void*, const void*) { NoRetailImage("ExtractYAxisColumn"); }
  void* __cdecl RotateByConjugate(const void*, void*, const void*) { NoRetailImage("RotateByConjugate"); }
  void* __cdecl QuatFromAxisAngleVector(void*, const void*) { NoRetailImage("QuatFromAxisAngleVector"); }
  void* __cdecl EulerRollToQuat(const void*, void*, float) { NoRetailImage("EulerRollToQuat"); }
  int __cdecl VecLimitLengthTo(void*, float) { NoRetailImage("VecLimitLengthTo"); }
  void __cdecl MatrixToQuat(const void*, void*) { NoRetailImage("MatrixToQuat"); }
  void __cdecl MatrixRowsToQuatCanonical(const void*, void*) { NoRetailImage("MatrixRowsToQuatCanonical"); }
  void __cdecl QuatToAxisAndAngle(const void*, void*, void*) { NoRetailImage("QuatToAxisAndAngle"); }
  void* __cdecl TiltShortestArcDelta(const void*, void*, const void*) { NoRetailImage("TiltShortestArcDelta"); }
  float __cdecl NormalizeAngle(float) { NoRetailImage("NormalizeAngle"); }
  void* __cdecl Multiply3x3(void*, const void*, const void*) { NoRetailImage("Multiply3x3"); }
  void* __cdecl EulerHPRToMatrix(void*, float, float, float) { NoRetailImage("EulerHPRToMatrix"); }
  void* __cdecl BlendOrientation(const void*, const void*, float, void*, void*) { NoRetailImage("BlendOrientation"); }

  void __cdecl SetFiringArc(void*, float, float, float, float, float, float) { NoRetailImage("SetFiringArc"); }
  void __cdecl SetAimingArc(void*, float, float, float, float, float, float) { NoRetailImage("SetAimingArc"); }
  int __cdecl BuilderArmUpdateTrackingAxis(void*, const void*, float, float, float, int)
  {
    NoRetailImage("BuilderArmUpdateTrackingAxis");
  }
  int __cdecl AimCheckTracking(void*, const void*, float, float, float, float, int) { NoRetailImage("AimCheckTracking"); }
  float __cdecl WrapPositiveModulo(float, float) { NoRetailImage("WrapPositiveModulo"); }

  int __cdecl RateGameRateToSpeed(float) { NoRetailImage("RateGameRateToSpeed"); }
  float __cdecl QuantizeEdgeCost(float, float) { NoRetailImage("QuantizeEdgeCost"); }
  void* __cdecl CoordsToGridRect(void*, const void*, int, int) { NoRetailImage("CoordsToGridRect"); }
  void __cdecl ProjectBoxOntoAxis(const void*, const void*, float*, float*) { NoRetailImage("ProjectBoxOntoAxis"); }
  void* __cdecl MatrixColumnsToQuat(const void*, void*) { NoRetailImage("MatrixColumnsToQuat"); }
  int __cdecl IsValidVector3f(const void*) { NoRetailImage("IsValidVector3f"); }
  void* __cdecl VAxes3FromQuat(void*, const void*) { NoRetailImage("VAxes3FromQuat"); }
  int __cdecl FloorSecondsToTicks(float) { NoRetailImage("FloorSecondsToTicks"); }
  void* __cdecl GridPosFromWorld(void*, const void*, int) { NoRetailImage("GridPosFromWorld"); }
  void* __cdecl SegmentFromEndpoints(void*, const void*, const void*) { NoRetailImage("SegmentFromEndpoints"); }
  void* __cdecl AlignedBoundsFromBox(void*, const void*) { NoRetailImage("AlignedBoundsFromBox"); }
  void __cdecl VMatrix4Set(void*, const void*, const void*) { NoRetailImage("VMatrix4Set"); }

  int __cdecl ThisCallBool1(unsigned, const void*, const void*) { NoRetailImage("ThisCallBool1"); }
  int __cdecl ThisCallBool2(unsigned, const void*, const void*, void*) { NoRetailImage("ThisCallBool2"); }
  int __cdecl ThisCallBool3(unsigned, const void*, const void*, const void*, void*) { NoRetailImage("ThisCallBool3"); }
  int __cdecl ThisCallBool0(unsigned, void*) { NoRetailImage("ThisCallBool0"); }
  float __cdecl ThisCallFloat0(unsigned, void*) { NoRetailImage("ThisCallFloat0"); }

  float __cdecl HeightFieldElevation(const void*, float, float) { NoRetailImage("HeightFieldElevation"); }
  float __cdecl RandomStreamFRand(void*, float, float) { NoRetailImage("RandomStreamFRand"); }
  void* __cdecl VTransformInverse(void*, const void*) { NoRetailImage("VTransformInverse"); }
  float __cdecl Distance2D(const void*, const void*) { NoRetailImage("Distance2D"); }
  float __cdecl DistanceSquared2D(const void*, const void*) { NoRetailImage("DistanceSquared2D"); }
  int __cdecl IsValidVector2f(const void*) { NoRetailImage("IsValidVector2f"); }
  int __cdecl RayBoxSlabClip(void*, const void*) { NoRetailImage("RayBoxSlabClip"); }
  void __cdecl AniPoseBoneRotate(void*, const void*) { NoRetailImage("AniPoseBoneRotate"); }
  void __cdecl FallAxis(float, float, float*) { NoRetailImage("FallAxis"); }
  float __cdecl Atan2DifferenceSite(float, float, float, float) { NoRetailImage("Atan2DifferenceSite"); }
  float __cdecl DiveCurveSpeed(float, float) { NoRetailImage("DiveCurveSpeed"); }
  float __cdecl VelocityLength(const void*) { NoRetailImage("VelocityLength"); }
  int __cdecl TruncateFloatKey(float) { NoRetailImage("TruncateFloatKey"); }
  int __cdecl CeilFloatToInt(float) { NoRetailImage("CeilFloatToInt"); }

  void __cdecl OperatorDelete(void*) { NoRetailImage("OperatorDelete"); }
  void* __cdecl HeightFieldConstruct(void*, int, int) { NoRetailImage("HeightFieldConstruct"); }
  void __cdecl HeightFieldUpdateBounds(void*, int, int, int, int) { NoRetailImage("HeightFieldUpdateBounds"); }
  void* __cdecl HeightFieldIntersection(const void*, const void*, void*, void*) { NoRetailImage("HeightFieldIntersection"); }
  unsigned __cdecl MapOccupancyCaps(const void*, const void*, const void*) { NoRetailImage("MapOccupancyCaps"); }
  unsigned __cdecl OccupyFilter(const void*, const void*, const void*, unsigned) { NoRetailImage("OccupyFilter"); }
  unsigned __cdecl PathFinderIsInBounds(const void*, const void*, const void*, float*) { NoRetailImage("PathFinderIsInBounds"); }
  unsigned __cdecl MapWaterRatio(const void*) { NoRetailImage("MapWaterRatio"); }
  unsigned __cdecl PathFinderShouldSearchRect(const void*, const void*) { NoRetailImage("PathFinderShouldSearchRect"); }
  float __cdecl OctileDistanceCore(float, float) { NoRetailImage("OctileDistanceCore"); }
  void __cdecl LuaComputeSizes(const int*, int, int*, int*) { NoRetailImage("LuaComputeSizes"); }
  void __cdecl AABoxToRect(const void*, void*) { NoRetailImage("AABoxToRect"); }
  void __cdecl CoordsToWorldPos(const void*, const void*, void*, unsigned, int, int) { NoRetailImage("CoordsToWorldPos"); }
  unsigned __cdecl IntelGridIsVisibleRect(const void*, const void*) { NoRetailImage("IntelGridIsVisibleRect"); }
  unsigned __cdecl OccupyMobileCheck(const void*, const void*, const void*) { NoRetailImage("OccupyMobileCheck"); }
  unsigned __cdecl OccupyFootprintFits(const void*, const void*, const void*, unsigned) { NoRetailImage("OccupyFootprintFits"); }
  unsigned __cdecl MapIsWithin(const void*, const void*, float, unsigned) { NoRetailImage("MapIsWithin"); }
  unsigned __cdecl MapIsBlockingTerrain(const void*, unsigned, unsigned) { NoRetailImage("MapIsBlockingTerrain"); }
  void __cdecl GridLineInit(void*, int, float, float, float, float) { NoRetailImage("GridLineInit"); }
  void __cdecl GridLineAdvance(void*) { NoRetailImage("GridLineAdvance"); }
  void __cdecl GridLineCell(const void*, void*) { NoRetailImage("GridLineCell"); }
  int __cdecl GridLineBeyondEnd(const void*) { NoRetailImage("GridLineBeyondEnd"); }
  unsigned __cdecl LuaLog2(unsigned) { NoRetailImage("LuaLog2"); }
  unsigned __cdecl LuaInt2Fb(unsigned) { NoRetailImage("LuaInt2Fb"); }
  unsigned __cdecl LuaHGetStr(const void*, const void*) { NoRetailImage("LuaHGetStr"); }
  unsigned __cdecl LuaHGetNum(const void*, int) { NoRetailImage("LuaHGetNum"); }
  unsigned __cdecl LuaHGet(const void*, const void*) { NoRetailImage("LuaHGet"); }
  unsigned __cdecl LuaHMainPosition(const void*, const void*) { NoRetailImage("LuaHMainPosition"); }
  unsigned __cdecl LuaVEqualVal(const void*, const void*, const void*) { NoRetailImage("LuaVEqualVal"); }
  unsigned __cdecl LuaHIndex(const void*, const void*, const void*) { NoRetailImage("LuaHIndex"); }
  unsigned __cdecl LuaHNext(const void*, const void*, void*) { NoRetailImage("LuaHNext"); }
  unsigned __cdecl LuaHSet(const void*, void*, const void*) { NoRetailImage("LuaHSet"); }
  unsigned __cdecl LuaHSetNum(const void*, void*, int) { NoRetailImage("LuaHSetNum"); }
  unsigned __cdecl LuaVLessThan(const void*, const void*, const void*) { NoRetailImage("LuaVLessThan"); }
  unsigned __cdecl LuaAIndex(void*, int) { NoRetailImage("LuaAIndex"); }
  unsigned __cdecl LuaNegIndex(void*, int) { NoRetailImage("LuaNegIndex"); }
  unsigned __cdecl LuaType(void*, int) { NoRetailImage("LuaType"); }
  unsigned __cdecl LuaGetTop(void*) { NoRetailImage("LuaGetTop"); }
  void __cdecl LuaSetTop(void*, int) { NoRetailImage("LuaSetTop"); }
  void __cdecl LuaPushValue(void*, int) { NoRetailImage("LuaPushValue"); }
  float __cdecl LuaToNumber(void*, int) { NoRetailImage("LuaToNumber"); }
  void __cdecl LuaRawGetI(void*, int, int) { NoRetailImage("LuaRawGetI"); }
  void __cdecl LuaPushNumber(void*, float) { NoRetailImage("LuaPushNumber"); }
  unsigned __cdecl LuaNextApi(void*, int) { NoRetailImage("LuaNextApi"); }
  unsigned __cdecl LuaTGetTm(void*, int, const void*) { NoRetailImage("LuaTGetTm"); }
  unsigned __cdecl LuaVGetTable(void*, const void*, const void*, int) { NoRetailImage("LuaVGetTable"); }
  unsigned __cdecl LuaVIndex(void*, const void*, const void*, int) { NoRetailImage("LuaVIndex"); }
  void __cdecl LuaVSetTable(void*, const void*, void*, void*) { NoRetailImage("LuaVSetTable"); }
  unsigned __cdecl LuaToBoolean(void*, int) { NoRetailImage("LuaToBoolean"); }
  unsigned __cdecl LuaIsNumber(void*, int) { NoRetailImage("LuaIsNumber"); }
  void __cdecl LuaPushNil(void*) { NoRetailImage("LuaPushNil"); }
  void __cdecl LuaPushBoolean(void*, int) { NoRetailImage("LuaPushBoolean"); }
  void __cdecl LuaRawGet(void*, int) { NoRetailImage("LuaRawGet"); }
  void __cdecl LuaRawSetI(void*, int, int) { NoRetailImage("LuaRawSetI"); }
  void __cdecl LuaRawSet(void*, int) { NoRetailImage("LuaRawSet"); }
  void __cdecl VecLookAt(const void*, const void*, void*) { NoRetailImage("VecLookAt"); }
  void __cdecl VecMul4x3(const void*, void*, const void*) { NoRetailImage("VecMul4x3"); }
  unsigned __cdecl InfluenceGetThreatBits(const void*, int, int) { NoRetailImage("InfluenceGetThreatBits"); }
  void __cdecl InfluenceDecay(void*) { NoRetailImage("InfluenceDecay"); }
  void* __cdecl HeightFieldTierBounds(const void*, int, int, int, void*) { NoRetailImage("HeightFieldTierBounds"); }
  int __cdecl HeightFieldClipSegment(const void*, const void*, const void*, void*, void*) { NoRetailImage("HeightFieldClipSegment"); }
  void* __cdecl HeightFieldNormal(const void*, float, float, void*) { NoRetailImage("HeightFieldNormal"); }
  void __cdecl BitArrayConstruct(void*, unsigned, unsigned) { NoRetailImage("BitArrayConstruct"); }
  void __cdecl BitArrayFillRect(void*, int, int, int, int, int) { NoRetailImage("BitArrayFillRect"); }
  int __cdecl BitArrayGetRectOr(const void*, int, int, int, int, int) { NoRetailImage("BitArrayGetRectOr"); }
  int __cdecl BitArrayGetRectNeg(const void*, const void*) { NoRetailImage("BitArrayGetRectNeg"); }
} // namespace retail
