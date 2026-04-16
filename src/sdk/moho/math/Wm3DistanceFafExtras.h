#pragma once
// FAF SDK distance/intersection helpers — recovered from the FA binary as
// free function wrappers around upstream Wm3 distance/intersection classes.
// These are NOT in upstream Wm3, but they are recovered FA functions
// (FA addresses preserved in the per-helper Doxygen blocks).
//
// Lives outside dependencies/WildMagic3p8/ because they're FAF SDK glue, not
// Wild Magic library code. Used to live at src/sdk/wm3/Distance3.h.
#include "Wm3Box3.h"
#include "Wm3Box2.h"
#include "Wm3Line3.h"
#include "Wm3Segment3.h"
#include "Wm3Sphere3.h"
#include "Wm3TInteger.h"
#include "Wm3TRational.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

#include <cstddef>
#include <cstdint>

namespace Wm3
{
  /**
   * Address: 0x00A57240 (FUN_00A57240, fn)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackA(void* self) noexcept;

  /**
   * Address: 0x00A57250 (FUN_00A57250, nullsub_10)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackB(void* self) noexcept;

  /**
   * Address: 0x00A766B0 (FUN_00A766B0, nullsub_11)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackC(void* self) noexcept;

  /**
   * Address: 0x00A78870 (FUN_00A78870, Wm3::Query2TIntegerf::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the integer circumcircle query lane
   * in `Query2TIntegerf`.
   */
  [[nodiscard]] TInteger<4> Query2TIntegerfDet3(
    const TInteger<4>& x0,
    const TInteger<4>& y0,
    const TInteger<4>& z0,
    const TInteger<4>& x1,
    const TInteger<4>& y1,
    const TInteger<4>& z1,
    const TInteger<4>& x2,
    const TInteger<4>& y2,
    const TInteger<4>& z2
  );

  /**
   * Address: 0x00A78A20 (FUN_00A78A20, Wm3::Query2TIntegerd::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the integer circumcircle query lane
   * in `Query2TIntegerd`.
   */
  [[nodiscard]] TInteger<4> Query2TIntegerdDet3(
    const TInteger<4>& x0,
    const TInteger<4>& y0,
    const TInteger<4>& z0,
    const TInteger<4>& x1,
    const TInteger<4>& y1,
    const TInteger<4>& z1,
    const TInteger<4>& x2,
    const TInteger<4>& y2,
    const TInteger<4>& z2
  );

  /**
   * Address: 0x00A7B5C0 (FUN_00A7B5C0, Wm3::Query2TRationalf::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the rational circumcircle query lane
   * in `Query2TRationalf`.
   */
  [[nodiscard]] TRational<16> Query2TRationalfDet3(
    const TRational<16>& x0,
    const TRational<16>& y0,
    const TRational<16>& z0,
    const TRational<16>& x1,
    const TRational<16>& y1,
    const TRational<16>& z1,
    const TRational<16>& x2,
    const TRational<16>& y2,
    const TRational<16>& z2
  );

  /**
   * Address: 0x00A7B7B0 (FUN_00A7B7B0, Wm3::Query2TRationald::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the rational circumcircle query lane
   * in `Query2TRationald`.
   */
  [[nodiscard]] TRational<32> Query2TRationaldDet3(
    const TRational<32>& x0,
    const TRational<32>& y0,
    const TRational<32>& z0,
    const TRational<32>& x1,
    const TRational<32>& y1,
    const TRational<32>& z1,
    const TRational<32>& x2,
    const TRational<32>& y2,
    const TRational<32>& z2
  );

  /**
   * Address: 0x00A3AB80 (FUN_00A3AB80)
   *
   * What it does:
   * Writes one double-precision 3D cross product (`lhs x rhs`) into
   * `outCross` and returns that output pointer.
   */
  Vector3<double>* CrossVector3dInto(
    const Vector3<double>& lhs,
    Vector3<double>* outCross,
    const Vector3<double>& rhs
  ) noexcept;

  /**
   * Address: 0x00A45C00 (FUN_00A45C00, Wm3::DistVector3Box3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::GetSquared(Wm3::DistVector3Box3f *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented box and optionally writes closest point on box.
   * This helper exposes the recovered behavior with explicit args.
   */
  float DistVector3Box3fGetSquared(
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A457E0 (FUN_00A457E0, Wm3::DistVector3Box3f::Get)
   *
   * Wm3::Vector3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::Get(Wm3::DistVector3Box3f *this);
   *
   * What it does:
   * Returns distance from a point to an oriented box.
   */
  float DistVector3Box3fGet(
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A458C0 (FUN_00A458C0, Wm3::DistVector3Box3f::StaticGet)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::StaticGet(Wm3::DistVector3Box3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns point-to-box distance.
   */
  float DistVector3Box3fStaticGet(
    float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A45A60 (FUN_00A45A60, Wm3::DistVector3Box3f::StaticGetSquared)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::StaticGetSquared(Wm3::DistVector3Box3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns squared point-to-box distance.
   */
  float DistVector3Box3fStaticGetSquared(
    float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A460D0 (FUN_00A460D0, Wm3::DistVector3Box3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::GetSquared(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented double-precision box and optionally writes closest point.
   */
  double DistVector3Box3dGetSquared(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A45800 (FUN_00A45800, Wm3::DistVector3Box3d::Get)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::Get(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Returns distance from a point to an oriented double-precision box.
   */
  double DistVector3Box3dGet(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A45E90 (FUN_00A45E90, Wm3::DistVector3Box3d::StaticGet)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Box3<double> const&, Wm3::Vector3<double> const&, Wm3::Vector3<double>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::StaticGet(Wm3::DistVector3Box3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns point-to-box distance.
   */
  double DistVector3Box3dStaticGet(
    double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A45FB0 (FUN_00A45FB0, Wm3::DistVector3Box3d::StaticGetSquared)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Box3<double> const&, Wm3::Vector3<double> const&, Wm3::Vector3<double>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::StaticGetSquared(Wm3::DistVector3Box3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns squared point-to-box distance.
   */
  double DistVector3Box3dStaticGetSquared(
    double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A6CB50 (FUN_00A6CB50, Wm3::DistVector2Box2d::StaticGet)
   *
   * double, Wm3::Vector2<double> const&, Wm3::Box2<double> const&, Wm3::Vector2<double> const&,
   * Wm3::Vector2<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector2Box2d::StaticGet(Wm3::DistVector2Box2d *this, double t,
   * Wm3::Vector2d *velocity0, Wm3::Vector2d *velocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` and returns point-to-box distance.
   */
  double DistVector2Box2dStaticGet(
    double t,
    const Vector2<double>& vector,
    const Box2<double>& box,
    const Vector2<double>& vectorVelocity,
    const Vector2<double>& boxVelocity,
    Vector2<double>* closestPointOnBox = nullptr
  ) noexcept;

  /**
   * Address: 0x00A6CC60 (FUN_00A6CC60, Wm3::DistVector2Box2d::StaticGetSquared)
   *
   * double, Wm3::Vector2<double> const&, Wm3::Box2<double> const&, Wm3::Vector2<double> const&,
   * Wm3::Vector2<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector2Box2d::StaticGetSquared(Wm3::DistVector2Box2d *this, double t,
   * Wm3::Vector2d *velocity0, Wm3::Vector2d *velocity1);
   *
   * What it does:
   * Moves the point and box forward by time `t`, then returns the squared distance from the moved point to the moved
   * oriented box.
   */
  double DistVector2Box2dStaticGetSquared(
    double t,
    const Vector2<double>& vector,
    const Box2<double>& box,
    const Vector2<double>& vectorVelocity,
    const Vector2<double>& boxVelocity,
    Vector2<double>* closestPointOnBox = nullptr
  ) noexcept;

  struct BestCandidate2DStateDouble
  {
    double pointX;                // +0x00
    double pointY;                // +0x08
    double axisAX;                // +0x10
    double axisAY;                // +0x18
    double axisBX;                // +0x20
    double axisBY;                // +0x28
    double axisAProjectionHalf;   // +0x30
    double axisBProjectionHalf;   // +0x38
  };
  static_assert(sizeof(BestCandidate2DStateDouble) == 0x40, "BestCandidate2DStateDouble size must be 0x40");
  static_assert(offsetof(BestCandidate2DStateDouble, pointX) == 0x00, "BestCandidate2DStateDouble::pointX offset must be 0x00");
  static_assert(offsetof(BestCandidate2DStateDouble, pointY) == 0x08, "BestCandidate2DStateDouble::pointY offset must be 0x08");
  static_assert(offsetof(BestCandidate2DStateDouble, axisAX) == 0x10, "BestCandidate2DStateDouble::axisAX offset must be 0x10");
  static_assert(offsetof(BestCandidate2DStateDouble, axisAY) == 0x18, "BestCandidate2DStateDouble::axisAY offset must be 0x18");
  static_assert(offsetof(BestCandidate2DStateDouble, axisBX) == 0x20, "BestCandidate2DStateDouble::axisBX offset must be 0x20");
  static_assert(offsetof(BestCandidate2DStateDouble, axisBY) == 0x28, "BestCandidate2DStateDouble::axisBY offset must be 0x28");
  static_assert(
    offsetof(BestCandidate2DStateDouble, axisAProjectionHalf) == 0x30,
    "BestCandidate2DStateDouble::axisAProjectionHalf offset must be 0x30"
  );
  static_assert(
    offsetof(BestCandidate2DStateDouble, axisBProjectionHalf) == 0x38,
    "BestCandidate2DStateDouble::axisBProjectionHalf offset must be 0x38"
  );

  /**
   * Address: 0x00A68500 (FUN_00A68500)
   *
   * What it does:
   * Projects one edge and one probe delta onto two axes, then updates the
   * best-candidate state when the projection product metric improves.
   */
  void UpdateBestCandidate2DByProjectionMetric(
    const Vector2<double>& probePoint,
    BestCandidate2DStateDouble* bestCandidate,
    const Vector2<double>& axisB,
    const Vector2<double>& axisA,
    const Vector2<double>& segmentStart,
    const Vector2<double>& segmentEnd,
    const Vector2<double>& referencePoint,
    double* bestMetric
  ) noexcept;

  /**
   * Address: 0x00A685F0 (FUN_00A685F0)
   *
   * What it does:
   * Builds one axis-aligned `Box2<float>` from a packed 2D point array, with
   * optional byte-mask filtering.
   */
  Box2<float>* BuildAxisAlignedBox2fFromPointArray(
    Box2<float>* outBox,
    int pointCount,
    const Vector2<float>* points,
    const std::uint8_t* activeMask = nullptr
  ) noexcept;

  /**
   * Address: 0x00A694F0 (FUN_00A694F0)
   *
   * What it does:
   * Builds one axis-aligned `Box2<double>` from a packed 2D point array, with
   * optional byte-mask filtering.
   */
  Box2<double>* BuildAxisAlignedBox2dFromPointArray(
    Box2<double>* outBox,
    int pointCount,
    const Vector2<double>* points,
    const std::uint8_t* activeMask = nullptr
  ) noexcept;

  /**
   * Address: 0x00A4D9F0 (FUN_00A4D9F0)
   *
   * What it does:
   * Builds one `Sphere3<double>` from min/max bounds of a packed 3D point
   * array, with optional byte-mask filtering.
   */
  Sphere3<double>* BuildBoundingSphere3dFromPointArray(
    Sphere3<double>* outSphere,
    int pointCount,
    const Vector3<double>* points,
    const std::uint8_t* activeMask = nullptr
  ) noexcept;

  /**
   * Address: 0x00A484F0 (FUN_00A484F0, Wm3::DistVector3Segment3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Segment3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::GetSquared(Wm3::DistVector3Segment3f *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and optionally writes closest point on segment.
   */
  float DistVector3Segment3fGetSquared(
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A480E0 (FUN_00A480E0, Wm3::DistVector3Segment3f::Get)
   *
   * Wm3::Vector3<float> const&, Wm3::Segment3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::Get(Wm3::DistVector3Segment3f *this);
   *
   * What it does:
   * Returns distance from a point to a segment.
   */
  float DistVector3Segment3fGet(
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A48190 (FUN_00A48190, Wm3::DistVector3Segment3f::StaticGet)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Segment3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::StaticGet(Wm3::DistVector3Segment3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns point-to-segment distance.
   */
  float DistVector3Segment3fStaticGet(
    float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A48340 (FUN_00A48340, Wm3::DistVector3Segment3f::StaticGetSquared)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Segment3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::StaticGetSquared(Wm3::DistVector3Segment3f *this, float fT,
   * Wm3::Vector3f *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns squared point-to-segment
   * distance.
   */
  float DistVector3Segment3fStaticGetSquared(
    float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A48910 (FUN_00A48910, Wm3::DistVector3Segment3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::GetSquared(Wm3::DistVector3Segment3d *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and optionally writes closest point on segment.
   */
  double DistVector3Segment3dGetSquared(
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A48100 (FUN_00A48100, Wm3::DistVector3Segment3d::Get)
   *
   * Wm3::Vector3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::Get(Wm3::DistVector3Segment3d *this);
   *
   * What it does:
   * Returns distance from a point to a segment.
   */
  double DistVector3Segment3dGet(
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A486B0 (FUN_00A486B0, Wm3::DistVector3Segment3d::StaticGet)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::StaticGet(Wm3::DistVector3Segment3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns point-to-segment distance.
   */
  double DistVector3Segment3dStaticGet(
    double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A487E0 (FUN_00A487E0, Wm3::DistVector3Segment3d::StaticGetSquared)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::StaticGetSquared(Wm3::DistVector3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns squared point-to-segment
   * distance.
   */
  double DistVector3Segment3dStaticGetSquared(
    double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A81330 (FUN_00A81330, Wm3::DistLine3Segment3d::GetSquared)
   *
   * Wm3::Line3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * long double __thiscall Wm3::DistLine3Segment3d::GetSquared(Wm3::DistLine3Segment3d *this);
   *
   * What it does:
   * Computes squared distance between an infinite line and a bounded segment,
   * and optionally emits closest points on both primitives.
   */
  double DistLine3Segment3dGetSquared(
    const Line3<double>& line,
    const Segment3<double>& segment,
    Vector3<double>* closestPointOnLine = nullptr,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A809C0 (FUN_00A809C0, Wm3::DistLine3Segment3d::Get)
   *
   * Wm3::Line3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::Get(Wm3::DistLine3Segment3d *this);
   *
   * What it does:
   * Returns distance between an infinite line and a bounded segment.
   */
  double DistLine3Segment3dGet(
    const Line3<double>& line,
    const Segment3<double>& segment,
    Vector3<double>* closestPointOnLine = nullptr,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A810B0 (FUN_00A810B0, Wm3::DistLine3Segment3d::StaticGet)
   *
   * double, Wm3::Line3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::StaticGet(Wm3::DistLine3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves line and segment origins by time `t` and returns line-to-segment distance.
   */
  double DistLine3Segment3dStaticGet(
    double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* closestPointOnLine = nullptr,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A811F0 (FUN_00A811F0, Wm3::DistLine3Segment3d::StaticGetSquared)
   *
   * double, Wm3::Line3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::StaticGetSquared(Wm3::DistLine3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves line and segment origins by time `t` and returns squared line-to-segment distance.
   */
  double DistLine3Segment3dStaticGetSquared(
    double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* closestPointOnLine = nullptr,
    Vector3<double>* closestPointOnSegment = nullptr
  ) noexcept;

  /**
   * Address: 0x00A41560 (FUN_00A41560, Wm3::IntrBox3Sphere3f::Test)
   *
   * Wm3::Box3<float> const&, Wm3::Sphere3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrBox3Sphere3f::Test(Wm3::IntrBox3Sphere3f *this);
   *
   * What it does:
   * Tests static overlap between oriented box and sphere.
   */
  bool IntrBox3Sphere3fTest(const Box3<float>& box, const Sphere3<float>& sphere) noexcept;

  /**
   * Address: 0x00A43420 (FUN_00A43420, Wm3::IntrBox3Sphere3f::StaticFind)
   *
   * float, Wm3::Box3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&,
   * float*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * char __thiscall Wm3::IntrBox3Sphere3f::StaticFind(Wm3::IntrBox3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Sweeps the sphere against the box for relative motion up to `tMax`, producing first-contact time
   * and point when found.
   */
  bool IntrBox3Sphere3fStaticFind(
    float tMax,
    const Box3<float>& box,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* contactTime,
    Vector3<float>* contactPoint,
    int* intrType
  ) noexcept;

  /**
   * Address: 0x00A41740 (FUN_00A41740, Wm3::IntrBox3Sphere3f::GetVertexIntersection)
   *
   * float, float, float, float, float, float, float
   *
   * IDA signature:
   * double __cdecl Wm3::IntrBox3Sphere3f::GetVertexIntersection(float a1, float a2, float a3, float a4, float a5, float
   * a6, float a7);
   *
   * What it does:
   * Solves contact-time root for a vertex-region sweep test against sphere radius.
   */
  float IntrBox3Sphere3fGetVertexIntersection(
    float a1, float a2, float a3, float a4, float a5, float a6, float a7
  ) noexcept;

  /**
   * Address: 0x00A41800 (FUN_00A41800, Wm3::IntrBox3Sphere3f::GetEdgeIntersection)
   *
   * float, float, float, float, float, float
   *
   * IDA signature:
   * double __cdecl Wm3::IntrBox3Sphere3f::GetEdgeIntersection(float a1, float a2, float a3, float a4, float a5, float
   * a6);
   *
   * What it does:
   * Solves contact-time root for an edge-region sweep test against sphere radius.
   */
  float IntrBox3Sphere3fGetEdgeIntersection(float a1, float a2, float a3, float a4, float a5, float a6) noexcept;

  /**
   * Address: 0x00A41F50 (FUN_00A41F50, Wm3::IntrBox3Sphere3f::FindEdgeRegionIntersection)
   *
   * float, float, float, float, float, float, float, float, float, float*, float*, float*, bool
   *
   * IDA signature:
   * int __thiscall Wm3::IntrBox3Sphere3f::FindEdgeRegionIntersection(int this, float a2, float a3, float a4, float a5,
   * float a6, float a7, float a8, float a9, float a10, int a11, int a12, int a13, float a14);
   *
   * What it does:
   * Handles edge-region sweep logic and writes local contact coordinates when a candidate is found.
   * Return codes match binary convention: -1 immediate overlap, 0 no hit, 1 hit.
   */
  int IntrBox3Sphere3fFindEdgeRegionIntersection(
    float sphereRadius,
    float a2,
    float a3,
    float a4,
    float a5,
    float a6,
    float a7,
    float a8,
    float a9,
    float a10,
    float* a11,
    float* a12,
    float* a13,
    bool a14,
    float* contactTime = nullptr
  ) noexcept;

  /**
   * Address: 0x00A421E0 (FUN_00A421E0, Wm3::IntrBox3Sphere3f::FindVertexRegionIntersection)
   *
   * float, float, float, float, float, float, float, float, float, float*, float*, float*
   *
   * IDA signature:
   * int __thiscall sub_A421E0(int this, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float a9,
   * float a10, float *a11, float *a12, float *a13);
   *
   * What it does:
   * Handles vertex-region sweep logic and may recurse into edge-region helper paths.
   * Return codes match binary convention: -1 immediate overlap, 0 no hit, 1 hit.
   */
  int IntrBox3Sphere3fFindVertexRegionIntersection(
    float sphereRadius,
    float a2,
    float a3,
    float a4,
    float a5,
    float a6,
    float a7,
    float a8,
    float a9,
    float a10,
    float* a11,
    float* a12,
    float* a13,
    float* contactTime = nullptr
  ) noexcept;

  /**
   * Address: 0x00A46440 (FUN_00A46440, Wm3::IntrSegment3Box3f::Test)
   *
   * Wm3::Segment3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Box3f::Test(Wm3::IntrSegment3Box3f *this);
   *
   * What it does:
   * Runs SAT overlap test between segment and oriented box.
   */
  bool IntrSegment3Box3fTest(const Segment3<float>& segment, const Box3<float>& box) noexcept;

  /**
   * Address: 0x00A46C80 (FUN_00A46C80, Wm3::IntrSegment3Sphere3f::Test)
   *
   * Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Sphere3f::Test(Wm3::IntrSegment3Sphere3f *this);
   *
   * What it does:
   * Tests static overlap between a segment and sphere without emitting contact points.
   */
  bool IntrSegment3Sphere3fTest(const Segment3<float>& segment, const Sphere3<float>& sphere) noexcept;

  /**
   * Address: 0x00A4FE60 (FUN_00A4FE60, Wm3::IntrLine3Box3f::Test)
   *
   * Wm3::Line3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrLine3Box3f::Test(Wm3::IntrLine3Box3f *this);
   *
   * What it does:
   * Runs SAT cross-axis checks for infinite line vs oriented box overlap.
   */
  bool IntrLine3Box3fTest(const Line3<float>& line, const Box3<float>& box) noexcept;

  /**
   * Address: 0x00A4FCC0 (FUN_00A4FCC0, Wm3::IntrLine3Box3f::Clip)
   *
   * float, float, float*, float*
   *
   * IDA signature:
   * bool __cdecl Wm3::IntrLine3Box3f::Clip(float fDenom, float fNumer, float *rfT0, float *rfT1);
   *
   * What it does:
   * Clips one parametric slab constraint and tightens [`t0`,`t1`] when possible.
   */
  bool IntrLine3Box3fClip(float denom, float numer, float* t0, float* t1) noexcept;

  /**
   * Address: 0x00A50220 (FUN_00A50220, Wm3::IntrLine3Box3f::DoClipping)
   *
   * float, float, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, bool, int*,
   * Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * BOOL __cdecl Wm3::IntrLine3Box3f::DoClipping(float fT0, float fT1, Wm3::Vector3f *rkOrigin, Wm3::Vector3f
   * *rkDirection, const Wm3::Box3f *rkBox, char bSolid, int *riQuantity, Wm3::Vector3f *akPoint, int *riIntrType);
   *
   * What it does:
   * Clips a line interval against an oriented box and emits 0/1/2 intersection points plus type.
   */
  bool IntrLine3Box3fDoClipping(
    float t0,
    float t1,
    const Vector3<float>& origin,
    const Vector3<float>& direction,
    const Box3<float>& box,
    bool solid,
    int* quantity,
    Vector3<float>* points,
    int* intrType
  ) noexcept;

  /**
   * Address: 0x00A508F0 (FUN_00A508F0, Wm3::IntrLine3Box3f::Find)
   *
   * Wm3::Line3<float> const&, Wm3::Box3<float> const&, int*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * BOOL __thiscall Wm3::IntrLine3Box3f::Find(Wm3::IntrLine3Box3f *this);
   *
   * What it does:
   * Wrapper over `DoClipping` that uses full line interval [`-FLT_MAX`, `+FLT_MAX`] and `bSolid=true`.
   */
  bool IntrLine3Box3fFind(
    const Line3<float>& line, const Box3<float>& box, int* quantity, Vector3<float>* points, int* intrType
  ) noexcept;

  /**
   * Address: 0x00A462A0 (FUN_00A462A0, Wm3::IntrSegment3Box3f::Find)
   *
   * Wm3::Segment3<float> const&, Wm3::Box3<float> const&, bool, int*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Box3f::Find(Wm3::IntrSegment3Box3f *this);
   *
   * What it does:
   * Thin wrapper over `DoClipping` that clips `t` in [`-Extent`, `+Extent`] for segment-vs-box queries.
   */
  bool IntrSegment3Box3fFind(
    const Segment3<float>& segment,
    const Box3<float>& box,
    bool solid,
    int* quantity,
    Vector3<float>* points,
    int* intrType
  ) noexcept;

  /**
   * Address: 0x00A471C0 (FUN_00A471C0, Wm3::IntrSegment3Sphere3f::Find)
   *
   * Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, int*, Wm3::Vector3<float>*, float*, float
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Sphere3f::Find(Wm3::IntrSegment3Sphere3f *this);
   *
   * What it does:
   * Finds 0/1/2 static intersection points between a segment and sphere using the recovered threshold branch logic.
   */
  bool IntrSegment3Sphere3fFind(
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    int* quantity,
    Vector3<float>* points,
    float* segmentT,
    float zeroThreshold = 0.000001f
  ) noexcept;

  /**
   * Address: 0x00A46B10 (FUN_00A46B10, Wm3::IntrSegment3Sphere3f::StaticTest)
   *
   * float, Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * char __thiscall Wm3::IntrSegment3Sphere3f::StaticTest(Wm3::IntrSegment3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Dynamic overlap test path: first checks static segment-sphere overlap, then tests the relative sweep as
   * segment-vs-capsule.
   */
  bool IntrSegment3Sphere3fStaticTest(
    float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1
  ) noexcept;

  /**
   * Address: 0x00A46DB0 (FUN_00A46DB0, Wm3::IntrSegment3Sphere3f::StaticFind)
   *
   * float, Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&, float*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * char __thiscall Wm3::IntrSegment3Sphere3f::StaticFind(Wm3::IntrSegment3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Dynamic find path: resolves first relative sweep hit and computes contact point on the moving segment.
   */
  bool IntrSegment3Sphere3fStaticFind(
    float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* contactTime,
    Vector3<float>* contactPoint,
    int* intrType
  ) noexcept;
} // namespace Wm3
