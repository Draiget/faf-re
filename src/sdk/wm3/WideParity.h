#pragma once

#include "Box3.h"
#include "Capsule3.h"
#include "Line3.h"
#include "Segment3.h"
#include "Sphere3.h"
#include "Vector2.h"
#include "Vector3.h"

namespace Wm3
{
  // Declaration-only scaffolding for wider WildMagic parity.
  // Behavior recovery for these families is tracked in decomp/recovery/reports.

  template <class T, class TVector> class Distance;

  template <class T, class TVector> class Intersector;

  class Query;

  template <class T> class Query2;

  template <class T> class Query2Int64;

  template <class T> class Query2TInteger;

  template <class T> class Query2TRational;

  template <class T> class Query3;

  template <class T> class Query3Int64;

  template <class T> class Query3TInteger;

  template <class T> class Query3TRational;

  template <class T> class ConvexHull;

  template <class T> class ConvexHull1;

  template <class T> class ConvexHull2;

  template <class T> class ConvexHull3;

  template <class T> class DistVector2Box2;

  template <class T> class DistVector3Box3;

  template <class T> class DistVector3Segment3;

  template <class T> class DistSegment3Segment3;

  template <class T> class DistLine3Segment3;

  template <class T> class IntrBox2Box2;

  template <class T> class IntrBox2Circle2;

  template <class T> class IntrBox3Sphere3;

  template <class T> class IntrLine3Box3;

  template <class T> class IntrLine3Capsule3;

  template <class T> class IntrSegment3Box3;

  template <class T> class IntrSegment3Capsule3;

  template <class T> class IntrSegment3Sphere3;

  using Query2f = Query2<float>;
  using Query2d = Query2<double>;
  using Query2Int64f = Query2Int64<float>;
  using Query2Int64d = Query2Int64<double>;
  using Query2TIntegerf = Query2TInteger<float>;
  using Query2TIntegerd = Query2TInteger<double>;
  using Query2TRationalf = Query2TRational<float>;
  using Query2TRationald = Query2TRational<double>;

  using Query3f = Query3<float>;
  using Query3d = Query3<double>;
  using Query3Int64f = Query3Int64<float>;
  using Query3Int64d = Query3Int64<double>;
  using Query3TIntegerf = Query3TInteger<float>;
  using Query3TIntegerd = Query3TInteger<double>;
  using Query3TRationalf = Query3TRational<float>;
  using Query3TRationald = Query3TRational<double>;

  using ConvexHull1f = ConvexHull1<float>;
  using ConvexHull1d = ConvexHull1<double>;
  using ConvexHull2f = ConvexHull2<float>;
  using ConvexHull2d = ConvexHull2<double>;
  using ConvexHull3f = ConvexHull3<float>;
  using ConvexHull3d = ConvexHull3<double>;

  using DistVector2Box2f = DistVector2Box2<float>;
  using DistVector2Box2d = DistVector2Box2<double>;
  using DistVector3Box3f = DistVector3Box3<float>;
  using DistVector3Box3d = DistVector3Box3<double>;
  using DistVector3Segment3f = DistVector3Segment3<float>;
  using DistVector3Segment3d = DistVector3Segment3<double>;
  using DistSegment3Segment3f = DistSegment3Segment3<float>;
  using DistSegment3Segment3d = DistSegment3Segment3<double>;
  using DistLine3Segment3f = DistLine3Segment3<float>;
  using DistLine3Segment3d = DistLine3Segment3<double>;

  using IntrBox2Box2f = IntrBox2Box2<float>;
  using IntrBox2Box2d = IntrBox2Box2<double>;
  using IntrBox2Circle2f = IntrBox2Circle2<float>;
  using IntrBox2Circle2d = IntrBox2Circle2<double>;
  using IntrBox3Sphere3f = IntrBox3Sphere3<float>;
  using IntrBox3Sphere3d = IntrBox3Sphere3<double>;
  using IntrLine3Box3f = IntrLine3Box3<float>;
  using IntrLine3Box3d = IntrLine3Box3<double>;
  using IntrLine3Capsule3f = IntrLine3Capsule3<float>;
  using IntrLine3Capsule3d = IntrLine3Capsule3<double>;
  using IntrSegment3Box3f = IntrSegment3Box3<float>;
  using IntrSegment3Box3d = IntrSegment3Box3<double>;
  using IntrSegment3Capsule3f = IntrSegment3Capsule3<float>;
  using IntrSegment3Capsule3d = IntrSegment3Capsule3<double>;
  using IntrSegment3Sphere3f = IntrSegment3Sphere3<float>;
  using IntrSegment3Sphere3d = IntrSegment3Sphere3<double>;
} // namespace Wm3
