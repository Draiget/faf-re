#include "moho/render/tess/CTesselator.h"

#include <algorithm>
#include <bit>
#include <array>
#include <cstddef>
#include <limits>

#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  extern bool ren_ClipDecals;
  extern int ren_ClipDecalLevel;
  extern float ren_ShoreErrorCoeff;
  extern float ren_maxViewError;
  extern bool ren_ErrorCache;

  namespace
  {
    struct ITesselatorRuntimeView
    {
      void* mVtable = nullptr;
    };
    static_assert(sizeof(ITesselatorRuntimeView) == 0x04, "ITesselatorRuntimeView size must be 0x04");

    class ITesselatorVTableProbe
    {
    public:
      virtual ~ITesselatorVTableProbe() = default;
    };

    [[nodiscard]] void* RecoveredITesselatorVTable() noexcept
    {
      static ITesselatorVTableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }

    void WriteITesselatorVTable(ITesselatorRuntimeView* const object) noexcept
    {
      object->mVtable = RecoveredITesselatorVTable();
    }

    /**
     * Address: 0x0080B9A0 (FUN_0080B9A0)
     *
     * IDA signature:
     * void __thiscall sub_80B9A0(_DWORD *this)
     *
     * What it does:
     * Writes the `ITesselator` base-interface vtable lane in-place.
     */
    [[maybe_unused]] void InitializeITesselatorVTableThiscall(ITesselatorRuntimeView* const object) noexcept
    {
      WriteITesselatorVTable(object);
    }

    /**
     * Address: 0x0080EBA0 (FUN_0080EBA0)
     *
     * IDA signature:
     * _DWORD *__usercall sub_80EBA0@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Alias lane that writes the same `ITesselator` base-interface vtable and
     * returns the same object pointer.
     */
    [[maybe_unused]] ITesselatorRuntimeView* InitializeITesselatorVTableReturnLane(
      ITesselatorRuntimeView* const object
    ) noexcept
    {
      WriteITesselatorVTable(object);
      return object;
    }

    enum IntersectionResult : int
    {
      kSplit = 1,
      kAccept = 2,
      kReject = 3,
    };

    constexpr std::size_t kRectLookupMask = 0x1FFu;
    constexpr std::size_t kRectLimit = 65000u;

    [[nodiscard]] std::size_t LookupIndex(const std::int32_t x, const std::int32_t z) noexcept
    {
      const std::size_t maskedX = static_cast<std::size_t>(x) & kRectLookupMask;
      const std::size_t maskedZ = static_cast<std::size_t>(z) & kRectLookupMask;
      return maskedZ | (maskedX << 9u);
    }

    /**
     * Address: 0x00472340 (FUN_00472340)
     *
     * What it does:
     * Selects one AABB corner from `{Min, Max}` using a three-bit axis mask.
     */
    [[nodiscard]]
    Wm3::Vector3f SelectAabbCornerByMask(const Wm3::AxisAlignedBox3f& bounds, const std::uint32_t axisMask)
    {
      const Wm3::Vector3f* const extrema[2] = {&bounds.Min, &bounds.Max};

      Wm3::Vector3f out{};
      out.x = extrema[(axisMask >> 0u) & 1u]->x;
      out.y = extrema[(axisMask >> 1u) & 1u]->y;
      out.z = extrema[(axisMask >> 2u) & 1u]->z;
      return out;
    }

    [[nodiscard]] int MostSignificantBitIndexOrMinusOne(const std::uint32_t value) noexcept
    {
      if (value == 0u) {
        return -1;
      }
      return static_cast<int>(std::bit_width(value) - 1u);
    }

    [[nodiscard]] int AbsoluteValue(const int value) noexcept
    {
      return (value < 0) ? -value : value;
    }

    [[nodiscard]] int HeightFieldTierCount(const CHeightField& field) noexcept
    {
      if (field.mGrids.begin() == nullptr) {
        return 0;
      }
      return static_cast<int>(field.mGrids.end() - field.mGrids.begin());
    }

    /**
     * Address: 0x0080C5D0 (FUN_0080C5D0, func_Tesselate)
     *
     * What it does:
     * Recursively resolves one query rectangle against one split-work node and
     * returns matching range/min-max lanes for either full-tile coverage or
     * exact tile match.
     */
    [[nodiscard]] bool FindSplitWorkRange(
      const CTesselator& tesselator,
      const std::int32_t nodeIndex,
      const std::int32_t tileX,
      const std::int32_t tileZ,
      const std::int32_t level,
      const std::int32_t queryX,
      const std::int32_t queryZ,
      const std::int32_t querySize,
      std::int32_t* const outRangeStart,
      std::int32_t* const outRangeCount,
      std::int32_t* const outMinValue,
      std::int32_t* const outMaxValue
    )
    {
      if (tesselator.mSplitWorkQueue.start_ == nullptr) {
        return false;
      }

      const CTesselator::SplitWorkNode& node = tesselator.mSplitWorkQueue.start_[nodeIndex];
      const std::int32_t shift = level & 0x1F;
      const std::int32_t tileOriginX = tileX << shift;
      const std::int32_t tileOriginZ = tileZ << shift;
      const std::int32_t tileSpan = 1 << shift;

      if (tileSpan < querySize) {
        if (
          queryX <= tileOriginX && (queryX + querySize) >= (tileOriginX + tileSpan) && queryZ <= tileOriginZ
          && (queryZ + querySize) >= (tileOriginZ + tileSpan)
        ) {
          *outRangeStart = node.rangeStart;
          *outRangeCount = node.rangeCount;
          *outMinValue = node.minValue;
          *outMaxValue = node.maxValue;
          return true;
        }
        return false;
      }

      if (tileSpan == querySize && tileOriginX == queryX && tileOriginZ == queryZ) {
        *outRangeStart = node.rangeStart;
        *outRangeCount = node.rangeCount;
        *outMinValue = node.minValue;
        *outMaxValue = node.maxValue;
        return true;
      }

      if (
        node.childTopLeftIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childTopLeftIndex,
          2 * tileX,
          2 * tileZ,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      if (
        node.childTopRightIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childTopRightIndex,
          2 * tileX + 1,
          2 * tileZ,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      if (
        node.childBottomLeftIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childBottomLeftIndex,
          2 * tileX,
          2 * tileZ + 1,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      ) {
        return true;
      }

      return (
        node.childBottomRightIndex != -1
        && FindSplitWorkRange(
          tesselator,
          node.childBottomRightIndex,
          2 * tileX + 1,
          2 * tileZ + 1,
          level - 1,
          queryX,
          queryZ,
          querySize,
          outRangeStart,
          outRangeCount,
          outMinValue,
          outMaxValue
        )
      );
    }

    /**
     * Address: 0x0080DE80 (FUN_0080DE80, sub_80DE80)
     *
     * IDA signature:
     * void __userpurge sub_80DE80(int a1@<eax>, Moho::CTesselator *a2@<esi>, __int16 *arg0);
     *
     * What it does:
     * Emits the eight-triangle fan that fills one tier-1 quadtree cell's four
     * children directly, instead of recursing `TesselateTile` one level
     * further. Samples a 2(x)x3(z) grid of quantized rect-cache indices
     * anchored at `(x, z)` - each grid point is queried by its own
     * `GetIndexAt` call, including the three points queried twice more for a
     * second sample (`ren_ErrorCache` gates whether `GetIndexAt` reuses a
     * cached rect or appends a fresh one, so the repeat calls are not
     * redundant and must not be collapsed to a single sample).
     */
    void EmitTileSubdivisionFan(CTesselator& tesselator, const std::int32_t x, const std::int32_t z)
    {
      const std::uint16_t p00 = tesselator.GetIndexAt(0, x, z);
      const std::uint16_t p10 = tesselator.GetIndexAt(0, x + 1, z);
      const std::uint16_t p10b = tesselator.GetIndexAt(0, x + 1, z);
      const std::uint16_t p01 = tesselator.GetIndexAt(0, x, z + 1);
      const std::uint16_t p11 = tesselator.GetIndexAt(0, x + 1, z + 1);
      const std::uint16_t p11b = tesselator.GetIndexAt(0, x + 1, z + 1);
      const std::uint16_t p02 = tesselator.GetIndexAt(0, x, z + 2);
      const std::uint16_t p12 = tesselator.GetIndexAt(0, x + 1, z + 2);
      const std::uint16_t p12b = tesselator.GetIndexAt(0, x + 1, z + 2);

      tesselator.AppendCollisionTriangleIndices(p00, p10, p11);
      tesselator.AppendCollisionTriangleIndices(p00, p11, p01);
      tesselator.AppendCollisionTriangleIndices(p10, p10b, p11b);
      tesselator.AppendCollisionTriangleIndices(p10, p11b, p11);
      tesselator.AppendCollisionTriangleIndices(p01, p11, p12);
      tesselator.AppendCollisionTriangleIndices(p01, p12, p02);
      tesselator.AppendCollisionTriangleIndices(p11, p11b, p12b);
      tesselator.AppendCollisionTriangleIndices(p11, p12b, p12);
    }

    // Tighter than AddRect's own 65000-entry cap: leaves headroom so a skirt
    // pass never itself pushes the cache to the hard limit mid-tile.
    constexpr std::uint32_t kSkirtRectCountLimit = 0xFDE8u;

    /**
     * Address: 0x0080D130 (FUN_0080D130, sub_80D130)
     *
     * IDA signature:
     * void __userpurge sub_80D130(
     *   Moho::CTesselator *this@<ecx>, gpg::fastvector_short *a2@<ebx>,
     *   gpg::fastvector_short *a1, int a4, int a5, int a6, int a7);
     *
     * What it does:
     * Builds one "skirt" rect per index in `sourceIndices`: same (x, z) as the
     * sampled rect-cache entry, height clamped to the tessellator's cached
     * minimum terrain height (`mMinY`, quantized the same way `GetIndexAt`
     * quantizes a sampled height). Pushed directly onto `mRectCache` without
     * going through `AddRect` - skirt copies must never populate the spatial
     * lookup (`mLookup`), or a later `GetData` query at that (x, z) could
     * return the skirt's dropped-height copy instead of the real surface
     * vertex. `a4..a7` are received but never read by the shipped body.
     */
    void AppendSkirtSampleRects(
      CTesselator& tesselator,
      const gpg::core::FastVectorN<std::uint16_t, 25>& sourceIndices,
      gpg::core::FastVectorN<std::uint16_t, 25>& outSkirtIndices
    )
    {
      const auto skirtHeight = static_cast<std::uint16_t>(tesselator.mMinY * 128.0f);

      for (std::size_t i = 0; i < sourceIndices.Size(); ++i) {
        const CTesselator::Rect16& sourceRect = tesselator.GetRectCacheData()[sourceIndices[i]];

        if (tesselator.GetRectCacheCount() < static_cast<std::int32_t>(kSkirtRectCountLimit)) {
          CTesselator::Rect16 skirtRect{};
          skirtRect.xPos = sourceRect.xPos;
          skirtRect.xSize = skirtHeight;
          skirtRect.zPos = sourceRect.zPos;
          skirtRect.zSize = sourceRect.zSize;
          tesselator.mRectCache.PushBack(skirtRect);
        }

        outSkirtIndices.PushBack(static_cast<std::uint16_t>(tesselator.GetRectCacheCount() - 1));
      }
    }

    /**
     * Address: 0x0080D8B0 (FUN_0080D8B0, sub_80D8B0)
     *
     * What it does:
     * Quantizes one world-space clip-polygon corner into a `Rect16`, rounding
     * every lane up (`ceil`, not the truncating quantization `AddRect`'s
     * other callers use) - confirmed via the `frndint` + "value greater than
     * rounded" correction idiom at `0x0080D8B8-0x0080D8D7` (and twice more for
     * the y/z lanes), which is `ceil` computed through the x87 round-to-
     * nearest instruction, not `floor`. `zSize` is always written `1`
     * (`0x0080D935`), matching the same convention `EmitCollisionQuad` uses.
     * The corner's y lane is consumed as whatever scale `mClipPolygonScratch`
     * already carries it in (see `ClipDecalTrianglesInRect`) - this function
     * does no additional height scaling of its own.
     */
    [[nodiscard]] CTesselator::Rect16 QuantizeClipCornerToRect(const Wm3::Vector3f& corner) noexcept
    {
      CTesselator::Rect16 rect{};
      rect.xPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(std::ceil(corner.x)));
      rect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(std::ceil(corner.y)));
      rect.zPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(std::ceil(corner.z)));
      rect.zSize = 1u;
      return rect;
    }

    /**
     * Address: 0x0080D610 (FUN_0080D610, sub_80D610)
     *
     * What it does:
     * Standard Sutherland-Hodgman single-edge clip of segment
     * `pointA -> pointB` against `plane` (inside iff
     * `dot(point, plane.dir) - plane.dist < 0`): both inside appends
     * `pointB` verbatim; A inside/B outside appends the plane-intersection
     * point only; A outside/B inside appends the intersection point then
     * `pointB`; both outside appends nothing. The intersection is computed
     * by building an unbounded parametric line (`pos=pointA`,
     * `dir=normalize(pointB-pointA)`, `closest=-inf`, `farthest=+inf`) and
     * calling `moho::PlaneIntersection`.
     *
     * The binary encodes this via two branches that each re-test a sign
     * already fixed by the outer branch (dead code, confirmed unreachable on
     * every path by tracing both predecessor sets); this recovery implements
     * the equivalent 4-way form directly rather than reproducing the dead
     * re-tests.
     */
    void ClipEdgeAgainstPlane(
      const Wm3::Vector3f& pointA,
      const Wm3::Vector3f& pointB,
      const moho::VecDist& plane,
      gpg::core::FastVectorN<Wm3::Vector3f, 6>& output
    )
    {
      const auto signedDistance = [&plane](const Wm3::Vector3f& p) noexcept {
        return (p.x * plane.dir.x) + (p.y * plane.dir.y) + (p.z * plane.dir.z) - plane.dist;
      };

      const bool insideA = signedDistance(pointA) < 0.0f;
      const bool insideB = signedDistance(pointB) < 0.0f;

      const auto intersect = [&]() {
        moho::GeomLine3 edge{};
        edge.pos = pointA;
        Wm3::Vector3f dir{pointB.x - pointA.x, pointB.y - pointA.y, pointB.z - pointA.z};
        Wm3::Vector3f::Normalize(dir);
        edge.dir = dir;
        edge.closest = -std::numeric_limits<float>::infinity();
        edge.farthest = std::numeric_limits<float>::infinity();
        return moho::PlaneIntersection(edge, plane, nullptr);
      };

      if (insideA) {
        if (insideB) {
          output.PushBack(pointB);
        } else {
          output.PushBack(intersect());
        }
      } else if (insideB) {
        output.PushBack(intersect());
        output.PushBack(pointB);
      }
    }

    /**
     * Address: 0x0080D530 (FUN_0080D530, sub_80D530)
     *
     * What it does:
     * Clips the closed polygon in `tesselator.mClipPolygonScratch` against
     * one plane: walks every consecutive edge (including the wraparound edge
     * from the last point back to the first) through `ClipEdgeAgainstPlane`,
     * accumulating into a local scratch, then replaces
     * `mClipPolygonScratch`'s contents with that result.
     */
    void ClipPolygonAgainstPlane(CTesselator& tesselator, const moho::VecDist& plane)
    {
      const std::size_t pointCount = tesselator.mClipPolygonScratch.Size();
      if (pointCount == 0u) {
        return;
      }

      gpg::core::FastVectorN<Wm3::Vector3f, 6> clippedPolygon;
      for (std::size_t i = 1; i < pointCount; ++i) {
        ClipEdgeAgainstPlane(
          tesselator.mClipPolygonScratch[i - 1], tesselator.mClipPolygonScratch[i], plane, clippedPolygon
        );
      }
      ClipEdgeAgainstPlane(
        tesselator.mClipPolygonScratch[pointCount - 1], tesselator.mClipPolygonScratch[0], plane, clippedPolygon
      );

      tesselator.mClipPolygonScratch.ResetStorageToInline();
      for (std::size_t i = 0; i < clippedPolygon.Size(); ++i) {
        tesselator.mClipPolygonScratch.PushBack(clippedPolygon[i]);
      }
    }

    /**
     * Address: 0x0080D390 (FUN_0080D390, sub_80D390)
     *
     * What it does:
     * Scans `tesselator.mClipPolygonScratch` and, for each of the 4 axis-
     * aligned edges of the box `[boxXMin, boxXMax+1] x [boxZMin, boxZMax+1]`
     * that at least one point violates, clips the scratch polygon against
     * that edge's plane via `ClipPolygonAgainstPlane`. The `+1` on the max
     * bounds is exactly what the binary computes (`a2+1.0`, `a5+1.0`) -
     * preserved as-is, not "fixed".
     */
    void ClipPolygonAgainstRectEdges(
      CTesselator& tesselator,
      const float boxZMax,
      const float boxXMin,
      const float boxZMin,
      const float boxXMax
    )
    {
      const float zMaxPlusOne = boxZMax + 1.0f;
      const float xMaxPlusOne = boxXMax + 1.0f;

      std::uint8_t violationMask = 0u;
      for (std::size_t i = 0; i < tesselator.mClipPolygonScratch.Size(); ++i) {
        const Wm3::Vector3f& point = tesselator.mClipPolygonScratch[i];
        if (point.z > zMaxPlusOne) {
          violationMask |= 0x1u;
        }
        if (boxZMin > point.z) {
          violationMask |= 0x2u;
        }
        if (point.x > xMaxPlusOne) {
          violationMask |= 0x4u;
        }
        if (boxXMin > point.x) {
          violationMask |= 0x8u;
        }
      }

      if (violationMask == 0u) {
        return;
      }

      if (violationMask & 0x1u) {
        ClipPolygonAgainstPlane(tesselator, moho::VecDist{Wm3::Vector3f{0.0f, 0.0f, 1.0f}, zMaxPlusOne});
      }
      if (violationMask & 0x2u) {
        ClipPolygonAgainstPlane(tesselator, moho::VecDist{Wm3::Vector3f{0.0f, 0.0f, -1.0f}, -boxZMin});
      }
      if (violationMask & 0x4u) {
        ClipPolygonAgainstPlane(tesselator, moho::VecDist{Wm3::Vector3f{1.0f, 0.0f, 0.0f}, xMaxPlusOne});
      }
      if (violationMask & 0x8u) {
        ClipPolygonAgainstPlane(tesselator, moho::VecDist{Wm3::Vector3f{-1.0f, 0.0f, 0.0f}, -boxXMin});
      }
    }

    /**
     * Address: 0x0080D940 (FUN_0080D940, func_renClipDecals)
     *
     * What it does:
     * Walks a range of `indexCountInOut/3` cached triangles (3 uint16
     * indices per triangle in `mCollisionRectLut`, corners looked up in
     * `mRectCache`) starting at `indexRangeStartInOut`. For each triangle
     * whose XZ bounding box overlaps
     * `[queryXMin,queryXMax] x [queryZMin,queryZMax]`, rebuilds its 3 corners
     * as `Vector3f` points in `mClipPolygonScratch` (freeing any heap storage
     * and rebinding to inline first), clips against the rect via
     * `ClipPolygonAgainstRectEdges`, then fan-triangulates whatever points
     * remain: for each consecutive pair of surviving points (from index 1
     * onward), quantizes both points plus the shared first point
     * (`QuantizeClipCornerToRect`) into three new `mRectCache` rects and
     * appends one triangle's worth of indices. Reports
     * `3 * emittedTriangleCount` through `indexCountInOut`.
     */
    void ClipDecalTrianglesInRect(
      std::int32_t& indexRangeStartInOut,
      CTesselator& tesselator,
      const std::int32_t queryXMin,
      const std::int32_t queryZMin,
      const std::int32_t queryXMax,
      const std::int32_t queryZMax,
      std::uint32_t& indexCountInOut
    )
    {
      const std::int32_t initialRangeStart = indexRangeStartInOut;
      indexRangeStartInOut = static_cast<std::int32_t>(tesselator.mCollisionRectLut.Size());

      const std::uint32_t triangleCount = indexCountInOut / 3u;
      std::uint32_t emittedTriangleCount = 0u;
      if (triangleCount == 0u) {
        indexCountInOut = 0u;
        return;
      }

      std::size_t indexBase = static_cast<std::size_t>(initialRangeStart);
      for (std::uint32_t t = 0; t < triangleCount; ++t, indexBase += 3u) {
        const std::uint16_t i0 = tesselator.mCollisionRectLut[indexBase + 0];
        const std::uint16_t i1 = tesselator.mCollisionRectLut[indexBase + 1];
        const std::uint16_t i2 = tesselator.mCollisionRectLut[indexBase + 2];

        const CTesselator::Rect16& c0 = tesselator.GetRectCacheData()[i0];
        const CTesselator::Rect16& c1 = tesselator.GetRectCacheData()[i1];
        const CTesselator::Rect16& c2 = tesselator.GetRectCacheData()[i2];

        const std::uint16_t maxX = std::max({c0.xPos, c1.xPos, c2.xPos});
        if (static_cast<std::int32_t>(maxX) < queryXMin) {
          continue;
        }
        const std::uint16_t minX = std::min({c0.xPos, c1.xPos, c2.xPos});
        if (static_cast<std::int32_t>(minX) > queryXMax) {
          continue;
        }
        const std::uint16_t maxZ = std::max({c0.zPos, c1.zPos, c2.zPos});
        if (static_cast<std::int32_t>(maxZ) < queryZMin) {
          continue;
        }
        const std::uint16_t minZ = std::min({c0.zPos, c1.zPos, c2.zPos});
        if (static_cast<std::int32_t>(minZ) > queryZMax) {
          continue;
        }

        tesselator.mClipPolygonScratch.ResetStorageToInline();
        for (const CTesselator::Rect16* corner : {&c0, &c1, &c2}) {
          tesselator.mClipPolygonScratch.PushBack(
            Wm3::Vector3f{
              static_cast<float>(corner->xPos), static_cast<float>(corner->xSize), static_cast<float>(corner->zPos)
            }
          );
        }

        ClipPolygonAgainstRectEdges(
          tesselator, static_cast<float>(queryZMax), static_cast<float>(queryXMin), static_cast<float>(queryZMin),
          static_cast<float>(queryXMax)
        );

        const std::size_t clippedCount = tesselator.mClipPolygonScratch.Size();
        if (clippedCount <= 2u) {
          continue;
        }

        for (std::size_t v = 1; v < clippedCount - 1u; ++v) {
          const CTesselator::Rect16 rectA = QuantizeClipCornerToRect(tesselator.mClipPolygonScratch[0]);
          const CTesselator::Rect16 rectB = QuantizeClipCornerToRect(tesselator.mClipPolygonScratch[v]);
          const CTesselator::Rect16 rectC = QuantizeClipCornerToRect(tesselator.mClipPolygonScratch[v + 1]);

          // Raw push, not AddRect: clip-generated corners are not grid-
          // aligned, so caching them into mLookup (a grid-indexed cache)
          // would be wrong - same reasoning as AppendSkirtSampleRects.
          tesselator.mRectCache.PushBack(rectA);
          const auto idxA = static_cast<std::uint16_t>(tesselator.mRectCache.Size() - 1);
          tesselator.mRectCache.PushBack(rectB);
          const auto idxB = static_cast<std::uint16_t>(tesselator.mRectCache.Size() - 1);
          tesselator.mRectCache.PushBack(rectC);
          const auto idxC = static_cast<std::uint16_t>(tesselator.mRectCache.Size() - 1);
          tesselator.AppendCollisionTriangleIndices(idxA, idxB, idxC);
          ++emittedTriangleCount;
        }
      }

      indexCountInOut = 3u * emittedTriangleCount;
    }

    /**
     * Address: 0x0080C360 (FUN_0080C360, sub_80C360)
     *
     * What it does:
     * Recursively descends one `mSplitWorkQueue` node, testing its tile
     * bounds against the query rect. Recurses into every populated child
     * slot; a leaf (or a populated node whose children are all empty) either
     * clip-emits its cached triangle range against the rect (when
     * `ren_ClipDecals` is set and `level > ren_ClipDecalLevel`) or copies the
     * cached index range verbatim onto the end of `mCollisionRectLut`,
     * updating the touched `mRectCache` index range in
     * `outMinRectIndex`/`outMaxRectIndex`.
     *
     * The binary threads a pointer to `mCollisionRectLut` through every call
     * as a 10th parameter; the sole caller and all four recursive self-calls
     * always pass the same field, so the recovered form drops that
     * parameter. The binary's `int` return value is never read by its only
     * caller - changed to `void`.
     */
    void CollectSplitWorkRangeInRect(
      CTesselator& tesselator,
      const std::int32_t nodeIndex,
      const std::int32_t tileX,
      const std::int32_t tileZ,
      const std::int32_t level,
      const std::int32_t queryXMin,
      const std::int32_t queryZMin,
      const std::int32_t queryXMax,
      const std::int32_t queryZMax,
      std::int32_t* const outMinRectIndex,
      std::int32_t* const outMaxRectIndex
    )
    {
      const std::int32_t shift = level & 0x1F;
      const std::int32_t tileOriginX = tileX << shift;
      const std::int32_t tileOriginZ = tileZ << shift;
      const std::int32_t tileSpan = 1 << shift;

      const bool overlapsX = queryXMax >= tileOriginX && queryXMin < tileOriginX + tileSpan;
      const bool overlapsZ = queryZMax >= tileOriginZ && queryZMin < tileOriginZ + tileSpan;
      if (!overlapsX || !overlapsZ) {
        return;
      }

      const CTesselator::SplitWorkNode& node = tesselator.mSplitWorkQueue.start_[nodeIndex];
      bool recursedIntoChild = false;

      if (level > 1) {
        if (node.childTopLeftIndex != -1) {
          CollectSplitWorkRangeInRect(
            tesselator, node.childTopLeftIndex, 2 * tileX, 2 * tileZ, level - 1, queryXMin, queryZMin, queryXMax,
            queryZMax, outMinRectIndex, outMaxRectIndex
          );
          recursedIntoChild = true;
        }
        if (node.childTopRightIndex != -1) {
          CollectSplitWorkRangeInRect(
            tesselator, node.childTopRightIndex, (2 * tileX) + 1, 2 * tileZ, level - 1, queryXMin, queryZMin,
            queryXMax, queryZMax, outMinRectIndex, outMaxRectIndex
          );
          recursedIntoChild = true;
        }
        if (node.childBottomLeftIndex != -1) {
          CollectSplitWorkRangeInRect(
            tesselator, node.childBottomLeftIndex, 2 * tileX, (2 * tileZ) + 1, level - 1, queryXMin, queryZMin,
            queryXMax, queryZMax, outMinRectIndex, outMaxRectIndex
          );
          recursedIntoChild = true;
        }
        if (node.childBottomRightIndex != -1) {
          CollectSplitWorkRangeInRect(
            tesselator, node.childBottomRightIndex, (2 * tileX) + 1, (2 * tileZ) + 1, level - 1, queryXMin, queryZMin,
            queryXMax, queryZMax, outMinRectIndex, outMaxRectIndex
          );
          recursedIntoChild = true;
        }
      }

      if (recursedIntoChild) {
        return;
      }

      if (ren_ClipDecals && level > ren_ClipDecalLevel) {
        *outMinRectIndex = std::min(*outMinRectIndex, static_cast<std::int32_t>(tesselator.mRectCache.Size()));

        std::int32_t rangeStart = node.rangeStart;
        std::uint32_t rangeCount = static_cast<std::uint32_t>(node.rangeCount);
        ClipDecalTrianglesInRect(rangeStart, tesselator, queryXMin, queryZMin, queryXMax, queryZMax, rangeCount);

        *outMaxRectIndex = std::max(*outMaxRectIndex, static_cast<std::int32_t>(tesselator.mRectCache.Size()) - 1);
      } else {
        for (std::int32_t i = 0; i < node.rangeCount; ++i) {
          tesselator.mCollisionRectLut.PushBack(tesselator.mCollisionRectLut[node.rangeStart + i]);
        }
        *outMinRectIndex = std::min(*outMinRectIndex, node.minValue);
        *outMaxRectIndex = std::max(*outMaxRectIndex, node.maxValue);
      }
    }
  } // namespace

  /**
   * Address: 0x0080BAA0 (??0CTesselator@Moho@@QAE@@Z)
   * Mangled: ??0CTesselator@Moho@@QAE@@Z
   *
   * What it does:
   * Binds the source heightfield and initializes all inline fastvector
   * storage lanes used by terrain tessellation.
   */
  CTesselator::CTesselator(CHeightField* const field)
    : mField(field)
  {
  }

  /**
   * Address: 0x0080D2E0 (FUN_0080D2E0, Moho::CTesselator::GetHeightScale)
   *
   * What it does:
   * Returns the fixed 1/128 terrain height quantization scale. The shipped body
   * loads the constant 0.0078125 and returns it in st0.
   */
  float CTesselator::GetHeightScale() const
  {
    return 0.0078125F;
  }

  /**
   * Address: 0x0080BCC0 (FUN_0080BCC0, Moho::CTesselator::GetVec1)
   *
   * What it does:
   * Returns the base of the quantized terrain-vertex rect cache.
   *
   *   mov eax, [ecx+90h] ; retn
   */
  CTesselator::Rect16* CTesselator::GetRectCacheData() const
  {
    return const_cast<Rect16*>(mRectCache.data());
  }

  /**
   * Address: 0x0080BCD0 (FUN_0080BCD0, Moho::CTesselator::GetVec2)
   *
   * What it does:
   * Returns the base of the triangle-index lane that indexes the rect cache.
   *
   *   mov eax, [ecx+7EFE0h] ; retn
   */
  std::uint16_t* CTesselator::GetCollisionIndexData() const
  {
    return const_cast<std::uint16_t*>(mCollisionRectLut.data());
  }

  /**
   * Address: 0x0080BCE0 (FUN_0080BCE0, Moho::CTesselator::Size1)
   *
   * What it does:
   * Rect-cache element count. The binary takes the byte span and shifts it
   * right by three, `Rect16` being eight bytes wide.
   *
   *   mov eax, [ecx+94h]; sub eax, [ecx+90h]; sar eax, 3; retn
   */
  std::int32_t CTesselator::GetRectCacheCount() const
  {
    return static_cast<std::int32_t>(mRectCache.size());
  }

  /**
   * Address: 0x0080BCF0 (FUN_0080BCF0, Moho::CTesselator::Size2)
   *
   * What it does:
   * Triangle-index element count; `sar eax, 1` for the 16-bit elements.
   *
   *   mov eax, [ecx+7EFE4h]; sub eax, [ecx+7EFE0h]; sar eax, 1; retn
   */
  std::int32_t CTesselator::GetCollisionIndexCount() const
  {
    return static_cast<std::int32_t>(mCollisionRectLut.size());
  }

  /**
   * Address: 0x0080BD00 (FUN_0080BD00, Moho::CTesselator::GetSize2)
   *
   * What it does:
   * Index at which the terrain skirt's triangle indices begin.
   *
   *   mov eax, [ecx+7F028h] ; retn
   */
  std::int32_t CTesselator::GetSkirtIndexStart() const
  {
    return mSkirtIndexStart;
  }

  /**
   * Address: 0x0080BD10 (FUN_0080BD10, Moho::CTesselator::GetSize1)
   *
   * What it does:
   * Rect-cache index at which the terrain skirt's vertices begin.
   *
   *   mov eax, [ecx+7F02Ch] ; retn
   */
  std::int32_t CTesselator::GetSkirtVertexStart() const
  {
    return mSkirtVertexStart;
  }

  /**
   * Address: 0x0080BB70 (FUN_0080BB70, ??1CTesselator@Moho@@QAE@@Z)
   * Mangled: ??1CTesselator@Moho@@QAE@@Z
   *
   * What it does:
   * Releases heap-backed storage for all FastVectorN lanes and rebinds each
   * lane to inline storage metadata.
   */
  CTesselator::~CTesselator()
  {
    mClipPolygonScratch.ResetStorageToInline();
    mRectIndices.ResetStorageToInline();
    mSplitWorkQueue.ResetStorageToInline();
    mCollisionRectLut.ResetStorageToInline();
    mRectCache.ResetStorageToInline();
    mGeomSolid.planes_.ResetStorageToInline();
  }

  /**
   * Address: 0x0080E020 (FUN_0080E020, Moho::CTesselator::GetIntersectionResult)
   *
   * What it does:
   * Builds one tier-cell AABB, optionally clips it against active frustum
   * planes, then compares tier max error against view-scaled threshold.
   */
  int CTesselator::GetIntersectionResult(
    const int x,
    const int z,
    const int tier,
    std::uint32_t* const activePlaneMask
  )
  {
    const int cellX = x << tier;
    const int cellZ = z << tier;
    if (cellX < 0 || cellZ < 0) {
      return kReject;
    }

    if (cellX >= (mField->width - 1) || cellZ >= (mField->height - 1)) {
      return kReject;
    }

    const Wm3::Vector2f tierBounds = mField->GetTierBounds(x, z, tier);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = static_cast<float>(cellX);
    bounds.Min.y = tierBounds.x;
    bounds.Min.z = static_cast<float>(cellZ);
    bounds.Max.x = static_cast<float>(cellX + (1 << tier));
    bounds.Max.y = tierBounds.y;
    bounds.Max.z = static_cast<float>(cellZ + (1 << tier));

    const float waterElevation = mWaterElevation;
    const bool crossesWaterSurface = (waterElevation >= tierBounds.x) && (tierBounds.y >= waterElevation);

    if (*activePlaneMask != 0u) {
      float clippedMaxY = tierBounds.y;
      if (waterElevation > clippedMaxY) {
        clippedMaxY = waterElevation;
      }
      bounds.Max.y = clippedMaxY;

      if (!mGeomSolid.Intersects(bounds, activePlaneMask)) {
        return kReject;
      }

      bounds.Max.y = tierBounds.y;
    }

    const Wm3::Vector3f testCorner = SelectAabbCornerByMask(bounds, mCornerSelectionMask);
    const float tierMaxError = mField->GetTierMaxError(tier, x, z);
    const float shoreErrorCoeff = crossesWaterSurface ? ren_ShoreErrorCoeff : 1.0f;

    const Vector4f& row1 = mCam->viewport.r[1];
    const float projectedDepth =
      (row1.z * testCorner.z) + (row1.y * testCorner.y) + (row1.x * testCorner.x) + row1.w;

    const float maxAllowedError = shoreErrorCoeff * projectedDepth * ren_maxViewError;
    return (tierMaxError < maxAllowedError) ? kAccept : kSplit;
  }

  /**
   * Address: 0x0080BEC0 (FUN_0080BEC0, Moho::CTesselator::Tesselate)
   *
   * What it does:
   * Searches split-work quadtree lanes for query coverage and accumulates
   * matching range/min-max outputs.
   */
  bool CTesselator::Tesselate(
    const std::int32_t queryX,
    const std::int32_t queryZ,
    const std::int32_t querySize,
    std::int32_t* const outRangeStart,
    std::uint32_t* const outRangeCount,
    std::int32_t* const outMinValue,
    std::int32_t* const outMaxValue
  )
  {
    *outRangeStart = 0;
    *outRangeCount = 0;

    if (mRectIndices.start_ == mRectIndices.end_) {
      return false;
    }

    const std::int32_t widthMinusOne = mField->width - 1;
    const std::int32_t heightMinusOne = mField->height - 1;
    const std::int32_t widthBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(widthMinusOne));
    const std::int32_t heightBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(heightMinusOne));
    const std::int32_t tierBias = AbsoluteValue(widthBit - heightBit);

    std::int32_t gridColumns = widthMinusOne / heightMinusOne;
    if (gridColumns < 1) {
      gridColumns = 1;
    }

    std::int32_t gridRows = heightMinusOne / widthMinusOne;
    if (gridRows < 1) {
      gridRows = 1;
    }

    std::int32_t tileX = 0;
    std::int32_t outerToken = 0;
    while (outerToken < gridColumns) {
      std::int32_t tileZ = 0;
      if (gridRows > 0) {
        std::int32_t rectIndexOffset = tileX;
        do {
          const std::int32_t rootNodeIndex = mRectIndices.start_[rectIndexOffset];
          if (rootNodeIndex != -1) {
            std::int32_t foundRangeStart = widthMinusOne;
            std::int32_t foundRangeCount = 0;
            std::int32_t foundMin = 0;
            std::int32_t foundMax = 0;

            const std::int32_t tierCount = HeightFieldTierCount(*mField);
            if (
              FindSplitWorkRange(
                *this,
                rootNodeIndex,
                tileX,
                tileZ,
                tierCount - tierBias,
                queryX,
                queryZ,
                querySize,
                &foundRangeStart,
                &foundRangeCount,
                &foundMin,
                &foundMax
              )
            ) {
              if (*outRangeCount == 0u) {
                *outRangeStart = foundRangeStart;
                *outRangeCount = static_cast<std::uint32_t>(foundRangeCount);
                *outMinValue = foundMin;
                *outMaxValue = foundMax;
              } else {
                std::int32_t ignoredRangeStart = foundRangeStart;
                std::int32_t appendedRangeCount = foundRangeCount;
                std::int32_t appendedMin = foundMin;
                std::int32_t appendedMax = foundMax;

                (void)FindSplitWorkRange(
                  *this,
                  rootNodeIndex,
                  tileX,
                  tileZ,
                  tierCount - tierBias,
                  queryX,
                  queryZ,
                  querySize,
                  &ignoredRangeStart,
                  &appendedRangeCount,
                  &appendedMin,
                  &appendedMax
                );

                *outRangeCount += static_cast<std::uint32_t>(appendedRangeCount);
                if (*outMinValue >= appendedMin) {
                  *outMinValue = appendedMin;
                }
                if (*outMaxValue < appendedMax) {
                  *outMaxValue = appendedMax;
                }
              }
            }
          }

          ++tileZ;
          ++rectIndexOffset;
        } while (tileZ < gridRows);
      }

      tileX = ++outerToken;
    }

    return *outRangeCount > 0u;
  }

  /**
   * Address: 0x0080BA30 (FUN_0080BA30, Moho::CTesselator::GetData)
   *
   * What it does:
   * Reads one cached index from the 512x512 lookup ring and validates that the
   * pointed rect still matches `(x,z)`.
   */
  std::int16_t CTesselator::GetData(const std::int32_t z, const std::int32_t x) const
  {
    if (mRectCache.start_ == nullptr) {
      return -1;
    }

    const std::uint16_t index = mLookup[LookupIndex(x, z)];
    const Rect16& rect = mRectCache.start_[index];
    if (static_cast<std::int32_t>(rect.xPos) != x || static_cast<std::int32_t>(rect.zPos) != z) {
      return -1;
    }

    return static_cast<std::int16_t>(index);
  }

  /**
   * Address: 0x0080D2F0 (FUN_0080D2F0)
   *
   * IDA signature:
   * void __userpurge sub_80D2F0(Moho::CTesselator *this@<eax>, int i0, int i1, int i2);
   *
   * What it does:
   * Appends three 16-bit collision-triangle indices `{i0, i1, i2}` to the
   * tesselator's `mCollisionRectLut` FastVectorN lane in a single helper.
   * The binary inlines three copies of the `gpg::FastVectorN<u16, 25>::push_back`
   * tail: when `end == capacity`, grow via the shared move-words helper;
   * otherwise store `index` at `end` and advance `end` by two bytes.
   *
   * Placed alongside `EmitCollisionQuad` because both callsites push triangle
   * windings into the same collision index lane; `EmitCollisionQuad` invokes
   * this helper twice to publish its six-index quad winding.
   */
  void CTesselator::AppendCollisionTriangleIndices(
    const std::uint16_t i0,
    const std::uint16_t i1,
    const std::uint16_t i2
  )
  {
    mCollisionRectLut.PushBack(i0);
    mCollisionRectLut.PushBack(i1);
    mCollisionRectLut.PushBack(i2);
  }

  /**
   * Address: 0x0080DE00 (FUN_0080DE00, sub_80DE00)
   *
   * IDA signature:
   * int __userpurge sub_80DE00@<eax>(
   *   int ebx0@<ebx>, int *a2@<esi>,
   *   Moho::CTesselator *a1, char a4
   * );
   *
   * What it does:
   * Emits one collision-triangle fan from a polyline of vertex indices
   * `[indexRange.begin(), indexRange.end())` rooted at `baseIndex`. For each
   * adjacent pair `(prev, curr)` in the polyline (starting at index 1), the
   * helper publishes a triangle through
   * `CTesselator::AppendCollisionTriangleIndices` (FUN_0080D2F0):
   *   * forward winding (`forwardWinding != 0`): triangle
   *     `{baseIndex, indexRange[i], indexRange[i - 1]}`
   *   * reverse winding (`forwardWinding == 0`): triangle
   *     `{baseIndex, indexRange[i - 1], indexRange[i]}`
   * Skips any work for ranges with fewer than two indices. The binary
   * conservatively reloads the polyline begin pointer each iteration; the
   * source vector is never modified by `AppendCollisionTriangleIndices`
   * (which targets `mCollisionRectLut`), so the modern lift performs the
   * load once.
   */
  std::uint16_t* EmitCollisionTriangleFanFromIndexRange(
    CTesselator* const tesselator,
    const std::uint16_t baseIndex,
    gpg::core::FastVector<std::uint16_t>* const indexRange,
    const bool forwardWinding
  )
  {
    if (tesselator == nullptr || indexRange == nullptr) {
      return nullptr;
    }

    std::uint16_t* const begin = indexRange->begin();
    const std::size_t indexCount = static_cast<std::size_t>(indexRange->end() - begin);
    if (indexCount <= 1u) {
      return begin;
    }

    if (forwardWinding) {
      for (std::size_t i = 1u; i < indexCount; ++i) {
        tesselator->AppendCollisionTriangleIndices(baseIndex, begin[i], begin[i - 1u]);
      }
    } else {
      for (std::size_t i = 1u; i < indexCount; ++i) {
        tesselator->AppendCollisionTriangleIndices(baseIndex, begin[i - 1u], begin[i]);
      }
    }

    return begin;
  }

  /**
   * Address: 0x0080C120 (FUN_0080C120, Moho::CTesselator::Func9)
   *
   * What it does:
   * Quantizes four corner points into rect-cache entries and emits one
   * two-triangle winding into the collision index lane.
   */
  std::uint16_t* CTesselator::EmitCollisionQuad(
    const Wm3::Vector3f* const corners,
    std::int32_t* const outIndexStart,
    std::uint32_t* const outIndexCount,
    std::int32_t* const outRectStart,
    std::uint32_t* const outLastRectIndex
  )
  {
    static constexpr float kHeightScale = 128.0f;
    std::array<std::uint16_t, 4> cornerIndices{};

    *outRectStart = static_cast<std::int32_t>(mRectCache.Size());
    for (std::size_t i = 0; i < cornerIndices.size(); ++i) {
      const Wm3::Vector3f& corner = corners[i];
      Rect16 rect{};
      rect.xPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.x));
      rect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.y * kHeightScale));
      rect.zPos = static_cast<std::uint16_t>(static_cast<std::int32_t>(corner.z));
      rect.zSize = 1u;
      cornerIndices[i] = AddRect(rect);
    }

    *outIndexStart = static_cast<std::int32_t>(mCollisionRectLut.Size());
    *outIndexCount = 6u;
    *outLastRectIndex = cornerIndices[3];

    // Publish the two-triangle winding `{c2, c1, c0}` + `{c1, c2, c3}` via the
    // shared triple-append helper recovered from 0x0080D2F0.
    AppendCollisionTriangleIndices(cornerIndices[2], cornerIndices[1], cornerIndices[0]);
    AppendCollisionTriangleIndices(cornerIndices[1], cornerIndices[2], cornerIndices[3]);

    return (mCollisionRectLut.end_ != nullptr) ? (mCollisionRectLut.end_ - 1) : nullptr;
  }

  /**
   * Address: 0x0080C850 (FUN_0080C850, Moho::CTesselator::AddRect)
   *
   * What it does:
   * Appends one quantized height rect to the cache vector (bounded to 65000
   * entries) and updates the lookup map index for its `(x,z)` key.
   */
  std::uint16_t CTesselator::AddRect(const Rect16& rect)
  {
    const std::size_t count = mRectCache.Size();
    if (count >= kRectLimit) {
      return static_cast<std::uint16_t>(count - 1u);
    }

    mRectCache.PushBack(rect);
    const std::uint16_t result = static_cast<std::uint16_t>(count);
    mLookup[LookupIndex(rect.xPos, rect.zPos)] = result;
    return result;
  }

  /**
   * Address: 0x0080D230 (FUN_0080D230, Moho::CTesselator::GetIndexAt)
   *
   * What it does:
   * Computes scaled terrain coordinates for one tessellation cell, uses the
   * cache when enabled, and inserts a new rect from clamped heightfield sample
   * when the lookup misses.
   */
  std::uint16_t CTesselator::GetIndexAt(const std::int32_t size, const std::int32_t x, const std::int32_t z)
  {
    const std::int32_t scale = 1 << size;
    const std::int32_t gx = x * scale;
    const std::int32_t gz = z * scale;

    if (ren_ErrorCache) {
      const std::int16_t cached = GetData(gz, gx);
      if (cached != -1) {
        return static_cast<std::uint16_t>(cached);
      }
    }

    const std::int32_t width = mField->width;
    std::int32_t clampedX = width - 1;
    if (gx < clampedX) {
      clampedX = gx;
    }
    if (clampedX < 0) {
      clampedX = 0;
    }

    std::int32_t clampedZ = mField->height - 1;
    if (gz < clampedZ) {
      clampedZ = gz;
    }
    if (clampedZ < 0) {
      clampedZ = 0;
    }

    const std::uint16_t terrainWord = mField->data[clampedX + (clampedZ * width)];
    const float quantizedHeight = static_cast<float>(terrainWord) * 0.0078125f * 128.0f;

    Rect16 rect{};
    rect.xPos = static_cast<std::uint16_t>(gx);
    rect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(quantizedHeight));
    rect.zPos = static_cast<std::uint16_t>(gz);
    rect.zSize = 1u;
    return AddRect(rect);
  }

  /**
   * Address: 0x0080E9E0 (FUN_0080E9E0, Moho::CTesselator::CollectDataInRect)
   *
   * What it does:
   * Descends one adaptive tessellation lane while split criteria are met and
   * appends leaf index ids into `outIndices`.
   */
  std::uint16_t* CTesselator::CollectDataInRect(
    gpg::fastvector<std::uint16_t>* const outIndices,
    const std::int32_t tier,
    std::uint32_t* const activePlaneMask,
    const std::int32_t x,
    const std::int32_t z,
    const std::int32_t w,
    const std::int32_t h,
    const std::int32_t xsize,
    const std::int32_t zsize,
    const std::int32_t xoff,
    const std::int32_t zoff
  )
  {
    const std::uint8_t tierByte = static_cast<std::uint8_t>(tier);
    if (tier > 0 && GetIntersectionResult(x, z, tier, activePlaneMask) == kSplit) {
      std::uint32_t childPlaneMask = *activePlaneMask;
      const std::int32_t doubledXSize = 2 * xsize;
      const std::int32_t doubledZSize = 2 * zsize;

      CollectDataInRect(
        outIndices,
        tier - 1,
        &childPlaneMask,
        w + (2 * x),
        h + (2 * z),
        w,
        h,
        doubledXSize,
        doubledZSize,
        xoff,
        zoff
      );

      childPlaneMask = *activePlaneMask;
      return CollectDataInRect(
        outIndices,
        tier - 1,
        &childPlaneMask,
        w + (2 * x) + xoff,
        h + (2 * z) + zoff,
        w,
        h,
        xoff + doubledXSize,
        zoff + doubledZSize,
        xoff,
        zoff
      );
    }

    const std::uint16_t index = GetIndexAt(static_cast<std::int32_t>(tierByte), xsize + xoff, zoff + zsize);
    outIndices->PushBack(index);
    return outIndices->end_ - 1;
  }

  /**
   * Shared leaf body for `TesselateTile` (binary label `LABEL_14` inside
   * `sub_80E200` - see `TesselateTile`'s own address block for the two entry
   * points that jump here).
   *
   * What it does:
   * Collects the four cardinal-neighbor boundary index chains around
   * `(x, z)`, seeding south with west's last collected index and east with
   * north's last collected index so the four edges join without a crack at
   * the shared corners. When any chain collected more than its trivial two-
   * point seed, fans north and east directly (matching the binary's own
   * winding) and fans south and west through `EmitCollisionTriangleFanFromIndexRange`
   * (opposite winding convention - preserved exactly as shipped). Otherwise
   * every chain is trivial and the cell closes with one simple two-triangle
   * quad built from north/south alone.
   */
  void CTesselator::TesselateLeafCell(const std::int32_t x, const std::int32_t z, const std::int32_t tier)
  {
    const std::uint16_t centerIndex = GetIndexAt(tier, x, z);

    gpg::core::FastVectorN<std::uint16_t, 25> north;
    north.PushBack(centerIndex);
    std::uint32_t northMask = mActivePlaneMask;
    CollectDataInRect(&north, tier, &northMask, x, z - 1, 0, 1, x, z, 1, 0);

    gpg::core::FastVectorN<std::uint16_t, 25> west;
    west.PushBack(centerIndex);
    std::uint32_t westMask = mActivePlaneMask;
    CollectDataInRect(&west, tier, &westMask, x - 1, z, 1, 0, x, z, 0, 1);

    gpg::core::FastVectorN<std::uint16_t, 25> south;
    south.PushBack(west[west.Size() - 1]);
    std::uint32_t southMask = mActivePlaneMask;
    CollectDataInRect(&south, tier, &southMask, x, z + 1, 0, 0, x, z + 1, 1, 0);

    gpg::core::FastVectorN<std::uint16_t, 25> east;
    east.PushBack(north[north.Size() - 1]);
    std::uint32_t eastMask = mActivePlaneMask;
    CollectDataInRect(&east, tier, &eastMask, x + 1, z, 0, 0, x + 1, z, 0, 1);

    if (north.Size() > 2 || west.Size() > 2 || east.Size() > 2 || south.Size() > 2) {
      const std::uint16_t fanCenter = GetIndexAt(tier - 1, (2 * x) + 1, (2 * z) + 1);

      for (std::size_t i = 1; i < north.Size(); ++i) {
        AppendCollisionTriangleIndices(fanCenter, north[i - 1], north[i]);
      }
      for (std::size_t i = 1; i < east.Size(); ++i) {
        AppendCollisionTriangleIndices(fanCenter, east[i - 1], east[i]);
      }

      EmitCollisionTriangleFanFromIndexRange(this, fanCenter, &south, true);
      EmitCollisionTriangleFanFromIndexRange(this, fanCenter, &west, true);
    } else {
      AppendCollisionTriangleIndices(north[0], north[1], south[1]);
      AppendCollisionTriangleIndices(north[0], south[1], south[0]);
    }
  }

  /**
   * Address: 0x0080E200 (FUN_0080E200, sub_80E200)
   *
   * What it does:
   * Rejected cells return -1 immediately. A cell whose intersection test
   * calls for a split recurses into four half-size children at `tier - 1`
   * (or, once `tier` reaches 1, emits the finest-level fan directly via
   * `EmitTileSubdivisionFan` instead of a further recursive step) and
   * combines the children into one node spanning their collision-index
   * range; a node with every child rejected returns -1 too. An accepted
   * cell, or one whose `tier` has already reached 0, emits its own boundary
   * geometry via `TesselateLeafCell`. Every surviving path then scans the
   * collision-index range this call just appended for its min/max index
   * value, builds one `SplitWorkNode`, appends it to `mSplitWorkQueue`, and
   * returns the new node's index.
   */
  std::int32_t CTesselator::TesselateTile(
    const std::int32_t x,
    const std::int32_t z,
    const std::int32_t tier,
    std::uint32_t* const activePlaneMask
  )
  {
    SplitWorkNode node{};
    node.childTopLeftIndex = -1;
    node.childTopRightIndex = -1;
    node.childBottomLeftIndex = -1;
    node.childBottomRightIndex = -1;

    if (tier > 0) {
      const int intersection = GetIntersectionResult(x, z, tier, activePlaneMask);
      if (intersection == kReject) {
        return -1;
      }

      if (intersection == kSplit) {
        if (tier != 1) {
          std::uint32_t childMask = *activePlaneMask;
          node.childTopLeftIndex = TesselateTile(2 * x, 2 * z, tier - 1, &childMask);

          childMask = *activePlaneMask;
          node.childTopRightIndex = TesselateTile((2 * x) + 1, 2 * z, tier - 1, &childMask);

          childMask = *activePlaneMask;
          node.childBottomLeftIndex = TesselateTile(2 * x, (2 * z) + 1, tier - 1, &childMask);

          childMask = *activePlaneMask;
          node.childBottomRightIndex = TesselateTile((2 * x) + 1, (2 * z) + 1, tier - 1, &childMask);

          const std::int32_t children[4] = {
            node.childTopLeftIndex, node.childTopRightIndex, node.childBottomLeftIndex, node.childBottomRightIndex
          };

          node.rangeStart = -1;
          node.rangeCount = 0;
          for (const std::int32_t child : children) {
            if (child != -1) {
              if (node.rangeStart == -1) {
                node.rangeStart = mSplitWorkQueue[child].rangeStart;
              }
              node.rangeCount += mSplitWorkQueue[child].rangeCount;
            }
          }

          if (node.rangeStart == -1) {
            return -1;
          }
        } else {
          node.rangeStart = static_cast<std::int32_t>(mCollisionRectLut.Size());
          EmitTileSubdivisionFan(*this, 2 * x, 2 * z);
          node.rangeCount = static_cast<std::int32_t>(mCollisionRectLut.Size()) - node.rangeStart;
        }
      } else {
        node.rangeStart = static_cast<std::int32_t>(mCollisionRectLut.Size());
        TesselateLeafCell(x, z, tier);
        node.rangeCount = static_cast<std::int32_t>(mCollisionRectLut.Size()) - node.rangeStart;
      }
    } else {
      node.rangeStart = static_cast<std::int32_t>(mCollisionRectLut.Size());
      TesselateLeafCell(x, z, tier);
      node.rangeCount = static_cast<std::int32_t>(mCollisionRectLut.Size()) - node.rangeStart;
    }

    std::int32_t minValue = std::numeric_limits<std::int32_t>::max();
    std::int32_t maxValue = 0;
    const std::uint16_t* const collisionData = GetCollisionIndexData();
    for (std::int32_t i = node.rangeStart; i < node.rangeStart + node.rangeCount; ++i) {
      const std::int32_t value = collisionData[i];
      if (minValue >= value) {
        minValue = value;
      }
      if (maxValue < value) {
        maxValue = value;
      }
    }
    node.minValue = minValue;
    node.maxValue = maxValue;

    mSplitWorkQueue.PushBack(node);
    return static_cast<std::int32_t>(mSplitWorkQueue.Size()) - 1;
  }

  /**
   * Address: 0x0080CF10 (FUN_0080CF10, Moho::CTesselator::TesselateData)
   *
   * What it does:
   * Emits one skirt strip along a tile-block edge: seeds a local index chain
   * with the edge's center vertex, collects the edge's boundary indices,
   * builds a matching height-clamped skirt chain via `AppendSkirtSampleRects`,
   * then triangulates the strip between the two chains.
   */
  void CTesselator::TesselateData(
    const std::int32_t tier,
    const std::int32_t x,
    const std::int32_t z,
    const std::int32_t w,
    const std::int32_t h,
    const std::int32_t xsize,
    const std::int32_t zsize,
    const std::int32_t xoff,
    const std::int32_t zoff
  )
  {
    const std::uint16_t centerIndex = GetIndexAt(tier, xsize, zsize);

    gpg::core::FastVectorN<std::uint16_t, 25> edgeIndices;
    edgeIndices.PushBack(centerIndex);
    std::uint32_t planeMask = mActivePlaneMask;
    CollectDataInRect(&edgeIndices, tier, &planeMask, x, z, w, h, xsize, zsize, xoff, zoff);

    gpg::core::FastVectorN<std::uint16_t, 25> skirtIndices;
    AppendSkirtSampleRects(*this, edgeIndices, skirtIndices);

    for (std::size_t i = 1; i < edgeIndices.Size(); ++i) {
      AppendCollisionTriangleIndices(skirtIndices[i - 1], skirtIndices[i], edgeIndices[i]);
      AppendCollisionTriangleIndices(skirtIndices[i - 1], edgeIndices[i], edgeIndices[i - 1]);
    }
  }

  /**
   * Address: 0x0080C8D0 (FUN_0080C8D0, Moho::CTesselator::Func1)
   *
   * What it does:
   * Per-frame tessellation rebuild - see the header for the full summary.
   * Field-offset citations: corner-selection mask write at 0x0080C9CD
   * (immediately before the `sub_471A30` frustum-solid refresh call),
   * active-plane mask write at 0x0080C9F0 (immediately after it, computed
   * from the now-refreshed plane count); `mMinY` write at 0x0080C958 into
   * `+0x8C` (the offset previously modelled as the never-referenced
   * `mInitialPlaneMask`); `mSkirtIndexStart`/`mSkirtVertexStart` writes at
   * 0x0080CC93/0x0080CCA0, matching the citation already on those fields.
   */
  void CTesselator::Rebuild(GeomCamera3* const camera, IWldTerrainRes* const terrainResource)
  {
    std::fill(std::begin(mLookup), std::end(mLookup), std::uint16_t{0});

    CHeightField* const field = terrainResource->GetHeightField();
    mWaterElevation = terrainResource->IsWaterEnabled() ? terrainResource->GetWaterElevation() : -10000.0f;

    const std::int32_t tierCount = HeightFieldTierCount(*field);
    const Wm3::AxisAlignedBox3f terrainBounds = field->GetTierBox(0, 0, tierCount);
    mMinY = terrainBounds.Min.y;

    mCam = camera;

    const float inverseViewZX = -0.0f - camera->inverseView.r[2].x;
    const float inverseViewZY = -0.0f - camera->inverseView.r[2].y;
    const float inverseViewZZ = -0.0f - camera->inverseView.r[2].z;
    mCornerSelectionMask = (std::bit_cast<std::uint32_t>(inverseViewZX) >> 31)
      | (2u * ((std::bit_cast<std::uint32_t>(inverseViewZY) >> 31)
        | (2u * (std::bit_cast<std::uint32_t>(inverseViewZZ) >> 31))));

    mGeomSolid = camera->solid2;
    mActivePlaneMask = (1u << mGeomSolid.planes_.Size()) - 1u;

    mRectCache.ResetStorageToInline();

    // Binary: `v47 = (width-1 > 0) ? 0 : (width-1); if (v47 < 0) v47 = 0;` (and
    // the identical shape for height/v15) - for any real terrain (width,
    // height >= 1) this evaluates to 0 in every case, so the sample is always
    // the heightfield's own (0, 0) corner, not a clamped far corner.
    const float baselineHeight = static_cast<float>(mField->data[0]) * 0.0078125f;

    Rect16 baselineRect{};
    baselineRect.xPos = 0;
    baselineRect.xSize = static_cast<std::uint16_t>(static_cast<std::int32_t>(baselineHeight * 128.0f));
    baselineRect.zPos = 0;
    baselineRect.zSize = 1;
    mRectCache.PushBack(baselineRect);

    mCollisionRectLut.ResetStorageToInline();
    mSplitWorkQueue.ResetStorageToInline();
    mRectIndices.ResetStorageToInline();

    const std::int32_t widthMinusOne = mField->width - 1;
    const std::int32_t heightMinusOne = mField->height - 1;
    const std::int32_t widthBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(widthMinusOne));
    const std::int32_t heightBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(heightMinusOne));
    const std::int32_t tierBias = AbsoluteValue(widthBit - heightBit);

    std::int32_t gridColumns = widthMinusOne / heightMinusOne;
    if (gridColumns < 1) {
      gridColumns = 1;
    }
    std::int32_t gridRows = heightMinusOne / widthMinusOne;
    if (gridRows < 1) {
      gridRows = 1;
    }

    for (std::int32_t blockX = 0; blockX < gridColumns; ++blockX) {
      for (std::int32_t blockZ = 0; blockZ < gridRows; ++blockZ) {
        std::uint32_t planeMask = mActivePlaneMask;
        const std::int32_t tier = HeightFieldTierCount(*mField) - tierBias;
        const std::int32_t nodeIndex = TesselateTile(blockX, blockZ, tier, &planeMask);
        mRectIndices.PushBack(nodeIndex);
      }
    }

    mSkirtIndexStart = GetCollisionIndexCount();
    mSkirtVertexStart = GetRectCacheCount();

    for (std::int32_t blockX = 0; blockX < gridColumns; ++blockX) {
      for (std::int32_t blockZ = 0; blockZ < gridRows; ++blockZ) {
        const std::int32_t tier = HeightFieldTierCount(*mField) - tierBias;

        if (blockZ == 0) {
          TesselateData(tier, blockX, 0, 0, 0, blockX, 0, 1, 0);
        }
        if (blockX == 0) {
          TesselateData(tier, 0, blockZ, 0, 0, 0, blockZ, 0, 1);
        }
        if (blockX == gridColumns - 1) {
          TesselateData(tier, blockX, blockZ, 1, 0, blockX + 1, blockZ, 0, 1);
        }
        if (blockZ == gridRows - 1) {
          TesselateData(tier, blockX, blockZ, 0, 1, blockX, blockZ + 1, 1, 0);
        }
      }
    }
  }

  /**
   * Address: 0x0080BD20 (FUN_0080BD20, Moho::CTesselator::Func6)
   *
   * What it does:
   * Walks the same width/height-ratio tile grid as `Tesselate()` (matching
   * its `gridColumns`/`gridRows`/`tierBias` derivation exactly), and for
   * every occupied tile descends `mSplitWorkQueue` via
   * `CollectSplitWorkRangeInRect` to gather every split-work leaf
   * overlapping the query rect into `mCollisionRectLut`, either verbatim or
   * decal-clipped depending on `ren_ClipDecals`/`ren_ClipDecalLevel`.
   */
  bool CTesselator::CollectClippedCollisionIndicesInRect(
    const std::int32_t queryXMin,
    const std::int32_t queryZMin,
    const std::int32_t queryXMax,
    const std::int32_t queryZMax,
    std::int32_t* const outBaselineIndexCount,
    std::uint32_t* const outAddedIndexCount,
    std::int32_t* const outMinRectIndex,
    std::int32_t* const outMaxRectIndex
  )
  {
    const std::int32_t widthMinusOne = mField->width - 1;
    const std::int32_t heightMinusOne = mField->height - 1;
    const std::int32_t widthBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(widthMinusOne));
    const std::int32_t heightBit = MostSignificantBitIndexOrMinusOne(static_cast<std::uint32_t>(heightMinusOne));
    const std::int32_t tierBias = AbsoluteValue(widthBit - heightBit);

    *outBaselineIndexCount = static_cast<std::int32_t>(mCollisionRectLut.Size());
    *outMinRectIndex = std::numeric_limits<std::int32_t>::max();
    *outMaxRectIndex = 0;

    std::int32_t gridColumns = widthMinusOne / heightMinusOne;
    if (gridColumns < 1) {
      gridColumns = 1;
    }
    std::int32_t gridRows = heightMinusOne / widthMinusOne;
    if (gridRows < 1) {
      gridRows = 1;
    }

    const std::int32_t tierCount = HeightFieldTierCount(*mField);

    for (std::int32_t tileX = 0; tileX < gridColumns; ++tileX) {
      for (std::int32_t tileZ = 0; tileZ < gridRows; ++tileZ) {
        const std::int32_t rootNodeIndex = mRectIndices[tileX + tileZ];
        if (rootNodeIndex != -1) {
          CollectSplitWorkRangeInRect(
            *this, rootNodeIndex, tileX, tileZ, tierCount - tierBias, queryXMin, queryZMin, queryXMax, queryZMax,
            outMinRectIndex, outMaxRectIndex
          );
        }
      }
    }

    *outAddedIndexCount =
      static_cast<std::uint32_t>(mCollisionRectLut.Size()) - static_cast<std::uint32_t>(*outBaselineIndexCount);
    if (*outMinRectIndex == std::numeric_limits<std::int32_t>::max()) {
      *outMinRectIndex = 0;
    }
    return *outAddedIndexCount > 0u;
  }
} // namespace moho
