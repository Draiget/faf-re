#include "moho/math/Wm3DistanceFafExtras.h"
#include "Wm3Capsule3.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace Wm3
{
  namespace
  {
    constexpr float kWm3Epsilon = 0.000001f;

    inline bool NearlyZero(const float v, const float eps = kWm3Epsilon) noexcept
    {
      return std::fabs(v) <= eps;
    }

    int AddUniqueRoot(const float value, float* const outRoots, int count) noexcept
    {
      if (!std::isfinite(value)) {
        return count;
      }

      for (int i = 0; i < count; ++i) {
        if (std::fabs(outRoots[i] - value) <= 0.0001f) {
          return count;
        }
      }

      outRoots[count] = value;
      return count + 1;
    }

    int SolveQuadratic(const float a, const float b, const float c, float* const outRoots) noexcept
    {
      if (NearlyZero(a)) {
        if (NearlyZero(b)) {
          return 0;
        }
        outRoots[0] = -c / b;
        return 1;
      }

      const float discr = b * b - 4.0f * a * c;
      if (discr < 0.0f) {
        return 0;
      }

      if (NearlyZero(discr)) {
        outRoots[0] = -b / (2.0f * a);
        return 1;
      }

      const float root = SqrtfBinary(discr);
      const float inv2a = 1.0f / (2.0f * a);
      float r0 = (-b - root) * inv2a;
      float r1 = (-b + root) * inv2a;
      if (r1 < r0) {
        std::swap(r0, r1);
      }
      outRoots[0] = r0;
      outRoots[1] = r1;
      return 2;
    }

    int LineCapsuleIntersectionRoots(
      const Vector3<float>& lineOrigin,
      const Vector3<float>& lineDirection,
      const Capsule3<float>& capsule,
      float* const outRoots
    ) noexcept
    {
      int count = 0;

      const Vector3<float> axisScaled = Vector3<float>::Scale(capsule.Segment.Direction, capsule.Segment.Extent);
      const Vector3<float> segA = Vector3<float>::Sub(capsule.Segment.Origin, axisScaled);
      const Vector3<float> segB = Vector3<float>::Add(capsule.Segment.Origin, axisScaled);
      const Vector3<float> segV = Vector3<float>::Sub(segB, segA);

      const float segVV = Vector3<float>::Dot(segV, segV);
      if (NearlyZero(segVV)) {
        float roots[2]{};
        const Vector3<float> w0 = Vector3<float>::Sub(lineOrigin, segA);
        const float a = Vector3<float>::Dot(lineDirection, lineDirection);
        const float b = 2.0f * Vector3<float>::Dot(lineDirection, w0);
        const float c = Vector3<float>::Dot(w0, w0) - capsule.Radius * capsule.Radius;
        const int rc = SolveQuadratic(a, b, c, roots);
        for (int i = 0; i < rc; ++i) {
          count = AddUniqueRoot(roots[i], outRoots, count);
        }
        if (count == 2 && outRoots[1] < outRoots[0]) {
          std::swap(outRoots[0], outRoots[1]);
        }
        return count;
      }

      const Vector3<float> w0 = Vector3<float>::Sub(lineOrigin, segA);
      const float dd = Vector3<float>::Dot(lineDirection, lineDirection);
      const float dw = Vector3<float>::Dot(lineDirection, w0);
      const float ww = Vector3<float>::Dot(w0, w0);
      const float dv = Vector3<float>::Dot(lineDirection, segV);
      const float wv = Vector3<float>::Dot(w0, segV);
      const float rr = capsule.Radius * capsule.Radius;

      auto addRegionRoots =
        [&](const float minS, const float maxS, const bool endpointA, const bool endpointB) noexcept {
          float roots[2]{};

          if (endpointA || endpointB) {
            const Vector3<float> endpoint = endpointA ? segA : segB;
            const Vector3<float> we = Vector3<float>::Sub(lineOrigin, endpoint);
            const float a = dd;
            const float b = 2.0f * Vector3<float>::Dot(lineDirection, we);
            const float c = Vector3<float>::Dot(we, we) - rr;
            const int rc = SolveQuadratic(a, b, c, roots);
            for (int i = 0; i < rc; ++i) {
              const float s = wv + roots[i] * dv;
              if (s >= minS - 0.0001f && s <= maxS + 0.0001f) {
                count = AddUniqueRoot(roots[i], outRoots, count);
              }
            }
            return;
          }

          const float a = dd - (dv * dv) / segVV;
          const float b = 2.0f * (dw - (wv * dv) / segVV);
          const float c = ww - (wv * wv) / segVV - rr;
          const int rc = SolveQuadratic(a, b, c, roots);
          for (int i = 0; i < rc; ++i) {
            const float s = wv + roots[i] * dv;
            if (s >= minS - 0.0001f && s <= maxS + 0.0001f) {
              count = AddUniqueRoot(roots[i], outRoots, count);
            }
          }
        };

      // Region where closest point is endpoint A.
      addRegionRoots(-std::numeric_limits<float>::infinity(), 0.0f, true, false);
      // Region where closest point is interior of segment AB.
      addRegionRoots(0.0f, segVV, false, false);
      // Region where closest point is endpoint B.
      addRegionRoots(segVV, std::numeric_limits<float>::infinity(), false, true);

      if (count > 1) {
        std::sort(outRoots, outRoots + count);
      }
      if (count > 2) {
        count = 2;
      }
      return count;
    }

    int ClipRootsToPathExtent(
      const float* const roots, const int rootCount, const float extent, float* const clipped
    ) noexcept
    {
      int count = 0;
      for (int i = 0; i < rootCount; ++i) {
        if (std::fabs(roots[i]) <= extent + 0.0001f) {
          count = AddUniqueRoot(roots[i], clipped, count);
        }
      }
      if (count > 1) {
        std::sort(clipped, clipped + count);
      }
      return count;
    }

    struct IntrBox3Sphere3fState
    {
      float sphereRadius{};
      float contactTime{};
    };

    inline void WriteIfNotNull(float* const out, const float value) noexcept
    {
      if (out) {
        *out = value;
      }
    }

    bool RayIntersectsOrientedBox(
      const Vector3<float>& rayOrigin,
      const Vector3<float>& rayDirection,
      const Box3<float>& box,
      float* const tEnterOut
    ) noexcept
    {
      const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
      const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
      const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};
      const Vector3<float> center{box.Center[0], box.Center[1], box.Center[2]};

      const Vector3<float> diff = Vector3<float>::Sub(rayOrigin, center);
      const float o[3] = {
        Vector3<float>::Dot(diff, axis0), Vector3<float>::Dot(diff, axis1), Vector3<float>::Dot(diff, axis2)
      };
      const float d[3] = {
        Vector3<float>::Dot(rayDirection, axis0),
        Vector3<float>::Dot(rayDirection, axis1),
        Vector3<float>::Dot(rayDirection, axis2)
      };

      float t0 = 0.0f;
      float t1 = std::numeric_limits<float>::max();
      for (int i = 0; i < 3; ++i) {
        const float extent = box.Extent[i];
        if (NearlyZero(d[i])) {
          if (o[i] < -extent || o[i] > extent) {
            return false;
          }
          continue;
        }

        const float invD = 1.0f / d[i];
        float tNear = (-extent - o[i]) * invD;
        float tFar = (extent - o[i]) * invD;
        if (tNear > tFar) {
          std::swap(tNear, tFar);
        }

        t0 = std::max(t0, tNear);
        t1 = std::min(t1, tFar);
        if (t0 > t1) {
          return false;
        }
      }

      if (tEnterOut) {
        *tEnterOut = t0;
      }
      return true;
    }

    /**
     * Address: 0x00A41880 (FUN_00A41880, sub_A41880)
     *
     * this, float, float, float, float, float, float, float, float, float, float*, float*, float*, bool
     *
     * IDA signature:
     * int __thiscall sub_A41880(int this, float arg0, float arg4, float a4, float a5, float a6, float a7, float a8,
     * float a9, float a10, float *a11, float *a12, float *a13, float a14);
     *
     * What it does:
     * Solves face-region sweep intersection for one outside axis and emits local contact coordinates.
     */
    int IntrBox3Sphere3fSubA41880(
      IntrBox3Sphere3fState& state,
      const float arg0,
      const float arg4,
      const float a4,
      const float a5,
      const float a6,
      const float a7,
      const float a8,
      const float a9,
      const float a10,
      float* const a11,
      float* const a12,
      float* const a13,
      const bool a14
    ) noexcept
    {
      if (a4 + state.sphereRadius >= a7 && a14) {
        state.contactTime = 0.0f;
        return -1;
      }

      if (a10 >= 0.0f) {
        return 0;
      }

      const float radiusSquared = state.sphereRadius * state.sphereRadius;
      const float v40 = a8 * a8 + a10 * a10;
      const float v41 = a10 * a10 + a9 * a9;
      const float v36 = a7 - a4;

      int v37 = 1;
      float v49 = a5 - arg0;
      float v32 = v36 * a8 - v49 * a10;
      if (a8 < 0.0f) {
        v37 = -1;
        v49 = arg0 + a5;
        v32 = v49 * a10 - v36 * a8;
      }

      int v39 = 1;
      float v35 = a6 - arg4;
      float v31 = v36 * a9 - v35 * a10;
      if (a9 < 0.0f) {
        v39 = -1;
        v35 = arg4 + a6;
        v31 = v35 * a10 - v36 * a9;
      }

      const float v42 = a8 * state.sphereRadius * static_cast<float>(v37);
      if (v42 >= v32) {
        const float v50 = a9 * state.sphereRadius * static_cast<float>(v39);
        if (v50 >= v31) {
          state.contactTime = (state.sphereRadius - v36) / a10;
          WriteIfNotNull(a11, a8 * state.contactTime + a5);
          WriteIfNotNull(a12, a9 * state.contactTime + a6);
          WriteIfNotNull(a13, a4);
          return 1;
        }

        if (v41 * radiusSquared >= v31 * v31) {
          state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(v35, v36, a9, a10, v41, radiusSquared);
          WriteIfNotNull(a11, state.contactTime * a8 + a5);
          WriteIfNotNull(a12, static_cast<float>(v39) * arg4);
          WriteIfNotNull(a13, a4);
          return 1;
        }

        return 0;
      }

      if (v40 * radiusSquared < v32 * v32) {
        return 0;
      }

      const float v46 = a9 * state.sphereRadius * static_cast<float>(v39);
      if (v46 >= v31) {
        state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(v49, v36, a8, a10, v40, radiusSquared);
        WriteIfNotNull(a11, static_cast<float>(v37) * arg0);
        WriteIfNotNull(a12, a9 * state.contactTime + a6);
        WriteIfNotNull(a13, a4);
        return 1;
      }

      if (v41 * radiusSquared < v31 * v31) {
        return 0;
      }

      const Vector3<float> a3{a8, a9, a10};
      const Vector3<float> v44{v49, v35, v36};
      const Vector3<float> a2 = Vector3<float>::Cross(v44, a3);
      if (Vector3<float>::LengthSq(a2) > Vector3<float>::LengthSq(a3) * radiusSquared) {
        return 0;
      }

      state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v49, v35, v36, a8, a9, a10, radiusSquared);
      WriteIfNotNull(a11, static_cast<float>(v37) * arg0);
      WriteIfNotNull(a12, static_cast<float>(v39) * arg4);
      WriteIfNotNull(a13, a4);
      return 1;
    }

    /**
     * Address: 0x00A41CC0 (FUN_00A41CC0, sub_A41CC0)
     *
     * this, float, float, float, float, float, float, float, float, float, float*, float*, float*
     *
     * IDA signature:
     * int __thiscall sub_A41CC0(int this, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float
     * a9, float a10, float *a11, float *a12, float *a13);
     *
     * What it does:
     * Solves edge/vertex transition sweep for mixed edge-region cases.
     */
    int IntrBox3Sphere3fSubA41CC0(
      IntrBox3Sphere3fState& state,
      const float a2,
      const float a3,
      const float a4,
      const float a5,
      const float a6,
      const float a7,
      const float a8,
      const float a9,
      const float a10,
      float* const a11,
      float* const a12,
      float* const a13
    ) noexcept
    {
      const float radiusSquared = state.sphereRadius * state.sphereRadius;

      int v47 = 1;
      float v46 = a2 - a4;
      float v17 = a6 * a9;
      const float v18 = a8;
      float v19 = v46 * a8;
      float v57 = v17 - v19;
      float v20 = v46 * a10;
      const float v21 = a10;
      float v58 = a7 * a9 - v20;
      if (a9 < 0.0f) {
        v47 = -1;
        v46 = a2 + a4;
        v19 = v46 * a8;
        v17 = a6 * a9;
        v57 = v19 - v17;
        v20 = v46 * a10;
        v58 = v20 - a7 * a9;
      }

      if (v57 < 0.0f || v58 < 0.0f || state.sphereRadius * state.sphereRadius * (a9 * a9) >= v58 * v58 + v57 * v57) {
        const float v56 = v18 * v18 + v21 * v21;
        state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(a6, a7, v18, v21, v56, radiusSquared);
        WriteIfNotNull(a11, a3);
        WriteIfNotNull(a12, state.contactTime * a9 + a2);
        WriteIfNotNull(a13, a5);
        return 1;
      }

      const float v51 = v20 - a7 * a9;
      const float v52 = a7 * v18 - a6 * v21;
      const float v53 = v17 - v19;
      const float v54 = v53 * v53 + v52 * v52 + v51 * v51;
      const float v55 = v21 * v21 + v18 * v18 + a9 * a9;
      if (v54 > v55 * radiusSquared) {
        return 0;
      }

      state.contactTime = IntrBox3Sphere3fGetVertexIntersection(a6, v46, a7, v18, a9, v21, radiusSquared);
      WriteIfNotNull(a11, a3);
      WriteIfNotNull(a12, static_cast<float>(v47) * a4);
      WriteIfNotNull(a13, a5);
      return 1;
    }
  } // namespace

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
    const float a1, const float a2, const float a3, const float a4, const float a5, const float a6, const float a7
  ) noexcept
  {
    const float v10 = a2 * a5 + a1 * a4 + a3 * a6;
    const float v9 = a1 * a1 + a2 * a2 + a3 * a3 - a7;
    const float v11 = a6 * a6 + a4 * a4 + a5 * a5;
    const float v12 = v10 * v10 - v11 * v9;
    const float v13 = SqrtfBinary(std::fabs(v12));
    const float v14 = 1.0f / v13;
    return static_cast<float>(v14 * v9 / (1.0f - v14 * v10));
  }

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
  float IntrBox3Sphere3fGetEdgeIntersection(
    const float a1, const float a2, const float a3, const float a4, const float a5, const float a6
  ) noexcept
  {
    const float v12 = a1 * a3 + a2 * a4;
    const float v7 = a1 * a1 + a2 * a2 - a6;
    const float v9 = v12 * v12 - v7 * a5;
    const float v10 = SqrtfBinary(std::fabs(v9));
    const float v11 = 1.0f / v10;
    return static_cast<float>(v11 * v7 / (1.0f - v11 * v12));
  }

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
    const float sphereRadius,
    const float a2,
    const float a3,
    const float a4,
    const float a5,
    const float a6,
    const float a7,
    const float a8,
    const float a9,
    const float a10,
    float* const a11,
    float* const a12,
    float* const a13,
    const bool a14,
    float* const contactTime
  ) noexcept
  {
    IntrBox3Sphere3fState state{};
    state.sphereRadius = sphereRadius;
    state.contactTime = 0.0f;

    const float v20 = a5 - a2;
    const float v21 = a7 - a4;
    if (a14) {
      const float v23 = v21 * v21 + v20 * v20 - state.sphereRadius * state.sphereRadius;
      if (v23 <= 0.0f) {
        state.contactTime = 0.0f;
        WriteIfNotNull(contactTime, state.contactTime);
        return -1;
      }
    }

    const float v24 = v21 * a10 + v20 * a8;
    if (v24 >= 0.0f) {
      WriteIfNotNull(contactTime, state.contactTime);
      return 0;
    }

    const float v25 = v20 * a10 - v21 * a8;
    int result = 0;
    if (v25 >= 0.0f) {
      if (a8 < 0.0f) {
        const float v26 = -state.sphereRadius * a8;
        if (v26 < v25) {
          result = IntrBox3Sphere3fSubA41880(state, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, false);
        } else {
          result = IntrBox3Sphere3fSubA41CC0(state, a6, a4, a3, a2, v21, v20, a10, a9, a8, a13, a12, a11);
        }
      }
    } else if (a10 < 0.0f) {
      const float v27 = state.sphereRadius * a10;
      if (v27 > v25) {
        result = IntrBox3Sphere3fSubA41880(state, a4, a3, a2, a7, a6, a5, a10, a9, a8, a13, a12, a11, false);
      } else {
        result = IntrBox3Sphere3fSubA41CC0(state, a6, a2, a3, a4, v20, v21, a8, a9, a10, a11, a12, a13);
      }
    }

    WriteIfNotNull(contactTime, state.contactTime);
    return result;
  }

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
    const float sphereRadius,
    const float a2,
    const float a3,
    const float a4,
    const float a5,
    const float a6,
    const float a7,
    const float a8,
    const float a9,
    const float a10,
    float* const a11,
    float* const a12,
    float* const a13,
    float* const contactTime
  ) noexcept
  {
    IntrBox3Sphere3fState state{};
    state.sphereRadius = sphereRadius;
    state.contactTime = 0.0f;

    const float v45 = a5 - a2;
    const float v47 = a6 - a3;
    const float v41 = a7 - a4;
    const float v40 = state.sphereRadius * state.sphereRadius;
    const float v48 = v41 * v41 + v47 * v47 + v45 * v45 - v40;
    if (v48 <= 0.0f) {
      state.contactTime = 0.0f;
      WriteIfNotNull(contactTime, state.contactTime);
      return -1;
    }

    if (v41 * a10 + v47 * a9 + v45 * a8 >= 0.0f) {
      WriteIfNotNull(contactTime, state.contactTime);
      return 0;
    }

    const float v42 = v41 * a9 - v47 * a10;
    const float v43 = v41 * a8 - v45 * a10;
    const float v39 = v45 * a9 - v47 * a8;
    const float v49 = v42 * v42;
    const float v46 = v43 * v43;
    const float v44 = v39 * v39;

    const float v21 = 0.0f;
    if (v43 < 0.0f && v39 >= 0.0f) {
      const float v50 = a8 * a8;
      if (v50 * v40 >= v44 + v46) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
    }

    if (v21 > v39 && v21 > v42) {
      const float v51 = a9 * a9;
      if (v51 * v40 >= v44 + v49) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
    }

    float v22 = v21;
    float v23 = a8;
    if (!(v21 > v43 || v21 > v42)) {
      const float v52 = a10 * a10;
      if (v52 * v40 >= v46 + v49) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
      v22 = 0.0f;
      v23 = a8;
    }

    int result = 0;
    if (v22 <= v43 || v22 > v39) {
      if (v22 <= v39 || v22 <= v42) {
        result = IntrBox3Sphere3fFindEdgeRegionIntersection(
          state.sphereRadius, a2, a4, a3, a5, a7, a6, v23, a10, a9, a11, a13, a12, false, &state.contactTime
        );
      } else {
        result = IntrBox3Sphere3fFindEdgeRegionIntersection(
          state.sphereRadius, a2, a3, a4, a5, a6, a7, v23, a9, a10, a11, a12, a13, false, &state.contactTime
        );
      }
    } else {
      result = IntrBox3Sphere3fFindEdgeRegionIntersection(
        state.sphereRadius, a3, a2, a4, a6, a5, a7, a9, v23, a10, a12, a11, a13, false, &state.contactTime
      );
    }

    WriteIfNotNull(contactTime, state.contactTime);
    return result;
  }

  /**
   * Address: 0x00A45C00 (FUN_00A45C00, Wm3::DistVector3Box3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::GetSquared(Wm3::DistVector3Box3f *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented box and writes the closest point.
   */
  float DistVector3Box3fGetSquared(
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> center{box.Center[0], box.Center[1], box.Center[2]};
    const Vector3<float> diff = Vector3<float>::Sub(vector, center);

    Vector3<float> closest = center;
    float squaredDistance = 0.0f;

    for (int i = 0; i < 3; ++i) {
      const Vector3<float> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const float projected = Vector3<float>::Dot(diff, axis);

      float clamped = projected;
      if (projected < -box.Extent[i]) {
        const float delta = projected + box.Extent[i];
        squaredDistance += delta * delta;
        clamped = -box.Extent[i];
      } else if (projected > box.Extent[i]) {
        const float delta = projected - box.Extent[i];
        squaredDistance += delta * delta;
        clamped = box.Extent[i];
      }

      closest = Vector3<float>::Add(closest, Vector3<float>::Scale(axis, clamped));
    }

    if (closestPointOnBox) {
      *closestPointOnBox = closest;
    }
    return squaredDistance;
  }

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
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    return SqrtfBinary(DistVector3Box3fGetSquared(vector, box, closestPointOnBox));
  }

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
    const float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Box3<float> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3fGet(movedVector, movedBox, closestPointOnBox);
  }

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
    const float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Box3<float> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3fGetSquared(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A460D0 (FUN_00A460D0, Wm3::DistVector3Box3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::GetSquared(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented box and optionally writes the closest point.
   */
  double DistVector3Box3dGetSquared(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> center{box.Center[0], box.Center[1], box.Center[2]};
    const Vector3<double> diff = Vector3<double>::Sub(vector, center);

    Vector3<double> closest = center;
    double squaredDistance = 0.0;

    for (int i = 0; i < 3; ++i) {
      const Vector3<double> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const double projected = Vector3<double>::Dot(diff, axis);

      double clamped = projected;
      if (projected < -box.Extent[i]) {
        const double delta = projected + box.Extent[i];
        squaredDistance += delta * delta;
        clamped = -box.Extent[i];
      } else if (projected > box.Extent[i]) {
        const double delta = projected - box.Extent[i];
        squaredDistance += delta * delta;
        clamped = box.Extent[i];
      }

      closest = Vector3<double>::Add(closest, Vector3<double>::Scale(axis, clamped));
    }

    if (closestPointOnBox) {
      *closestPointOnBox = closest;
    }
    return squaredDistance;
  }

  /**
   * Address: 0x00A45800 (FUN_00A45800, Wm3::DistVector3Box3d::Get)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::Get(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Returns distance from a point to an oriented box.
   */
  double DistVector3Box3dGet(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistVector3Box3dGetSquared(vector, box, closestPointOnBox));
  }

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
    const double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Box3<double> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3dGet(movedVector, movedBox, closestPointOnBox);
  }

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
    const double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Box3<double> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3dGetSquared(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A484F0 (FUN_00A484F0, Wm3::DistVector3Segment3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Segment3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::GetSquared(Wm3::DistVector3Segment3f *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and writes the closest point.
   */
  float DistVector3Segment3fGetSquared(
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> diff = Vector3<float>::Sub(vector, segment.Origin);
    float t = Vector3<float>::Dot(segment.Direction, diff);

    if (t < -segment.Extent) {
      t = -segment.Extent;
    } else if (t > segment.Extent) {
      t = segment.Extent;
    }

    const Vector3<float> closest = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
    const Vector3<float> delta = Vector3<float>::Sub(closest, vector);

    if (closestPointOnSegment) {
      *closestPointOnSegment = closest;
    }
    return Vector3<float>::Dot(delta, delta);
  }

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
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    return SqrtfBinary(DistVector3Segment3fGetSquared(vector, segment, closestPointOnSegment));
  }

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
    const float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Segment3<float> movedSegment = segment;
    movedSegment.Origin = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segmentVelocity, t));

    return DistVector3Segment3fGet(movedVector, movedSegment, closestPointOnSegment);
  }

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
    const float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Segment3<float> movedSegment = segment;
    movedSegment.Origin = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segmentVelocity, t));

    return DistVector3Segment3fGetSquared(movedVector, movedSegment, closestPointOnSegment);
  }

  /**
   * Address: 0x00A48910 (FUN_00A48910, Wm3::DistVector3Segment3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::GetSquared(Wm3::DistVector3Segment3d *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and writes the closest point.
   */
  double DistVector3Segment3dGetSquared(
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> diff = Vector3<double>::Sub(vector, segment.Origin);
    double t = Vector3<double>::Dot(segment.Direction, diff);

    if (t < -segment.Extent) {
      t = -segment.Extent;
    } else if (t > segment.Extent) {
      t = segment.Extent;
    }

    const Vector3<double> closest = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segment.Direction, t));
    const Vector3<double> delta = Vector3<double>::Sub(closest, vector);

    if (closestPointOnSegment) {
      *closestPointOnSegment = closest;
    }
    return Vector3<double>::Dot(delta, delta);
  }

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
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistVector3Segment3dGetSquared(vector, segment, closestPointOnSegment));
  }

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
    const double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistVector3Segment3dGet(movedVector, movedSegment, closestPointOnSegment);
  }

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
    const double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistVector3Segment3dGetSquared(movedVector, movedSegment, closestPointOnSegment);
  }

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
   * and writes closest points on both primitives.
   */
  double DistLine3Segment3dGetSquared(
    const Line3<double>& line,
    const Segment3<double>& segment,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> diff = Vector3<double>::Sub(line.Origin, segment.Origin);
    const double a01 = -Vector3<double>::Dot(line.Direction, segment.Direction);
    const double b0 = Vector3<double>::Dot(diff, line.Direction);
    const double c = Vector3<double>::Dot(diff, diff);
    const double det = std::fabs(1.0 - a01 * a01);

    double lineParam = 0.0;
    double segmentParam = 0.0;
    double sqrDist = 0.0;

    if (det < 0.00000001) {
      lineParam = -b0;
      segmentParam = 0.0;
      sqrDist = b0 * lineParam + c;
    } else {
      const double b1 = -Vector3<double>::Dot(diff, segment.Direction);
      const double segmentNumerator = a01 * b0 - b1;
      const double extDet = segment.Extent * det;

      if (segmentNumerator < -extDet) {
        segmentParam = -segment.Extent;
        lineParam = -(a01 * segmentParam + b0);
        sqrDist = -lineParam * lineParam + segmentParam * (segmentParam + 2.0 * b1) + c;
      } else if (segmentNumerator > extDet) {
        segmentParam = segment.Extent;
        lineParam = -(a01 * segmentParam + b0);
        sqrDist = -lineParam * lineParam + segmentParam * (segmentParam + 2.0 * b1) + c;
      } else {
        const double invDet = 1.0 / det;
        lineParam = (a01 * b1 - b0) * invDet;
        segmentParam = segmentNumerator * invDet;
        sqrDist = lineParam * (lineParam + a01 * segmentParam + 2.0 * b0) +
          segmentParam * (a01 * lineParam + segmentParam + 2.0 * b1) + c;
      }
    }

    const Vector3<double> closestLinePoint =
      Vector3<double>::Add(line.Origin, Vector3<double>::Scale(line.Direction, lineParam));
    const Vector3<double> closestSegmentPoint =
      Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segment.Direction, segmentParam));

    if (closestPointOnLine) {
      *closestPointOnLine = closestLinePoint;
    }
    if (closestPointOnSegment) {
      *closestPointOnSegment = closestSegmentPoint;
    }

    return std::fabs(sqrDist);
  }

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
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistLine3Segment3dGetSquared(line, segment, closestPointOnLine, closestPointOnSegment));
  }

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
    const double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    Line3<double> movedLine = line;
    movedLine.Origin = Vector3<double>::Add(line.Origin, Vector3<double>::Scale(lineVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistLine3Segment3dGet(movedLine, movedSegment, closestPointOnLine, closestPointOnSegment);
  }

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
    const double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    Line3<double> movedLine = line;
    movedLine.Origin = Vector3<double>::Add(line.Origin, Vector3<double>::Scale(lineVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistLine3Segment3dGetSquared(movedLine, movedSegment, closestPointOnLine, closestPointOnSegment);
  }

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
  bool IntrBox3Sphere3fTest(const Box3<float>& box, const Sphere3<float>& sphere) noexcept
  {
    const Vector3<float> delta{
      sphere.Center.x - box.Center[0], sphere.Center.y - box.Center[1], sphere.Center.z - box.Center[2]
    };

    float distanceSquared = 0.0f;
    for (int i = 0; i < 3; ++i) {
      const Vector3<float> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const float projected = std::fabs(Vector3<float>::Dot(delta, axis));
      const float outside = projected - box.Extent[i];
      if (outside > 0.0f) {
        distanceSquared += outside * outside;
      }
    }

    return distanceSquared <= sphere.Radius * sphere.Radius;
  }

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
   * Sweeps sphere center by relative velocity against box extents expanded by radius, then computes
   * first contact point on the original oriented box.
   */
  bool IntrBox3Sphere3fStaticFind(
    const float tMax,
    const Box3<float>& box,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* const contactTime,
    Vector3<float>* const contactPoint,
    int* const intrType
  ) noexcept
  {
    if (intrType) {
      *intrType = 0;
    }

    if (IntrBox3Sphere3fTest(box, sphere)) {
      if (contactTime) {
        *contactTime = 0.0f;
      }
      if (contactPoint) {
        *contactPoint = sphere.Center;
      }
      if (intrType) {
        *intrType = 8;
      }
      return true;
    }

    const Vector3<float> relativeVelocity = Vector3<float>::Sub(velocity1, velocity0);
    if (Vector3<float>::LengthSq(relativeVelocity) <= kWm3Epsilon * kWm3Epsilon) {
      return false;
    }

    Box3<float> expanded = box;
    expanded.Extent[0] += sphere.Radius;
    expanded.Extent[1] += sphere.Radius;
    expanded.Extent[2] += sphere.Radius;

    float tEnter = 0.0f;
    if (!RayIntersectsOrientedBox(sphere.Center, relativeVelocity, expanded, &tEnter)) {
      return false;
    }

    if (tEnter < 0.0f) {
      tEnter = 0.0f;
    }
    if (tMax < tEnter) {
      return false;
    }

    const Vector3<float> sphereCenterAtContact =
      Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(velocity1, tEnter));

    Vector3<float> closest{};
    DistVector3Box3fGetSquared(sphereCenterAtContact, box, &closest);

    if (contactTime) {
      *contactTime = tEnter;
    }
    if (contactPoint) {
      *contactPoint = closest;
    }
    if (intrType) {
      *intrType = 1;
    }
    return true;
  }

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
  bool IntrSegment3Box3fTest(const Segment3<float>& segment, const Box3<float>& box) noexcept
  {
    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const Vector3<float> diff{
      segment.Origin.x - box.Center[0], segment.Origin.y - box.Center[1], segment.Origin.z - box.Center[2]
    };

    const float directionDotAxis[3] = {
      Vector3<float>::Dot(segment.Direction, axis0),
      Vector3<float>::Dot(segment.Direction, axis1),
      Vector3<float>::Dot(segment.Direction, axis2)
    };
    const float absDirectionDotAxis[3] = {
      std::fabs(directionDotAxis[0]), std::fabs(directionDotAxis[1]), std::fabs(directionDotAxis[2])
    };

    const float diffDotAxis[3] = {
      Vector3<float>::Dot(diff, axis0), Vector3<float>::Dot(diff, axis1), Vector3<float>::Dot(diff, axis2)
    };
    const float absDiffDotAxis[3] = {std::fabs(diffDotAxis[0]), std::fabs(diffDotAxis[1]), std::fabs(diffDotAxis[2])};

    for (int i = 0; i < 3; ++i) {
      const float limit = segment.Extent * absDirectionDotAxis[i] + box.Extent[i];
      if (absDiffDotAxis[i] > limit) {
        return false;
      }
    }

    const Vector3<float> wCrossD = Vector3<float>::Cross(segment.Direction, diff);

    const float test0 = std::fabs(Vector3<float>::Dot(wCrossD, axis0));
    const float limit0 = box.Extent[1] * absDirectionDotAxis[2] + box.Extent[2] * absDirectionDotAxis[1];
    if (test0 > limit0) {
      return false;
    }

    const float test1 = std::fabs(Vector3<float>::Dot(wCrossD, axis1));
    const float limit1 = box.Extent[0] * absDirectionDotAxis[2] + box.Extent[2] * absDirectionDotAxis[0];
    if (test1 > limit1) {
      return false;
    }

    const float test2 = std::fabs(Vector3<float>::Dot(wCrossD, axis2));
    const float limit2 = box.Extent[0] * absDirectionDotAxis[1] + box.Extent[1] * absDirectionDotAxis[0];
    if (test2 > limit2) {
      return false;
    }

    return true;
  }

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
  bool IntrSegment3Sphere3fTest(const Segment3<float>& segment, const Sphere3<float>& sphere) noexcept
  {
    const Vector3<float> diff = Vector3<float>::Sub(segment.Origin, sphere.Center);
    const float a0 = Vector3<float>::Dot(diff, diff) - sphere.Radius * sphere.Radius;
    const float a1 = Vector3<float>::Dot(diff, segment.Direction);
    const float discr = a1 * a1 - a0;
    if (discr < 0.0f) {
      return false;
    }

    const float q0 = a0 + segment.Extent * segment.Extent;
    const float twoA1Extent = (a1 + a1) * segment.Extent;
    const float qMinus = q0 - twoA1Extent;
    const float qPlus = q0 + twoA1Extent;
    if (qPlus * qMinus <= 0.0f) {
      return true;
    }

    if (qMinus <= 0.0f) {
      return false;
    }
    return segment.Extent > std::fabs(a1);
  }

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
  bool IntrLine3Box3fTest(const Line3<float>& line, const Box3<float>& box) noexcept
  {
    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const Vector3<float> diff{
      line.Origin.x - box.Center[0], line.Origin.y - box.Center[1], line.Origin.z - box.Center[2]
    };

    const Vector3<float> wCrossD = Vector3<float>::Cross(line.Direction, diff);
    const float absDotD0 = std::fabs(Vector3<float>::Dot(axis0, line.Direction));
    const float absDotD1 = std::fabs(Vector3<float>::Dot(axis1, line.Direction));
    const float absDotD2 = std::fabs(Vector3<float>::Dot(axis2, line.Direction));

    const float absCross0 = std::fabs(Vector3<float>::Dot(axis0, wCrossD));
    if (box.Extent[1] * absDotD2 + box.Extent[2] * absDotD1 < absCross0) {
      return false;
    }

    const float absCross1 = std::fabs(Vector3<float>::Dot(axis1, wCrossD));
    if (box.Extent[0] * absDotD2 + box.Extent[2] * absDotD0 < absCross1) {
      return false;
    }

    const float absCross2 = std::fabs(Vector3<float>::Dot(axis2, wCrossD));
    return box.Extent[1] * absDotD0 + box.Extent[0] * absDotD1 >= absCross2;
  }

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
  bool IntrLine3Box3fClip(const float denom, const float numer, float* const t0, float* const t1) noexcept
  {
    if (denom > 0.0f) {
      if ((*t1) * denom < numer) {
        return false;
      }
      if ((*t0) * denom < numer) {
        *t0 = numer / denom;
      }
      return true;
    }

    if (denom < 0.0f) {
      if ((*t0) * denom < numer) {
        return false;
      }
      if ((*t1) * denom < numer) {
        *t1 = numer / denom;
      }
      return true;
    }

    return numer <= 0.0f;
  }

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
    const bool solid,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    int localQuantity = 0;
    int localIntrType = 0;
    Vector3<float> localPoints[2]{};
    int* const outQuantity = quantity ? quantity : &localQuantity;
    int* const outIntrType = intrType ? intrType : &localIntrType;
    Vector3<float>* const outPoints = points ? points : localPoints;

    const Vector3<float> diff{origin.x - box.Center[0], origin.y - box.Center[1], origin.z - box.Center[2]};

    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const float boxOrigin[3] = {
      Vector3<float>::Dot(axis0, diff), Vector3<float>::Dot(axis1, diff), Vector3<float>::Dot(axis2, diff)
    };
    const float boxDirection[3] = {
      Vector3<float>::Dot(axis0, direction),
      Vector3<float>::Dot(axis1, direction),
      Vector3<float>::Dot(axis2, direction)
    };

    const float initialT0 = t0;
    const float initialT1 = t1;

    const bool clipped = IntrLine3Box3fClip(boxDirection[0], -boxOrigin[0] - box.Extent[0], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[0], boxOrigin[0] - box.Extent[0], &t0, &t1) &&
                         IntrLine3Box3fClip(boxDirection[1], -boxOrigin[1] - box.Extent[1], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[1], boxOrigin[1] - box.Extent[1], &t0, &t1) &&
                         IntrLine3Box3fClip(boxDirection[2], -boxOrigin[2] - box.Extent[2], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[2], boxOrigin[2] - box.Extent[2], &t0, &t1);

    if (clipped && (solid || initialT0 != t0 || initialT1 != t1)) {
      if (t0 >= t1) {
        *outIntrType = 1;
        *outQuantity = 1;
        outPoints[0] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t0));
      } else {
        *outIntrType = 2;
        *outQuantity = 2;
        outPoints[0] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t0));
        outPoints[1] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t1));
      }
      return *outIntrType != 0;
    }

    *outQuantity = 0;
    *outIntrType = 0;
    return false;
  }

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
    const Line3<float>& line,
    const Box3<float>& box,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    const float maxT = std::numeric_limits<float>::max();
    return IntrLine3Box3fDoClipping(-maxT, maxT, line.Origin, line.Direction, box, true, quantity, points, intrType);
  }

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
    const bool solid,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    return IntrLine3Box3fDoClipping(
      -segment.Extent, segment.Extent, segment.Origin, segment.Direction, box, solid, quantity, points, intrType
    );
  }

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
    int* const quantity,
    Vector3<float>* const points,
    float* const segmentT,
    const float zeroThreshold
  ) noexcept
  {
    int outQuantity = 0;

    const Vector3<float> diff = Vector3<float>::Sub(segment.Origin, sphere.Center);
    const float a0 = Vector3<float>::Dot(diff, diff) - sphere.Radius * sphere.Radius;
    const float a1 = Vector3<float>::Dot(segment.Direction, diff);
    const float discr = a1 * a1 - a0;

    if (discr < 0.0f) {
      if (quantity) {
        *quantity = 0;
      }
      return false;
    }

    const float q0 = a0 + segment.Extent * segment.Extent;
    const float q1 = 2.0f * a1 * segment.Extent;
    const float qMinus = q0 - q1;
    const float qPlus = q0 + q1;

    if (qPlus * qMinus > 0.0f) {
      if (qMinus <= 0.0f || segment.Extent <= std::fabs(a1)) {
        if (quantity) {
          *quantity = 0;
        }
        return false;
      }

      if (zeroThreshold > discr) {
        const float t = -a1;
        if (segmentT) {
          segmentT[0] = t;
        }
        if (points) {
          points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
        }
        outQuantity = 1;
      } else {
        const float root = SqrtfBinary(discr);
        const float t0 = -a1 - root;
        const float t1 = root - a1;

        if (segmentT) {
          segmentT[0] = t0;
          segmentT[1] = t1;
        }
        if (points) {
          points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t0));
          points[1] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t1));
        }
        outQuantity = 2;
      }
    } else {
      const float root = SqrtfBinary(discr);
      const float t = (qMinus <= 0.0f) ? (root - a1) : (-a1 - root);

      if (segmentT) {
        segmentT[0] = t;
      }
      if (points) {
        points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
      }
      outQuantity = 1;
    }

    if (quantity) {
      *quantity = outQuantity;
    }
    return outQuantity > 0;
  }

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
    const float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1
  ) noexcept
  {
    (void)tMax;

    if (IntrSegment3Sphere3fTest(segment, sphere)) {
      return true;
    }

    Vector3<float> relative = Vector3<float>::Sub(velocity1, velocity0);
    const float relativeLength = Vector3<float>::Normalize(relative);

    Segment3<float> sweepSegment{};
    sweepSegment.Origin =
      Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(Vector3<float>::Sub(velocity1, velocity0), 0.5f));
    sweepSegment.Direction = relative;
    sweepSegment.Extent = relativeLength * 0.5f;

    Capsule3<float> capsule{};
    capsule.Segment = segment;
    capsule.Radius = sphere.Radius;

    float roots[2]{};
    const int rootCount = LineCapsuleIntersectionRoots(sweepSegment.Origin, sweepSegment.Direction, capsule, roots);
    float clipped[2]{};
    return ClipRootsToPathExtent(roots, rootCount, sweepSegment.Extent, clipped) > 0;
  }

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
    const float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* const contactTime,
    Vector3<float>* const contactPoint,
    int* const intrType
  ) noexcept
  {
    int localQuantity = 0;
    Vector3<float> localPoints[2]{};
    float localSegmentT[2]{};
    if (IntrSegment3Sphere3fFind(segment, sphere, &localQuantity, localPoints, localSegmentT, kWm3Epsilon)) {
      if (contactTime) {
        *contactTime = 0.0f;
      }
      if (contactPoint) {
        *contactPoint = sphere.Center;
      }
      if (intrType) {
        *intrType = 8;
      }
      return true;
    }

    const Vector3<float> relativeDelta = Vector3<float>::Sub(velocity1, velocity0);
    Vector3<float> relativeDirection = relativeDelta;
    const float relativeLength = Vector3<float>::Normalize(relativeDirection);

    Segment3<float> sweepSegment{};
    sweepSegment.Origin = Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(relativeDelta, 0.5f));
    sweepSegment.Direction = relativeDirection;
    sweepSegment.Extent = relativeLength * 0.5f;

    Capsule3<float> capsule{};
    capsule.Segment = segment;
    capsule.Radius = sphere.Radius;

    float roots[2]{};
    const int rootCount = LineCapsuleIntersectionRoots(sweepSegment.Origin, sweepSegment.Direction, capsule, roots);
    float clipped[2]{};
    const int clippedCount = ClipRootsToPathExtent(roots, rootCount, sweepSegment.Extent, clipped);
    if (clippedCount <= 0) {
      if (intrType) {
        *intrType = 0;
      }
      return false;
    }

    const float t = clipped[0];
    if (tMax < t) {
      if (intrType) {
        *intrType = 0;
      }
      return false;
    }

    if (contactTime) {
      *contactTime = t;
    }

    const Vector3<float> sphereCenterAtT = Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(velocity1, t));
    const Vector3<float> segmentOriginAtT = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(velocity0, t));

    const float projected =
      Vector3<float>::Dot(segment.Direction, Vector3<float>::Sub(sphereCenterAtT, segmentOriginAtT));
    float clamped = projected;
    if (clamped < -segment.Extent) {
      clamped = -segment.Extent;
    } else if (clamped > segment.Extent) {
      clamped = segment.Extent;
    }

    if (contactPoint) {
      *contactPoint = Vector3<float>::Add(segmentOriginAtT, Vector3<float>::Scale(segment.Direction, clamped));
    }

    if (intrType) {
      // Binary path leaves this as non-penetration type for dynamic-hit branch.
      *intrType = 0;
    }
    return true;
  }
} // namespace Wm3
