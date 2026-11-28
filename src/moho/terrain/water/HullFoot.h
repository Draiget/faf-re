#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

// The volume of a body that the water has to make room for: for every cell of a grid over the model (x, z) the lowest
// and the highest height of the mesh in that cell (the column of material the cell holds). Pure functions on plain
// numbers (no engine types).
//
// The water simulation lets a body push the water like a body does: at every frame the volume of the part of each
// column that is under the surface is worked out in the world, and what changed since the last frame is handed to the
// simulation (HullDisplacement.h). A bow that moves into water raises it, a stern that leaves a place lowers it and
// throws foam, a turn, a drift, a hull that heaves or an aircraft that drops into the sea all do the same and the V of
// a wake is what the simulation makes of it: nothing in the shape of a wake is written down.
namespace moho::water
{
  constexpr int kFootMax = 24;

  struct HullFoot
  {
    bool valid = false;
    int nx = 0;
    int nz = 0;
    float x0 = 0.0f; // the model corner of the grid
    float z0 = 0.0f;
    float cellX = 1.0f; // the size of a cell (model units)
    float cellZ = 1.0f;
    float bottom[kFootMax * kFootMax]{};
    float top[kFootMax * kFootMax]{};
    bool has[kFootMax * kFootMax]{};
  };

  // `vertex(i, x, y, z)` fills the position of vertex i, `triangle(t, a, b, c)` the three vertex indices of triangle t.
  template <class Vertex, class Triangle>
  HullFoot ComputeHullFoot(
    const std::size_t vertexCount,
    Vertex&& vertex,
    const std::size_t triangleCount,
    Triangle&& triangle
  )
  {
    HullFoot foot;
    if (vertexCount < 4U || triangleCount < 2U) {
      return foot;
    }
    float xMin = 1.0e30f, xMax = -1.0e30f, zMin = 1.0e30f, zMax = -1.0e30f;
    for (std::size_t i = 0; i < vertexCount; ++i) {
      float x, y, z;
      vertex(i, x, y, z);
      if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) {
        return foot;
      }
      xMin = std::min(xMin, x);
      xMax = std::max(xMax, x);
      zMin = std::min(zMin, z);
      zMax = std::max(zMax, z);
    }
    const float extentX = xMax - xMin;
    const float extentZ = zMax - zMin;
    const float longest = std::max(extentX, extentZ);
    if (!(longest > 0.05f)) {
      return foot;
    }
    const float cell = longest / static_cast<float>(kFootMax);
    foot.nx = std::min(std::max(static_cast<int>(std::ceil(extentX / cell)), 1), kFootMax);
    foot.nz = std::min(std::max(static_cast<int>(std::ceil(extentZ / cell)), 1), kFootMax);
    foot.cellX = extentX / static_cast<float>(foot.nx);
    foot.cellZ = extentZ / static_cast<float>(foot.nz);
    foot.x0 = xMin;
    foot.z0 = zMin;
    for (int i = 0; i < kFootMax * kFootMax; ++i) {
      foot.bottom[i] = 1.0e30f;
      foot.top[i] = -1.0e30f;
    }
    const auto cellOf = [&](const float x, const float z, int& cx, int& cz) {
      cx = std::min(std::max(static_cast<int>((x - foot.x0) / foot.cellX), 0), foot.nx - 1);
      cz = std::min(std::max(static_cast<int>((z - foot.z0) / foot.cellZ), 0), foot.nz - 1);
    };
    const auto put = [&](const int cx, const int cz, const float y) {
      const int k = cz * kFootMax + cx;
      foot.bottom[k] = std::min(foot.bottom[k], y);
      foot.top[k] = std::max(foot.top[k], y);
      foot.has[k] = true;
    };
    for (std::size_t i = 0; i < vertexCount; ++i) {
      float x, y, z;
      vertex(i, x, y, z);
      int cx, cz;
      cellOf(x, z, cx, cz);
      put(cx, cz, y);
    }
    // the triangles cover the cells between their vertices: the height of the triangle's plane at the centre of every
    // cell the triangle covers
    for (std::size_t t = 0; t < triangleCount; ++t) {
      std::uint32_t ia, ib, ic;
      triangle(t, ia, ib, ic);
      if (ia >= vertexCount || ib >= vertexCount || ic >= vertexCount) {
        continue;
      }
      float ax, ay, az, bx, by, bz, cx, cy, cz;
      vertex(ia, ax, ay, az);
      vertex(ib, bx, by, bz);
      vertex(ic, cx, cy, cz);
      const float det = (bz - cz) * (ax - cx) + (cx - bx) * (az - cz);
      if (std::fabs(det) < 1.0e-9f) {
        continue; // standing on its edge: it covers no area from above
      }
      int x0c, z0c, x1c, z1c;
      cellOf(std::min(ax, std::min(bx, cx)), std::min(az, std::min(bz, cz)), x0c, z0c);
      cellOf(std::max(ax, std::max(bx, cx)), std::max(az, std::max(bz, cz)), x1c, z1c);
      for (int jz = z0c; jz <= z1c; ++jz) {
        for (int ix = x0c; ix <= x1c; ++ix) {
          const float px = foot.x0 + (static_cast<float>(ix) + 0.5f) * foot.cellX;
          const float pz = foot.z0 + (static_cast<float>(jz) + 0.5f) * foot.cellZ;
          const float l1 = ((bz - cz) * (px - cx) + (cx - bx) * (pz - cz)) / det;
          const float l2 = ((cz - az) * (px - cx) + (ax - cx) * (pz - cz)) / det;
          const float l3 = 1.0f - l1 - l2;
          if (l1 >= -0.02f && l2 >= -0.02f && l3 >= -0.02f) {
            put(ix, jz, l1 * ay + l2 * by + l3 * cy);
          }
        }
      }
    }
    int cells = 0;
    for (int jz = 0; jz < foot.nz; ++jz) {
      for (int ix = 0; ix < foot.nx; ++ix) {
        cells += foot.has[jz * kFootMax + ix] ? 1 : 0;
      }
    }
    foot.valid = cells >= 2;
    return foot;
  }
} // namespace moho::water
