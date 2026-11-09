#include "moho/sim/WaterBodies.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>

namespace moho
{
  namespace
  {
    constexpr std::size_t kMaxWaterBodies = 255u;

    void AddLog(std::vector<std::string>* const log, const char* const text)
    {
      if (log != nullptr) {
        log->emplace_back(text);
      }
    }

    /// `value` truncated toward the cell below it and clamped to `[0, count - 1]`; NaN gives 0.
    [[nodiscard]] std::int32_t ClampedCell(const float value, const std::int32_t count) noexcept
    {
      if (!(value >= 0.0f)) {
        return 0;
      }
      if (value >= static_cast<float>(count - 1)) {
        return count - 1;
      }
      return static_cast<std::int32_t>(value);
    }
  } // namespace

  std::vector<float> WaterBodyOutlinePolygon(const std::vector<float>& points)
  {
    std::vector<float> polygon;
    const std::size_t count = points.size() / 2u;
    if (count < 3u) {
      return polygon;
    }
    polygon.reserve(count * static_cast<std::size_t>(kWaterBodyOutlineSteps) * 2u);
    const auto at = [&](const std::size_t index, const std::size_t axis) { return points[(index % count) * 2u + axis]; };
    for (std::size_t span = 0; span < count; ++span) {
      for (std::int32_t step = 0; step < kWaterBodyOutlineSteps; ++step) {
        // Steps are a power of two, so t, t^2 and t^3 are exact.
        const float t = static_cast<float>(step) / static_cast<float>(kWaterBodyOutlineSteps);
        const float t2 = t * t;
        const float t3 = t2 * t;
        for (std::size_t axis = 0; axis < 2u; ++axis) {
          const float p0 = at(span + count - 1u, axis);
          const float p1 = at(span, axis);
          const float p2 = at(span + 1u, axis);
          const float p3 = at(span + 2u, axis);
          const float a = 2.0f * p1;
          const float b = p2 - p0;
          const float c = ((2.0f * p0) - (5.0f * p1)) + ((4.0f * p2) - p3);
          const float d = ((3.0f * p1) - p0) + (p3 - (3.0f * p2));
          polygon.push_back(0.5f * (((a + (b * t)) + (c * t2)) + (d * t3)));
        }
      }
    }
    return polygon;
  }

  bool WaterBodyPolygonContains(const std::vector<float>& polygon, const float x, const float z) noexcept
  {
    const std::size_t count = polygon.size() / 2u;
    bool inside = false;
    for (std::size_t i = 0, j = count - 1u; i < count; j = i++) {
      const float xi = polygon[i * 2u];
      const float zi = polygon[i * 2u + 1u];
      const float xj = polygon[j * 2u];
      const float zj = polygon[j * 2u + 1u];
      if ((zi > z) != (zj > z)) {
        const float crossX = xi + ((z - zi) / (zj - zi)) * (xj - xi);
        if (x < crossX) {
          inside = !inside;
        }
      }
    }
    return inside;
  }

  std::unique_ptr<CWaterBodies> CWaterBodies::Build(
    const std::uint16_t* const heights,
    const std::int32_t width,
    const std::int32_t height,
    const float heightScale,
    const std::vector<SWaterBodyDesc>& descs,
    std::vector<std::string>* const log
  )
  {
    if (heights == nullptr || width < 2 || height < 2 || descs.empty()) {
      return nullptr;
    }

    std::unique_ptr<CWaterBodies> result(new CWaterBodies());
    result->mVertexWidth = width;
    result->mVertexHeight = height;
    result->mVertexBody.assign(static_cast<std::size_t>(width) * static_cast<std::size_t>(height), 0u);

    std::vector<std::int32_t> pending;
    char line[256];
    for (std::size_t descIndex = 0; descIndex < descs.size(); ++descIndex) {
      const SWaterBodyDesc& desc = descs[descIndex];
      if (result->mBodies.size() >= kMaxWaterBodies) {
        std::snprintf(line, sizeof(line), "water body %zu skipped: a map has at most 255", descIndex + 1u);
        AddLog(log, line);
        continue;
      }

      std::int32_t x0 = 0;
      std::int32_t z0 = 0;
      std::int32_t x1 = width - 1;
      std::int32_t z1 = height - 1;
      if (desc.hasBounds) {
        x0 = std::max(x0, std::min(desc.x0, desc.x1));
        z0 = std::max(z0, std::min(desc.z0, desc.z1));
        x1 = std::min(x1, std::max(desc.x0, desc.x1));
        z1 = std::min(z1, std::max(desc.z0, desc.z1));
      }

      // An outline narrows the fill to the vertices inside its curve.
      std::vector<float> polygon;
      if (!desc.outline.empty()) {
        polygon = WaterBodyOutlinePolygon(desc.outline);
        if (polygon.empty()) {
          std::snprintf(line, sizeof(line), "water body %zu skipped: an outline needs at least 3 points", descIndex + 1u);
          AddLog(log, line);
          continue;
        }
        float minX = polygon[0];
        float maxX = polygon[0];
        float minZ = polygon[1];
        float maxZ = polygon[1];
        for (std::size_t i = 0; i < polygon.size(); i += 2u) {
          minX = std::min(minX, polygon[i]);
          maxX = std::max(maxX, polygon[i]);
          minZ = std::min(minZ, polygon[i + 1u]);
          maxZ = std::max(maxZ, polygon[i + 1u]);
        }
        const float lastX = static_cast<float>(width - 1);
        const float lastZ = static_cast<float>(height - 1);
        x0 = std::max(x0, static_cast<std::int32_t>(std::clamp(std::floor(minX), 0.0f, lastX)));
        z0 = std::max(z0, static_cast<std::int32_t>(std::clamp(std::floor(minZ), 0.0f, lastZ)));
        x1 = std::min(x1, static_cast<std::int32_t>(std::clamp(std::ceil(maxX), 0.0f, lastX)));
        z1 = std::min(z1, static_cast<std::int32_t>(std::clamp(std::ceil(maxZ), 0.0f, lastZ)));
      }
      const auto inside = [&](const std::int32_t x, const std::int32_t z) {
        return polygon.empty() || WaterBodyPolygonContains(polygon, static_cast<float>(x), static_cast<float>(z));
      };

      if (!desc.hasSeed) {
        if (polygon.empty()) {
          std::snprintf(line, sizeof(line), "water body %zu skipped: no Seed and no Outline", descIndex + 1u);
          AddLog(log, line);
          continue;
        }
        const auto number = static_cast<std::uint8_t>(result->mBodies.size() + 1u);
        std::uint32_t taken = 0;
        for (std::int32_t z = z0; z <= z1; ++z) {
          for (std::int32_t x = x0; x <= x1; ++x) {
            const std::size_t index = static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x);
            if (result->mVertexBody[index] == 0u && static_cast<float>(heights[index]) * heightScale < desc.fillTo &&
                inside(x, z)) {
              result->mVertexBody[index] = number;
              ++taken;
            }
          }
        }
        if (taken == 0u) {
          std::snprintf(line, sizeof(line), "water body %zu skipped: no terrain inside its outline is below %g",
                        descIndex + 1u, static_cast<double>(desc.fillTo));
          AddLog(log, line);
          continue;
        }
        SWaterBody body;
        body.elevation = desc.dry ? kWaterBodyNoWater : desc.elevation;
        body.deep = desc.dry ? kWaterBodyNoWater : desc.deep;
        body.abyss = desc.dry ? kWaterBodyNoWater : desc.abyss;
        result->mBodies.push_back(body);
        continue;
      }

      const float seedX = std::floor(desc.seedX + 0.5f);
      const float seedZ = std::floor(desc.seedZ + 0.5f);
      if (!(seedX >= static_cast<float>(x0) && seedX <= static_cast<float>(x1) &&
            seedZ >= static_cast<float>(z0) && seedZ <= static_cast<float>(z1))) {
        std::snprintf(
          line, sizeof(line), "water body %zu skipped: seed (%g, %g) is off the map or outside its bounds",
          descIndex + 1u, static_cast<double>(desc.seedX), static_cast<double>(desc.seedZ)
        );
        AddLog(log, line);
        continue;
      }

      const std::int32_t sx = static_cast<std::int32_t>(seedX);
      const std::int32_t sz = static_cast<std::int32_t>(seedZ);
      const std::size_t seedIndex = static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx);
      const auto below = [&](const std::size_t index) {
        return static_cast<float>(heights[index]) * heightScale < desc.fillTo;
      };
      if (result->mVertexBody[seedIndex] != 0u || !below(seedIndex) || !inside(sx, sz)) {
        std::snprintf(
          line, sizeof(line), "water body %zu skipped: terrain at its seed (%g, %g) is not below %g or is another body's",
          descIndex + 1u, static_cast<double>(desc.seedX), static_cast<double>(desc.seedZ), static_cast<double>(desc.fillTo)
        );
        AddLog(log, line);
        continue;
      }

      const auto number = static_cast<std::uint8_t>(result->mBodies.size() + 1u);
      SWaterBody body;
      body.elevation = desc.dry ? kWaterBodyNoWater : desc.elevation;
      body.deep = desc.dry ? kWaterBodyNoWater : desc.deep;
      body.abyss = desc.dry ? kWaterBodyNoWater : desc.abyss;
      result->mBodies.push_back(body);

      // Four-way fill over vertices, from the seed.
      pending.clear();
      result->mVertexBody[seedIndex] = number;
      pending.push_back(sz * width + sx);
      while (!pending.empty()) {
        const std::int32_t index = pending.back();
        pending.pop_back();
        const std::int32_t x = index % width;
        const std::int32_t z = index / width;
        const std::int32_t neighbours[4][2] = {{x - 1, z}, {x + 1, z}, {x, z - 1}, {x, z + 1}};
        for (const auto& neighbour : neighbours) {
          const std::int32_t nx = neighbour[0];
          const std::int32_t nz = neighbour[1];
          if (nx < x0 || nx > x1 || nz < z0 || nz > z1) {
            continue;
          }
          const std::size_t next = static_cast<std::size_t>(nz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(nx);
          if (result->mVertexBody[next] != 0u || !below(next) || !inside(nx, nz)) {
            continue;
          }
          result->mVertexBody[next] = number;
          pending.push_back(nz * width + nx);
        }
      }
    }

    if (result->mBodies.empty()) {
      return nullptr;
    }

    // Cells: the lowest body number among the four corners.
    const std::int32_t cellWidth = width - 1;
    const std::int32_t cellHeight = height - 1;
    result->mCellBody.assign(static_cast<std::size_t>(cellWidth) * static_cast<std::size_t>(cellHeight), 0u);
    for (SWaterBody& body : result->mBodies) {
      body.x0 = cellWidth;
      body.z0 = cellHeight;
      body.x1 = 0;
      body.z1 = 0;
    }
    bool anyCell = false;
    for (std::int32_t z = 0; z < cellHeight; ++z) {
      for (std::int32_t x = 0; x < cellWidth; ++x) {
        std::uint8_t owner = 0u;
        for (std::int32_t dz = 0; dz < 2; ++dz) {
          for (std::int32_t dx = 0; dx < 2; ++dx) {
            const std::uint8_t corner = result->mVertexBody[static_cast<std::size_t>(z + dz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x + dx)];
            if (corner != 0u && (owner == 0u || corner < owner)) {
              owner = corner;
            }
          }
        }
        if (owner == 0u) {
          continue;
        }
        result->mCellBody[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellWidth) + static_cast<std::size_t>(x)] = owner;
        SWaterBody& body = result->mBodies[owner - 1u];
        ++body.cellCount;
        body.x0 = std::min(body.x0, x);
        body.z0 = std::min(body.z0, z);
        body.x1 = std::max(body.x1, x + 1);
        body.z1 = std::max(body.z1, z + 1);
        anyCell = true;
      }
    }
    for (SWaterBody& body : result->mBodies) {
      if (body.cellCount == 0u) {
        body.x0 = body.z0 = body.x1 = body.z1 = 0;
      }
    }

    if (!anyCell) {
      return nullptr;
    }
    static std::atomic<std::uint32_t> sGenerations{0};
    result->mGeneration = ++sGenerations;
    return result;
  }

  std::uint8_t CWaterBodies::BodyOfBlock(const std::int32_t x, const std::int32_t z) const noexcept
  {
    std::uint8_t owner = 0u;
    for (std::int32_t dz = 0; dz < 2; ++dz) {
      for (std::int32_t dx = 0; dx < 2; ++dx) {
        const std::uint8_t body = BodyOfCell(x + dx, z + dz);
        if (body != 0u && (owner == 0u || body < owner)) {
          owner = body;
        }
      }
    }
    return owner;
  }

  std::uint8_t CWaterBodies::BodyOfCell(const std::int32_t x, const std::int32_t z) const noexcept
  {
    const std::int32_t cellWidth = CellWidth();
    const std::int32_t cx = std::clamp(x, 0, cellWidth - 1);
    const std::int32_t cz = std::clamp(z, 0, CellHeight() - 1);
    return mCellBody[static_cast<std::size_t>(cz) * static_cast<std::size_t>(cellWidth) + static_cast<std::size_t>(cx)];
  }

  std::uint8_t CWaterBodies::BodyOfVertex(const std::int32_t x, const std::int32_t z) const noexcept
  {
    const std::int32_t vx = std::clamp(x, 0, mVertexWidth - 1);
    const std::int32_t vz = std::clamp(z, 0, mVertexHeight - 1);
    return mVertexBody[static_cast<std::size_t>(vz) * static_cast<std::size_t>(mVertexWidth) + static_cast<std::size_t>(vx)];
  }

  float CWaterBodies::LevelAt(const float x, const float z, const float seaLevel) const noexcept
  {
    const std::uint8_t body = BodyOfCell(ClampedCell(x, CellWidth()), ClampedCell(z, CellHeight()));
    return body != 0u ? mBodies[body - 1u].elevation : seaLevel;
  }

  float CWaterBodies::LevelOfVertex(const std::int32_t x, const std::int32_t z, const float seaLevel) const noexcept
  {
    const std::uint8_t body = BodyOfVertex(x, z);
    return body != 0u ? mBodies[body - 1u].elevation : seaLevel;
  }

  float CWaterBodies::HighestLevel() const noexcept
  {
    float highest = kWaterBodyNoWater;
    for (const SWaterBody& body : mBodies) {
      highest = std::max(highest, body.elevation);
    }
    return highest;
  }
} // namespace moho
