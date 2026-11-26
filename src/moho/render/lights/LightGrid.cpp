#include "moho/render/lights/LightGrid.h"

#include <algorithm>
#include <cmath>

namespace moho::lights
{
  GridLayout GridLayout::ForMap(
    const float sizeX,
    const float sizeZ
  )
  {
    GridLayout layout;
    const float sx = std::isfinite(sizeX) && sizeX > 1.0f ? sizeX : 1.0f;
    const float sz = std::isfinite(sizeZ) && sizeZ > 1.0f ? sizeZ : 1.0f;
    const float longest = std::max(sx, sz);
    layout.cellSize = std::max(kMinCellSize, longest / static_cast<float>(kMaxGridCells));
    layout.cellsX = std::min<std::uint32_t>(kMaxGridCells, static_cast<std::uint32_t>(std::ceil(sx / layout.cellSize)));
    layout.cellsZ = std::min<std::uint32_t>(kMaxGridCells, static_cast<std::uint32_t>(std::ceil(sz / layout.cellSize)));
    layout.cellsX = std::max<std::uint32_t>(1, layout.cellsX);
    layout.cellsZ = std::max<std::uint32_t>(1, layout.cellsZ);
    return layout;
  }

  std::uint32_t LightGridImage::DataRows(
    const std::uint32_t lightCount
  )
  {
    const std::uint32_t texels = std::max<std::uint32_t>(1, lightCount) * kTexelsPerLight;
    return (texels + kDataWidth - 1) / kDataWidth;
  }

  float Occluder::Radius() const
  {
    float s = 0.0f;
    for (int i = 0; i < 3; ++i) {
      s += axis[i][0] * axis[i][0] + axis[i][1] * axis[i][1] + axis[i][2] * axis[i][2];
    }
    return std::sqrt(s);
  }

  namespace
  {
    // The table texel of cell (cx, cz): x = first light list texel, y = light list texels, z = first occluder list
    // texel, w = occluder list texels.
    const float* TableTexel(
      const LightGridImage& image,
      const std::uint32_t cx,
      const std::uint32_t cz
    )
    {
      const std::size_t cell = static_cast<std::size_t>(cz) * image.layout.cellsX + cx;
      if (cx >= image.layout.cellsX || cz >= image.layout.cellsZ || (cell + 1) * 4u > image.grid.size()) {
        return nullptr;
      }
      return &image.grid[cell * 4u];
    }

    // The entries of a list of `texels` texels at `first`, up to `capacity`; entries are index + 1, zero ends a list.
    std::uint32_t ReadList(
      const LightGridImage& image,
      const float first,
      const float texels,
      std::uint32_t* const indices,
      const std::uint32_t capacity
    )
    {
      std::uint32_t n = 0;
      const auto start = static_cast<std::size_t>(first);
      const auto count = static_cast<std::size_t>(texels) * 4u;
      for (std::size_t i = 0; i < count && n < capacity; ++i) {
        const std::size_t at = start * 4u + i;
        if (at >= image.grid.size()) {
          break;
        }
        const float entry = image.grid[at];
        if (entry == 0.0f) {
          break;
        }
        indices[n++] = static_cast<std::uint32_t>(entry) - 1u;
      }
      return n;
    }
  } // namespace

  std::uint32_t LightGridImage::CellCount(
    const std::uint32_t cx,
    const std::uint32_t cz
  ) const
  {
    const float* const table = TableTexel(*this, cx, cz);
    if (table == nullptr) {
      return 0u;
    }
    std::uint32_t scratch[kMaxLightsPerCell];
    return ReadList(*this, table[0], table[1], scratch, kMaxLightsPerCell);
  }

  std::uint32_t LightGridImage::CellLights(
    const float x,
    const float z,
    std::uint32_t (&indices)[kMaxLightsPerCell]
  ) const
  {
    const float fx = std::floor((x - layout.originX) / layout.cellSize);
    const float fz = std::floor((z - layout.originZ) / layout.cellSize);
    if (
      !(fx >= 0.0f && fz >= 0.0f && fx < static_cast<float>(layout.cellsX) && fz < static_cast<float>(layout.cellsZ)) ||
      grid.empty()
    ) {
      return 0;
    }
    const float* const table = TableTexel(*this, static_cast<std::uint32_t>(fx), static_cast<std::uint32_t>(fz));
    return table == nullptr ? 0u : ReadList(*this, table[0], table[1], indices, kMaxLightsPerCell);
  }

  std::uint32_t LightGridImage::CellOccluders(
    const float x,
    const float z,
    std::uint32_t (&indices)[kMaxOccludersPerCell]
  ) const
  {
    const float fx = std::floor((x - layout.originX) / layout.cellSize);
    const float fz = std::floor((z - layout.originZ) / layout.cellSize);
    if (
      !(fx >= 0.0f && fz >= 0.0f && fx < static_cast<float>(layout.cellsX) && fz < static_cast<float>(layout.cellsZ)) ||
      grid.empty()
    ) {
      return 0;
    }
    const float* const table = TableTexel(*this, static_cast<std::uint32_t>(fx), static_cast<std::uint32_t>(fz));
    return table == nullptr ? 0u : ReadList(*this, table[2], table[3], indices, kMaxOccludersPerCell);
  }

  void BuildLightGrid(
    const std::vector<Light>& lights,
    const GridLayout& layout,
    LightGridImage& image,
    const std::vector<Occluder>* const occluders,
    const bool withCells
  )
  {
    image.layout = layout;
    image.cellsLit = 0;
    image.overflow = 0;
    image.outsideMap = 0;
    image.skipped = 0;

    const std::size_t requested = std::min(lights.size(), kMaxGridLights);
    image.lightCount = 0;
    image.data.assign(
      static_cast<std::size_t>(LightGridImage::DataRows(static_cast<std::uint32_t>(requested))) * kDataWidth * 4u, 0.0f
    );
    image.entries = 0;
    image.occluderCount = 0;
    image.occluderEntries = 0;
    image.occluders.clear();
    // the table first: one texel per cell, all zero (no list); the lists are appended behind it
    const std::size_t tableTexels = static_cast<std::size_t>(layout.cellsX) * layout.cellsZ;
    image.grid.clear();
    if (withCells) {
      image.grid.assign(tableTexels * 4u, 0.0f);
    }

    // Every (cell, light) pair the lights' footprints produce, with what the light adds at the middle of the cell.
    struct CellLight
    {
      std::uint32_t cell;
      float contribution;
      std::uint32_t light;
    };
    std::vector<CellLight> pairs;
    if (withCells) {
      pairs.reserve(requested * 16u);
    }
    // How many lights each cell lists so far. The lights come strongest first; a light that would take a cell past
    // kMaxLightsPerCell is left out *everywhere* (a whole light that is missing is a faint change over its whole
    // footprint). Cutting each cell's own list instead dropped a different set of lights in each cell of a crowded
    // fight (a hundred units, a thousand glow lights in a few cells), and the lighting jumped at the borders of those
    // cells: big lit squares.
    std::vector<std::uint16_t> listed(withCells ? static_cast<std::size_t>(layout.cellsX) * layout.cellsZ : 0u, 0);

    const float invCell = 1.0f / layout.cellSize;
    const float spanX = static_cast<float>(layout.cellsX) * layout.cellSize;
    const float spanZ = static_cast<float>(layout.cellsZ) * layout.cellSize;

    for (std::size_t i = 0; i < requested; ++i) {
      const Light& l = lights[i];
      const bool finite = std::isfinite(l.pos[0]) && std::isfinite(l.pos[1]) && std::isfinite(l.pos[2]) &&
        std::isfinite(l.radius) && std::isfinite(l.rgb[0]) && std::isfinite(l.rgb[1]) && std::isfinite(l.rgb[2]) &&
        l.radius > 0.0f;
      if (!finite) {
        ++image.skipped;
        continue;
      }

      // The light keeps the next free index even if its footprint misses the map: the shader may still be handed its
      // index by a cell of another light, never by this one, so an unreferenced entry is harmless and the indices stay
      // equal to the ranking.
      const std::uint32_t index = image.lightCount++;
      float* const a = &image.data[static_cast<std::size_t>(index) * kTexelsPerLight * 4u];
      a[0] = l.pos[0];
      a[1] = l.pos[1];
      a[2] = l.pos[2];
      a[3] = l.kind == Kind::Spot
        ? -l.radius
        : l.radius; // a spotlight has a negative radius: the shader tells it from a capsule by that
      a[4] = l.rgb[0];
      a[5] = l.rgb[1];
      a[6] = l.rgb[2];
      a[7] = static_cast<float>(l.kind);
      const bool capsule = l.kind == Kind::Beam || l.kind == Kind::Trail;
      const bool spot = l.kind == Kind::Spot;
      a[8] = capsule || spot ? l.end[0] : l.pos[0];
      a[9] = capsule || spot ? l.end[1] : l.pos[1];
      a[10] = capsule || spot ? l.end[2] : l.pos[2];
      a[11] = spot ? l.cone : 0.0f;

      // Cells whose rectangle the light's footprint reaches: a circle, or for a capsule the circle swept along the
      // segment.
      const bool finiteEnd =
        !capsule || (std::isfinite(l.end[0]) && std::isfinite(l.end[1]) && std::isfinite(l.end[2]));
      if (!finiteEnd) {
        ++image.skipped;
        --image.lightCount;
        continue;
      }
      if (!withCells) {
        continue; // the field needs the light's data only
      }
      const float ex = capsule ? l.end[0] : l.pos[0];
      const float ez = capsule ? l.end[2] : l.pos[2];
      const float minX = std::min(l.pos[0], ex) - l.radius - layout.originX;
      const float maxX = std::max(l.pos[0], ex) + l.radius - layout.originX;
      const float minZ = std::min(l.pos[2], ez) - l.radius - layout.originZ;
      const float maxZ = std::max(l.pos[2], ez) + l.radius - layout.originZ;
      if (maxX < 0.0f || maxZ < 0.0f || minX >= spanX || minZ >= spanZ) {
        ++image.outsideMap;
        continue;
      }
      const std::uint32_t cx0 = static_cast<std::uint32_t>(std::max(0.0f, std::floor(minX * invCell)));
      const std::uint32_t cz0 = static_cast<std::uint32_t>(std::max(0.0f, std::floor(minZ * invCell)));
      const std::uint32_t cx1 =
        static_cast<std::uint32_t>(std::min(static_cast<float>(layout.cellsX - 1), std::floor(maxX * invCell)));
      const std::uint32_t cz1 =
        static_cast<std::uint32_t>(std::min(static_cast<float>(layout.cellsZ - 1), std::floor(maxZ * invCell)));

      const std::size_t firstPair = pairs.size();
      const float r2 = l.radius * l.radius;
      const float segX = ex - l.pos[0];
      const float segZ = ez - l.pos[2];
      const float segLen2 = segX * segX + segZ * segZ;
      const float halfDiag = 0.7072f * layout.cellSize;
      for (std::uint32_t cz = cz0; cz <= cz1; ++cz) {
        // distance along z from the light to this cell's rectangle
        const float cellMinZ = layout.originZ + static_cast<float>(cz) * layout.cellSize;
        const float dz = std::max(std::max(cellMinZ - l.pos[2], l.pos[2] - (cellMinZ + layout.cellSize)), 0.0f);
        for (std::uint32_t cx = cx0; cx <= cx1; ++cx) {
          const float cellMinX = layout.originX + static_cast<float>(cx) * layout.cellSize;
          if (!capsule) {
            const float dx = std::max(std::max(cellMinX - l.pos[0], l.pos[0] - (cellMinX + layout.cellSize)), 0.0f);
            if (dx * dx + dz * dz > r2) {
              continue; // the corner of the square box the circle does not reach
            }
          } else {
            // the cell's centre against the segment, with the cell's half diagonal as margin (conservative)
            const float px = cellMinX + 0.5f * layout.cellSize - l.pos[0];
            const float pz = cellMinZ + 0.5f * layout.cellSize - l.pos[2];
            const float t =
              segLen2 > 1.0e-6f ? std::min(1.0f, std::max(0.0f, (px * segX + pz * segZ) / segLen2)) : 0.0f;
            const float qx = px - segX * t;
            const float qz = pz - segZ * t;
            const float reach = l.radius + halfDiag;
            if (qx * qx + qz * qz > reach * reach) {
              continue;
            }
          }
          // What the light adds at the middle of the cell: the shader's windowed falloff at the closest point of the
          // light's segment.
          const float px = cellMinX + 0.5f * layout.cellSize - l.pos[0];
          const float pz = cellMinZ + 0.5f * layout.cellSize - l.pos[2];
          const float t =
            capsule && segLen2 > 1.0e-6f ? std::min(1.0f, std::max(0.0f, (px * segX + pz * segZ) / segLen2)) : 0.0f;
          const float qx = px - segX * t;
          const float qz = pz - segZ * t;
          const float falloff = std::max(0.0f, 1.0f - (qx * qx + qz * qz) / r2);
          const float peak = std::max(l.rgb[0], std::max(l.rgb[1], l.rgb[2]));
          pairs.push_back(CellLight{static_cast<std::uint32_t>(cz) * layout.cellsX + cx, peak * falloff, index});
        }
      }
      bool crowded = false;
      for (std::size_t k = firstPair; k < pairs.size() && !crowded; ++k) {
        crowded = listed[pairs[k].cell] >= kMaxLightsPerCell;
      }
      if (crowded) {
        image.overflow += static_cast<std::uint32_t>(pairs.size() - firstPair);
        pairs.resize(firstPair);
      } else {
        for (std::size_t k = firstPair; k < pairs.size(); ++k) {
          ++listed[pairs[k].cell];
        }
      }
    }

    // A cell lists every light that reaches it, strongest at the cell's middle first (the shader's `Few` path reads
    // only the first texels).
    std::sort(pairs.begin(), pairs.end(), [](const CellLight& a, const CellLight& b) {
      if (a.cell != b.cell) {
        return a.cell < b.cell;
      }
      if (a.contribution != b.contribution) {
        return a.contribution > b.contribution;
      }
      return a.light < b.light;
    });
    const std::size_t capacityTexels = static_cast<std::size_t>(kGridTexelWidth) * kGridRows;
    std::size_t cursor = withCells ? tableTexels : 0u;
    for (std::size_t first = 0; first < pairs.size();) {
      std::size_t last = first;
      while (last < pairs.size() && pairs[last].cell == pairs[first].cell) {
        ++last;
      }
      const std::size_t count = last - first;
      std::size_t kept = std::min<std::size_t>(count, kMaxLightsPerCell);
      if (cursor + (kept + 3u) / 4u > capacityTexels) {
        kept = 0; // no room left in the texture: the cell stays empty (counted as overflow)
      }
      image.overflow += static_cast<std::uint32_t>(count - kept);
      if (kept > 0) {
        const std::size_t listTexels = (kept + 3u) / 4u;
        image.grid.resize((cursor + listTexels) * 4u, 0.0f);
        for (std::size_t k = 0; k < kept; ++k) {
          image.grid[cursor * 4u + k] = static_cast<float>(pairs[first + k].light + 1u);
        }
        float* const table = &image.grid[static_cast<std::size_t>(pairs[first].cell) * 4u];
        table[0] = static_cast<float>(cursor);
        table[1] = static_cast<float>(listTexels);
        cursor += listTexels;
        image.entries += static_cast<std::uint32_t>(kept);
        ++image.cellsLit;
      }
      first = last;
    }
    // ---- shadow casters
    if (occluders != nullptr && !occluders->empty() && !lights.empty()) {
      // the ones that touch the sphere of a light that casts shadows, largest first, at most kMaxOccluders
      struct Candidate
      {
        std::size_t index;
        float radius;
      };
      std::vector<Candidate> chosen;
      for (std::size_t o = 0; o < occluders->size(); ++o) {
        const Occluder& occluder = (*occluders)[o];
        const float radius = occluder.Radius();
        if (
          !(radius > 0.05f) || !std::isfinite(radius) || !std::isfinite(occluder.center[0]) ||
          !std::isfinite(occluder.center[2])
        ) {
          continue;
        }
        bool relevant = false;
        for (std::size_t i = 0; i < requested && !relevant; ++i) {
          const Light& l = lights[i];
          if (!(l.radius > 0.0f) || l.radius > kMaxShadowLightRadius || !std::isfinite(l.pos[0])) {
            continue;
          }
          const float dx = occluder.center[0] - l.pos[0];
          const float dy = occluder.center[1] - l.pos[1];
          const float dz = occluder.center[2] - l.pos[2];
          const float reach = l.radius + radius;
          relevant = dx * dx + dy * dy + dz * dz <= reach * reach;
        }
        if (relevant) {
          chosen.push_back(Candidate{o, radius});
        }
      }
      std::stable_sort(chosen.begin(), chosen.end(), [](const Candidate& a, const Candidate& b) {
        return a.radius > b.radius;
      });
      if (chosen.size() > kMaxOccluders) {
        chosen.resize(kMaxOccluders);
      }
      image.occluderCount = static_cast<std::uint32_t>(chosen.size());
      image.occluders.assign(static_cast<std::size_t>(image.OccluderRows()) * kDataWidth * 4u, 0.0f);
      struct CellOccluder
      {
        std::uint32_t cell;
        std::uint32_t occluder; // rank among the chosen = its index in the data texture
      };
      std::vector<CellOccluder> cellPairs;
      for (std::size_t k = 0; k < chosen.size(); ++k) {
        const Occluder& o = (*occluders)[chosen[k].index];
        float* const t = &image.occluders[k * kOccluderTexels * 4u];
        t[0] = o.center[0];
        t[1] = o.center[1];
        t[2] = o.center[2];
        for (int a = 0; a < 3; ++a) {
          const float length2 = o.axis[a][0] * o.axis[a][0] + o.axis[a][1] * o.axis[a][1] + o.axis[a][2] * o.axis[a][2];
          float* const texel = t + (a + 1) * 4;
          texel[0] = o.axis[a][0];
          texel[1] = o.axis[a][1];
          texel[2] = o.axis[a][2];
          texel[3] = length2 > 1.0e-8f ? 1.0f / length2 : 0.0f;
        }
        if (!withCells) {
          continue; // the cells the occluder shadows are listed for the grid path only
        }
        // the cells the occluder can shadow: its bounding circle grown by the reach
        const float reach = chosen[k].radius + kShadowReach;
        const float minX = o.center[0] - reach - layout.originX;
        const float maxX = o.center[0] + reach - layout.originX;
        const float minZ = o.center[2] - reach - layout.originZ;
        const float maxZ = o.center[2] + reach - layout.originZ;
        if (maxX < 0.0f || maxZ < 0.0f || minX >= spanX || minZ >= spanZ) {
          continue;
        }
        const auto cx0 = static_cast<std::uint32_t>(std::max(0.0f, std::floor(minX * invCell)));
        const auto cz0 = static_cast<std::uint32_t>(std::max(0.0f, std::floor(minZ * invCell)));
        const auto cx1 =
          static_cast<std::uint32_t>(std::min(static_cast<float>(layout.cellsX - 1), std::floor(maxX * invCell)));
        const auto cz1 =
          static_cast<std::uint32_t>(std::min(static_cast<float>(layout.cellsZ - 1), std::floor(maxZ * invCell)));
        for (std::uint32_t cz = cz0; cz <= cz1; ++cz) {
          const float cellMinZ = layout.originZ + static_cast<float>(cz) * layout.cellSize;
          const float dz = std::max(std::max(cellMinZ - o.center[2], o.center[2] - (cellMinZ + layout.cellSize)), 0.0f);
          for (std::uint32_t cx = cx0; cx <= cx1; ++cx) {
            const float cellMinX = layout.originX + static_cast<float>(cx) * layout.cellSize;
            const float dx =
              std::max(std::max(cellMinX - o.center[0], o.center[0] - (cellMinX + layout.cellSize)), 0.0f);
            if (dx * dx + dz * dz <= reach * reach) {
              cellPairs.push_back(CellOccluder{cz * layout.cellsX + cx, static_cast<std::uint32_t>(k)});
            }
          }
        }
      }
      // the largest first in each cell (the rank is the order of `chosen`), at most kMaxOccludersPerCell
      std::sort(cellPairs.begin(), cellPairs.end(), [](const CellOccluder& a, const CellOccluder& b) {
        return a.cell != b.cell ? a.cell < b.cell : a.occluder < b.occluder;
      });
      for (std::size_t first = 0; first < cellPairs.size();) {
        std::size_t last = first;
        while (last < cellPairs.size() && cellPairs[last].cell == cellPairs[first].cell) {
          ++last;
        }
        std::size_t kept = std::min<std::size_t>(last - first, kMaxOccludersPerCell);
        const std::size_t listTexels = (kept + 3u) / 4u;
        if (cursor + listTexels > capacityTexels) {
          break; // no room left in the texture
        }
        image.grid.resize((cursor + listTexels) * 4u, 0.0f);
        for (std::size_t k = 0; k < kept; ++k) {
          image.grid[cursor * 4u + k] = static_cast<float>(cellPairs[first + k].occluder + 1u);
        }
        float* const table = &image.grid[static_cast<std::size_t>(cellPairs[first].cell) * 4u];
        table[2] = static_cast<float>(cursor);
        table[3] = static_cast<float>(listTexels);
        cursor += listTexels;
        image.occluderEntries += static_cast<std::uint32_t>(kept);
        first = last;
      }
    }
    image.gridTexels = static_cast<std::uint32_t>(cursor);
    // whole rows, so the upload copies full rows
    if (withCells) {
      image.grid.resize(static_cast<std::size_t>(image.GridRows()) * kGridTexelWidth * 4u, 0.0f);
    }
  }
} // namespace moho::lights
