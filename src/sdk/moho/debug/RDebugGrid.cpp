#include "moho/debug/RDebugGrid.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "gpg/core/containers/BitArray2D.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/ui/SDebugDecal.h"
#include "moho/ui/SDebugLine.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector3.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace
{
  struct GridHeightSamplesView
  {
    const std::uint16_t* samples = nullptr;
    int width = 0;
    int height = 0;
  };

  struct ByteMaskGridRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    const std::int8_t* samples = nullptr; // +0x04
    std::uint32_t width = 0u; // +0x08
    std::uint32_t height = 0u; // +0x0C
  };
  static_assert(sizeof(ByteMaskGridRuntimeView) == 0x10, "ByteMaskGridRuntimeView size must be 0x10");
  static_assert(offsetof(ByteMaskGridRuntimeView, samples) == 0x04, "ByteMaskGridRuntimeView::samples offset must be 0x04");
  static_assert(offsetof(ByteMaskGridRuntimeView, width) == 0x08, "ByteMaskGridRuntimeView::width offset must be 0x08");
  static_assert(offsetof(ByteMaskGridRuntimeView, height) == 0x0C, "ByteMaskGridRuntimeView::height offset must be 0x0C");

  struct ByteMaskSelectionRuntimeView
  {
    const ByteMaskGridRuntimeView* grid = nullptr; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::int32_t selectedValue = 0; // +0x08
  };
  static_assert(sizeof(ByteMaskSelectionRuntimeView) == 0x0C, "ByteMaskSelectionRuntimeView size must be 0x0C");
  static_assert(
    offsetof(ByteMaskSelectionRuntimeView, selectedValue) == 0x08,
    "ByteMaskSelectionRuntimeView::selectedValue offset must be 0x08"
  );

  struct Stride712CursorRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uintptr_t baseAddress = 0u; // +0x04
  };
  static_assert(sizeof(Stride712CursorRuntimeView) == 0x08, "Stride712CursorRuntimeView size must be 0x08");
  static_assert(
    offsetof(Stride712CursorRuntimeView, baseAddress) == 0x04,
    "Stride712CursorRuntimeView::baseAddress offset must be 0x04"
  );

  struct Stride72RangeRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uintptr_t beginAddress = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uintptr_t endAddress = 0u; // +0x0C
  };
  static_assert(sizeof(Stride72RangeRuntimeView) == 0x10, "Stride72RangeRuntimeView size must be 0x10");
  static_assert(
    offsetof(Stride72RangeRuntimeView, beginAddress) == 0x04,
    "Stride72RangeRuntimeView::beginAddress offset must be 0x04"
  );
  static_assert(offsetof(Stride72RangeRuntimeView, endAddress) == 0x0C, "Stride72RangeRuntimeView::endAddress offset must be 0x0C");

  /**
   * Address: 0x0064CFA0 (FUN_0064CFA0)
   *
   * What it does:
   * Returns one signed byte-mask sample at `(x, y)` when indices are in-range;
   * otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t SampleSignedByteMaskAt(
    const ByteMaskGridRuntimeView* const grid,
    const std::uint32_t x,
    const std::uint32_t y
  ) noexcept
  {
    if (grid == nullptr || grid->samples == nullptr) {
      return 0;
    }
    if (x >= grid->width || y >= grid->height) {
      return 0;
    }

    const std::size_t sampleIndex = static_cast<std::size_t>(x + (y * grid->width));
    return static_cast<std::int32_t>(grid->samples[sampleIndex]);
  }

  /**
   * Address: 0x0064CFD0 (FUN_0064CFD0)
   *
   * What it does:
   * Returns one selector payload when the byte-mask lane at `(x, y)` is set;
   * otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t ResolveSelectionValueForByteMask(
    const std::uint32_t x,
    const ByteMaskSelectionRuntimeView* const selection,
    const std::uint32_t y
  ) noexcept
  {
    if (selection == nullptr || selection->grid == nullptr || selection->grid->samples == nullptr) {
      return 0;
    }
    if (x >= selection->grid->width || y >= selection->grid->height) {
      return 0;
    }

    const std::size_t sampleIndex = static_cast<std::size_t>(x + (y * selection->grid->width));
    return selection->grid->samples[sampleIndex] != 0 ? selection->selectedValue : 0;
  }

  /**
   * Address: 0x0064D1F0 (FUN_0064D1F0)
   *
   * What it does:
   * Maps one debug-grid mode selector to packed ARGB color lanes.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ResolveDebugGridColorByMode(const std::int32_t mode) noexcept
  {
    switch (mode) {
      case 0:
        return 0xFFFFFFFFu;
      case 1:
        return 0xFFFF0000u;
      case 2:
        return 0xFF00FF00u;
      default:
        return 0xFF0000FFu;
    }
  }

  /**
   * Address: 0x0064E240 (FUN_0064E240)
   *
   * What it does:
   * Returns one `base + index * 0x2C8` address lane from a stride-712 view.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t ResolveStride712ElementAddress(
    const std::int32_t index,
    const Stride712CursorRuntimeView* const view
  ) noexcept
  {
    return view->baseAddress + (static_cast<std::uintptr_t>(index) * 0x2C8u);
  }

  /**
   * Address: 0x0064E2D0 (FUN_0064E2D0)
   *
   * What it does:
   * Returns element count for one stride-72 pointer range, or zero when the
   * begin lane is null.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t CountStride72Elements(const Stride72RangeRuntimeView* const view) noexcept
  {
    if (view == nullptr || view->beginAddress == 0u) {
      return 0;
    }

    const std::intptr_t byteSpan =
      static_cast<std::intptr_t>(view->endAddress) - static_cast<std::intptr_t>(view->beginAddress);
    return static_cast<std::int32_t>(byteSpan / 72);
  }

  /**
   * Address: 0x0064CF00 (FUN_0064CF00)
   *
   * What it does:
   * Clamps one `(x,z)` index pair into the valid 16-bit sample grid and
   * returns world-space point `{x, sample/128.0f, z}`.
   */
  [[maybe_unused]] [[nodiscard]] Wm3::Vector3f BuildClampedGridSamplePoint(
    const GridHeightSamplesView& grid,
    const int x,
    const int z
  ) noexcept
  {
    Wm3::Vector3f out{};
    out.x = static_cast<float>(x);
    out.z = static_cast<float>(z);
    out.y = 0.0f;

    if (grid.samples == nullptr || grid.width <= 0 || grid.height <= 0) {
      return out;
    }

    const int clampedX = std::clamp(x, 0, grid.width - 1);
    const int clampedZ = std::clamp(z, 0, grid.height - 1);
    const std::size_t sampleIndex = static_cast<std::size_t>(clampedX + (clampedZ * grid.width));
    const std::uint16_t sample = grid.samples[sampleIndex];
    out.y = static_cast<float>(sample) * (1.0f / 128.0f);
    return out;
  }

  /**
   * Address: 0x0064D000 (FUN_0064D000)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `RDebugGrid`.
   */
  [[nodiscard]] gpg::RType* ResolveRDebugGridTypeCachePrimary()
  {
    gpg::RType* type = moho::RDebugGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugGrid));
      moho::RDebugGrid::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064E250 (FUN_0064E250)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches `RDebugGrid` reflection
   * type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveRDebugGridTypeCacheSecondary()
  {
    gpg::RType* type = moho::RDebugGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugGrid));
      moho::RDebugGrid::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064D1C0 (FUN_0064D1C0)
   *
   * What it does:
   * Returns one debug-grid distance lane by selector:
   * `0 -> 75.0f`, `1 -> 500.0f`, otherwise `+inf`.
   */
  [[maybe_unused]] float ResolveRDebugGridDistanceBySelector(const int selector) noexcept
  {
    if (selector == 0) {
      return 75.0f;
    }
    if (selector == 1) {
      return 500.0f;
    }
    return std::numeric_limits<float>::infinity();
  }

  /**
   * Address: 0x0064EDB0 (FUN_0064EDB0, Moho::RDebugGrid non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one `RDebugGrid`
   * instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugGridNonDeletingBody(moho::RDebugGrid* const overlay) noexcept
  {
    if (overlay == nullptr) {
      return;
    }

    auto* const node = static_cast<moho::TDatListItem<moho::RDebugOverlay, void>*>(static_cast<moho::RDebugOverlay*>(overlay));
    node->ListUnlinkSelf();
  }

  // Height-sample word scale (1/128) applied when converting stored 16-bit
  // terrain samples into world-space elevation. Matches ds:flt_E4F6DC.
  constexpr float kHeightSampleScale = 1.0f / 128.0f;

  // Number of grid-line samples per world cell before decimation kicks in.
  // Matches the `count > 10` decimation branch in FUN_0064D220.
  constexpr int kGridLineSampleDecimationLimit = 10;

  /**
   * Address: 0x0064D190 (FUN_0064D190)
   *
   * IDA signature:
   * int __fastcall sub_64D190(int a1, unsigned int a2);
   *
   * What it does:
   * Computes 10^exponent by binary exponentiation over the bits of `exponent`.
   * Used to derive the grid-cell stride for one subdivision depth.
   */
  [[nodiscard]] int IntegerPowerOfTen(unsigned int exponent) noexcept
  {
    int base = 10;
    int result = 1;
    for (; exponent != 0u; base *= base) {
      if ((exponent & 1u) != 0u) {
        result *= base;
      }
      exponent >>= 1;
    }
    return result;
  }

  /**
   * Address: 0x0064D220 (FUN_0064D220, sub_64D220)
   *
   * IDA signature:
   * void __usercall sub_64D220(int count@<eax>, float x, float z, float dx,
   *   float dz, int color, Moho::CHeightField *hf, Moho::CDebugCanvas *canvas);
   *
   * What it does:
   * Draws a terrain-conforming poly-line from `(x,z)` stepping by `(dx,dz)`.
   * For dense lines (count > 10) it decimates by 10 (coarser steps), then walks
   * `count` segments sampling terrain elevation at each end and emitting a debug
   * line per segment until the step leaves the height field bounds.
   */
  void DrawElevationFollowingGridLine(
    int count,
    float x,
    float z,
    float dx,
    float dz,
    std::int32_t color,
    const moho::CHeightField* const hf,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    // Decimate very dense lines: keep segment count small by folding factors of
    // ten into the step size (matches the `count > 10` loop in the binary).
    if (count > kGridLineSampleDecimationLimit) {
      do {
        count /= 10;
        dx *= 10.0f;
        dz *= 10.0f;
      } while (count > kGridLineSampleDecimationLimit);
    }

    float prevX = x;
    float prevZ = z;
    float prevElevation = hf->GetElevation(x, z);

    if (count <= 0) {
      return;
    }

    float curX = x;
    float curZ = z;
    for (int step = 0; step < count; ++step) {
      curZ = curZ + dz;
      const float nextX = curX + dx;
      if (nextX > static_cast<float>(hf->width - 1)) {
        break;
      }
      if (curZ > static_cast<float>(hf->height - 1)) {
        break;
      }

      const float elevation = hf->GetElevation(nextX, curZ);

      moho::SDebugLine line{};
      line.p0.x = prevX;
      line.p0.y = prevElevation;
      line.p0.z = prevZ;
      line.p1.x = nextX;
      line.p1.y = elevation;
      line.p1.z = curZ;
      line.depth0 = color;
      line.depth1 = color;
      canvas->DebugDrawLine(line);

      curX = nextX;
      prevElevation = elevation;
      prevX = nextX;
      prevZ = curZ;
    }
  }

  // Integer cell rectangle (in height-field sample units) covered by one decal
  // pass. Matches the four-int `{xMin, zMin, xMax, zMax}` stack block that
  // FUN_0064D3A0 passes to FUN_0064F090 as the implicit (ecx) argument.
  struct GridCellRect
  {
    int xMin = 0;
    int zMin = 0;
    int xMax = 0;
    int zMax = 0;
  };

  // Per-pass decal parameters: the occupancy bit-grid to sample, the ARGB
  // color used for set/clear lanes, and the world-space cell stride. Matches
  // the `{maskGrid, colorSet, colorClear, stride}` stack block (FUN_0064D3A0).
  struct GridCellDecalParams
  {
    const gpg::BitArray2D* maskGrid = nullptr;
    std::int32_t colorSet = 0;
    std::int32_t colorClear = 0;
    std::int32_t stride = 1;
  };

  // Raw bit test used by FUN_0064F090 against the occupancy grid: no bounds
  // check (the caller guarantees the cell range), one bit per cell packed into
  // 32-bit words, row pitch `maskGrid.width` words.
  [[nodiscard]] bool IsOccupancyLaneSet(const gpg::BitArray2D& maskGrid, unsigned int cellX, unsigned int cellZ) noexcept
  {
    const std::uint32_t word =
      static_cast<std::uint32_t>(maskGrid.ptr[cellX + (cellZ >> 5) * static_cast<unsigned int>(maskGrid.width)]);
    return (word & (1u << (cellZ & 0x1Fu))) != 0u;
  }

  /**
   * Address: 0x0064F090 (FUN_0064F090, sub_64F090)
   *
   * IDA signature:
   * unsigned int __cdecl sub_64F090(_DWORD *bounds@<ecx>, _DWORD *params, hf, canvas);
   *
   * What it does:
   * Rasterizes one debug-decal quad per occupied grid cell inside `bounds`. For
   * each cell it picks a color from the occupancy-grid bit, samples the four
   * corner elevations (each clamped independently to the height field), builds an
   * `SDebugDecal` quad winding `(x+s,z) -> (x+s,z+s) -> (x,z+s) -> (x,z)`, and
   * appends it to the debug canvas decal buffer. Cells whose selected color has a
   * zero alpha byte are skipped.
   */
  void DrawGridCellDecalQuads(
    const GridCellRect& bounds,
    const GridCellDecalParams& params,
    const moho::CHeightField* const hf,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    const int stride = params.stride;
    const int cellX0 = bounds.xMin / stride;
    const int cellX1 = (bounds.xMax + stride - 1) / stride;
    const int cellZ0 = bounds.zMin / stride;
    const int cellZ1 = (bounds.zMax + stride - 1) / stride;

    const int maxSampleX = hf->width - 1;
    const int maxSampleZ = hf->height - 1;
    const std::uint16_t* const samples = hf->data;

    const auto clampSampleX = [maxSampleX](int value) noexcept {
      return std::clamp(value, 0, maxSampleX);
    };
    const auto clampSampleZ = [maxSampleZ](int value) noexcept {
      return std::clamp(value, 0, maxSampleZ);
    };
    const auto elevationAt = [&](int sampleX, int sampleZ) noexcept {
      return static_cast<float>(samples[clampSampleX(sampleX) + clampSampleZ(sampleZ) * hf->width])
        * kHeightSampleScale;
    };

    for (int cellZ = cellZ0; cellZ < cellZ1; ++cellZ) {
      const int worldZ = stride * cellZ;
      const int worldZNext = worldZ + stride;
      for (int cellX = cellX0; cellX < cellX1; ++cellX) {
        const int worldX = stride * cellX;
        const bool maskSet =
          IsOccupancyLaneSet(*params.maskGrid, static_cast<unsigned int>(cellX), static_cast<unsigned int>(cellZ));
        const std::int32_t color = maskSet ? params.colorSet : params.colorClear;
        if ((static_cast<std::uint32_t>(color) & 0xFF000000u) == 0u) {
          continue;
        }

        const int worldXNext = worldX + stride;

        moho::SDebugDecal decal{};
        // corner0 : (worldX+stride, worldZ)
        decal.corner0.x = static_cast<float>(worldXNext);
        decal.corner0.y = elevationAt(worldXNext, worldZ);
        decal.corner0.z = static_cast<float>(worldZ);
        // corner1 : (worldX+stride, worldZ+stride)
        decal.corner1.x = static_cast<float>(worldXNext);
        decal.corner1.y = elevationAt(worldXNext, worldZNext);
        decal.corner1.z = static_cast<float>(worldZNext);
        // corner2 : (worldX, worldZ+stride)
        decal.corner2.x = static_cast<float>(worldX);
        decal.corner2.y = elevationAt(worldX, worldZNext);
        decal.corner2.z = static_cast<float>(worldZNext);
        // corner3 : (worldX, worldZ)
        decal.corner3.x = static_cast<float>(worldX);
        decal.corner3.y = elevationAt(worldX, worldZ);
        decal.corner3.z = static_cast<float>(worldZ);
        decal.color = static_cast<std::uint32_t>(color);

        canvas->decals.push_back(decal);
      }
    }
  }

  // Maps a debug-grid subdivision-depth selector to its ARGB color:
  // 0 -> white, 1 -> red, 2 -> green, otherwise blue. Matches the inline
  // color ladders in FUN_0064D3A0 (values are negative ARGB constants).
  [[nodiscard]] std::int32_t ResolveGridDepthColor(unsigned int selector) noexcept
  {
    switch (selector) {
      case 0u:
        return static_cast<std::int32_t>(0xFFFFFFFFu); // white
      case 1u:
        return static_cast<std::int32_t>(0xFFFF0000u); // red
      case 2u:
        return static_cast<std::int32_t>(0xFF00FF00u); // green
      default:
        return static_cast<std::int32_t>(0xFF0000FFu); // blue
    }
  }

  // Distance threshold (in world units) at which a grid subdivision level stops
  // subdividing and starts drawing: 0 -> 75, 1 -> 500, otherwise +inf.
  [[nodiscard]] float ResolveGridSubdivisionDistance(unsigned int selector) noexcept
  {
    if (selector == 1u) {
      return 75.0f;
    }
    if (selector == 2u) {
      return 500.0f;
    }
    return std::numeric_limits<float>::infinity();
  }

  /**
   * Address: 0x0064D3A0 (FUN_0064D3A0, sub_64D3A0)
   *
   * IDA signature:
   * char __cdecl sub_64D3A0(int x, int z, unsigned int depth, unsigned int depthX,
   *   unsigned int depthZ, unsigned int activePlaneMask, GeomCamera3 *camera,
   *   Moho::CHeightField *hf, COGrid *oGrid, Moho::CDebugCanvas *canvas);
   *
   * What it does:
   * Recursively walks one grid cell of the debug overlay. It builds the cell's
   * world AABB (from tier min/max heights), frustum-culls it against the camera,
   * and if the cell projects large enough for its level it subdivides into a
   * `10 x 10` block of sub-cells; otherwise it draws the cell's X and Z grid
   * lines (terrain-conforming) and three colored decal passes.
   */
  bool DrawGridCellRecursive(
    int x,
    int z,
    unsigned int depth,
    unsigned int depthX,
    unsigned int depthZ,
    unsigned int activePlaneMask,
    moho::GeomCamera3* const camera,
    const moho::CHeightField* const hf,
    moho::COGrid* const oGrid,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    const int cellStride = IntegerPowerOfTen(depth);

    // Choose the height-field tier whose cell size covers this stride, clamped
    // to the available tier count.
    const int tierCount = static_cast<int>(hf->mGrids.size());
    int tier = static_cast<int>(std::bit_width(static_cast<unsigned int>(cellStride - 1)));
    if (tier > tierCount) {
      tier = tierCount;
    }
    if (tier < 0) {
      tier = 0;
    }

    const moho::SMinMax<std::uint16_t> tierBounds = hf->GetTierBoundsUWord(tier, x >> tier, z >> tier);
    const float minHeight = static_cast<float>(tierBounds.min) * kHeightSampleScale;
    const float maxHeight = static_cast<float>(tierBounds.max) * kHeightSampleScale;

    const int cellZEnd = std::min(cellStride + z, hf->height - 1);
    const int cellXEnd = std::min(cellStride + x, hf->width - 1);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = static_cast<float>(x);
    bounds.Min.y = minHeight;
    bounds.Min.z = static_cast<float>(z);
    bounds.Max.x = static_cast<float>(cellXEnd);
    bounds.Max.y = maxHeight;
    bounds.Max.z = static_cast<float>(cellZEnd);

    bool result = camera->solid2.Intersects(bounds, &activePlaneMask);
    if (!result) {
      return result;
    }

    if (depth != 0u) {
      const float subdivideDistance = ResolveGridSubdivisionDistance(depth);

      // Screen-projected size heuristic: viewport matrix row 1 applied to the
      // cell center. GeomCamera3::viewport is a VMatrix4 (+0x284); the binary
      // reads row 1 lanes at +0x10/+0x14/+0x18/+0x1C = r[1].x/.y/.z/.w.
      const Wm3::AxisAlignedBox3f& cell = bounds;
      const moho::Vector4f& viewportRow = camera->viewport.r[1];
      const float centerX = (cell.Max.x + cell.Min.x) * 0.5f;
      const float centerY = (cell.Max.y + cell.Min.y) * 0.5f;
      const float centerZ = (cell.Max.z + cell.Min.z) * 0.5f;
      const float projectedSize =
        (((centerZ * viewportRow.z) + (centerY * viewportRow.y)) + (viewportRow.x * centerX)) + viewportRow.w;

      if (subdivideDistance > projectedSize) {
        const int subStride = IntegerPowerOfTen(depth - 1);
        for (int subZ = z; subZ < cellZEnd; subZ += subStride) {
          if (subZ >= hf->height - 1) {
            break;
          }
          for (int subX = x; subX < cellXEnd; subX += subStride) {
            if (subX >= hf->width - 1) {
              break;
            }
            const unsigned int childDepthZ = (subZ != z) ? (depth - 1u) : depthZ;
            const unsigned int childDepthX = (subX != x) ? (depth - 1u) : depthX;
            result = DrawGridCellRecursive(
              subX,
              subZ,
              depth - 1u,
              childDepthX,
              childDepthZ,
              activePlaneMask,
              camera,
              hf,
              oGrid,
              canvas
            );
          }
        }
        return result;
      }
    }

    // Leaf cell: draw its two terrain-conforming grid lines (one stepping in X,
    // one stepping in Z, each colored by its own subdivision selector).
    const std::int32_t colorZ = ResolveGridDepthColor(depthZ);
    DrawElevationFollowingGridLine(
      cellStride, static_cast<float>(x), static_cast<float>(z), 1.0f, 0.0f, colorZ, hf, canvas
    );

    const std::int32_t colorX = ResolveGridDepthColor(depthX);
    DrawElevationFollowingGridLine(
      cellStride, static_cast<float>(x), static_cast<float>(z), 0.0f, 1.0f, colorX, hf, canvas
    );

    // Then three colored occupancy-decal passes across the same cell rectangle.
    // The rectangle spans [x .. min(x+stride, width-1)] and
    // [z .. min(z+stride, height-1)] in sample units.
    GridCellRect decalRect{};
    decalRect.xMin = x;
    decalRect.zMin = z;
    decalRect.xMax = std::min(cellStride + x, hf->width - 1);
    decalRect.zMax = std::min(cellStride + z, hf->height - 1);

    GridCellDecalParams decalParams{};
    decalParams.colorClear = 0;
    decalParams.stride = 1;

    // Pass 1: dynamic occupancy grid (COGrid::mOccupation, +0x58) in yellow.
    decalParams.maskGrid = &oGrid->mOccupation;
    decalParams.colorSet = static_cast<std::int32_t>(0x807F7F00u);
    DrawGridCellDecalQuads(decalRect, decalParams, hf, canvas);

    // Pass 2: terrain occupancy grid (COGrid::terrainOccupation, +0x38) in green.
    decalParams.maskGrid = &oGrid->terrainOccupation;
    decalParams.colorSet = static_cast<std::int32_t>(0x8000FF00u);
    DrawGridCellDecalQuads(decalRect, decalParams, hf, canvas);

    // Pass 3: water occupancy grid (COGrid::waterOccupation, +0x48) in blue.
    decalParams.maskGrid = &oGrid->waterOccupation;
    decalParams.colorSet = static_cast<std::int32_t>(0x800000FFu);
    DrawGridCellDecalQuads(decalRect, decalParams, hf, canvas);

    return result;
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugGrid::sType = nullptr;

  /**
   * Address: 0x0064ED10 (FUN_0064ED10)
   *
   * What it does:
   * Initializes the grid-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugGrid::RDebugGrid() = default;

  /**
   * Address: 0x0064D020 (FUN_0064D020, Moho::RDebugGrid::GetClass)
   */
  gpg::RType* RDebugGrid::GetClass() const
  {
    return ResolveRDebugGridTypeCachePrimary();
  }

  /**
   * Address: 0x0064D040 (FUN_0064D040, Moho::RDebugGrid::GetDerivedObjectRef)
   */
  gpg::RRef RDebugGrid::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x0064ED30 (FUN_0064ED30, Moho::RDebugGrid::dtr)
   */
  RDebugGrid::~RDebugGrid() = default;

  /**
   * Address: 0x0064D7A0 (FUN_0064D7A0, Moho::RDebugGrid::OnTick)
   *
   * IDA signature:
   * char __stdcall Moho::RDebugGrid::OnTick(Moho::Sim *sim);
   *
   * What it does:
   * Drives the world-grid debug overlay for the active sim map. Computes the
   * coarsest power-of-ten grid step that still spans the whole height field,
   * then (if a debug canvas is active) recursively rasterizes the grid overlay
   * from the map's occupancy grid, height field, and current view frustum.
   */
  void RDebugGrid::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mMapData == nullptr) {
      return;
    }

    CDebugCanvas* const canvas = sim->GetDebugCanvas();
    CHeightField* const heightField = sim->mMapData->mHeightField.get();
    GeomCamera3* const viewCamera = sim->mSyncFilter.geoCams.data();

    // Smallest exponent `n` such that 10^n covers both height-field dimensions.
    unsigned int gridStepExponent = 0u;
    for (;;) {
      const int gridStep = IntegerPowerOfTen(gridStepExponent);
      if (gridStep >= heightField->width - 1 && gridStep >= heightField->height - 1) {
        break;
      }
      ++gridStepExponent;
    }

    if (canvas != nullptr) {
      // All frustum planes start active for the top-level cell; the mask has one
      // bit per clipping plane in the view frustum solid.
      const unsigned int planeCount = static_cast<unsigned int>(viewCamera->solid2.planes_.size());
      const unsigned int activePlaneMask = (1u << planeCount) - 1u;

      DrawGridCellRecursive(
        0,
        0,
        gridStepExponent,
        gridStepExponent,
        gridStepExponent,
        activePlaneMask,
        viewCamera,
        heightField,
        sim->mOGrid,
        canvas
      );
    }
  }
} // namespace moho
