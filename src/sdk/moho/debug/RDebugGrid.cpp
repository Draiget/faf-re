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
  /**
   * Address: 0x0064D000 (FUN_0064D000)
   * Address: 0x0064E250 (FUN_0064E250 -- the second emission of this same
   * inline cache. Both bodies read `[0x010C73F4]`, and on a miss push
   * `&typeid(RDebugGrid)` (`0x00F73CA4`) into `gpg::LookupRType` and store the
   * result back; they differ only in the relative displacement of that one
   * `call`, which is why `/OPT:ICF` could not fold them. Formerly transcribed
   * a second time as `ResolveRDebugGridTypeCacheSecondary`, `[[maybe_unused]]`
   * with zero callers.)
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
        decal.corner0 = hf->GetClampedSamplePoint(worldXNext, worldZ);
        decal.corner1 = hf->GetClampedSamplePoint(worldXNext, worldZNext);
        decal.corner2 = hf->GetClampedSamplePoint(worldX, worldZNext);
        decal.corner3 = hf->GetClampedSamplePoint(worldX, worldZ);
        decal.color = static_cast<std::uint32_t>(color);

        canvas->decals.push_back(decal);
      }
    }
  }

  /**
   * Address: 0x0064D1F0 (FUN_0064D1F0)
   *
   * What it does:
   * Maps a debug-grid subdivision-depth selector to its ARGB color:
   * 0 -> white, 1 -> red, 2 -> green, otherwise blue.
   *
   * `FUN_0064D1F0` is this function's own out-of-line COMDAT (`sub eax,0 /
   * sub eax,1 / sub eax,1` over `0xFFFFFFFF`, `0xFFFF0000`, `0xFF00FF00`,
   * `0xFF0000FF`), which nothing calls because every use site inlined it --
   * `FUN_0064D3A0` carries the identical ladder twice, at 0x0064D617 over
   * `depthZ` (`[ebp+0x18]`) and at 0x0064D672 over `depthX` (`[ebp+0x14]`),
   * in that order. It had been transcribed here a second time as
   * `ResolveDebugGridColorByMode`.
   */
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

  /**
   * Address: 0x0064D1C0 (FUN_0064D1C0)
   *
   * What it does:
   * Distance threshold (in world units) at which a grid subdivision *level*
   * stops subdividing and starts drawing: level 0 -> 75, level 1 -> 500,
   * deeper -> +inf (draw immediately).
   *
   * The level is `depth - 1`, not `depth`. `FUN_0064D1C0` is this function's
   * own out-of-line COMDAT and its switch is normalised on 0 (`sub eax,0 /
   * je 75.0f` at `ds:0x00E4F700`, `sub eax,1 / je 500.0f` at
   * `ds:0x00E4F704`); the inlined copy inside `FUN_0064D3A0` does the
   * decrement first -- `add edx,-1` at 0x0064D521, then the same two
   * compares at 0x0064D526/0x0064D543. Passing `depth` and testing 1/2 is
   * behaviourally identical but emits the subtraction in the wrong place,
   * so the argument is spelled as the binary spells it.
   */
  [[nodiscard]] float ResolveGridSubdivisionDistance(unsigned int level) noexcept
  {
    switch (level) {
      case 0u:
        return 75.0f;
      case 1u:
        return 500.0f;
      default:
        return std::numeric_limits<float>::infinity();
    }
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
      const float subdivideDistance = ResolveGridSubdivisionDistance(depth - 1u);

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
