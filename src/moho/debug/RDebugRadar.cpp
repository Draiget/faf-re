#include "moho/debug/RDebugRadar.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SMinMax.h"
#include "moho/ui/SDebugDecal.h"
#include "Wm3AxisAlignedBox3.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace
{
  // Scale applied to stored 16-bit intel/height samples when converting to
  // world-space elevation (matches ds:flt_E4F6DC = 1/128).
  constexpr float kHeightSampleScale = 1.0f / 128.0f;

  // Below this world-cell span the recursive radar walker stops subdividing and
  // rasterizes the recon-coverage decals (matches the `span > 32` branch in
  // FUN_0064D9F0).
  constexpr int kRadarCellSubdivideLimit = 32;

  // ARGB coverage colors for each recon-grid lane (values are the signed
  // constants written into the decal params by FUN_0064D9F0).
  constexpr std::uint32_t kVisionGridColor = 0x800000FFu; // blue
  constexpr std::uint32_t kWaterGridColor = 0x800000FFu;  // blue
  constexpr std::uint32_t kRadarGridColor = 0x8000FF00u;  // green
  constexpr std::uint32_t kSonarGridColor = 0x80FFFF00u;  // yellow
  constexpr std::uint32_t kOmniGridColor = 0x80FF0000u;   // red
  constexpr std::uint32_t kRciGridColor = 0x80FF00FFu;    // magenta
  constexpr std::uint32_t kSciGridColor = 0x80FF00FFu;    // magenta
  constexpr std::uint32_t kVciGridColor = 0x80FF80FFu;    // pink

  /**
   * One recon-coverage decal pass: the intel-grid handle whose per-cell
   * coverage byte selects set/clear, and the ARGB color used when a cell is
   * covered. This is the three-word stack block `FUN_0064D9F0` builds and
   * hands to `FUN_0064F400` -- a whole `boost::shared_ptr<CIntelGrid>` (its
   * `{px, pi}` pair, which is what keeps the grid alive across the draw)
   * followed by the color at +0x08.
   */
  struct ReconCoverageDecalPass
  {
    boost::SharedPtrRaw<moho::CIntelGrid> grid{}; // +0x00 {px, pi}
    std::uint32_t color = 0u;                     // +0x08

    /**
     * Address: 0x0064CFA0 (FUN_0064CFA0)
     *
     * What it does:
     * Reads one cell's signed coverage count out of the pass's grid, or 0
     * when the cell lies outside the grid. `CIntelGrid::Raster` applies +/-1
     * per covering source, so the stored byte is a count, not a flag -- which
     * is why the binary widens it with `movsx` instead of a `setne`.
     *
     * The bounds test is the unsigned pair `x >= mWidth || z >= mHeight`, and
     * the index is `mGrid[z * mWidth + x]`, both exactly as
     * `CIntelGrid::IsVisible(const Wm3::Vector2i&)` (0x005BE180) spells them.
     * Zero callers: every use site inlined it and the linker kept the COMDAT.
     */
    [[nodiscard]] std::int8_t CoverageAt(const std::uint32_t cellX, const std::uint32_t cellZ) const noexcept
    {
      const moho::CIntelGrid* const intelGrid = grid.px;
      if (cellX >= intelGrid->mWidth || cellZ >= intelGrid->mHeight) {
        return 0;
      }
      return intelGrid->mGrid[cellZ * intelGrid->mWidth + cellX];
    }

    /**
     * Address: 0x0064CFD0 (FUN_0064CFD0)
     *
     * What it does:
     * This pass's color for one cell: the pass color where the cell is
     * covered, otherwise zero (whose zero alpha byte makes the rasterizer
     * skip the quad). Same body as `CoverageAt` plus a `cmp byte, 0` and the
     * `[pass+8]` color load -- which is how the color's offset in the stack
     * block is known.
     */
    [[nodiscard]] std::uint32_t ColorAt(const std::uint32_t cellX, const std::uint32_t cellZ) const noexcept
    {
      return CoverageAt(cellX, cellZ) != 0 ? color : 0u;
    }
  };
  static_assert(sizeof(ReconCoverageDecalPass) == 0x0C, "ReconCoverageDecalPass size must be 0x0C");
  static_assert(offsetof(ReconCoverageDecalPass, color) == 0x08, "ReconCoverageDecalPass::color offset must be 0x08");

  /**
   * Address: 0x0064F400 (FUN_0064F400, sub_64F400)
   *
   * IDA signature:
   * unsigned int __usercall sub_64F400@<eax>(_DWORD *params@<ecx>,
   *   Moho::CHeightField *hf, Moho::CDebugCanvas *canvas);
   *
   * What it does:
   * Rasterizes one recon-coverage decal quad for every intel-grid cell inside
   * the whole height field. For each cell it reads the coverage byte from the
   * intel grid (cell size = `grid->mGridSize`); covered cells get the pass
   * color, uncovered cells get zero. Cells whose selected color has a zero
   * alpha byte are skipped. Each covered cell samples the four corner elevations
   * (clamped independently to the height field) and appends an `SDebugDecal`
   * quad winding `(x+s,z) -> (x+s,z+s) -> (x,z+s) -> (x,z)` to the debug canvas
   * decal buffer.
   */
  void DrawReconCoverageDecalQuads(
    const ReconCoverageDecalPass& pass,
    const moho::CHeightField* const hf,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    const int cellSize = static_cast<int>(pass.grid.px->mGridSize);

    // Whole-field cell range in grid units (ceil-divide the far edges).
    const int cellX0 = static_cast<int>(hf->width) / cellSize;
    const int cellX1 = (static_cast<int>(hf->width) + cellSize - 1) / cellSize;
    const int cellZ0 = static_cast<int>(hf->height) / cellSize;
    const int cellZ1 = (static_cast<int>(hf->height) + cellSize - 1) / cellSize;

    // Iterate cells in `x`-major order; the binary tracks both the grid index
    // and the world-space start of each cell (index * cellSize).
    for (int cellX = cellX0; cellX < cellX1; ++cellX) {
      const int worldX = cellSize * cellX;
      for (int cellZ = cellZ0; cellZ < cellZ1; ++cellZ) {
        const int worldZ = cellSize * cellZ;

        const std::uint32_t color =
          pass.ColorAt(static_cast<std::uint32_t>(cellX), static_cast<std::uint32_t>(cellZ));
        if ((color & 0xFF000000u) == 0u) {
          continue;
        }

        const int worldXNext = worldX + cellSize;
        const int worldZNext = worldZ + cellSize;

        moho::SDebugDecal decal{};
        decal.corner0 = hf->GetClampedSamplePoint(worldXNext, worldZ);
        decal.corner1 = hf->GetClampedSamplePoint(worldXNext, worldZNext);
        decal.corner2 = hf->GetClampedSamplePoint(worldX, worldZNext);
        decal.corner3 = hf->GetClampedSamplePoint(worldX, worldZ);
        decal.color = color;

        canvas->decals.push_back(decal);
      }
    }
  }

  /**
   * What it does:
   * Fetches one recon grid through the given `IAiReconDB` accessor, and if the
   * grid handle is live, rasterizes its coverage decal pass in `color`. The
   * grid handle is held for the duration of the draw and released at scope end
   * (the intrusive shared-ownership drop the binary spells as FUN_005BE250 /
   * FUN_0064DFE0).
   */
  void DrawReconGrid(
    boost::SharedPtrRaw<moho::CIntelGrid> (moho::IAiReconDB::*accessor)() const,
    const moho::IAiReconDB* const reconDB,
    const std::uint32_t color,
    const moho::CHeightField* const hf,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    boost::SharedPtrRaw<moho::CIntelGrid> grid = (reconDB->*accessor)();
    if (grid.px != nullptr) {
      ReconCoverageDecalPass pass{};
      pass.grid = grid;
      pass.color = color;
      DrawReconCoverageDecalQuads(pass, hf, canvas);
    }
    grid.release();
  }

  /**
   * Address: 0x0064D9F0 (FUN_0064D9F0, sub_64D9F0)
   *
   * IDA signature:
   * void __cdecl sub_64D9F0(int x, int z, int span, int reconDB,
   *   Moho::CHeightField *hf, unsigned int activePlaneMask, int camera,
   *   int canvas);
   *
   * What it does:
   * Recursively walks one square block of the map for the radar debug overlay.
   * It builds the block's world AABB (from the covering height tier's min/max
   * heights), frustum-culls it against the camera, and if the block projects
   * larger than 32 world cells it subdivides into four quadrants. Leaf blocks
   * rasterize the eight recon-coverage grids (vision/water conditional on a live
   * handle; radar/sonar/omni/RCI/SCI/VCI unconditional) as colored decal quads.
   */
  void TraverseRadarCellsRecursive(
    int x,
    int z,
    int span,
    moho::IAiReconDB* const reconDB,
    const moho::CHeightField* const hf,
    std::uint32_t activePlaneMask,
    moho::GeomCamera3* const camera,
    moho::CDebugCanvas* const canvas
  ) noexcept
  {
    // Choose the height tier whose cell covers this span, clamped to the tier
    // count. `_BitScanReverse(span-1) + 1` = ceil(log2(span)).
    const int tierCount = static_cast<int>(hf->mGrids.size());
    int tier = static_cast<int>(std::bit_width(static_cast<unsigned int>(span - 1)));
    if (tier > tierCount) {
      tier = tierCount;
    }
    if (tier < 0) {
      tier = 0;
    }

    const moho::SMinMax<std::uint16_t> tierBounds = hf->GetTierBoundsUWord(tier, x >> tier, z >> tier);
    const float minHeight = static_cast<float>(tierBounds.min) * kHeightSampleScale;
    const float maxHeight = static_cast<float>(tierBounds.max) * kHeightSampleScale;

    const int cellZEnd = std::min(z + span, hf->height - 1);
    const int cellXEnd = std::min(x + span, hf->width - 1);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = static_cast<float>(x);
    bounds.Min.y = minHeight;
    bounds.Min.z = static_cast<float>(z);
    bounds.Max.x = static_cast<float>(cellXEnd);
    bounds.Max.y = maxHeight;
    bounds.Max.z = static_cast<float>(cellZEnd);

    if (!camera->solid2.Intersects(bounds, &activePlaneMask)) {
      return;
    }

    if (span > kRadarCellSubdivideLimit) {
      const int half = span >> 1;
      TraverseRadarCellsRecursive(x, z, half, reconDB, hf, activePlaneMask, camera, canvas);
      TraverseRadarCellsRecursive(x + half, z, half, reconDB, hf, activePlaneMask, camera, canvas);
      TraverseRadarCellsRecursive(x, z + half, half, reconDB, hf, activePlaneMask, camera, canvas);
      TraverseRadarCellsRecursive(x + half, z + half, half, reconDB, hf, activePlaneMask, camera, canvas);
      return;
    }

    // Leaf block: draw each recon-coverage grid as colored decal quads.
    // Vision and water are only drawn when their grid handle is live.
    {
      boost::SharedPtrRaw<moho::CIntelGrid> visionGrid = reconDB->ReconGetVisionGrid();
      const bool visionLive = visionGrid.px != nullptr;
      visionGrid.release();
      if (visionLive) {
        DrawReconGrid(&moho::IAiReconDB::ReconGetVisionGrid, reconDB, kVisionGridColor, hf, canvas);
      }
    }
    {
      boost::SharedPtrRaw<moho::CIntelGrid> waterGrid = reconDB->ReconGetWaterGrid();
      const bool waterLive = waterGrid.px != nullptr;
      waterGrid.release();
      if (waterLive) {
        DrawReconGrid(&moho::IAiReconDB::ReconGetWaterGrid, reconDB, kWaterGridColor, hf, canvas);
      }
    }

    DrawReconGrid(&moho::IAiReconDB::ReconGetRadarGrid, reconDB, kRadarGridColor, hf, canvas);
    DrawReconGrid(&moho::IAiReconDB::ReconGetSonarGrid, reconDB, kSonarGridColor, hf, canvas);
    DrawReconGrid(&moho::IAiReconDB::ReconGetOmniGrid, reconDB, kOmniGridColor, hf, canvas);
    DrawReconGrid(&moho::IAiReconDB::ReconGetRCIGrid, reconDB, kRciGridColor, hf, canvas);
    DrawReconGrid(&moho::IAiReconDB::ReconGetSCIGrid, reconDB, kSciGridColor, hf, canvas);
    DrawReconGrid(&moho::IAiReconDB::ReconGetVCIGrid, reconDB, kVciGridColor, hf, canvas);
  }

  /**
   * Address: 0x0064D860 (FUN_0064D860)
   * Address: 0x0064E290 (FUN_0064E290 -- the second emission of this same
   * inline cache, differing only in the relative displacement of its one
   * `call gpg::LookupRType`, which is why `/OPT:ICF` could not fold the two.
   * Formerly transcribed a second time as
   * `ResolveRDebugRadarTypeCacheSecondary`, `[[maybe_unused]]` with zero
   * callers.)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `RDebugRadar`.
   */
  [[nodiscard]] gpg::RType* ResolveRDebugRadarTypeCachePrimary()
  {
    gpg::RType* type = moho::RDebugRadar::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugRadar));
      moho::RDebugRadar::sType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  gpg::RType* RDebugRadar::sType = nullptr;

  /**
   * Address: 0x0064ED20 (FUN_0064ED20)
   *
   * What it does:
   * Initializes the radar-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugRadar::RDebugRadar() = default;

  /**
   * Address: 0x0064D880 (FUN_0064D880, Moho::RDebugRadar::GetClass)
   */
  gpg::RType* RDebugRadar::GetClass() const
  {
    return ResolveRDebugRadarTypeCachePrimary();
  }

  /**
   * Address: 0x0064D8A0 (FUN_0064D8A0, Moho::RDebugRadar::GetDerivedObjectRef)
   */
  gpg::RRef RDebugRadar::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x0064ED70 (FUN_0064ED70, Moho::RDebugRadar::dtr)
   */
  RDebugRadar::~RDebugRadar() = default;

  /**
   * Address: 0x0064E020 (FUN_0064E020, Moho::RDebugRadar::OnTick)
   *
   * IDA signature:
   * Moho::CDebugCanvas *__stdcall Moho::RDebugRadar::OnTick(Moho::Sim *sim);
   *
   * What it does:
   * Drives the recon-coverage debug overlay for the active sim map. If a debug
   * canvas is active, it resolves the primary army's recon database and walks
   * the map in square blocks (sized by the larger of the two height-field
   * dimensions), rasterizing each block's recon-coverage grids that survive
   * frustum culling.
   */
  void RDebugRadar::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mMapData == nullptr) {
      return;
    }

    CHeightField* const heightField = sim->mMapData->mHeightField.get();
    CDebugCanvas* const canvas = sim->GetDebugCanvas();
    GeomCamera3* const viewCamera = sim->mSyncFilter.geoCams.data();
    if (canvas == nullptr) {
      return;
    }

    // All frustum planes start active for the top-level block; the mask has one
    // bit per clipping plane in the view frustum solid.
    const unsigned int planeCount = static_cast<unsigned int>(viewCamera->solid2.planes_.size());
    const unsigned int activePlaneMask = (1u << planeCount) - 1u;

    // Recon database of the first army. The binary selects the first army (or a
    // null pointer when the army list is empty) and then queries its recon DB
    // unconditionally, exactly as reproduced here.
    CArmyImpl* const primaryArmy = sim->mArmiesList.empty() ? nullptr : sim->mArmiesList.front();
    IAiReconDB* const reconDB = primaryArmy->GetReconDB();

    // Square block span = larger of the two field extents; both loop bounds use
    // the same span so the whole map is covered in equal-sized blocks.
    const int width = heightField->width - 1;
    const int height = heightField->height - 1;
    const int span = std::max(width, height);

    for (int z = 0; static_cast<unsigned int>(z) < static_cast<unsigned int>(heightField->height - 1); z += span) {
      for (int x = 0; static_cast<unsigned int>(x) < static_cast<unsigned int>(heightField->width - 1); x += span) {
        TraverseRadarCellsRecursive(x, z, span, reconDB, heightField, activePlaneMask, viewCamera, canvas);
      }
    }
  }
} // namespace moho
