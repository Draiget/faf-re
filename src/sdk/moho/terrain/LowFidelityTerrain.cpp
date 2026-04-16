#include "moho/terrain/LowFidelityTerrain.h"

#include <cstdint>

#include <boost/detail/sp_counted_base.hpp>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/tess/CTesselator.h"
#include "moho/terrain/water/WaterFactory.h"

namespace
{
  constexpr std::int32_t kSkirtMaxIndexCount = 199998;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;

  template <typename T>
  void DeleteOwned(T*& lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    delete lane;
    lane = nullptr;
  }

  void ReleaseSharedCount(boost::detail::sp_counted_base*& sharedCount) noexcept
  {
    if (sharedCount != nullptr) {
      sharedCount->release();
      sharedCount = nullptr;
    }
  }

  struct LowFidelityTriangleBatchRuntime
  {
    std::uint32_t pad00[5];         // +0x00
    moho::CD3DVertexSheet* vtx;     // +0x14
    moho::CD3DIndexSheet* idx;      // +0x18
    std::uint32_t pad1C;            // +0x1C
    std::int32_t indexCount;        // +0x20
    std::int32_t endVertexInclusive; // +0x24
  };
  static_assert(offsetof(LowFidelityTriangleBatchRuntime, vtx) == 0x14, "LowFidelityTriangleBatchRuntime::vtx");
  static_assert(offsetof(LowFidelityTriangleBatchRuntime, idx) == 0x18, "LowFidelityTriangleBatchRuntime::idx");
  static_assert(
    offsetof(LowFidelityTriangleBatchRuntime, indexCount) == 0x20,
    "LowFidelityTriangleBatchRuntime::indexCount"
  );
  static_assert(
    offsetof(LowFidelityTriangleBatchRuntime, endVertexInclusive) == 0x24,
    "LowFidelityTriangleBatchRuntime::endVertexInclusive"
  );

  /**
   * Address: 0x00807F50 (FUN_00807F50, low-fidelity indexed draw helper)
   *
   * What it does:
   * Issues one triangle-list draw for one prebuilt low-fidelity terrain batch
   * when the batch has a non-zero index count.
   */
  [[maybe_unused]] void DrawLowFidelityTerrainBatch(const LowFidelityTriangleBatchRuntime& batch)
  {
    if (batch.indexCount == 0 || batch.vtx == nullptr || batch.idx == nullptr) {
      return;
    }

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    moho::CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = batch.vtx;
    vertexView.startVertex = 0;
    vertexView.baseVertex = 0;
    vertexView.endVertex = batch.endVertexInclusive;

    moho::CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = batch.idx;
    indexView.startIndex = 0;
    indexView.indexCount = batch.indexCount;

    std::int32_t primitiveType = 4;
    (void)device->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }
} // namespace

namespace moho
{
  extern bool ren_Terrain;
  extern bool ren_Skirt;

  boost::shared_ptr<RD3DTextureResource> sTerrainGridTexture;
  WaterSurface* sTerrainWaterSurface = nullptr;
  CD3DTextureBatcher* texture_batcher = nullptr;

  /**
   * Address: 0x00807FC0 (??0LowFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??0LowFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes low-fidelity terrain runtime ownership lanes and both inline
   * patch-index storage vectors.
   */
  LowFidelityTerrain::LowFidelityTerrain() = default;

  /**
   * Address: 0x00808590 (FUN_00808590, Moho::LowFidelityTerrain::Destroy)
   *
   * What it does:
   * Releases owned tessellator/render-sheet lanes and drops retained decal
   * mask texture ownership.
   */
  void LowFidelityTerrain::Destroy()
  {
    DeleteOwned(mTesselator);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTerrainIndexSheet);
    mDecalMask.reset();
    DeleteOwned(mDynamicVertexSheet);
    DeleteOwned(mDynamicIndexSheet);
  }

  /**
   * Address: 0x00808070 (??1LowFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??1LowFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Tears down low-fidelity terrain runtime resources and restores inline
   * patch-index storage ownership.
   */
  LowFidelityTerrain::~LowFidelityTerrain()
  {
    Destroy();
    DeleteOwned(mDynamicIndexSheet);
    DeleteOwned(mDynamicVertexSheet);
    mSecondaryPatchData.ResetStorageToInline();
    mPrimaryPatchData.ResetStorageToInline();
    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTesselator);
  }

  /**
   * Address: 0x00809D80 (FUN_00809D80, ??3LowFidelityTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the low-fidelity terrain destructor lane and conditionally frees the
   * object storage when the delete flag requests heap release.
   */
  LowFidelityTerrain* LowFidelityTerrain::DeleteWithFlag(
    LowFidelityTerrain* const object,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    object->~LowFidelityTerrain();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(object);
    }
    return object;
  }

  /**
   * Address: 0x008081A0 (FUN_008081A0, Moho::LowFidelityTerrain::Create)
   *
   * What it does:
   * Binds the terrain resource, clears shared global terrain-water assets,
   * then dispatches initialization.
   */
  bool LowFidelityTerrain::Create(TerrainWaterResourceView* const terrainResource)
  {
    mTerrainResource = terrainResource;

    sTerrainGridTexture.reset();
    DeleteOwned(sTerrainWaterSurface);
    DeleteOwned(texture_batcher);

    return Init();
  }

  /**
   * Address: 0x00808240 (FUN_00808240, Moho::LowFidelityTerrain::Init)
   *
   * What it does:
   * Rebuilds low-fidelity terrain tessellation and render-sheet ownership
   * lanes for the active terrain resource.
   */
  bool LowFidelityTerrain::Init()
  {
    TerrainMapRuntimeView* const terrainMap = mTerrainResource->mMap;
    CHeightField* const heightField = reinterpret_cast<CHeightField*>(terrainMap->mHeightFieldObject);

    CTesselator* const nextTesselator = new CTesselator(heightField);
    if (nextTesselator != mTesselator) {
      DeleteOwned(mTesselator);
      mTesselator = nextTesselator;
    }

    WaterSurface* const nextWaterSurface = CreateWaterFidelity(mTerrainResource);
    if (nextWaterSurface != sTerrainWaterSurface) {
      DeleteOwned(sTerrainWaterSurface);
      sTerrainWaterSurface = nextWaterSurface;
    }

    ID3DDeviceResources* const terrainResources = D3D_GetDevice()->GetResources();
    CD3DVertexFormat* const terrainVertexFormat = terrainResources->GetVertexFormat(10);

    CD3DVertexSheet* const nextTerrainVertexSheet = terrainResources->NewVertexSheet(1U, 0xFFFF, terrainVertexFormat);
    if (nextTerrainVertexSheet != mTerrainVertexSheet) {
      DeleteOwned(mTerrainVertexSheet);
      mTerrainVertexSheet = nextTerrainVertexSheet;
    }

    CD3DIndexSheet* const nextTerrainIndexSheet = terrainResources->CreateIndexSheet(true, 0x30D3E);
    if (nextTerrainIndexSheet != mTerrainIndexSheet) {
      DeleteOwned(mTerrainIndexSheet);
      mTerrainIndexSheet = nextTerrainIndexSheet;
    }

    CD3DVertexFormat* const dynamicVertexFormat = D3D_GetDevice()->GetResources()->GetVertexFormat(4);
    if (!sTerrainGridTexture) {
      terrainResources->GetTexture(sTerrainGridTexture, "/textures/engine/gridtest.dds", 0, true);
    }

    if (texture_batcher == nullptr) {
      texture_batcher = new CD3DTextureBatcher();
    }

    ID3DDeviceResources* const dynamicResources = D3D_GetDevice()->GetResources();

    CD3DVertexSheet* const nextDynamicVertexSheet = dynamicResources->NewVertexSheet(1U, 1000, dynamicVertexFormat);
    if (nextDynamicVertexSheet != mDynamicVertexSheet) {
      DeleteOwned(mDynamicVertexSheet);
      mDynamicVertexSheet = nextDynamicVertexSheet;
    }

    CD3DIndexSheet* const nextDynamicIndexSheet = dynamicResources->CreateIndexSheet(false, 1500);
    if (nextDynamicIndexSheet != mDynamicIndexSheet) {
      DeleteOwned(mDynamicIndexSheet);
      mDynamicIndexSheet = nextDynamicIndexSheet;
    }

    std::int16_t* const indices = mDynamicIndexSheet->Lock(0U, 1500U, true, false);
    std::uint32_t writeIndex = 0;
    for (std::int16_t quadStart = 0; quadStart < 1000; quadStart = static_cast<std::int16_t>(quadStart + 4)) {
      indices[writeIndex + 0] = quadStart;
      indices[writeIndex + 1] = static_cast<std::int16_t>(quadStart + 1);
      indices[writeIndex + 2] = static_cast<std::int16_t>(quadStart + 2);
      indices[writeIndex + 3] = quadStart;
      indices[writeIndex + 4] = static_cast<std::int16_t>(quadStart + 2);
      indices[writeIndex + 5] = static_cast<std::int16_t>(quadStart + 3);
      writeIndex += 6;
    }
    mDynamicIndexSheet->Unlock();

    return true;
  }

  /**
   * Address: 0x00809B30 (FUN_00809B30, Moho::LowFidelityTerrain::DrawWaterLine)
   *
   * What it does:
   * Dispatches the shared low-fidelity water alpha-mask render lane for the
   * active terrain camera.
   */
  void LowFidelityTerrain::DrawWaterLine(const std::int32_t /*arg0*/, const std::int32_t /*arg1*/)
  {
    (void)sTerrainWaterSurface->RenderWaterLayerAlphaMask(mCamera);
  }

  /**
   * Address: 0x00809C80 (FUN_00809C80, Moho::LowFidelityTerrain::DrawTerrainSkirt)
   *
   * What it does:
   * Selects the terrain-skirt technique and submits one indexed triangle-list
   * draw from low-fidelity skirt lanes when terrain/skirt toggles and skirt
   * range gating permit.
   */
  void LowFidelityTerrain::DrawTerrainSkirt()
  {
    if (!ren_Terrain || !ren_Skirt || mSkirtStartIndex == mSkirtEndIndex) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectTechnique("TTerrainSkirt");

    std::int32_t indexCount = static_cast<std::int32_t>(mSkirtEndIndex - mSkirtStartIndex);
    if (indexCount > kSkirtMaxIndexCount) {
      indexCount = kSkirtMaxIndexCount;
    }

    std::int32_t primitiveType = kTriangleListPrimitiveType;

    CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = mTerrainIndexSheet;
    indexView.startIndex = static_cast<std::int32_t>(mSkirtStartIndex);
    indexView.indexCount = indexCount;

    CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = mTerrainVertexSheet;
    vertexView.startVertex = 0;
    vertexView.baseVertex = mSkirtBaseVertex;
    vertexView.endVertex = mSkirtEndVertex;

    (void)device->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }

  /**
   * Address: 0x00809B20 (FUN_00809B20, Moho::LowFidelityTerrain::DrawTerrainNormal)
   *
   * What it does:
   * Preserves the low-fidelity terrain normal pass as an intentional no-op
   * hook for this terrain fidelity lane.
   */
  void LowFidelityTerrain::DrawTerrainNormal(const std::int32_t /*arg0*/, const std::int32_t /*arg1*/)
  {}

  /**
   * Address: 0x00809D30 (FUN_00809D30, Moho::LowFidelityTerrain::DrawTerrain)
   *
   * What it does:
   * Releases one retained shared-control lane passed by the render caller and
   * leaves terrain draw behavior as an empty hook for this fidelity path.
   */
  void LowFidelityTerrain::DrawTerrain(
    const std::int32_t /*arg0*/,
    boost::detail::sp_counted_base* retainedControl,
    const std::int32_t /*arg1*/
  )
  {
    ReleaseSharedCount(retainedControl);
  }

  /**
   * Address: 0x00809D70 (FUN_00809D70, Moho::LowFidelityTerrain::DrawDirtyTerrain)
   *
   * What it does:
   * Preserves the dirty-terrain pass hook as an intentional no-op for this
   * low-fidelity terrain lane.
   */
  void LowFidelityTerrain::DrawDirtyTerrain(const std::int32_t /*arg0*/)
  {}
} // namespace moho
