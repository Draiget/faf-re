#include "moho/terrain/water/LowFidelityWater.h"

#include <cstdint>

#include "gpg/core/utils/Global.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"

namespace moho
{
  struct TerrainHeightFieldRuntimeView
  {
    std::uint16_t* data; // +0x00
    std::int32_t width;  // +0x04
    std::int32_t height; // +0x08
  };

  struct TerrainMapRuntimeView
  {
    TerrainHeightFieldRuntimeView* mHeightFieldObject; // +0x0000
    void* mHeightFieldRef;                             // +0x0004
    std::uint8_t pad_0008_1534[0x152C];               // +0x0008
    std::uint8_t mWaterEnabled;                       // +0x1534
    std::uint8_t pad_1535_1537[3];                    // +0x1535
    float mWaterElevation;                            // +0x1538
  };

  static_assert(
    offsetof(TerrainMapRuntimeView, mWaterEnabled) == 0x1534,
    "TerrainMapRuntimeView::mWaterEnabled offset must be 0x1534"
  );
  static_assert(
    offsetof(TerrainMapRuntimeView, mWaterElevation) == 0x1538,
    "TerrainMapRuntimeView::mWaterElevation offset must be 0x1538"
  );

  namespace
  {
    constexpr float kDisabledWaterElevation = -10000.0f;
    constexpr int kLowFidelityWaterVertexFormatToken = 3;
    constexpr int kLowFidelityWaterVertexCount = 4;
    constexpr int kLowFidelityWaterIndexCount = 6;

    struct LowFidelityWaterVertex
    {
      float x;
      float y;
      float z;
      float u;
      float v;
    };

    static_assert(sizeof(LowFidelityWaterVertex) == 0x14, "LowFidelityWaterVertex size must be 0x14");

    struct WaterExtents2D
    {
      float x;
      float z;
    };

    [[nodiscard]] WaterExtents2D GetWaterMapExtents(const TerrainWaterResourceView& terrainResource)
    {
      const TerrainHeightFieldRuntimeView* const field = terrainResource.mMap->mHeightFieldObject;
      const float halfWidth = static_cast<float>((field->width - 1) >> 1);
      const float halfHeight = static_cast<float>((field->height - 1) >> 1);
      return {halfWidth * 2.0f, halfHeight * 2.0f};
    }
  } // namespace

  /**
   * Address: 0x0080FA10 (FUN_0080FA10)
   *
   * TerrainWaterResourceView *
   *
   * IDA signature:
   * char __thiscall Moho::LowFidelityWater::InitVerts(float *this, int terrainRes);
   *
   * What it does:
   * Rebuilds one low-fidelity water quad vertex/index-sheet pair from the
   * current terrain map dimensions and water elevation.
   */
  bool LowFidelityWater::InitVerts(TerrainWaterResourceView* const terrainRes)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    mTerrainRes = terrainRes;
    TerrainMapRuntimeView* const terrainMap = reinterpret_cast<TerrainMapRuntimeView*>(terrainRes->mMap);
    mWaterElevation = terrainMap->mWaterEnabled != 0 ? terrainMap->mWaterElevation : kDisabledWaterElevation;

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kLowFidelityWaterVertexFormatToken);
    if (vertexFormat == nullptr) {
      gpg::Die("unable to create vertex format for low fidelity water");
    }

    CD3DVertexSheet* const nextVertexSheet = resources->NewVertexSheet(0U, kLowFidelityWaterVertexCount, vertexFormat);
    if (nextVertexSheet != mVertexSheet && mVertexSheet != nullptr) {
      delete mVertexSheet;
    }
    mVertexSheet = nextVertexSheet;
    if (mVertexSheet == nullptr) {
      gpg::Die("unable to create vertex sheet for low fidelity water");
    }

    const WaterExtents2D mapExtents = GetWaterMapExtents(*terrainRes);
    ID3DVertexStream* const vertexStream = mVertexSheet->GetVertStream(0U);
    const int vertexCount = mVertexSheet->Func5();
    auto* const vertices = static_cast<LowFidelityWaterVertex*>(vertexStream->Lock(0, vertexCount, false, false));

    vertices[0] = {0.0f, mWaterElevation, 0.0f, 0.0f, 0.0f};
    vertices[1] = {mapExtents.x, mWaterElevation, 0.0f, 1.0f, 0.0f};
    vertices[2] = {0.0f, mWaterElevation, mapExtents.z, 0.0f, 1.0f};
    vertices[3] = {mapExtents.x, mWaterElevation, mapExtents.z, 1.0f, 1.0f};

    vertexStream->Unlock();

    CD3DIndexSheet* const nextIndexSheet = resources->CreateIndexSheet(false, kLowFidelityWaterIndexCount);
    if (nextIndexSheet != mIndexSheet && mIndexSheet != nullptr) {
      delete mIndexSheet;
    }
    mIndexSheet = nextIndexSheet;
    if (mIndexSheet == nullptr) {
      gpg::Die("unable to index sheet for low fidelity water");
    }

    const std::uint32_t indexCount = mIndexSheet->GetSize();
    std::int16_t* const indices = mIndexSheet->Lock(0U, indexCount, true, false);

    indices[0] = 0;
    indices[1] = 2;
    indices[2] = 1;
    indices[3] = 1;
    indices[4] = 2;
    indices[5] = 3;

    mIndexSheet->Unlock();
    return true;
  }

  /**
   * Address: 0x0080FC40 (FUN_0080FC40)
   *
   * What it does:
   * Releases retained low-fidelity water vertex/index sheet ownership and
   * clears the bound terrain-resource lane.
   */
  std::int32_t LowFidelityWater::ReleaseRenderSheets()
  {
    std::int32_t releaseResult = 0;

    if (mVertexSheet != nullptr) {
      delete mVertexSheet;
      releaseResult = 1;
    }
    mVertexSheet = nullptr;

    if (mIndexSheet != nullptr) {
      delete mIndexSheet;
      releaseResult = 1;
    }
    mIndexSheet = nullptr;

    mTerrainRes = nullptr;
    return releaseResult;
  }

  /**
   * Address: 0x0080FC70 (FUN_0080FC70)
   *
   * std::uint32_t
   *
   * What it does:
   * No-op reserved virtual lane retained for binary slot fidelity.
   */
  void LowFidelityWater::ReservedNoOp(const std::uint32_t /*reservedToken*/)
  {
  }
} // namespace moho
