#include "moho/terrain/HighFidelityTerrain.h"

#include <cstdint>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/tess/CTesselator.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/TerrainDynamicTextureHelpers.h"
#include "moho/terrain/water/WaterFactory.h"
#include "moho/terrain/water/WaterShaderVars.h"
#include "moho/terrain/water/WaterSurface.h"

namespace
{
  using TextureSheetHandle = boost::shared_ptr<moho::CD3DDynamicTextureSheet>;
  using TextureResourceHandle = boost::shared_ptr<moho::RD3DTextureResource>;

  moho::WaterSurface* sHighFidelityWaterSurface = nullptr;
  TextureSheetHandle sHighFidelityNoiseFillTexture{};
  TextureSheetHandle sHighFidelityCubicBlendLookupTexture{};
  moho::CD3DTextureBatcher* sHighFidelityTextureBatcher = nullptr;
  TextureResourceHandle sHighFidelityGridTexture{};

  constexpr float kDisabledWaterElevation = -10000.0f;
  constexpr std::uint32_t kDynamicIndexCount = 15000;
  constexpr std::uint16_t kDynamicVertexLoopStop = 10002u;
  constexpr std::int32_t kTriangleListPrimitiveToken = 4;
  constexpr int kNoiseFillTextureFormat = 2;
  constexpr const char* kNoiseFillName = "NoiseFill";
  constexpr const char* kNoiseFillShaderSource =
    "float4 NoiseFill( float2 vTexCoord : POSITION, float2 vTexelSize : PSIZE) : COLOR{    return (float4( "
    "noise(vTexCoord*20.0f),                    noise(vTexCoord*20.0f),                    0,                    "
    "1)/2.0f + .5f) * (vTexelSize.x * 128.0f);};";

  template <typename T>
  void DeleteOwned(T*& lane) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    delete lane;
    lane = nullptr;
  }

  template <typename T>
  void ReplaceOwned(T*& lane, T* const nextLane) noexcept
  {
    if (lane == nextLane) {
      return;
    }

    DeleteOwned(lane);
    lane = nextLane;
  }

  void FillDynamicQuadIndices(moho::CD3DIndexSheet* const indexSheet)
  {
    std::int16_t* const indices = indexSheet->Lock(0U, kDynamicIndexCount, true, false);
    if (indices == nullptr) {
      return;
    }

    std::int16_t* write = indices;
    for (std::uint16_t indexToken = 2; indexToken < kDynamicVertexLoopStop; indexToken = static_cast<std::uint16_t>(indexToken + 4)) {
      *(write + 0) = static_cast<std::int16_t>(indexToken - 2);
      *(write + 1) = static_cast<std::int16_t>(indexToken - 1);
      *(write + 2) = static_cast<std::int16_t>(indexToken + 0);
      *(write + 3) = static_cast<std::int16_t>(indexToken - 2);
      *(write + 4) = static_cast<std::int16_t>(indexToken + 0);
      *(write + 5) = static_cast<std::int16_t>(indexToken + 1);
      write += 6;
    }

    indexSheet->Unlock();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007FF940 (??0HighFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??0HighFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes high-fidelity terrain runtime ownership lanes, shoreline
   * subobject, both inline patch-index vectors, and identity transform state.
   */
  HighFidelityTerrain::HighFidelityTerrain()
  {
    mTerrainTransform.orient_.w = 1.0f;
    mTerrainTransform.orient_.x = 0.0f;
    mTerrainTransform.orient_.y = 0.0f;
    mTerrainTransform.orient_.z = 0.0f;
    mTerrainTransform.pos_.x = 0.0f;
    mTerrainTransform.pos_.y = 0.0f;
    mTerrainTransform.pos_.z = 0.0f;
  }

  /**
   * Address: 0x007FFB80 (FUN_007FFB80, Moho::HighFidelityTerrain::Create)
   *
   * What it does:
   * Binds the terrain resource, resets shared high-fidelity helper ownership
   * lanes, then dispatches initialization.
   */
  bool HighFidelityTerrain::Create(TerrainWaterResourceView* const terrainResource)
  {
    mTerrainResource = terrainResource;

    DeleteOwned(sHighFidelityWaterSurface);
    sHighFidelityNoiseFillTexture.reset();
    sHighFidelityCubicBlendLookupTexture.reset();
    DeleteOwned(sHighFidelityTextureBatcher);

    return Init();
  }

  /**
   * Address: 0x008002E0 (FUN_008002E0, Moho::HighFidelityTerrain::Destroy)
   *
   * What it does:
   * Releases shoreline/tessellator/render-sheet ownership and drops retained
   * decal-mask texture ownership.
   */
  void HighFidelityTerrain::Destroy()
  {
    mShoreline.Destroy();
    DeleteOwned(mTesselator);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mDynamicVertexSheet);
    DeleteOwned(mDynamicIndexSheet);
    mDecalMask.reset();
  }

  /**
   * Address: 0x007FFC60 (FUN_007FFC60, Moho::HighFidelityTerrain::Init)
   *
   * What it does:
   * Rebuilds high-fidelity terrain sheets/tessellation, regenerates shoreline
   * cells, and lazily initializes shared terrain texture helpers.
   */
  bool HighFidelityTerrain::Init()
  {
    if (mTerrainResource == nullptr) {
      return false;
    }

    CHeightField* const heightField = reinterpret_cast<CHeightField*>(mTerrainResource->mMap->mHeightFieldObject);
    ReplaceOwned(mTesselator, new CTesselator(heightField));

    mShoreline.Generate(mTerrainResource);

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    CD3DVertexFormat* const terrainVertexFormat = resources->GetVertexFormat(10);
    ReplaceOwned(mTerrainVertexSheet, resources->NewVertexSheet(1U, 0xFFFF, terrainVertexFormat));
    ReplaceOwned(mTerrainIndexSheet, resources->CreateIndexSheet(true, 199998));

    CD3DVertexFormat* const dynamicVertexFormat = resources->GetVertexFormat(4);
    ReplaceOwned(mDynamicVertexSheet, resources->NewVertexSheet(1U, 10000, dynamicVertexFormat));
    ReplaceOwned(mDynamicIndexSheet, resources->CreateIndexSheet(false, static_cast<int>(kDynamicIndexCount)));
    FillDynamicQuadIndices(mDynamicIndexSheet);

    if (sHighFidelityWaterSurface == nullptr) {
      ReplaceOwned(sHighFidelityWaterSurface, CreateWaterFidelity(mTerrainResource));
    }

    const TerrainHeightFieldRuntimeView* const heightFieldRuntime = mTerrainResource->mMap->mHeightFieldObject;
    const int widthMinusOne = heightFieldRuntime->width - 1;
    const int heightMinusOne = heightFieldRuntime->height - 1;
    const int quarterWidth = (widthMinusOne / 2) / 2;
    const int quarterHeight = (heightMinusOne / 2) / 2;

    if (!sHighFidelityNoiseFillTexture) {
      (void)resources->NewDynamicTextureSheet(
        sHighFidelityNoiseFillTexture,
        quarterWidth,
        quarterHeight,
        kNoiseFillTextureFormat
      );

      ID3DDeviceResources::DynamicTextureSheetWeakHandle weakNoiseFillTexture(sHighFidelityNoiseFillTexture);
      (void)resources->Func9(
        static_cast<int>(reinterpret_cast<std::uintptr_t>(kNoiseFillName)),
        static_cast<int>(reinterpret_cast<std::uintptr_t>(kNoiseFillShaderSource)),
        weakNoiseFillTexture
      );
    }

    if (!sHighFidelityCubicBlendLookupTexture) {
      sHighFidelityCubicBlendLookupTexture = CreateTerrainCubicBlendLookupTextureTransient();
    }

    if (sHighFidelityTextureBatcher == nullptr) {
      sHighFidelityTextureBatcher = new CD3DTextureBatcher();
    }

    if (!sHighFidelityGridTexture) {
      resources->GetTexture(sHighFidelityGridTexture, "/textures/engine/gridtest.dds", 0, true);
    }

    return true;
  }

  /**
   * Address: 0x008033E0 (FUN_008033E0, Moho::HighFidelityTerrain::DrawWaterline)
   *
   * What it does:
   * Dispatches high-fidelity water utility-mask rendering and then draws the
   * current shoreline sheet using the active camera.
   */
  void HighFidelityTerrain::DrawWaterline(const std::int32_t /*arg0*/, const std::int32_t /*arg1*/)
  {
    (void)sHighFidelityWaterSurface->RenderWaterLayerAlphaMask(mCamera);
    DrawShoreline(&mShoreline, mCamera);
  }

  /**
   * Address: 0x008131D0 (FUN_008131D0, Moho::HighFidelityTerrain::DrawShoreline)
   *
   * What it does:
   * Binds shoreline shader state, writes camera + water elevation uniforms,
   * and submits the shoreline vertex-sheet primitive list.
   */
  void HighFidelityTerrain::DrawShoreline(const Shoreline* const shoreline, const GeomCamera3* const camera)
  {
    if (!ren_Shoreline || shoreline->mShorelineTris == 0) {
      return;
    }

    IWldTerrainRes* terrainRes = nullptr;
    if (CWldSession* const activeSession = WLD_GetActiveSession();
        activeSession != nullptr && activeSession->mWldMap != nullptr) {
      terrainRes = activeSession->mWldMap->mTerrainRes;
    }

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("water2");
    device->SelectTechnique("TShoreline");

    GetWater2WorldToViewShorelineShaderVar().SetMatrix4x4(&camera->view);
    GetWater2ProjectionShorelineShaderVar().SetMatrix4x4(&camera->projection);

    const auto* const terrainView = reinterpret_cast<const TerrainWaterResourceView*>(terrainRes);
    const TerrainMapRuntimeView* const map = terrainView->mMap;
    const float waterElevation = (map->mWaterEnabled != 0) ? map->mWaterElevation : kDisabledWaterElevation;
    GetWater2WaterElevationTShorelineShaderVar().SetFloat(waterElevation);

    CD3DVertexSheetViewRuntime shorelineView{};
    shorelineView.sheet = shoreline->mVertexSheet.get();
    shorelineView.startVertex = 0;
    shorelineView.baseVertex = 0;
    shorelineView.endVertex = shoreline->mShorelineTris * 3 - 1;

    std::int32_t primitiveType = kTriangleListPrimitiveToken;
    (void)device->DrawPrimitiveList(&shorelineView, &primitiveType);
  }

  /**
   * Address: 0x007FFA40 (??1HighFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??1HighFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Tears down high-fidelity terrain resources, restores both inline patch
   * vector storage lanes, and then unwinds shoreline + base terrain state.
   */
  HighFidelityTerrain::~HighFidelityTerrain()
  {
    Destroy();

    DeleteOwned(mDynamicIndexSheet);
    DeleteOwned(mDynamicVertexSheet);
    mSecondaryPatchData.ResetStorageToInline();

    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mTerrainVertexSheet);

    DeleteOwned(mTesselator);
    mPrimaryPatchData.ResetStorageToInline();
  }

  /**
   * Address: 0x00803970 (FUN_00803970, ??3HighFidelityTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the high-fidelity terrain destructor lane and conditionally frees
   * the object storage when the delete flag requests heap release.
   */
  HighFidelityTerrain* HighFidelityTerrain::DeleteWithFlag(
    HighFidelityTerrain* const object,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    object->~HighFidelityTerrain();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(object);
    }
    return object;
  }
} // namespace moho
