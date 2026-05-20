#include "moho/terrain/MediumFidelityTerrain.h"

#include <cstdint>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/tess/CTesselator.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/TerrainDynamicTextureHelpers.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/terrain/water/WaterFactory.h"

namespace
{
  using TextureSheetHandle = boost::shared_ptr<moho::CD3DDynamicTextureSheet>;
  using TextureResourceHandle = boost::shared_ptr<moho::RD3DTextureResource>;

  TextureResourceHandle sMediumFidelityGridTexture{};
  moho::WaterSurface* sMediumFidelityWaterSurface = nullptr;
  TextureSheetHandle sMediumFidelityNoiseFillTexture{};
  TextureSheetHandle sMediumFidelityCubicBlendLookupTexture{};
  moho::CD3DTextureBatcher* sMediumFidelityTextureBatcher = nullptr;

  constexpr std::uint32_t kOverlayIndexCount = 15000;
  constexpr std::uint16_t kOverlayVertexLoopStop = 0x2712u;
  constexpr std::int32_t kSkirtMaxIndexCount = 199998;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;
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

  void FillOverlayQuadIndices(moho::CD3DIndexSheet* const indexSheet)
  {
    std::int16_t* const indices = indexSheet->Lock(0U, kOverlayIndexCount, true, false);
    if (indices == nullptr) {
      return;
    }

    std::int16_t* write = indices;
    for (std::uint16_t indexToken = 2; indexToken < kOverlayVertexLoopStop; indexToken = static_cast<std::uint16_t>(indexToken + 4)) {
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
  extern bool ren_Terrain;
  extern bool ren_Skirt;

  /**
   * Address: 0x00803A10 (FUN_00803A10, ??0MediumFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??0MediumFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes medium-fidelity terrain ownership lanes and both inline
   * patch-index vector stores.
   */
  MediumFidelityTerrain::MediumFidelityTerrain()
  {
    mTerrainResource = nullptr;
    mCamera = nullptr;

    mTesselator = nullptr;
    mTerrainVertexSheet = nullptr;
    mTerrainIndexSheet = nullptr;

    mOverlayVertexSheet = nullptr;
    mOverlayIndexSheet = nullptr;

    mOverlayTransform.orient_.w = 1.0f;
    mOverlayTransform.orient_.x = 0.0f;
    mOverlayTransform.orient_.y = 0.0f;
    mOverlayTransform.orient_.z = 0.0f;
    mOverlayTransform.pos_.x = 0.0f;
    mOverlayTransform.pos_.y = 0.0f;
    mOverlayTransform.pos_.z = 0.0f;
    mUnknown47534 = 0U;
  }

  /**
   * Address: 0x00803C00 (FUN_00803C00, Moho::MediumFidelityTerrain::Create)
   *
   * What it does:
   * Binds the terrain resource, resets shared medium-fidelity helper
   * ownership lanes, then dispatches initialization.
   */
  bool MediumFidelityTerrain::Create(TerrainWaterResourceView* const terrainResource)
  {
    mTerrainResource = terrainResource;

    DeleteOwned(sMediumFidelityWaterSurface);
    sMediumFidelityNoiseFillTexture.reset();
    sMediumFidelityCubicBlendLookupTexture.reset();
    DeleteOwned(sMediumFidelityTextureBatcher);

    return Init();
  }

  /**
   * Address: 0x00804350 (FUN_00804350)
   *
   * What it does:
   * Releases all owned tesselator/sheet lanes and clears the shared decal
   * mask ownership handle.
   */
  void MediumFidelityTerrain::Destroy()
  {
    DeleteOwned(mTesselator);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mOverlayVertexSheet);
    DeleteOwned(mOverlayIndexSheet);
    mDecalMask.reset();
  }

  /**
   * Address: 0x00803CE0 (FUN_00803CE0, Moho::MediumFidelityTerrain::Init)
   *
   * What it does:
   * Rebuilds medium-fidelity terrain tessellation/sheet lanes, fills dynamic
   * quad index buffers, and lazily initializes runtime texture helpers.
   */
  bool MediumFidelityTerrain::Init()
  {
    if (mTerrainResource == nullptr) {
      return false;
    }

    CHeightField* const heightField = reinterpret_cast<CHeightField*>(mTerrainResource->mMap->mHeightFieldObject);
    ReplaceOwned(mTesselator, new CTesselator(heightField));

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    CD3DVertexFormat* const terrainVertexFormat = resources->GetVertexFormat(10);
    ReplaceOwned(mTerrainVertexSheet, resources->NewVertexSheet(1U, 0xFFFF, terrainVertexFormat));
    ReplaceOwned(mTerrainIndexSheet, resources->CreateIndexSheet(true, 199998));

    CD3DVertexFormat* const overlayVertexFormat = resources->GetVertexFormat(4);
    ReplaceOwned(mOverlayVertexSheet, resources->NewVertexSheet(1U, 10000, overlayVertexFormat));
    ReplaceOwned(mOverlayIndexSheet, resources->CreateIndexSheet(false, static_cast<int>(kOverlayIndexCount)));
    FillOverlayQuadIndices(mOverlayIndexSheet);

    if (sMediumFidelityWaterSurface == nullptr) {
      ReplaceOwned(sMediumFidelityWaterSurface, CreateWaterFidelity(mTerrainResource));
    }

    const TerrainHeightFieldRuntimeView* const heightFieldRuntime = mTerrainResource->mMap->mHeightFieldObject;
    const int widthMinusOne = heightFieldRuntime->width - 1;
    const int heightMinusOne = heightFieldRuntime->height - 1;
    const int quarterWidth = (widthMinusOne / 2) / 2;
    const int quarterHeight = (heightMinusOne / 2) / 2;

    if (!sMediumFidelityNoiseFillTexture) {
      (void)resources->CreateDynamicTextureSheet2(
        sMediumFidelityNoiseFillTexture,
        quarterWidth,
        quarterHeight,
        kNoiseFillTextureFormat
      );

      ID3DDeviceResources::DynamicTextureSheetWeakHandle weakNoiseFillTexture(sMediumFidelityNoiseFillTexture);
      (void)resources->Func9(
        static_cast<int>(reinterpret_cast<std::uintptr_t>(kNoiseFillName)),
        static_cast<int>(reinterpret_cast<std::uintptr_t>(kNoiseFillShaderSource)),
        weakNoiseFillTexture
      );
    }

    if (!sMediumFidelityCubicBlendLookupTexture) {
      sMediumFidelityCubicBlendLookupTexture = CreateTerrainCubicBlendLookupTexture();
    }

    if (sMediumFidelityTextureBatcher == nullptr) {
      sMediumFidelityTextureBatcher = new CD3DTextureBatcher();
    }

    if (!sMediumFidelityGridTexture) {
      resources->GetTexture(sMediumFidelityGridTexture, "/textures/engine/gridtest.dds", 0, true);
    }

    return true;
  }

  /**
   * Address: 0x00804DF0 (FUN_00804DF0, Moho::MediumFidelityTerrain::LoadShaderVars)
   *
   * What it does:
   * Binds terrain shader texture lanes from world stratum material + water map,
   * updates terrain-scale and viewport normalization constants, and forwards
   * the optional terrain-normal map texture handle for terrain normal passes.
   */
  void MediumFidelityTerrain::LoadShaderVars(boost::weak_ptr<gpg::gal::TextureD3D9> terrainNormalTexture)
  {
    auto& shaderVars = GetTerrainShaderVars();

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);
    StratumMaterial& strata = terrainRes->GetStratumMaterial();
    strata.SetSizeTo(reinterpret_cast<CWldTerrainRes*>(terrainRes));

    BindTextureShaderVar(shaderVars.skirtTexture, boost::static_pointer_cast<ID3DTextureSheet>(sMediumFidelityGridTexture));
    BindTextureShaderVar(shaderVars.utilityTextureA, strata.mStratumMask0);
    BindTextureShaderVar(shaderVars.utilityTextureB, strata.mStratumMask1);
    BindTextureShaderVar(shaderVars.utilityTextureC, terrainRes->GetWaterMap());

    BindTextureShaderVar(shaderVars.lowerAlbedoTexture, strata.mLowerAlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum0AlbedoTexture, strata.mStratum0AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum1AlbedoTexture, strata.mStratum1AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum2AlbedoTexture, strata.mStratum2AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum3AlbedoTexture, strata.mStratum3AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum4AlbedoTexture, strata.mStratum4AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum5AlbedoTexture, strata.mStratum5AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum6AlbedoTexture, strata.mStratum6AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum7AlbedoTexture, strata.mStratum7AlbedoTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.upperAlbedoTexture, strata.mUpperAlbedoTexture.mTextureSheet);

    BindTextureShaderVar(shaderVars.lowerNormalTexture, strata.mLowerNormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum0NormalTexture, strata.mStratum0NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum1NormalTexture, strata.mStratum1NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum2NormalTexture, strata.mStratum2NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum3NormalTexture, strata.mStratum3NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum4NormalTexture, strata.mStratum4NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum5NormalTexture, strata.mStratum5NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum6NormalTexture, strata.mStratum6NormalTexture.mTextureSheet);
    BindTextureShaderVar(shaderVars.stratum7NormalTexture, strata.mStratum7NormalTexture.mTextureSheet);

    SetShaderVarMem(shaderVars.lowerAlbedoTile, 4U, &strata.mLowerAlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum0AlbedoTile, 4U, &strata.mStratum0AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum1AlbedoTile, 4U, &strata.mStratum1AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum2AlbedoTile, 4U, &strata.mStratum2AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum3AlbedoTile, 4U, &strata.mStratum3AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum4AlbedoTile, 4U, &strata.mStratum4AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum5AlbedoTile, 4U, &strata.mStratum5AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum6AlbedoTile, 4U, &strata.mStratum6AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum7AlbedoTile, 4U, &strata.mStratum7AlbedoTexture.mScaleX);
    SetShaderVarMem(shaderVars.upperAlbedoTile, 4U, &strata.mUpperAlbedoTexture.mScaleX);

    SetShaderVarMem(shaderVars.lowerNormalTile, 4U, &strata.mLowerNormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum0NormalTile, 4U, &strata.mStratum0NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum1NormalTile, 4U, &strata.mStratum1NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum2NormalTile, 4U, &strata.mStratum2NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum3NormalTile, 4U, &strata.mStratum3NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum4NormalTile, 4U, &strata.mStratum4NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum5NormalTile, 4U, &strata.mStratum5NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum6NormalTile, 4U, &strata.mStratum6NormalTexture.mScaleX);
    SetShaderVarMem(shaderVars.stratum7NormalTile, 4U, &strata.mStratum7NormalTexture.mScaleX);

    shaderVars.normalTexture.GetTexture(terrainNormalTexture);

    const auto* const activeMap = WLD_GetActiveSession()->mWldMap;
    const auto* const activeTerrainView = reinterpret_cast<const TerrainWaterResourceView*>(activeMap->mTerrainRes);
    const TerrainHeightFieldRuntimeView* const heightField = activeTerrainView->mMap->mHeightFieldObject;

    const float terrainScale[4] = {
      1.0f / static_cast<float>(heightField->width - 1),
      1.0f / static_cast<float>(heightField->height - 1),
      0.0f,
      1.0f
    };
    SetShaderVarMem(shaderVars.terrainScale, 4U, terrainScale);

    CD3DDevice* const device = D3D_GetDevice();
    (void)device->GetHeadWidth(0U);
    (void)device->GetHeadHeight(0U);

    const float inverseViewportWidth = 1.0f / static_cast<float>(mViewportRenderWidth);
    const float inverseViewportHeight = 1.0f / static_cast<float>(mViewportRenderHeight);
    const float viewportWidthNdc = static_cast<float>(mViewportWidth) * inverseViewportWidth;
    const float viewportHeightNdc = static_cast<float>(mViewportHeight) * inverseViewportHeight;

    const float viewportScale[2] = {
      viewportWidthNdc * 0.5f,
      viewportHeightNdc * -0.5f
    };

    const float viewportOffset[2] = {
      (viewportWidthNdc * 0.5f) + (static_cast<float>(mViewportOriginX) * inverseViewportWidth) + (inverseViewportWidth * 0.5f),
      (inverseViewportHeight * 0.5f)
        + ((static_cast<float>(mViewportOriginY) * inverseViewportHeight) + (viewportHeightNdc * 0.5f))
    };

    SetShaderVarMem(shaderVars.viewportScale, 2U, viewportScale);
    SetShaderVarMem(shaderVars.viewportOffset, 2U, viewportOffset);
  }

  /**
   * Address: 0x00807410 (FUN_00807410, Moho::MediumFidelityTerrain::DrawWaterLine)
   *
   * What it does:
   * Dispatches the shared medium-fidelity water alpha-mask render lane for the
   * active terrain camera.
   */
  void MediumFidelityTerrain::DrawWaterLine(const std::int32_t /*arg0*/, const std::int32_t /*arg1*/)
  {
    (void)sMediumFidelityWaterSurface->RenderWaterLayerAlphaMask(mCamera);
  }

  /**
   * Address: 0x00805530 (FUN_00805530, Moho::MediumFidelityTerrain::DrawTerrainSkirt)
   *
   * What it does:
   * Selects the terrain-skirt technique and emits one indexed triangle-list
   * draw using medium-fidelity skirt lanes when terrain/skirt flags are
   * enabled and index-count constraints pass.
   */
  void MediumFidelityTerrain::DrawTerrainSkirt()
  {
    if (!ren_Terrain || !ren_Skirt) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectTechnique("TTerrainSkirt");

    std::int32_t indexCount = static_cast<std::int32_t>(mSkirtEndIndex - mSkirtStartIndex);
    if (indexCount > kSkirtMaxIndexCount) {
      indexCount = kSkirtMaxIndexCount;
    } else if (indexCount <= 0) {
      return;
    }

    if ((indexCount % 3) != 0) {
      return;
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

    (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }

  /**
   * Address: 0x00803AD0 (FUN_00803AD0, ??1MediumFidelityTerrain@Moho@@QAE@@Z)
   * Mangled: ??1MediumFidelityTerrain@Moho@@QAE@@Z
   *
   * What it does:
   * Tears down medium-fidelity terrain resources, restores inline vector
   * storage ownership, and then dispatches base teardown.
   */
  MediumFidelityTerrain::~MediumFidelityTerrain()
  {
    Destroy();

    DeleteOwned(mOverlayIndexSheet);
    DeleteOwned(mOverlayVertexSheet);
    mSecondaryPatchIndices.ResetStorageToInline();

    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTesselator);
    mPrimaryPatchIndices.ResetStorageToInline();
  }

  /**
   * Address: 0x00807990 (FUN_00807990, ??3MediumFidelityTerrain@Moho@@QAE@@Z)
   *
   * What it does:
   * Runs the medium-fidelity terrain destructor lane and conditionally frees
   * the object storage when the delete flag requests heap release.
   */
  MediumFidelityTerrain* MediumFidelityTerrain::DeleteWithFlag(
    MediumFidelityTerrain* const object,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    object->~MediumFidelityTerrain();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(object);
    }
    return object;
  }
} // namespace moho
