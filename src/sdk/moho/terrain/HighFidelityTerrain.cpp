#include "moho/terrain/HighFidelityTerrain.h"

#include <cstdint>

#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/ShaderVar.h"
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
#include "moho/terrain/water/WaterFactory.h"
#include "moho/terrain/water/WaterShaderVars.h"
#include "moho/terrain/water/WaterSurface.h"

namespace
{
  using TextureSheetHandle = boost::shared_ptr<moho::CD3DDynamicTextureSheet>;
  using TextureResourceHandle = boost::shared_ptr<moho::RD3DTextureResource>;
  using GenericTextureSheetHandle = boost::shared_ptr<moho::ID3DTextureSheet>;
  using TextureWeakHandle = boost::weak_ptr<gpg::gal::TextureD3D9>;

  moho::WaterSurface* sHighFidelityWaterSurface = nullptr;
  TextureSheetHandle sHighFidelityNoiseFillTexture{};
  TextureSheetHandle sHighFidelityCubicBlendLookupTexture{};
  moho::CD3DTextureBatcher* sHighFidelityTextureBatcher = nullptr;
  TextureResourceHandle sHighFidelityGridTexture{};

  constexpr float kDisabledWaterElevation = -10000.0f;
  constexpr std::uint32_t kDynamicIndexCount = 15000;
  constexpr std::uint16_t kDynamicVertexLoopStop = 10002u;
  constexpr std::int32_t kTriangleListPrimitiveToken = 4;
  constexpr std::int32_t kSkirtMaxIndexCount = 199998;
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

  struct TerrainShaderVarSet
  {
    moho::ShaderVar skirtTexture;
    moho::ShaderVar utilityTextureA;
    moho::ShaderVar utilityTextureB;
    moho::ShaderVar utilityTextureC;

    moho::ShaderVar lowerAlbedoTexture;
    moho::ShaderVar stratum0AlbedoTexture;
    moho::ShaderVar stratum1AlbedoTexture;
    moho::ShaderVar stratum2AlbedoTexture;
    moho::ShaderVar stratum3AlbedoTexture;
    moho::ShaderVar stratum4AlbedoTexture;
    moho::ShaderVar stratum5AlbedoTexture;
    moho::ShaderVar stratum6AlbedoTexture;
    moho::ShaderVar stratum7AlbedoTexture;
    moho::ShaderVar upperAlbedoTexture;

    moho::ShaderVar lowerNormalTexture;
    moho::ShaderVar stratum0NormalTexture;
    moho::ShaderVar stratum1NormalTexture;
    moho::ShaderVar stratum2NormalTexture;
    moho::ShaderVar stratum3NormalTexture;
    moho::ShaderVar stratum4NormalTexture;
    moho::ShaderVar stratum5NormalTexture;
    moho::ShaderVar stratum6NormalTexture;
    moho::ShaderVar stratum7NormalTexture;

    moho::ShaderVar lowerAlbedoTile;
    moho::ShaderVar stratum0AlbedoTile;
    moho::ShaderVar stratum1AlbedoTile;
    moho::ShaderVar stratum2AlbedoTile;
    moho::ShaderVar stratum3AlbedoTile;
    moho::ShaderVar stratum4AlbedoTile;
    moho::ShaderVar stratum5AlbedoTile;
    moho::ShaderVar stratum6AlbedoTile;
    moho::ShaderVar stratum7AlbedoTile;
    moho::ShaderVar upperAlbedoTile;

    moho::ShaderVar lowerNormalTile;
    moho::ShaderVar stratum0NormalTile;
    moho::ShaderVar stratum1NormalTile;
    moho::ShaderVar stratum2NormalTile;
    moho::ShaderVar stratum3NormalTile;
    moho::ShaderVar stratum4NormalTile;
    moho::ShaderVar stratum5NormalTile;
    moho::ShaderVar stratum6NormalTile;
    moho::ShaderVar stratum7NormalTile;

    moho::ShaderVar normalTexture;
    moho::ShaderVar terrainScale;
    moho::ShaderVar viewportScale;
    moho::ShaderVar viewportOffset;

    TerrainShaderVarSet()
    {
      moho::RegisterShaderVar("SkirtTexture", &skirtTexture, "terrain");
      moho::RegisterShaderVar("UtilityTextureA", &utilityTextureA, "terrain");
      moho::RegisterShaderVar("UtilityTextureB", &utilityTextureB, "terrain");
      moho::RegisterShaderVar("UtilityTextureC", &utilityTextureC, "terrain");

      moho::RegisterShaderVar("LowerAlbedoTexture", &lowerAlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum0AlbedoTexture", &stratum0AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum1AlbedoTexture", &stratum1AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum2AlbedoTexture", &stratum2AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum3AlbedoTexture", &stratum3AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum4AlbedoTexture", &stratum4AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum5AlbedoTexture", &stratum5AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum6AlbedoTexture", &stratum6AlbedoTexture, "terrain");
      moho::RegisterShaderVar("Stratum7AlbedoTexture", &stratum7AlbedoTexture, "terrain");
      moho::RegisterShaderVar("UpperAlbedoTexture", &upperAlbedoTexture, "terrain");

      moho::RegisterShaderVar("LowerNormalTexture", &lowerNormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum0NormalTexture", &stratum0NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum1NormalTexture", &stratum1NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum2NormalTexture", &stratum2NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum3NormalTexture", &stratum3NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum4NormalTexture", &stratum4NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum5NormalTexture", &stratum5NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum6NormalTexture", &stratum6NormalTexture, "terrain");
      moho::RegisterShaderVar("Stratum7NormalTexture", &stratum7NormalTexture, "terrain");

      moho::RegisterShaderVar("LowerAlbedoTile", &lowerAlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum0AlbedoTile", &stratum0AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum1AlbedoTile", &stratum1AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum2AlbedoTile", &stratum2AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum3AlbedoTile", &stratum3AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum4AlbedoTile", &stratum4AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum5AlbedoTile", &stratum5AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum6AlbedoTile", &stratum6AlbedoTile, "terrain");
      moho::RegisterShaderVar("Stratum7AlbedoTile", &stratum7AlbedoTile, "terrain");
      moho::RegisterShaderVar("UpperAlbedoTile", &upperAlbedoTile, "terrain");

      moho::RegisterShaderVar("LowerNormalTile", &lowerNormalTile, "terrain");
      moho::RegisterShaderVar("Stratum0NormalTile", &stratum0NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum1NormalTile", &stratum1NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum2NormalTile", &stratum2NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum3NormalTile", &stratum3NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum4NormalTile", &stratum4NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum5NormalTile", &stratum5NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum6NormalTile", &stratum6NormalTile, "terrain");
      moho::RegisterShaderVar("Stratum7NormalTile", &stratum7NormalTile, "terrain");

      moho::RegisterShaderVar("NormalTexture", &normalTexture, "terrain");
      moho::RegisterShaderVar("TerrainScale", &terrainScale, "terrain");
      moho::RegisterShaderVar("ViewportScale", &viewportScale, "terrain");
      moho::RegisterShaderVar("ViewportOffset", &viewportOffset, "terrain");
    }
  };

  [[nodiscard]] TerrainShaderVarSet& GetTerrainShaderVars()
  {
    static TerrainShaderVarSet shaderVars{};
    return shaderVars;
  }

  void BindTextureShaderVar(moho::ShaderVar& shaderVar, const GenericTextureSheetHandle& textureSheet)
  {
    moho::ID3DTextureSheet::TextureHandle textureHandle{};
    if (textureSheet != nullptr) {
      textureSheet->GetTexture(textureHandle);
    }
    shaderVar.GetTexture(TextureWeakHandle(textureHandle));
  }

  void BindTextureShaderVar(
    moho::ShaderVar& shaderVar,
    const boost::SharedPtrRaw<moho::RD3DTextureResource>& textureResource
  )
  {
    const boost::shared_ptr<moho::RD3DTextureResource> retainedTexture = boost::SharedPtrFromRawRetained(textureResource);
    BindTextureShaderVar(shaderVar, boost::static_pointer_cast<moho::ID3DTextureSheet>(retainedTexture));
  }

  void SetShaderVarMem(moho::ShaderVar& shaderVar, const std::uint32_t floatCount, const float* const values)
  {
    if (shaderVar.Exists()) {
      shaderVar.mEffectVariable->SetMem(floatCount, values);
    }
  }
} // namespace

namespace moho
{
  extern bool ren_Terrain;
  extern bool ren_Skirt;

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
   * Address: 0x00800DC0 (FUN_00800DC0, Moho::HighFidelityTerrain::LoadShaderVars)
   *
   * What it does:
   * Binds terrain shader texture lanes from world stratum material + water map,
   * updates terrain-scale and viewport normalization constants, and forwards
   * the optional terrain-normal map texture handle for terrain normal passes.
   */
  void HighFidelityTerrain::LoadShaderVars(boost::weak_ptr<gpg::gal::TextureD3D9> terrainNormalTexture)
  {
    auto& shaderVars = GetTerrainShaderVars();

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);
    StratumMaterial& strata = terrainRes->GetStratumMaterial();
    strata.SetSizeTo(reinterpret_cast<CWldTerrainRes*>(terrainRes));

    BindTextureShaderVar(shaderVars.skirtTexture, boost::static_pointer_cast<ID3DTextureSheet>(sHighFidelityGridTexture));
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
   * Address: 0x008014F0 (FUN_008014F0, Moho::HighFidelityTerrain::DrawTerrainSkirt)
   *
   * What it does:
   * Selects the terrain-skirt technique and emits one indexed triangle-list
   * draw using high-fidelity skirt lanes when terrain/skirt flags are enabled
   * and index-count constraints pass.
   */
  void HighFidelityTerrain::DrawTerrainSkirt()
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

    std::int32_t primitiveType = kTriangleListPrimitiveToken;

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
   * Address: 0x00801460 (FUN_00801460, Moho::HighFidelityTerrain::DrawTriangles)
   *
   * What it does:
   * Draws one terrain triangle-list pass using `mTerrainIndexSheet` and
   * `mTerrainVertexSheet` with `(start=0, base=0)` and clamped index count.
   */
  void HighFidelityTerrain::DrawTriangles()
  {
    std::int32_t indexCount = static_cast<std::int32_t>(mSkirtStartIndex);
    if (indexCount <= 0 || (indexCount % 3) != 0) {
      return;
    }

    if (indexCount > kSkirtMaxIndexCount) {
      indexCount = kSkirtMaxIndexCount;
    }

    std::int32_t primitiveType = kTriangleListPrimitiveToken;

    CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = mTerrainIndexSheet;
    indexView.startIndex = 0;
    indexView.indexCount = indexCount;

    CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = mTerrainVertexSheet;
    vertexView.startVertex = 0;
    vertexView.baseVertex = 0;
    vertexView.endVertex = static_cast<std::int32_t>(mUnknown30);

    (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
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
