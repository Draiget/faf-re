#include "moho/terrain/HighFidelityTerrain.h"

#include <cstdint>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/tess/CTesselator.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/MediumFidelityTerrain.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/TerrainDynamicTextureHelpers.h"
#include "moho/terrain/TerrainShaderVars.h"
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
} // namespace

namespace moho
{
  extern bool ren_Terrain;
  extern bool ren_Skirt;

  // The primary patch lane is reinterpreted as the decal command lane by
  // the decal passes, exactly as low fidelity does: 0x10 header + 500 * 0x18
  // == 0x2EF0, the same span as FastVectorN<uint32_t, 3000>.
  using HighFidelityDecalCommandLane = gpg::core::FastVectorN<TerrainDecalDrawCommand, 500>;

  // The secondary patch lane is the splat vertex lane for the splat pass:
  // 0x10 header + 10000 * 0x1C == the same span as
  // FastVectorN<uint32_t, 70000>.
  using HighFidelitySplatVertexLane = gpg::core::FastVectorN<TerrainSplatVertex, 10000>;
  extern bool ren_Decals;
  extern bool ren_DecalOverDraw;
  extern bool ren_bicubicnormals;
  extern bool ren_glowingDecals;
  extern bool ren_ShowNormals;

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
  void HighFidelityTerrain::LoadShaderVars(const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture)
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

    shaderVars.normalTexture.SetRenderTargetTexture(terrainNormalTexture);

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
   * Address: 0x008015C0 (FUN_008015C0, func_SetTerrainVariables)
   *
   * IDA signature:
   * struct_ShaderVar *__thiscall func_SetTerrainVariables(
   *     HighFidelityTerrain *this, int a2);
   *
   * What it does:
   * Selects the `terrain` effect and binds every terrain-lighting shader var
   * for one pass. Camera lanes come from `mCamera`: view, projection, the
   * half-angle between the sun direction and the camera forward axis, the
   * camera forward direction, and the camera world position. Lighting lanes
   * come from the terrain resource: lighting multiplier, sun direction /
   * ambience / colour, specular colour and shadow-fill colour. A supplied
   * shadow context binds its enabled flag, shadow matrix and active shadow
   * texture; otherwise the shadows lane is written disabled. Finally the
   * noise, decal-mask and bi-cubic-lookup sheets are bound.
   *
   * This is the high-fidelity twin of MediumFidelityTerrain::
   * LoadTerrainLighting (0x00805600); the two differ only in which
   * per-fidelity noise / bi-cubic sheet globals they bind.
   */
  void HighFidelityTerrain::LoadTerrainLighting(TerrainShadowContext* const shadowContext)
  {
    auto& shaderVars = GetTerrainShaderVars();

    D3D_GetDevice()->SelectFxFile("terrain");

    const GeomCamera3& camera = *mCamera;

    if (shaderVars.viewMatrix.Exists()) {
      shaderVars.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (shaderVars.projMatrix.Exists()) {
      shaderVars.projMatrix.SetMatrix4x4(&camera.projection);
    }

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    const float lightingMultiplier = terrainRes->GetLightingMultiplier();
    if (shaderVars.lightingMultiplier.Exists()) {
      shaderVars.lightingMultiplier.SetFloat(lightingMultiplier);
    }

    const Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
    SetShaderVarMem(shaderVars.sunDirection, 3U, &sunDirection.x);

    const Wm3::Vector3f sunAmbience = terrainRes->GetSunAmbience();
    SetShaderVarMem(shaderVars.sunAmbience, 3U, &sunAmbience.x);

    const Wm3::Vector3f sunColor = terrainRes->GetSunColor();
    SetShaderVarMem(shaderVars.sunColor, 3U, &sunColor.x);

    // Half-angle vector: normalize(sunDirection + inverseView.r[2]). The binary
    // spells each component `sunDir - (-0.0 - invView.r[2].c)`, which is an
    // addition because the constant is -0.0.
    const Vector4f& cameraBasisZ = camera.inverseView.r[2];
    float halfAngle[3] = {
      sunDirection.x + cameraBasisZ.x,
      sunDirection.y + cameraBasisZ.y,
      sunDirection.z + cameraBasisZ.z
    };
    const float halfAngleLength =
      std::sqrt((halfAngle[0] * halfAngle[0]) + (halfAngle[1] * halfAngle[1]) + (halfAngle[2] * halfAngle[2]));
    if (halfAngleLength > 0.0f) {
      const float inverseLength = 1.0f / halfAngleLength;
      halfAngle[0] *= inverseLength;
      halfAngle[1] *= inverseLength;
      halfAngle[2] *= inverseLength;
    } else {
      halfAngle[0] = 0.0f;
      halfAngle[1] = 0.0f;
      halfAngle[2] = 0.0f;
    }
    SetShaderVarMem(shaderVars.halfAngle, 3U, halfAngle);

    // Camera forward direction: -inverseView.r[2].
    const float cameraDirection[3] = {
      -cameraBasisZ.x,
      -cameraBasisZ.y,
      -cameraBasisZ.z
    };
    SetShaderVarMem(shaderVars.cameraDirection, 3U, cameraDirection);

    // Camera world position: inverseView.r[3] (translation row).
    const Vector4f& cameraTranslation = camera.inverseView.r[3];
    const float cameraPosition[3] = {
      cameraTranslation.x,
      cameraTranslation.y,
      cameraTranslation.z
    };
    SetShaderVarMem(shaderVars.cameraPosition, 3U, cameraPosition);

    const Vector4f specularColor = terrainRes->GetSpecularColor();
    SetShaderVarMem(shaderVars.specularColor, 4U, &specularColor.x);

    const Wm3::Vector3f shadowFillColor = terrainRes->GetShadowFillColor();
    SetShaderVarMem(shaderVars.shadowFillColor, 3U, &shadowFillColor.x);

    if (shadowContext != nullptr) {
      // The binary zero-extends the raw shadow-enabled byte into a 4-byte blob.
      const std::uint32_t shadowsEnabledBlob =
        static_cast<std::uint32_t>(static_cast<std::uint8_t>(shadowContext->shadowsEnabled));
      SetShaderVarPtr(shaderVars.shadowsEnabled, &shadowsEnabledBlob, 4U);

      if (shaderVars.shadowMatrix.Exists()) {
        shaderVars.shadowMatrix.SetMatrix4x4(&shadowContext->shadowMatrix);
      }

      const boost::shared_ptr<CD3DRenderTarget> shadowTexture = GetActiveShadowTexture(*shadowContext);
      shaderVars.shadowTexture.SetRenderTargetTexture(shadowTexture);
    } else {
      const std::uint32_t shadowsDisabledBlob = 0U;
      SetShaderVarPtr(shaderVars.shadowsEnabled, &shadowsDisabledBlob, 4U);
    }

    shaderVars.noiseTexture.GetTexture(sHighFidelityNoiseFillTexture);
    shaderVars.decalMaskTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(boost::static_pointer_cast<ID3DTextureSheet>(mDecalMask))
    );
    shaderVars.biCubicLookup.GetTexture(sHighFidelityCubicBlendLookupTexture);
  }

  /**
   * Address: 0x00802C30 (FUN_00802C30, Moho::HighFidelityTerrain::OverDrawDecals)
   *
   * IDA signature:
   * void callcnv_53 sub_802C30(HighFidelityTerrain *a1, MeshRenderer *a4, float a3);
   * (`a4` is the game tick, which IDA types as a pointer because it arrives in
   * a register - see the note on the frame seed below.)
   *
   * What it does:
   * Draws the normal-mapped terrain decals. Walks the decal command lane once,
   * drawing every `Normals` and `NormalsAlpha` command, and re-selects the
   * technique only when the run switches between the two types. Under
   * `ren_DecalOverDraw` both runs use `TDecalOverDraw` instead.
   *
   * Note this differs from MediumFidelityTerrain::DrawNormalMappedDecals as
   * currently recovered, which stops at the first `NormalsAlpha` command. Here
   * the alpha command is drawn and the walk continues; the binary tracks the
   * active technique in a flag rather than terminating.
   */
  void HighFidelityTerrain::OverDrawDecals(const std::int32_t gameTick, const float deltaSeconds)
  {
    if (!ren_Decals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    D3D_GetDevice()->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : "TDecalsNormals");

    const GeomCamera3& camera = *mCamera;

    // Every render-state bind + indexed draw for one decal command. Shared by
    // both the normals run and the alpha run, which is why the binary reaches
    // it from two places.
    const auto drawDecalCommand = [&](const TerrainDecalDrawCommand& command) {
      CWldTerrainDecal& decal = *command.decal;

      if (shaderVars.viewMatrix.Exists()) {
        shaderVars.viewMatrix.SetMatrix4x4(&camera.view);
      }
      if (shaderVars.projMatrix.Exists()) {
        shaderVars.projMatrix.SetMatrix4x4(&camera.projection);
      }
      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }
      if (shaderVars.tangentMatrix.Exists()) {
        shaderVars.tangentMatrix.SetMatrix4x4(&decal.mTangentMatrix);
      }
      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      // GetTexture(slot, phaseOffset, frameSeed): the float is the frame delta
      // and the int seed is the game tick, which is the only type-consistent
      // reading of the two values the caller threads through.
      const boost::shared_ptr<ID3DTextureSheet> texture = decal.GetTexture(0, deltaSeconds, gameTick);
      shaderVars.decalNormalTexture.GetTexture(
        boost::static_pointer_cast<CD3DDynamicTextureSheet>(texture));

      std::int32_t primitiveType = kTriangleListPrimitiveToken;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = mTerrainIndexSheet;
      indexView.startIndex = command.startIndex;
      indexView.indexCount = command.indexCount;

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = mTerrainVertexSheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = command.baseVertex;
      vertexView.endVertex = command.endVertex;

      (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    };

    bool alphaTechniqueActive = false;
    const auto& decalCommands = reinterpret_cast<const HighFidelityDecalCommandLane&>(mPrimaryPatchData);

    for (const TerrainDecalDrawCommand& command : decalCommands) {
      const EWldTerrainDecalType type = command.decal->mType;

      if (type == WldTerrainDecalType_NormalsAlpha) {
        if (!alphaTechniqueActive) {
          alphaTechniqueActive = true;
          D3D_GetDevice()->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : "TDecalsNormalsAlpha");
        }
        drawDecalCommand(command);
        continue;
      }

      if (type == WldTerrainDecalType_Normals) {
        if (alphaTechniqueActive) {
          alphaTechniqueActive = false;
          D3D_GetDevice()->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : "TDecalsNormals");
        }
        drawDecalCommand(command);
      }
    }
  }

  /**
   * Address: 0x00802F20 (FUN_00802F20, Moho::HighFidelityTerrain::DrawTerrainNormal)
   * Primary vtable slot 9 (vftable @0x00E41A14).
   *
   * IDA signature:
   * void __thiscall Moho::HighFidelityTerrain::DrawTerrainNormal(
   *     HighFidelityTerrain *this, MeshRenderer *a2, float a3);
   *
   * What it does:
   * Fills the off-screen terrain-normal buffer that
   * `WRenViewport::TransformTerrainNormals` samples one call later for its
   * `TCreateBasis` pass.
   *
   * Selects the `terrain` effect and resolves the pass technique from the
   * active stratum material's `normals` string annotation, falling back to
   * `TTerrainNormals`. Binds terrain lighting with no shadow context and the
   * base shader vars with no scratch handle, draws the terrain triangles and -
   * unless decal over-draw is on - the normal-mapped decals. Then switches to
   * the basis technique and walks every normal-map tile, binding that tile's
   * scale/offset and the E_X / E_Y / Size_Source basis constants before
   * drawing its tesselated geometry.
   *
   * This is the high-fidelity twin of MediumFidelityTerrain::DrawTerrainNormal
   * (0x00806F50); the two differ only in which lighting helper they call.
   */
  void HighFidelityTerrain::DrawTerrainNormal(const std::int32_t gameTick, const float deltaSeconds)
  {
    if (!ren_Terrain) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();
    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("terrain");

    // The technique name is an annotation on the stratum material's shader
    // rather than a literal, so a map can override the normal pass.
    CD3DEffect* const effect = device->GetCurEffect();
    const msvc8::string technique = effect->GetStringAnnotation(
      terrainRes->GetStratumMaterial().mShaderName,
      msvc8::string{"normals"},
      msvc8::string{"TTerrainNormals"});
    device->SelectTechnique(technique.c_str());

    LoadTerrainLighting(nullptr);
    LoadShaderVars({});
    DrawTriangles();
    if (!ren_DecalOverDraw) {
      OverDrawDecals(gameTick, deltaSeconds);
    }

    device->SelectTechnique(ren_bicubicnormals ? "TTerrainBasisBiCubic" : "TTerrainBasis");

    const std::int32_t normalMapCount = terrainRes->GetNormalMapCount();
    for (std::int32_t tile = 0; tile < normalMapCount; ++tile) {
      const SNormalMapInfo info = terrainRes->GetNormalMapInfo(tile);

      shaderVars.utilityTextureA.GetTexture(info.mTexture);

      SetShaderVarMem(shaderVars.normalMapScale, 4U, &info.mXResolution);
      SetShaderVarMem(shaderVars.normalMapOffset, 4U, &info.mOffsetScaleX);

      const float basisEX[2] = {1.0F / info.mWidth, 0.0F};
      SetShaderVarMem(shaderVars.normalBasisEX, 2U, basisEX);
      const float basisEY[2] = {0.0F, 1.0F / info.mHeight};
      SetShaderVarMem(shaderVars.normalBasisEY, 2U, basisEY);
      SetShaderVarMem(shaderVars.normalBasisSizeSource, 2U, &info.mWidth);

      const std::int32_t querySize = (static_cast<std::int32_t>(info.mWidth) < static_cast<std::int32_t>(info.mHeight))
                                       ? static_cast<std::int32_t>(info.mHeight)
                                       : static_cast<std::int32_t>(info.mWidth);

      std::int32_t rangeStart = 0;
      std::uint32_t rangeCount = 0;
      std::int32_t minValue = 0;
      std::int32_t maxValue = 0;
      (void)mTesselator->Tesselate(
        static_cast<std::int32_t>(info.mTileOriginX),
        static_cast<std::int32_t>(info.mTileOriginY),
        querySize,
        &rangeStart,
        &rangeCount,
        &minValue,
        &maxValue);

      if (rangeStart + static_cast<std::int32_t>(rangeCount) >= kSkirtMaxIndexCount) {
        continue;
      }
      if (rangeCount == 0U || (rangeCount % 3U) != 0U) {
        continue;
      }

      std::int32_t primitiveType = kTriangleListPrimitiveToken;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = mTerrainIndexSheet;
      indexView.startIndex = rangeStart;
      indexView.indexCount = static_cast<std::int32_t>(rangeCount);

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = mTerrainVertexSheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = minValue;
      vertexView.endVertex = maxValue;

      (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }
  }

  /**
   * Address: 0x008025B0 (FUN_008025B0, sub_8025B0)
   *
   * What it does:
   * Draws every queued decal command whose type equals `decalType`, under the
   * caller's technique (or `TDecalOverDraw` when `ren_DecalOverDraw` is set),
   * binding each decal's texture matrix, albedo + specular sheets and alpha.
   */
  void HighFidelityTerrain::DrawDecalPass(
    const std::int32_t gameTick, const float deltaSeconds,
    const std::int32_t decalType, const char* const techniqueName)
  {
    if (!ren_Decals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    D3D_GetDevice()->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : techniqueName);

    const auto& decalCommands = reinterpret_cast<const HighFidelityDecalCommandLane&>(mPrimaryPatchData);
    for (const TerrainDecalDrawCommand& command : decalCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (static_cast<std::int32_t>(decal.mType) != decalType) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      shaderVars.decalAlbedoTexture.GetTexture(
        boost::static_pointer_cast<CD3DDynamicTextureSheet>(decal.GetTexture(0, deltaSeconds, gameTick)));
      shaderVars.decalSpecTexture.GetTexture(
        boost::static_pointer_cast<CD3DDynamicTextureSheet>(decal.GetTexture(1, deltaSeconds, gameTick)));

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      std::int32_t primitiveType = kTriangleListPrimitiveToken;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = mTerrainIndexSheet;
      indexView.startIndex = command.startIndex;
      indexView.indexCount = command.indexCount;

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = mTerrainVertexSheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = command.baseVertex;
      vertexView.endVertex = command.endVertex;

      (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }
  }

  /**
   * Address: 0x00802830 (FUN_00802830, sub_802830)
   *
   * What it does:
   * Copies the whole splat vertex lane into the dynamic vertex sheet's stream
   * and draws it as one `TSplats` quad list against the texture batcher's
   * composite texture. Four vertices per quad, six indices per quad.
   */
  void HighFidelityTerrain::DrawSplatComposite()
  {
    const auto& splatVertices = reinterpret_cast<const HighFidelitySplatVertexLane&>(mSecondaryPatchData);
    const std::size_t splatVertexCount = splatVertices.size();
    if (splatVertexCount == 0) {
      return;
    }

    void* const lockedVertices =
      mDynamicVertexSheet->GetVertStream(0U)->Lock(0, static_cast<std::int32_t>(splatVertexCount), false, true);
    std::memcpy(lockedVertices, splatVertices.data(), sizeof(TerrainSplatVertex) * splatVertexCount);
    mDynamicVertexSheet->GetVertStream(0U)->Unlock();

    D3D_GetDevice()->SelectTechnique("TSplats");

    auto& shaderVars = GetTerrainShaderVars();
    shaderVars.decalAlbedoTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(sHighFidelityTextureBatcher->GetCompositeTexture())
    );

    std::int32_t primitiveType = kTriangleListPrimitiveToken;

    CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = mDynamicIndexSheet;
    indexView.startIndex = 0;
    indexView.indexCount = 6 * (static_cast<std::int32_t>(splatVertexCount) / 4);

    CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = mDynamicVertexSheet;
    vertexView.startVertex = 0;
    vertexView.baseVertex = 0;
    vertexView.endVertex = static_cast<std::int32_t>(splatVertexCount) - 1;

    (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }

  /**
   * Address: 0x00802A20 (FUN_00802A20, sub_802A20)
   *
   * What it does:
   * Draws every glowing decal command (`mType == WldTerrainDecalType_Glow`)
   * with the `TDecalsGlow` technique. Gated on `ren_Decals` and
   * `ren_glowingDecals` together.
   */
  void HighFidelityTerrain::DrawGlowingDecals(const std::int32_t gameTick, const float deltaSeconds)
  {
    if (!ren_Decals || !ren_glowingDecals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    D3D_GetDevice()->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : "TDecalsGlow");

    const auto& decalCommands = reinterpret_cast<const HighFidelityDecalCommandLane&>(mPrimaryPatchData);
    for (const TerrainDecalDrawCommand& command : decalCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (decal.mType != WldTerrainDecalType_Glow) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      shaderVars.decalAlbedoTexture.GetTexture(
        boost::static_pointer_cast<CD3DDynamicTextureSheet>(decal.GetTexture(0, deltaSeconds, gameTick)));

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      std::int32_t primitiveType = kTriangleListPrimitiveToken;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = mTerrainIndexSheet;
      indexView.startIndex = command.startIndex;
      indexView.indexCount = command.indexCount;

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = mTerrainVertexSheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = command.baseVertex;
      vertexView.endVertex = command.endVertex;

      (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }
  }

  /**
   * Address: 0x00801BE0 (FUN_00801BE0, Moho::HighFidelityTerrain::DrawNormals)
   * Primary vtable slot 8 (vftable @0x00E41A14).
   *
   * IDA signature:
   * int __thiscall Moho::HighFidelityTerrain::DrawNormals(
   *     HighFidelityTerrain *this, MeshRenderer *a4, float a5,
   *     boost::weak_ptr arg8, int arg10);
   *
   * What it does:
   * The high-fidelity terrain normal/decal render pass. Binds terrain lighting
   * for the shadow context, then either forwards to the debug
   * normal-visualization path (`ren_ShowNormals`) or runs the full decal pass:
   * binds the water ramp and the three water-elevation constants, selects the
   * active stratum-material technique, loads the base shader vars, draws the
   * terrain triangles, then the glow-mask / albedo / XP decal passes, the splat
   * composite, the glowing decals, and - under `ren_DecalOverDraw` - the
   * normal-mapped decals. Returns true when terrain rendering is enabled.
   *
   * The water elevations fall back to -10000.0f (the decompiler's
   * -971227136 = 0xC61C4000) when the map has no water, putting every
   * elevation test safely below the terrain.
   */
  bool HighFidelityTerrain::DrawNormals(
    const std::int32_t gameTick,
    const float deltaSeconds,
    const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture,
    TerrainShadowContext* const shadowContext)
  {
    if (!ren_Terrain) {
      return false;
    }

    LoadTerrainLighting(shadowContext);

    if (ren_ShowNormals) {
      DrawTerrainNormal(gameTick, deltaSeconds);
      return true;
    }

    auto& shaderVars = GetTerrainShaderVars();
    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    // Water ramp texture from the terrain's water shader properties.
    CWaterShaderProperties* const waterProperties = terrainRes->GetWaterShaderProperties();
    shaderVars.waterRamp.GetTexture(waterProperties->GetWaterRamp());

    StratumMaterial& strata = terrainRes->GetStratumMaterial();
    D3D_GetDevice()->SelectTechnique(strata.mShaderName.c_str());

    // Absent water puts every elevation below the terrain so the shader's
    // depth tests never trigger.
    constexpr float kNoWaterElevation = -10000.0F;
    const TerrainMapRuntimeView& map = *mTerrainResource->mMap;

    if (shaderVars.waterElevation.Exists()) {
      shaderVars.waterElevation.SetFloat(
        map.mWaterEnabled ? map.mWaterElevation : kNoWaterElevation);
    }
    if (shaderVars.waterElevationDeep.Exists()) {
      shaderVars.waterElevationDeep.SetFloat(
        map.mWaterEnabled ? map.mWaterElevationDeep : kNoWaterElevation);
    }
    if (shaderVars.waterElevationAbyss.Exists()) {
      shaderVars.waterElevationAbyss.SetFloat(
        map.mWaterEnabled ? map.mWaterElevationAbyss : kNoWaterElevation);
    }

    (void)terrainRes->IsInEditMode();

    LoadShaderVars(terrainNormalTexture);
    DrawTriangles();

    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_GlowMask, "TDecalGlowMask");
    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_Albedo, "TDecals");
    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_AlbedoXp, "TDecalsXP");
    DrawSplatComposite();
    DrawGlowingDecals(gameTick, deltaSeconds);

    if (ren_DecalOverDraw) {
      OverDrawDecals(gameTick, deltaSeconds);
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
