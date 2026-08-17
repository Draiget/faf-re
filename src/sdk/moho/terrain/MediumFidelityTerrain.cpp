#include "moho/terrain/MediumFidelityTerrain.h"

#include <cmath>
#include <cstdint>
#include <cstring>

#include "Wm3Vector3.h"
#include "gpg/gal/Matrix.h"
#include "moho/math/Vector4f.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/camera/GeomCamera3.h"
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
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterFactory.h"
#include "moho/render/d3d/CD3DRenderTarget.h"

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
  // Sentinel water-elevation value (dword_E4F6E4 = 0xC61C4000 = -10000.0f) bound
  // when the active map has no water enabled.
  constexpr float kWaterElevationSentinel = -10000.0f;
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
  /**
   * Address: 0x007FEE70 (FUN_007FEE70, sub_7FEE70)
   *
   * IDA signature:
   * _DWORD *__usercall sub_7FEE70@<eax>(_DWORD *result@<eax>, int a2@<ecx>);
   *
   * What it does:
   * Returns the active retained shadow texture for a cast-shadow terrain pass.
   * Selects the secondary texture at +0x2F0 when the byte flag at +0x0C is set,
   * otherwise the primary texture at +0x2E0, and returns a retained (strong-ref)
   * copy of that `boost::shared_ptr<gpg::gal::TextureD3D9>`.
   */
  [[nodiscard]] boost::shared_ptr<CD3DRenderTarget> GetActiveShadowTexture(
    const TerrainShadowContext& shadowContext
  )
  {
    return shadowContext.useSecondaryShadowTexture ? shadowContext.secondaryShadowTexture
                                                   : shadowContext.primaryShadowTexture;
  }
  extern bool ren_Terrain;
  extern bool ren_Skirt;
  extern bool ren_Decals;
  extern bool ren_ShowNormals;
  extern bool ren_DecalOverDraw;
  extern bool ren_glowingDecals;
  extern bool ren_bicubicnormals;

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
  void MediumFidelityTerrain::LoadShaderVars(const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture)
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
   * Address: 0x00805600 (FUN_00805600, sub_805600)
   *
   * IDA signature:
   * struct_ShaderVar *__thiscall sub_805600(int this, int a2);
   *
   * What it does:
   * Selects the `terrain` effect, then binds every terrain-lighting shader var.
   * Matrix / camera lanes come from `mCamera` (GeomCamera3): `view`, `projection`,
   * the half-angle between the sun direction and the camera forward axis
   * (`inverseView.r[2]`), the camera forward direction (`-inverseView.r[2]`), and
   * the camera world position (`inverseView.r[3]`). Lighting lanes come from the
   * terrain resource: lighting multiplier, sun direction/ambience/color, specular
   * color and shadow-fill color. When a shadow context is supplied its enabled
   * flag, shadow matrix and active shadow texture are bound; otherwise the shadows
   * lane is written disabled. Finally the noise / decal-mask / bi-cubic-lookup
   * textures are bound.
   */
  void MediumFidelityTerrain::LoadTerrainLighting(TerrainShadowContext* const shadowContext)
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

    // Half-angle vector: normalize(sunDirection + inverseView.r[2]).
    // The binary computes `sunDir - (-0.0 - invView.r[2].c)` per component,
    // which is `sunDir.c + invView.r[2].c` (the constant is -0.0).
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

    // The binary binds these three directly through the shader-var
    // shared_ptr<CD3DDynamicTextureSheet> lane (struct_ShaderVar::GetTexture,
    // 0x00438140). The noise-fill and bi-cubic-lookup sheets are the shared
    // medium-fidelity sheet globals; the decal mask is the base-class terrain
    // decal texture, reinterpreted as a dynamic sheet through the common
    // ID3DTextureSheet base (both derive from it at offset 0).
    shaderVars.noiseTexture.GetTexture(sMediumFidelityNoiseFillTexture);
    shaderVars.decalMaskTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(boost::static_pointer_cast<ID3DTextureSheet>(mDecalMask))
    );
    shaderVars.biCubicLookup.GetTexture(sMediumFidelityCubicBlendLookupTexture);
  }

  /**
   * Address: 0x00805B50 (FUN_00805B50, Moho::MediumFidelityTerrain::CondDrawTerrainTechnique)
   *
   * IDA signature:
   * void __userpurge Moho::MediumFidelityTerrain::CondDrawTerrainTechnique(
   *     int this@<ecx>, int@<esi>, float, int params);
   *
   * What it does:
   * Draws one terrain pass under a caller-chosen technique. Gated on
   * `ren_Terrain` like the rest of the class: selects the `terrain` effect and
   * the named technique, binds the pass's view/projection matrices and the
   * tesselator height scale, then issues the terrain triangle list.
   *
   * Unlike LowFidelityTerrain::DrawTerrainDepth the technique is not a
   * literal - it comes from the params block, which is what makes this the
   * `Cond` variant.
   */
  void MediumFidelityTerrain::CondDrawTerrainTechnique(const STerrainTechniqueDrawParams& params)
  {
    if (!ren_Terrain) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("terrain");
    device->SelectTechnique(params.mTechniqueName.c_str());

    auto& shaderVars = GetTerrainShaderVars();
    if (shaderVars.viewMatrix.Exists()) {
      shaderVars.viewMatrix.SetMatrix4x4(&params.mView);
    }
    if (shaderVars.projMatrix.Exists()) {
      shaderVars.projMatrix.SetMatrix4x4(&params.mProjection);
    }

    // The height scale is read before the Exists() guard in the binary, so the
    // tesselator call happens whether or not the var is bound.
    const float heightScale = mTesselator->GetHeightScale();
    if (shaderVars.heightScale.Exists()) {
      shaderVars.heightScale.SetFloat(heightScale);
    }

    DrawTriangles();
  }

  /**
   * Address: 0x00805490 (FUN_00805490, sub_805490)
   *
   * IDA signature:
   * void __usercall sub_805490(_DWORD *a1@<edi>);
   *
   * What it does:
   * Draws one terrain triangle-list pass from `mTerrainIndexSheet` /
   * `mTerrainVertexSheet` with `(startIndex=0, baseVertex=0)` and
   * `endVertex=mUnknown30`, using the legacy skirt-start index count clamped to
   * 199998. Skips the draw when that count is non-positive or not divisible by 3.
   */
  void MediumFidelityTerrain::DrawTriangles()
  {
    std::int32_t indexCount = static_cast<std::int32_t>(mSkirtStartIndex);
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
   * Address: 0x00807660 (FUN_00807660, Moho::MediumFidelityTerrain::DrawTerrain)
   *
   * IDA signature:
   * int __thiscall Moho::MediumFidelityTerrain::DrawTerrain(
   *     void *this, boost::shared_ptr_CD3DDynamicTextureSheet a2, int *a3);
   *
   * What it does:
   * Runs one full opaque terrain pass. Rebinds all lighting shader vars with no
   * shadow source, re-selects the `terrain` effect, selects the caller-provided
   * technique, binds the overlay texture, loads the base terrain shader vars, and
   * submits the terrain triangle list. The retained overlay-texture handle is
   * released as the by-value shared_ptr parameter goes out of scope.
   */
  void MediumFidelityTerrain::DrawTerrain(
    boost::shared_ptr<CD3DDynamicTextureSheet> overlayTexture,
    const msvc8::string* const techniqueName
  )
  {
    auto& shaderVars = GetTerrainShaderVars();

    LoadTerrainLighting(nullptr);

    D3D_GetDevice()->SelectFxFile("terrain");
    D3D_GetDevice()->SelectTechnique(techniqueName->c_str());

    shaderVars.overlayTexture.GetTexture(overlayTexture);

    LoadShaderVars({});

    DrawTriangles();
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

  namespace
  {
    /// Binds one decal command's index/vertex sub-range and submits a single
    /// indexed triangle-list draw over the terrain sheets. Shared by every decal
    /// draw helper below (their D3D view construction is byte-identical).
    void SubmitDecalCommandDraw(
      CD3DVertexSheet* const vertexSheet,
      CD3DIndexSheet* const indexSheet,
      const TerrainDecalDrawCommand& command
    )
    {
      std::int32_t primitiveType = kTriangleListPrimitiveType;

      CD3DIndexSheetViewRuntime indexView{};
      indexView.sheet = indexSheet;
      indexView.startIndex = command.startIndex;
      indexView.indexCount = command.indexCount;

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = vertexSheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = command.baseVertex;
      vertexView.endVertex = command.endVertex;

      (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }

    /// Resolves one animated decal texture slot and binds it into `target`.
    /// Mirrors the binary's `CWldTerrainDecal::GetTexture(slot, lod, frameSeed)`
    /// call followed by `struct_ShaderVar::GetTexture`. The frame seed is the raw
    /// game tick, which IDA mistypes as a MeshRenderer* because it arrives
    /// in a register (see WRenViewport::RenderCompositeTerrain @0x007F827E).
    void BindDecalTexture(
      ShaderVar& target,
      CWldTerrainDecal& decal,
      const int slot,
      const float lod,
      const std::int32_t gameTick
    )
    {
      const boost::shared_ptr<ID3DTextureSheet> texture =
        decal.GetTexture(slot, lod, gameTick);
      target.GetTexture(boost::static_pointer_cast<CD3DDynamicTextureSheet>(texture));
    }
  } // namespace

  /**
   * Address: 0x008065E0 (FUN_008065E0, sub_8065E0)
   *
   * IDA signature:
   * void __stdcall sub_8065E0(MediumFidelityTerrain *a1, MeshRenderer *a4,
   *     float a5, int argC, const char *arg10);
   *
   * What it does:
   * Draws each queued decal command whose decal type equals `decalType`. Selects
   * the caller technique (or `TDecalOverDraw` when `ren_DecalOverDraw` is on),
   * binds the decal texture matrix, the slot-0 albedo and slot-1 spec textures,
   * and the decal alpha, then submits one indexed triangle-list draw per match.
   */
  void MediumFidelityTerrain::DrawDecalPass(
    const std::int32_t gameTick,
    const float lod,
    const std::int32_t decalType,
    const char* const techniqueName
  )
  {
    if (!ren_Decals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    if (ren_DecalOverDraw) {
      D3D_GetDevice()->SelectTechnique("TDecalOverDraw");
    } else {
      D3D_GetDevice()->SelectTechnique(techniqueName);
    }

    for (const TerrainDecalDrawCommand& command : mDecalDrawCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (static_cast<std::int32_t>(decal.mType) != decalType) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      BindDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, gameTick);
      BindDecalTexture(shaderVars.decalSpecTexture, decal, 1, lod, gameTick);

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      SubmitDecalCommandDraw(mTerrainVertexSheet, mTerrainIndexSheet, command);
    }
  }

  /**
   * Address: 0x00806860 (FUN_00806860, sub_806860)
   *
   * IDA signature:
   * int __usercall sub_806860@<eax>(MediumFidelityTerrain *this@<esi>);
   *
   * What it does:
   * Uploads the composited splat-vertex lane into the overlay vertex sheet, selects
   * the `TSplats` technique, binds the shared texture-batcher composite texture into
   * the decal albedo lane, and submits one indexed triangle-list draw covering all
   * splat quads (`6 * (count / 4)` indices over `count` vertices). No-op when empty.
   */
  void MediumFidelityTerrain::DrawSplatComposite()
  {
    const std::size_t splatVertexCount = mSplatVertices.size();
    if (splatVertexCount == 0) {
      return;
    }

    // Copy the whole splat lane into the overlay vertex sheet's stream buffer.
    void* const lockedVertices =
      mOverlayVertexSheet->GetVertStream(0U)->Lock(0, static_cast<std::int32_t>(splatVertexCount), false, true);
    std::memcpy(lockedVertices, mSplatVertices.data(), sizeof(TerrainSplatVertex) * splatVertexCount);
    mOverlayVertexSheet->GetVertStream(0U)->Unlock();

    D3D_GetDevice()->SelectTechnique("TSplats");

    auto& shaderVars = GetTerrainShaderVars();
    shaderVars.decalAlbedoTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(sMediumFidelityTextureBatcher->GetCompositeTexture())
    );

    std::int32_t primitiveType = kTriangleListPrimitiveType;

    CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = mOverlayIndexSheet;
    indexView.startIndex = 0;
    indexView.indexCount = 6 * (static_cast<std::int32_t>(splatVertexCount) / 4);

    CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = mOverlayVertexSheet;
    vertexView.startVertex = 0;
    vertexView.baseVertex = 0;
    vertexView.endVertex = static_cast<std::int32_t>(splatVertexCount) - 1;

    (void)D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }

  /**
   * Address: 0x00806A50 (FUN_00806A50, sub_806A50)
   *
   * IDA signature:
   * void __stdcall sub_806A50(MediumFidelityTerrain *a1, MeshRenderer *a4, float a5);
   *
   * What it does:
   * Draws each glowing decal command (`mType == 6`) with the `TDecalsGlow`
   * technique (or `TDecalOverDraw` under `ren_DecalOverDraw`): binds the decal
   * matrix, slot-0 albedo texture, and decal alpha, then submits one indexed
   * triangle-list draw per glowing decal. No-op unless both `ren_Decals` and
   * `ren_glowingDecals` are enabled.
   */
  void MediumFidelityTerrain::DrawGlowingDecals(const std::int32_t gameTick, const float lod)
  {
    if (!ren_Decals || !ren_glowingDecals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    if (ren_DecalOverDraw) {
      D3D_GetDevice()->SelectTechnique("TDecalOverDraw");
    } else {
      D3D_GetDevice()->SelectTechnique("TDecalsGlow");
    }

    for (const TerrainDecalDrawCommand& command : mDecalDrawCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (decal.mType != WldTerrainDecalType_Glow) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      BindDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, gameTick);

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      SubmitDecalCommandDraw(mTerrainVertexSheet, mTerrainIndexSheet, command);
    }
  }

  /**
   * Address: 0x00806C60 (FUN_00806C60, sub_806C60)
   *
   * IDA signature:
   * void __stdcall sub_806C60(MediumFidelityTerrain *a1, MeshRenderer *a4, float a5);
   *
   * What it does:
   * Draws the normal-mapped decal commands (`mType == WldTerrainDecalType_Normals`)
   * with `TDecalsNormals` (or `TDecalOverDraw` under `ren_DecalOverDraw`). Iteration
   * stops at the first `WldTerrainDecalType_NormalsAlpha` sentinel, which is then
   * drawn once as an alpha pass with `TDecalsNormalsAlpha` (or `TDecalOverDraw`).
   * Each drawn command binds the camera view/proj matrices, the decal + tangent
   * matrices, the decal alpha, and the slot-0 normal texture, then submits one
   * indexed triangle-list draw. No-op unless `ren_Decals` is enabled.
   *
   * Note: the shipped code carries a state flag that could re-select the opaque
   * technique between an alpha pass and a following opaque decal, but that flag
   * only ever becomes set on the terminal alpha sentinel (which returns), so the
   * reselect never fires during forward iteration and is omitted here for clarity.
   */
  void MediumFidelityTerrain::DrawNormalMappedDecals(const std::int32_t gameTick, const float lod)
  {
    if (!ren_Decals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    if (ren_DecalOverDraw) {
      D3D_GetDevice()->SelectTechnique("TDecalOverDraw");
    } else {
      D3D_GetDevice()->SelectTechnique("TDecalsNormals");
    }

    const GeomCamera3& camera = *mCamera;

    // Emits every render-state bind + indexed draw for a single decal command.
    // Shared by the normal-mapped commands and the terminal alpha sentinel.
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

      BindDecalTexture(shaderVars.decalNormalTexture, decal, 0, lod, gameTick);

      SubmitDecalCommandDraw(mTerrainVertexSheet, mTerrainIndexSheet, command);
    };

    for (const TerrainDecalDrawCommand& command : mDecalDrawCommands) {
      const EWldTerrainDecalType type = command.decal->mType;

      if (type == WldTerrainDecalType_NormalsAlpha) {
        // Terminal sentinel: draw one alpha pass and stop.
        if (ren_DecalOverDraw) {
          D3D_GetDevice()->SelectTechnique("TDecalOverDraw");
        } else {
          D3D_GetDevice()->SelectTechnique("TDecalsNormalsAlpha");
        }
        drawDecalCommand(command);
        return;
      }

      if (type == WldTerrainDecalType_Normals) {
        drawDecalCommand(command);
      }
    }
  }

  /**
   * Address: 0x00806F50 (FUN_00806F50, Moho::MediumFidelityTerrain::DrawTerrainNormal)
   * Primary vtable slot 9 (vftable @0x00E41A54).
   *
   * IDA signature:
   * void __fastcall Moho::MediumFidelityTerrain::DrawTerrainNormal(
   *     int ecx0, int edx0, int a3, float arg4);
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
   * Unlike the low-fidelity tile loop this one additionally requires the
   * tesselated index count to be a whole number of triangles (`% 3 == 0`)
   * before issuing the draw.
   */
  void MediumFidelityTerrain::DrawTerrainNormal(const std::int32_t gameTick, const float deltaSeconds)
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
      DrawNormalMappedDecals(gameTick, deltaSeconds);
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

      std::int32_t primitiveType = kTriangleListPrimitiveType;

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
   * Address: 0x00805C20 (FUN_00805C20, Moho::MediumFidelityTerrain::DrawNormals)
   * Primary vtable slot 8 (vftable @0x00E41A54).
   *
   * IDA signature:
   * int __thiscall Moho::MediumFidelityTerrain::DrawNormals(
   *     MediumFidelityTerrain *this, MeshRenderer *a2, float a3,
   *     int a4, volatile signed __int32 *a5, int a6);
   *
   * What it does:
   * The terrain normal/decal render pass. When terrain rendering is disabled,
   * releases the by-value weak scratch handle and returns 0. Otherwise binds the
   * terrain lighting for `shadowContext`, then either forwards to the debug
   * normal-visualization path (`ren_ShowNormals`) or runs the full decal/splat
   * pass: binds the water ramp and the three water-elevation constants, selects the
   * active stratum-material technique, retains the scratch handle across the base
   * shader-var load, draws the terrain triangles, the glow-mask decals, the albedo
   * decals, the splat composite, the glowing decals, and (under `ren_DecalOverDraw`)
   * the normal-mapped decals. Returns 1.
   */
  bool MediumFidelityTerrain::DrawNormals(
    const std::int32_t gameTick,
    const float deltaSeconds,
    const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture,
    TerrainShadowContext* const shadowContext
  )
  {
    if (!ren_Terrain) {
      return false;
    }

    auto& shaderVars = GetTerrainShaderVars();

    LoadTerrainLighting(shadowContext);

    if (ren_ShowNormals) {
      DrawTerrainNormal(gameTick, deltaSeconds);
      return true;
    }

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    // Water ramp texture from the terrain's water shader properties.
    CWaterShaderProperties* const waterProperties = terrainRes->GetWaterShaderProperties();
    shaderVars.waterRamp.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(waterProperties->GetWaterRamp())
    );

    // Select the active stratum-material technique.
    const StratumMaterial& stratumMaterial = terrainRes->GetStratumMaterial();
    D3D_GetDevice()->SelectTechnique(stratumMaterial.mShaderName.c_str());

    // Water elevation constants (defaulting to the -10000.0 sentinel when the map
    // has no water enabled). The runtime map object at mTerrainResource->mMap is
    // the same object read by the binary at [terrainRes + 4].
    const TerrainMapRuntimeView& map = *mTerrainResource->mMap;
    const float waterElevation = map.mWaterEnabled ? map.mWaterElevation : kWaterElevationSentinel;
    if (shaderVars.waterElevation.Exists()) {
      shaderVars.waterElevation.SetFloat(waterElevation);
    }

    const float waterElevationDeep = map.mWaterEnabled ? map.mWaterElevationDeep : kWaterElevationSentinel;
    if (shaderVars.waterElevationDeep.Exists()) {
      shaderVars.waterElevationDeep.SetFloat(waterElevationDeep);
    }

    const float waterElevationAbyss = map.mWaterEnabled ? map.mWaterElevationAbyss : kWaterElevationSentinel;
    if (shaderVars.waterElevationAbyss.Exists()) {
      shaderVars.waterElevationAbyss.SetFloat(waterElevationAbyss);
    }

    // The binary reads the terrain-res edit-mode flag here and discards it.
    (void)terrainRes->IsInEditMode();

    // Load the base terrain shader vars, forwarding the caller's weak scratch
    // handle (the terrain normal texture) exactly as the shipped code does.
    LoadShaderVars(terrainNormalTexture);

    DrawTriangles();

    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_GlowMask, "TDecalGlowMask");
    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_Albedo, "TDecals");
    DrawSplatComposite();
    DrawGlowingDecals(gameTick, deltaSeconds);

    if (ren_DecalOverDraw) {
      DrawNormalMappedDecals(gameTick, deltaSeconds);
    }

    return true;
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
    mSplatVertices.ResetStorageToInline();

    DeleteOwned(mTerrainIndexSheet);
    DeleteOwned(mTerrainVertexSheet);
    DeleteOwned(mTesselator);
    mDecalDrawCommands.ResetStorageToInline();
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
