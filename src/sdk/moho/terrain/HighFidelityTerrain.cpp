#include "moho/terrain/HighFidelityTerrain.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Logging.h"   // TEMPORARY PROBE (do not commit)
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StatItem.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
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
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterShaderVars.h"
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
  constexpr float kMinDecalAlpha = 0.0039215689f;
  constexpr std::int32_t kMaxSplatsPerFrame = 2500;
  constexpr int kNoiseFillTextureFormat = 2;

  [[nodiscard]] std::int32_t FloorToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }
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

  /// Fixed-point scale of the 16-bit terrain height grid (1/128). Byte-verified
  /// from `flt_E4F6DC` @0x00E4F6DC = 0x3C000000.
  constexpr float kHeightWordScale = 0.0078125f;

  /// Vertex colour of the dirty-terrain overlay quads (opaque white; the tint
  /// comes from the batch texture). 0x00801F81/0x008021E4/... `mov ..., -1`.
  constexpr std::uint32_t kDirtyRectVertexColor = 0xFFFFFFFFu;

  /// Solid-colour batch texture the dirty-terrain overlay is drawn with:
  /// half-transparent magenta. 0x00801FB4 `push 8000FFFFh`.
  constexpr std::uint32_t kDirtyRectOverlayColor = 0x8000FFFFu;

  /**
   * Builds one corner vertex of a dirty-rectangle overlay quad: the grid
   * position as-is, the terrain height sampled at the clamped grid cell, and
   * the caller's UV.
   *
   * The binary open-codes the clamp four times over
   * 0x008020F3-0x0080228E - `min` against the last grid index first, then `max`
   * against zero - rather than calling `CHeightField::GetHeightAt`
   * (0x00478490), whose null/size guard is absent here. The two agree for every
   * in-range field, but the clamp is reproduced rather than substituted so the
   * degenerate-field behaviour stays the binary's.
   */
  [[nodiscard]] moho::CD3DPrimBatcher::Vertex MakeDirtyRectCornerVertex(
    const moho::CHeightField& field,
    const std::int32_t x,
    const std::int32_t z,
    const float u,
    const float v
  ) noexcept
  {
    const std::int32_t sampleX = std::max(std::min(x, field.width - 1), 0);
    const std::int32_t sampleZ = std::max(std::min(z, field.height - 1), 0);

    moho::CD3DPrimBatcher::Vertex vertex{};
    vertex.mX = static_cast<float>(x);
    vertex.mY = static_cast<float>(field.data[(sampleZ * field.width) + sampleX]) * kHeightWordScale;
    vertex.mZ = static_cast<float>(z);
    vertex.mColor = kDirtyRectVertexColor;
    vertex.mU = u;
    vertex.mV = v;
    return vertex;
  }

  /**
   * Dirty-rectangle visibility predicate for the debug overlay: strict interior
   * overlap with the camera footprint first (0x00802070-0x008020AA, which is
   * `gpg::Rect2i::Overlaps` inlined verbatim, both positive-area guards
   * included), and failing that an inclusive containment test of the dirty rect
   * inside the footprint (0x008020B7-0x008020DD).
   *
   * `CWldMap.cpp` carries the same predicate with the two arms swapped
   * (`ShouldSyncDirtyRectInCameraBounds`); it is file-private there, and the
   * arm order here is the one 0x00801EE0 evaluates.
   */
  [[nodiscard]] bool DirtyRectVisibleInCameraFootprint(
    const gpg::Rect2i& cameraFootprint,
    const gpg::Rect2i& dirtyRect
  ) noexcept
  {
    if (cameraFootprint.Overlaps(dirtyRect)) {
      return true;
    }

    return dirtyRect.x0 >= cameraFootprint.x0
      && cameraFootprint.x1 >= dirtyRect.x1
      && dirtyRect.z0 >= cameraFootprint.z0
      && cameraFootprint.z1 >= dirtyRect.z1;
  }
} // namespace

namespace moho
{
  extern bool ren_Terrain;
  extern bool ren_Skirt;

  /**
   * Address: 0x010A643D (?ren_ShowDirtyTerrain@Moho@@3_NA)
   *
   * What it does:
   * Debug toggle read by `HighFidelityTerrain::DrawDirtyTerrain` (0x00801F01)
   * as the single gate on the dirty-rectangle overlay pass. The address lies in
   * the zero-fill tail of `.data` (raw size 0x60000 ends before it), so the
   * shipped image default is `false`.
   *
   * Defined once in `moho/misc/RuntimeTuningGlobals.cpp` alongside the rest of
   * the `ren_*` toggle table, which is where the binary's own zero-fill lane
   * for this address belongs; declared `extern` here (as
   * `MediumFidelityTerrain.cpp` already does for the same global) so the two
   * fidelity backends read the one object rather than each getting a private
   * copy.
   */
  extern bool ren_ShowDirtyTerrain;

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
  extern bool ren_GenerateMesh;
  extern bool ren_ForceUpdateMinimapTerrain;
  extern bool ren_NormalDecals;
  extern bool ren_Splats;
  extern bool ren_IgnoreDecalLOD;
  extern int ren_DecalFidelity;
  extern float ren_DecalFadeFraction;

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
   * Part of 0x00809E80 (the device-teardown sweep). Declared in the header
   * because these statics are private to this translation unit.
   *
   * Binary order at 0x00809E81..0x00809F60: batcher (0x010BF738) deleted, water
   * surface (0x010C0ABC) through its scalar deleting destructor, then the three
   * shared textures dropped.
   */
  void ReleaseHighFidelityTerrainSharedResources() noexcept
  {
    DeleteOwned(sHighFidelityTextureBatcher);
    DeleteOwned(sHighFidelityWaterSurface);
    sHighFidelityNoiseFillTexture.reset();
    sHighFidelityCubicBlendLookupTexture.reset();
    sHighFidelityGridTexture.reset();
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

    Wm3::Vector3f sunAmbience = terrainRes->GetSunAmbience();
    // TEMPORARY PROBE (do not commit). Measured ambience is (0,0,0) while sun
    // colour/direction/multiplier all carry real map values. With zero ambient
    // the terrain is lit purely by N.L, so a dead normal texture would render
    // it uniformly near-black -- exactly the observed RGB ~32/31/23. Forcing a
    // non-zero ambient separates the two: if terrain becomes visible, the
    // albedo/geometry path is fine and the defect is in the normal/lighting
    // term; if it stays black, the problem is upstream of shading entirely.
    if (getenv("FAF_FORCE_AMBIENT") != nullptr) {
      sunAmbience.x = 0.5f;
      sunAmbience.y = 0.5f;
      sunAmbience.z = 0.5f;
    }
    SetShaderVarMem(shaderVars.sunAmbience, 3U, &sunAmbience.x);

    const Wm3::Vector3f sunColor = terrainRes->GetSunColor();
    SetShaderVarMem(shaderVars.sunColor, 3U, &sunColor.x);

    // TEMPORARY PROBE (do not commit). Terrain rasterizes but comes out
    // near-black (RGB ~32/31/23) with the correct effect bound, the correct
    // technique, 3571 triangles and shadows disabled -- so the remaining
    // suspects are the lighting terms themselves. Zero sun colour / ambience /
    // multiplier would produce exactly this.
    {
      static int sLightBudget = 0;
      if (sLightBudget < 4) {
        ++sLightBudget;
        gpg::Warnf(
          "[LIGHTDIAG] mult=%.3f sunDir=(%.3f,%.3f,%.3f) sunColor=(%.3f,%.3f,%.3f) ambience=(%.3f,%.3f,%.3f)",
          lightingMultiplier,
          sunDirection.x, sunDirection.y, sunDirection.z,
          sunColor.x, sunColor.y, sunColor.z,
          sunAmbience.x, sunAmbience.y, sunAmbience.z);
      }
    }

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

      // TEMPORARY PROBE (do not commit). Terrain rasterizes but comes out
      // near-black (frame-dump sampling: RGB ~32/31/23). Shadow::
      // PrepareLightCamera refuses to build a light camera when zoom exceeds
      // ren_ShadowLOD (250) and the live camera zoom is 854-883, so the shadow
      // map may never be rendered this frame while shadowsEnabled stays 1 --
      // the shader would then multiply terrain by an empty (fully-shadowed)
      // texture. Report the flag and whether a texture is actually bound.
      {
        static int sShadowBudget = 0;
        if (sShadowBudget < 4) {
          ++sShadowBudget;
          gpg::Warnf("[SHADOWDIAG] shadowsEnabled=%u shadowTexture=%08X",
                     shadowsEnabledBlob,
                     static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(shadowTexture.get())));
        }
      }
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
   * Address: 0x008003E0 (FUN_008003E0, Moho::HighFidelityTerrain::Func3)
   * Primary vtable slot 5 (vftable @0x00E41A94; TerrainCommon slot 5).
   *
   * What it does:
   * Per-frame render-context update; see the header declaration for the
   * full behavioral summary.
   */
  void HighFidelityTerrain::UpdateRenderContext(
    const std::int32_t gameTick,
    const float deltaSeconds,
    GeomCamera3* const camera,
    const std::int32_t* const viewportBlock,
    const bool minimapPass,
    const std::int32_t forceRegenerate)
  {
    if (mTerrainResource == nullptr) {
      return;
    }

    if (forceRegenerate != 0) {
      mShoreline.Generate(mTerrainResource);
    }

    mCamera = camera;
    mViewportOriginX = viewportBlock[0];
    mViewportOriginY = viewportBlock[1];
    mViewportWidth = viewportBlock[2];
    mViewportHeight = viewportBlock[3];
    mViewportRenderWidth = viewportBlock[4];
    mViewportRenderHeight = viewportBlock[5];

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    bool dirty = terrainRes->IsInEditMode();
    if (!dirty) {
      dirty = mCamera->tranform.Compare(mTerrainTransform);
    }

    if (!minimapPass || ren_ForceUpdateMinimapTerrain || dirty) {
      mTerrainTransform = mCamera->tranform;

      bool decalsDirty = false;
      if (!minimapPass) {
        auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());
        decalsDirty = decalManager->HasPendingChanges();
      }

      mShoreline.Update(*mCamera);

      if (ren_GenerateMesh && (dirty || decalsDirty)) {
        mTesselator->Rebuild(mCamera, terrainRes);

        ShaderVar& terrainHeightScale = GetTerrainHeightScaleShaderVar();
        if (terrainHeightScale.Exists()) {
          terrainHeightScale.SetFloat(mTesselator->GetHeightScale());
        }
        ShaderVar& terrainTime = GetTerrainTimeShaderVar();
        if (terrainTime.Exists()) {
          terrainTime.SetFloat(static_cast<float>(gameTick) + deltaSeconds);
        }

        mSkirtStartIndex = static_cast<std::uint32_t>(mTesselator->GetSkirtIndexStart());
        mUnknown30 = static_cast<std::uint32_t>(mTesselator->GetSkirtVertexStart() - 1);
        mSkirtEndIndex = static_cast<std::uint32_t>(mTesselator->GetCollisionIndexCount());
        mSkirtEndVertex = mTesselator->GetRectCacheCount() - 1;

        mSkirtBaseVertex = std::numeric_limits<std::int32_t>::max();
        const std::uint16_t* const collisionIndexData = mTesselator->GetCollisionIndexData();
        for (std::uint32_t i = mSkirtStartIndex; i < mSkirtEndIndex; ++i) {
          mSkirtBaseVertex = std::min(mSkirtBaseVertex, static_cast<std::int32_t>(collisionIndexData[i]));
        }

        mPrimaryPatchData.ResetStorageToInline();

        if (!minimapPass && ren_Decals) {
          auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());

          gpg::fastvector<UserEntity*> visibleDecals;
          (void)decalManager->EntitiesInView(mCamera, visibleDecals, ren_IgnoreDecalLOD);
          const float lodAreaThreshold = decalManager->GetLodThreshold(ren_DecalFidelity);

          static StatItem* sEngineStatRenderFlatDecals = nullptr;
          static StatItem* sEngineStatRenderDecals = nullptr;

          auto& decalCommands = reinterpret_cast<HighFidelityDecalCommandLane&>(mPrimaryPatchData);

          for (UserEntity* const entity : visibleDecals) {
            auto* const decal = reinterpret_cast<CWldTerrainDecal*>(entity);

            if (!ren_NormalDecals
                && (decal->mType == WldTerrainDecalType_NormalsAlpha || decal->mType == WldTerrainDecalType_Normals)) {
              continue;
            }
            // Fidelity 0 always passes: the LOD-area threshold only gates
            // decals with fidelity != 0 (confirmed against the raw asm).
            if (decal->mFidelity != 0 && lodAreaThreshold > (decal->mScale.z * decal->mScale.x)) {
              continue;
            }

            const float midX = (decal->mBoundsMaxX + decal->mBoundsMinX) * 0.5f;
            const float midZ = (decal->mBoundsMaxZ + decal->mBoundsMinZ) * 0.5f;

            auto* const heightField = reinterpret_cast<CHeightField*>(mTerrainResource->mMap->mHeightFieldObject);
            const float elevation = heightField->GetElevation(midX, midZ);

            const Vector4f& row1 = mCamera->viewport.r[1];
            const float worldDistance = (midZ * row1.z) + (elevation * row1.y) + (midX * row1.x) + row1.w;

            float alpha;
            if (ren_IgnoreDecalLOD) {
              alpha = 1.0f;
            } else {
              alpha = decal->GetLODAlpha(worldDistance) * decal->mCurrentAlpha;
              if (alpha < kMinDecalAlpha) {
                continue;
              }
            }

            CWldTerrainDecal::Quad flatnessQuad{};
            const bool isFlat = decal->ComputeFlatness(flatnessQuad);

            TerrainDecalDrawCommand command{};
            command.alpha = alpha;
            command.decal = decal;

            if (isFlat) {
              std::uint32_t addedIndexCount = 0;
              (void)mTesselator->EmitCollisionQuad(
                reinterpret_cast<const Wm3::Vector3f*>(&flatnessQuad.mCorner0), &command.startIndex, &addedIndexCount,
                &command.baseVertex, reinterpret_cast<std::uint32_t*>(&command.endVertex));
              command.indexCount = static_cast<std::int32_t>(addedIndexCount);

              if (command.indexCount > 0 && (command.startIndex + command.indexCount) < kSkirtMaxIndexCount) {
                decalCommands.PushBack(command);

                if (sEngineStatRenderFlatDecals == nullptr) {
                  EngineStats* const engineStats = GetEngineStats();
                  sEngineStatRenderFlatDecals = engineStats->GetItem("Render_FlatDecals", true);
                  (void)sEngineStatRenderFlatDecals->Release(0);
                }
                _InterlockedExchangeAdd(
                  reinterpret_cast<volatile long*>(&sEngineStatRenderFlatDecals->mPrimaryValueBits), 1);
              }
            } else {
              std::int32_t baselineIndexCount = 0;
              std::uint32_t addedIndexCount = 0;
              std::int32_t minRectIndex = 0;
              std::int32_t maxRectIndex = 0;
              (void)mTesselator->CollectClippedCollisionIndicesInRect(
                FloorToInt(decal->mBoundsMinX), FloorToInt(decal->mBoundsMinZ), FloorToInt(decal->mBoundsMaxX),
                FloorToInt(decal->mBoundsMaxZ), &baselineIndexCount, &addedIndexCount, &minRectIndex, &maxRectIndex);

              if (addedIndexCount > 0
                  && (baselineIndexCount + static_cast<std::int32_t>(addedIndexCount)) < kSkirtMaxIndexCount) {
                command.startIndex = baselineIndexCount;
                command.indexCount = static_cast<std::int32_t>(addedIndexCount);
                command.baseVertex = minRectIndex;
                command.endVertex = maxRectIndex;
                decalCommands.PushBack(command);

                if (sEngineStatRenderDecals == nullptr) {
                  EngineStats* const engineStats = GetEngineStats();
                  sEngineStatRenderDecals = engineStats->GetItem("Render_Decals", true);
                  (void)sEngineStatRenderDecals->Release(0);
                }
                _InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&sEngineStatRenderDecals->mPrimaryValueBits), 1);
              }
            }
          }
        }
      }

      mSecondaryPatchData.ResetStorageToInline();

      if (!minimapPass && ren_Splats) {
        auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());

        gpg::fastvector<UserEntity*> visibleSplats;
        (void)decalManager->PropsInView(mCamera, visibleSplats, ren_IgnoreDecalLOD);

        auto& splatVertices = reinterpret_cast<HighFidelitySplatVertexLane&>(mSecondaryPatchData);

        std::int32_t splatBudget = 0;
        for (UserEntity* const entity : visibleSplats) {
          auto* const splat = reinterpret_cast<CWldSplat*>(entity);

          const CWldSplat::SplatVertex& firstVertex = splat->mSplatVertices[0];
          const Vector4f& row1 = mCamera->viewport.r[1];
          const float worldDistance = (firstVertex.mPosition.z * row1.z) + (firstVertex.mPosition.y * row1.y)
            + (firstVertex.mPosition.x * row1.x) + row1.w;

          if (worldDistance > splat->mCutoffLOD) {
            continue;
          }
          if (++splatBudget >= kMaxSplatsPerFrame) {
            break;
          }

          float fadeAlpha;
          if (splat->mNearCutoff <= 0.0f) {
            const float farFadeStart = splat->mCutoffLOD * ren_DecalFadeFraction;
            const float clampedDistance = std::min(worldDistance, splat->mCutoffLOD);
            const float fadeFloor = std::max(farFadeStart, std::min(clampedDistance, farFadeStart));
            fadeAlpha = 1.0f - ((clampedDistance - fadeFloor) / (splat->mCutoffLOD - fadeFloor));
          } else {
            const float nearFadeStart = splat->mNearCutoff * ren_DecalFadeFraction;
            const float clampedDistance = std::min(worldDistance, splat->mNearCutoff);
            const float fadeCeiling = std::max(clampedDistance, nearFadeStart);
            fadeAlpha = (fadeCeiling - nearFadeStart) / (splat->mNearCutoff - nearFadeStart);
          }
          const float bakedAlpha = fadeAlpha * splat->mCurrentAlpha;

          splat->UpdateBatchTexture(sHighFidelityTextureBatcher);
          splat->UpdateVertices();

          const std::size_t countBeforeAppend = splatVertices.Size();
          for (const CWldSplat::SplatVertex& sourceVertex : splat->mSplatVertices) {
            splatVertices.PushBack(reinterpret_cast<const TerrainSplatVertex&>(sourceVertex));
          }

          for (std::size_t v = countBeforeAppend; v < splatVertices.Size(); ++v) {
            *reinterpret_cast<float*>(splatVertices[v].bytes + 0x14) = bakedAlpha;
          }
        }
      }

      const std::int32_t rectCacheCount = mTesselator->GetRectCacheCount();
      std::int32_t collisionIndexCount = mTesselator->GetCollisionIndexCount();

      // TEMPORARY PROBE (do not commit). The HUD renders but the 3D viewport is
      // flat, while the world pass runs with a bound terrain, a healthy camera
      // (camPos=(512,757,939) over the map centre) and compiled shaders. This is
      // the real geometry-to-GPU path, so log what the tessellator actually
      // accepted. A previous regression here (fixed in a15c5cc8) saturated the
      // 65000-node cap and rejected all terrain; the healthy value was ~20.
      {
        static int sRectBudget = 0;
        if (sRectBudget < 8) {
          ++sRectBudget;
          gpg::Warnf("[TERRDIAG-HIGH] rectCacheCount=%d collisionIndexCount=%d", rectCacheCount, collisionIndexCount);
        }
      }
      if (collisionIndexCount > kSkirtMaxIndexCount) {
        collisionIndexCount = kSkirtMaxIndexCount;
      }

      if (rectCacheCount > 0) {
        void* const lockedVertices = mTerrainVertexSheet->GetVertStream(0U)->Lock(0, rectCacheCount, false, true);
        std::memcpy(lockedVertices, mTesselator->GetRectCacheData(), sizeof(CTesselator::Rect16) * rectCacheCount);
        mTerrainVertexSheet->GetVertStream(0U)->Unlock();
      }

      if (collisionIndexCount > 0) {
        std::int16_t* const lockedIndices = mTerrainIndexSheet->Lock(0, collisionIndexCount, false, true);
        std::memcpy(lockedIndices, mTesselator->GetCollisionIndexData(), sizeof(std::uint16_t) * collisionIndexCount);
        mTerrainIndexSheet->Unlock();
      }
    }
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

    // TEMPORARY PROBE (do not commit). frame.fx's BasisPS reads all four
    // channels of the normals target: raw.xy is the screen normal (written by
    // the TTerrainNormals pass above) and raw.zw is the heightmap normal,
    // written ONLY by this TTerrainBasis tile loop. Our dump of
    // mSecondaryTargetLocks[head] has blue == 0 everywhere, so if this count is
    // zero the loop never runs, B/A stay 0, and BasisPS computes
    // baseNormal.y = sqrt(1 - 1 - z*z) on garbage -- which is why TCreateBasis
    // emits a constant and terrain shades to near-black.
    {
      static int sNmBudget = 0;
      if (sNmBudget < 4) {
        ++sNmBudget;
        gpg::Warnf("[NORMALMAPDIAG] normalMapCount=%d", normalMapCount);
      }
    }

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

    // TEMPORARY PROBE (do not commit). The draw succeeds (DrawNormals returns
    // 1, rectCacheCount 122..128, colour writes on, depth cleared) yet emits no
    // pixels. The technique is selected BY NAME from the map's stratum
    // material -- an empty or unresolved name would bind nothing and draw
    // nothing, which matches the symptom exactly.
    {
      static int sTechBudget = 0;
      if (sTechBudget < 4) {
        ++sTechBudget;
        // DrawNormals never calls SelectFxFile("terrain") itself (faithful to
        // FUN_00801BE0) -- it relies on a prior pass having left the terrain
        // effect bound. Compare the currently-bound effect against "terrain"
        // and "frame" by pointer identity: if "frame" is bound, SelectTechnique
        // is setting a terrain technique on the wrong effect.
        CD3DDevice* const dev = D3D_GetDevice();
        ID3DDeviceResources* const res = dev->GetResources();
        gpg::Warnf("[TECHDIAG] stratum='%s' cur=%08X terrain=%08X frame=%08X",
                   strata.mShaderName.c_str(),
                   static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(dev->GetCurEffect())),
                   static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(res->FindEffect("terrain"))),
                   static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(res->FindEffect("frame"))));
      }
    }

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
   * Address: 0x00802340 (FUN_00802340, sub_802340)
   *
   * What it does:
   * The water-albedo decal pass. Re-selects the `terrain` effect and the
   * `TDecalsWaterAlbedo` technique (or `TDecalOverDraw`), rebinds the camera
   * matrices and the base shader vars, then draws every decal command of type
   * `WldTerrainDecalType_WaterAlbedo`.
   *
   * Low fidelity runs this as one more DrawDecalPass inside DrawNormals; the
   * medium and high paths defer it to the water pass so it composites over the
   * water surface.
   */
  void HighFidelityTerrain::DrawWaterAlbedoDecals(const std::int32_t gameTick, const float deltaSeconds)
  {
    if (!ren_Decals) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("terrain");
    device->SelectTechnique(ren_DecalOverDraw ? "TDecalOverDraw" : "TDecalsWaterAlbedo");

    const GeomCamera3& camera = *mCamera;
    if (shaderVars.viewMatrix.Exists()) {
      shaderVars.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (shaderVars.projMatrix.Exists()) {
      shaderVars.projMatrix.SetMatrix4x4(&camera.projection);
    }

    LoadShaderVars({});

    const auto& decalCommands = reinterpret_cast<const HighFidelityDecalCommandLane&>(mPrimaryPatchData);
    for (const TerrainDecalDrawCommand& command : decalCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (decal.mType != WldTerrainDecalType_WaterAlbedo) {
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
   * Address: 0x00803410 (FUN_00803410, Moho::HighFidelityTerrain::DrawWaterTerrain)
   * Primary vtable slot 11 (vftable @0x00E41A14).
   *
   * What it does:
   * Derives the `water2/ViewportScaleOffset` constant from the terrain grid
   * dimensions, hands the frame to the active WaterSurface fidelity, then
   * composites the water-albedo decals over the result.
   *
   * The scale/offset maps the terrain viewport rectangle into the render
   * target's normalised space: xy is the half-extent of the viewport relative
   * to the render target, zw the centre, with the half-texel term
   * (`0.5 / renderWidth`) folded into z.
   */
  void HighFidelityTerrain::DrawWaterTerrain(
    const std::int32_t tick,
    const float tickLerp,
    const boost::shared_ptr<ID3DRenderTarget> refractionTexture,
    const boost::shared_ptr<ID3DRenderTarget> reflectionTexture)
  {
    const float inverseRenderWidth = 1.0F / static_cast<float>(mViewportRenderWidth);
    const float inverseRenderHeight = 1.0F / static_cast<float>(mViewportRenderHeight);

    const float halfWidthScale = (inverseRenderWidth * static_cast<float>(mViewportWidth)) * 0.5F;
    const float heightScale = inverseRenderHeight * static_cast<float>(mViewportHeight);

    const float viewportScaleOffset[4] = {
      halfWidthScale,
      heightScale * -0.5F,
      (halfWidthScale + (inverseRenderWidth * static_cast<float>(mViewportOriginX)))
        + (inverseRenderWidth * 0.5F),
      (inverseRenderHeight * 0.5F)
        + ((inverseRenderHeight * static_cast<float>(mViewportOriginY)) + (heightScale * 0.5F))
    };
    SetShaderVarMem(GetWater2ViewportScaleOffsetShaderVar(), 4U, viewportScaleOffset);

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);
    (void)sHighFidelityWaterSurface->RenderWaterSurface(
      tick,
      tickLerp,
      mCamera,
      terrainRes->GetWaterShaderProperties(),
      refractionTexture,
      reflectionTexture);

    DrawWaterAlbedoDecals(tick, tickLerp);
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
   * Address: 0x00801A50 (FUN_00801A50, Moho::HighFidelityTerrain::DrawTerrainDepth)
   * Primary vtable slot 6.
   *
   * What it does:
   * Depth-only terrain pass. Selects the `terrain` effect's `TTerrainDepth`
   * technique, binds the camera view/projection and the tesselator height
   * scale, then issues the one prebuilt terrain batch.
   *
   * Each shader-var write is guarded by Exists() as in the binary - the
   * technique does not necessarily declare all three.
   */
  void HighFidelityTerrain::DrawTerrainDepth(const GeomCamera3& camera)
  {
    if (!ren_Terrain) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("terrain");
    device->SelectTechnique("TTerrainDepth");

    auto& shaderVars = GetTerrainShaderVars();
    if (shaderVars.viewMatrix.Exists()) {
      shaderVars.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (shaderVars.projMatrix.Exists()) {
      shaderVars.projMatrix.SetMatrix4x4(&camera.projection);
    }
    if (shaderVars.heightScale.Exists()) {
      shaderVars.heightScale.SetFloat(mTesselator->GetHeightScale());
    }

    DrawTriangles();
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

    // TEMPORARY PROBE (do not commit). This is the terrain's ONLY geometry
    // submission, and it silently early-returns on a zero or non-multiple-of-3
    // index count while DrawNormals still reports success -- exactly the
    // observed "draw succeeds, no pixels" shape.
    {
      static int sDrawBudget = 0;
      if (sDrawBudget < 6) {
        ++sDrawBudget;
        gpg::Warnf("[DRAWDIAG] DrawTriangles mSkirtStartIndex=%d -> %s",
                   indexCount,
                   (indexCount <= 0 || (indexCount % 3) != 0) ? "EARLY RETURN (nothing drawn)" : "submitting");
      }
    }

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
   * Address: 0x00801B10 (FUN_00801B10, Moho::HighFidelityTerrain::CondDrawTerrainTechnique)
   * Primary vtable slot 7 (vftable @0x00E41A14, slot @0x00E41A30 -> 0x00801B10).
   *
   * IDA signature:
   * void __userpurge Moho::HighFidelityTerrain::CondDrawTerrainTechnique(
   *     Moho::HighFidelityTerrain *this@<ecx>, float, std::string *params);
   *
   * What it does:
   * Draws one terrain pass under a caller-chosen technique. Gated on
   * `ren_Terrain` like the rest of the class: selects the `terrain` effect and
   * the technique named at `params + 0x00`, binds the pass's view matrix
   * (`params + 0x5C`, 0x00801B70) and projection matrix (`params + 0x1C`,
   * 0x00801B8F) and the tesselator height scale, then issues the terrain
   * triangle list.
   *
   * The height scale is fetched before the `Exists()` guard in the binary
   * (0x00801B95 calls the tesselator, 0x00801BAB tests the var), so the
   * tesselator call happens whether or not the var is bound.
   *
   * This is the exact twin of `MediumFidelityTerrain::CondDrawTerrainTechnique`
   * (0x00805B50) down to the instruction shape.
   */
  void HighFidelityTerrain::CondDrawTerrainTechnique(const STerrainTechniqueDrawParams& params)
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

    const float heightScale = mTesselator->GetHeightScale();
    if (shaderVars.heightScale.Exists()) {
      shaderVars.heightScale.SetFloat(heightScale);
    }

    DrawTriangles();
  }

  /**
   * Address: 0x00803640 (FUN_00803640, Moho::HighFidelityTerrain::DrawTerrainTechnique)
   * Primary vtable slot 13 (vftable @0x00E41A14, slot @0x00E41A48 -> 0x00803640).
   *
   * IDA signature:
   * void __thiscall Moho::HighFidelityTerrain::DrawTerrainTechnique(
   *     Moho::HighFidelityTerrain *this, boost::shared_ptr_CD3DDynamicTextureSheet overlay,
   *     std::string *techniqueName);
   *
   * What it does:
   * Runs one full opaque terrain pass. Rebinds all terrain-lighting shader vars
   * with no shadow source (0x00803662, `LoadTerrainLighting(nullptr)`),
   * re-selects the `terrain` effect, selects the caller-provided technique,
   * binds the overlay texture sheet into the `overlayTexture` shader var
   * (0x008036A5), loads the base terrain shader vars with an empty
   * terrain-normal handle (the zeroed 8-byte block built at
   * 0x008036AD-0x008036BA), and submits the terrain triangle list. The retained
   * overlay handle is released as the by-value `shared_ptr` parameter goes out
   * of scope (0x008036D3-0x00803703, the unwind funclet at 0x00BBD670).
   *
   * The binary calls `D3D_GetDevice` twice - once per selection - and that is
   * preserved here; the same shape is in
   * `MediumFidelityTerrain::DrawTerrain` (0x00807660).
   */
  void HighFidelityTerrain::DrawTerrainTechnique(
    boost::shared_ptr<CD3DDynamicTextureSheet> overlayTexture,
    const msvc8::string* const techniqueName
  )
  {
    LoadTerrainLighting(nullptr);

    D3D_GetDevice()->SelectFxFile("terrain");
    D3D_GetDevice()->SelectTechnique(techniqueName->c_str());

    GetTerrainShaderVars().overlayTexture.GetTexture(overlayTexture);

    LoadShaderVars({});

    DrawTriangles();
  }

  /**
   * Address: 0x00801EE0 (FUN_00801EE0, Moho::HighFidelityTerrain::DrawDirtyTerrain)
   * Primary vtable slot 14 (vftable @0x00E41A14, slot @0x00E41A4C -> 0x00801EE0).
   *
   * IDA signature:
   * void __thiscall Moho::HighFidelityTerrain::DrawDirtyTerrain(
   *     Moho::HighFidelityTerrain *this, Moho::CD3DPrimBatcher *batcher);
   *
   * What it does:
   * The dirty-rectangle debug overlay, gated on `ren_ShowDirtyTerrain`
   * (0x00801F01). Sets the prim batcher up for the `primbatcher` effect's
   * `TAlphaBlendLinearSampleNoDepth` technique - the binary inlines
   * `CD3DPrimBatcher::Setup` (0x00438560) here, right down to the
   * `mRebuildComposite = 0` store at 0x00801F39 - then binds the terrain
   * camera's projection and view matrices, in that order.
   *
   * It computes the terrain footprint of the camera frustum
   * (`CHeightField::ConvexIntersection` against `mCamera->solid2`), truncates
   * its X/Z bounds to grid indices, and binds a half-transparent magenta
   * solid-colour batch texture. Then, for every rectangle in the terrain
   * resource's debug dirty-rectangle list that either strictly overlaps that
   * footprint or is fully contained by it, it emits one height-conforming quad:
   * the four corners take the rectangle's own X/Z but sample terrain height at
   * the clamped grid cell, so the quad hugs the terrain. A final `Flush`
   * submits the batch.
   *
   * The terrain resource is read straight off the `sWldMap` global twice - once
   * for the height field, once for the dirty-rect list - exactly as
   * `HighFidelityTerrain::DrawShoreline` (0x008131D0) reads it in this file.
   */
  void HighFidelityTerrain::DrawDirtyTerrain(CD3DPrimBatcher* const batcher)
  {
    if (!ren_ShowDirtyTerrain) {
      return;
    }

    (void)batcher->Setup("TAlphaBlendLinearSampleNoDepth");

    const GeomCamera3& camera = *mCamera;
    batcher->SetProjectionMatrix(camera.projection);
    batcher->SetViewMatrix(camera.view);

    IWldTerrainRes* heightFieldSource = nullptr;
    if (CWldSession* const activeSession = WLD_GetActiveSession();
        activeSession != nullptr && activeSession->mWldMap != nullptr) {
      heightFieldSource = activeSession->mWldMap->mTerrainRes;
    }

    const auto* const heightFieldView = reinterpret_cast<const TerrainWaterResourceView*>(heightFieldSource);
    const auto* const heightField =
      reinterpret_cast<const CHeightField*>(heightFieldView->mMap->mHeightFieldObject);

    // Terrain footprint of the camera frustum, truncated to grid indices. The
    // binary keeps only the X/Z lanes of the box (0x00801F88-0x00801FA3
    // `cvttss2si` against Min.x / Min.z / Max.x / Max.z).
    const Wm3::AxisAlignedBox3f cameraBounds = heightField->ConvexIntersection(camera.solid2);
    const gpg::Rect2i cameraFootprint{
      static_cast<std::int32_t>(cameraBounds.Min.X()),
      static_cast<std::int32_t>(cameraBounds.Min.Z()),
      static_cast<std::int32_t>(cameraBounds.Max.X()),
      static_cast<std::int32_t>(cameraBounds.Max.Z())
    };

    // Temporary on purpose: the binary drops the control block immediately
    // after the bind (0x00801FE6-0x00802023), not at end of scope.
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(kDirtyRectOverlayColor));

    IWldTerrainRes* dirtyRectSource = nullptr;
    if (CWldSession* const activeSession = WLD_GetActiveSession();
        activeSession != nullptr && activeSession->mWldMap != nullptr) {
      dirtyRectSource = activeSession->mWldMap->mTerrainRes;
    }

    for (const gpg::Rect2i& dirtyRect : dirtyRectSource->GetDebugDirtyRects()) {
      if (!DirtyRectVisibleInCameraFootprint(cameraFootprint, dirtyRect)) {
        continue;
      }

      const CD3DPrimBatcher::Vertex nearLeft =
        MakeDirtyRectCornerVertex(*heightField, dirtyRect.x0, dirtyRect.z0, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex nearRight =
        MakeDirtyRectCornerVertex(*heightField, dirtyRect.x1, dirtyRect.z0, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex farRight =
        MakeDirtyRectCornerVertex(*heightField, dirtyRect.x1, dirtyRect.z1, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex farLeft =
        MakeDirtyRectCornerVertex(*heightField, dirtyRect.x0, dirtyRect.z1, 0.0f, 1.0f);

      batcher->DrawQuad(farLeft, farRight, nearRight, nearLeft);
    }

    batcher->Flush();
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
