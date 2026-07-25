#include "moho/terrain/LowFidelityTerrain.h"

#include <cstdint>
#include <cstring>

#include <boost/detail/sp_counted_base.hpp>

#include "Wm3Vector3.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/CWldTerrainDecalTYPETypeInfo.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/tess/CTesselator.h"
#include "moho/sim/CWldMap.h"
#include "moho/terrain/MediumFidelityTerrain.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/TerrainShaderVars.h"
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
  void DrawLowFidelityTerrainBatch(const LowFidelityTriangleBatchRuntime& batch)
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

  // ----- Decal / splat draw helpers -----
  // The low-fidelity decal-command lane is stored inline at mPrimaryPatchData
  // (+0x50); each element is a moho::TerrainDecalDrawCommand (24 bytes,
  // 3000 * uint32 == 500 * 24). The splat-vertex lane at mSecondaryPatchData
  // (+0x2F40) holds 28-byte splat vertices (7000 * uint32 == 1000 * 28).

  /// One composited splat vertex (28-byte element of the splat lane).
  struct LowFidelitySplatVertex
  {
    std::uint8_t bytes[0x1C];
  };
  static_assert(sizeof(LowFidelitySplatVertex) == 0x1C, "LowFidelitySplatVertex size must be 0x1C");

  using LowFidelityDecalCommandLane = gpg::core::FastVectorN<moho::TerrainDecalDrawCommand, 500>;
  using LowFidelitySplatVertexLane = gpg::core::FastVectorN<LowFidelitySplatVertex, 1000>;

  /// Binds one command's index/vertex sub-range and submits one indexed
  /// triangle-list draw over the terrain sheets (mirror of the medium-fidelity
  /// SubmitDecalCommandDraw helper).
  void SubmitLowFidelityDecalDraw(
    moho::CD3DVertexSheet* const vertexSheet,
    moho::CD3DIndexSheet* const indexSheet,
    const moho::TerrainDecalDrawCommand& command)
  {
    std::int32_t primitiveType = kTriangleListPrimitiveType;

    moho::CD3DIndexSheetViewRuntime indexView{};
    indexView.sheet = indexSheet;
    indexView.startIndex = command.startIndex;
    indexView.indexCount = command.indexCount;

    moho::CD3DVertexSheetViewRuntime vertexView{};
    vertexView.sheet = vertexSheet;
    vertexView.startVertex = 0;
    vertexView.baseVertex = command.baseVertex;
    vertexView.endVertex = command.endVertex;

    (void)moho::D3D_GetDevice()->DrawTriangleList(&vertexView, &indexView, &primitiveType);
  }

  /// Resolves one animated decal texture slot and binds it into `target`. Frame
  /// seed is the raw mesh-renderer pointer, exactly as the shipped code passes it.
  void BindLowFidelityDecalTexture(
    moho::ShaderVar& target,
    moho::CWldTerrainDecal& decal,
    const int slot,
    const float lod,
    moho::MeshRenderer* const renderer)
  {
    const boost::shared_ptr<moho::ID3DTextureSheet> texture =
      decal.GetTexture(slot, lod, static_cast<int>(reinterpret_cast<std::uintptr_t>(renderer)));
    target.GetTexture(boost::static_pointer_cast<moho::CD3DDynamicTextureSheet>(texture));
  }
} // namespace

namespace moho
{
  extern bool ren_Terrain;
  extern bool ren_Skirt;
  extern bool ren_Decals;
  extern bool ren_DecalOverDraw;
  extern bool ren_glowingDecals;

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

  /**
   * Address: 0x008079B0 (FUN_008079B0, Moho::LowFidelityTerrain::LoadShaderVars)
   *
   * What it does:
   * Selects the `terrain` effect + `LowFidelityTerrain` technique, then binds the
   * camera view/projection matrices, tesselator height scale, terrain scale, all
   * stratum albedo textures + tile scale lanes, and the decal-mask texture.
   */
  void LowFidelityTerrain::LoadShaderVars()
  {
    auto& shaderVars = GetTerrainShaderVars();

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("terrain");
    device->SelectTechnique("LowFidelityTerrain");

    const GeomCamera3& camera = *mCamera;
    if (shaderVars.viewMatrix.Exists()) {
      shaderVars.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (shaderVars.projMatrix.Exists()) {
      shaderVars.projMatrix.SetMatrix4x4(&camera.projection);
    }

    if (shaderVars.heightScale.Exists()) {
      shaderVars.heightScale.SetFloat(mTesselator->GetHeightScale());
    }

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    const TerrainHeightFieldRuntimeView* const heightField = mTerrainResource->mMap->mHeightFieldObject;
    const float terrainScale[4] = {
      1.0F / static_cast<float>(heightField->width - 1),
      1.0F / static_cast<float>(heightField->height - 1),
      0.0F,
      1.0F
    };
    SetShaderVarMem(shaderVars.terrainScale, 4U, terrainScale);

    StratumMaterial& strata = terrainRes->GetStratumMaterial();
    strata.SetSizeTo(reinterpret_cast<CWldTerrainRes*>(terrainRes));

    BindTextureShaderVar(shaderVars.utilityTextureA, strata.mStratumMask0);
    BindTextureShaderVar(shaderVars.utilityTextureB, strata.mStratumMask1);

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

    shaderVars.decalMaskTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(
        boost::static_pointer_cast<ID3DTextureSheet>(mDecalMask)));
  }

  /**
   * Address: 0x00807D20 (FUN_00807D20, Moho::LowFidelityTerrain::LoadTerrainLighting)
   *
   * What it does:
   * Selects the `LowFidelityLighting` technique, binds lighting multiplier, sun
   * direction/ambience/color and shadow-fill color from the terrain resource, and
   * enables + binds the cast-shadow lane when a shadow context is present.
   */
  void LowFidelityTerrain::LoadTerrainLighting(TerrainShadowContext* const shadowContext)
  {
    auto& shaderVars = GetTerrainShaderVars();

    D3D_GetDevice()->SelectTechnique("LowFidelityLighting");

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    if (shaderVars.lightingMultiplier.Exists()) {
      shaderVars.lightingMultiplier.SetFloat(terrainRes->GetLightingMultiplier());
    }

    const Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
    SetShaderVarMem(shaderVars.sunDirection, 3U, &sunDirection.x);

    const Wm3::Vector3f sunAmbience = terrainRes->GetSunAmbience();
    SetShaderVarMem(shaderVars.sunAmbience, 3U, &sunAmbience.x);

    const Wm3::Vector3f sunColor = terrainRes->GetSunColor();
    SetShaderVarMem(shaderVars.sunColor, 3U, &sunColor.x);

    const Wm3::Vector3f shadowFillColor = terrainRes->GetShadowFillColor();
    SetShaderVarMem(shaderVars.shadowFillColor, 3U, &shadowFillColor.x);

    if (shadowContext != nullptr) {
      const std::uint32_t shadowsEnabledBlob = 1U;
      SetShaderVarPtr(shaderVars.shadowsEnabled, &shadowsEnabledBlob, 4U);

      if (shaderVars.shadowMatrix.Exists()) {
        shaderVars.shadowMatrix.SetMatrix4x4(&shadowContext->shadowMatrix);
      }

      const boost::shared_ptr<gpg::gal::TextureD3D9> shadowTexture =
        shadowContext->useSecondaryShadowTexture ? shadowContext->secondaryShadowTexture
                                                  : shadowContext->primaryShadowTexture;
      shaderVars.shadowTexture.GetTexture(boost::weak_ptr<gpg::gal::TextureD3D9>(shadowTexture));
    } else {
      const std::uint32_t shadowsDisabledBlob = 0U;
      SetShaderVarPtr(shaderVars.shadowsEnabled, &shadowsDisabledBlob, 4U);
    }
  }

  /**
   * Address: 0x008094B0 (FUN_008094B0, sub_8094B0)
   *
   * What it does:
   * Draws every queued decal command whose type equals `decalType`.
   */
  void LowFidelityTerrain::DrawDecalPass(
    MeshRenderer* const renderer, const float lod, const std::int32_t decalType, const char* const techniqueName)
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

    const auto& decalCommands = reinterpret_cast<const LowFidelityDecalCommandLane&>(mPrimaryPatchData);
    for (const TerrainDecalDrawCommand& command : decalCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (static_cast<std::int32_t>(decal.mType) != decalType) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      BindLowFidelityDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, renderer);
      BindLowFidelityDecalTexture(shaderVars.decalSpecTexture, decal, 1, lod, renderer);

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      SubmitLowFidelityDecalDraw(mTerrainVertexSheet, mTerrainIndexSheet, command);
    }
  }

  /**
   * Address: 0x00809730 (FUN_00809730, sub_809730)
   *
   * What it does:
   * Draws every glowing decal command (mType == WldTerrainDecalType_Glow) with the
   * `TDecalsGlow` technique.
   */
  void LowFidelityTerrain::DrawGlowingDecals(MeshRenderer* const renderer, const float lod)
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

    const auto& decalCommands = reinterpret_cast<const LowFidelityDecalCommandLane&>(mPrimaryPatchData);
    for (const TerrainDecalDrawCommand& command : decalCommands) {
      CWldTerrainDecal& decal = *command.decal;
      if (decal.mType != WldTerrainDecalType_Glow) {
        continue;
      }

      if (shaderVars.decalMatrix.Exists()) {
        shaderVars.decalMatrix.SetMatrix4x4(&decal.mTexMatrix);
      }

      BindLowFidelityDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, renderer);

      if (shaderVars.decalAlpha.Exists()) {
        shaderVars.decalAlpha.SetFloat(command.alpha);
      }

      SubmitLowFidelityDecalDraw(mTerrainVertexSheet, mTerrainIndexSheet, command);
    }
  }

  /**
   * Address: 0x00809930 (FUN_00809930, sub_809930)
   *
   * What it does:
   * Uploads the composited splat-vertex lane into the dynamic vertex sheet,
   * selects the `LowFidelitySplat` technique, binds the shared texture-batcher
   * composite texture into the decal-albedo lane, and submits one indexed
   * triangle-list draw over all splat quads.
   */
  void LowFidelityTerrain::DrawSplatComposite()
  {
    const auto& splatVertices = reinterpret_cast<const LowFidelitySplatVertexLane&>(mSecondaryPatchData);
    const std::size_t splatVertexCount = splatVertices.size();
    if (splatVertexCount == 0) {
      return;
    }

    void* const lockedVertices =
      mDynamicVertexSheet->GetVertStream(0U)->Lock(0, static_cast<std::int32_t>(splatVertexCount), false, true);
    std::memcpy(lockedVertices, splatVertices.data(), sizeof(LowFidelitySplatVertex) * splatVertexCount);
    mDynamicVertexSheet->GetVertStream(0U)->Unlock();

    D3D_GetDevice()->SelectTechnique("LowFidelitySplat");

    auto& shaderVars = GetTerrainShaderVars();
    shaderVars.decalAlbedoTexture.GetTexture(
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(texture_batcher->GetCompositeTexture()));

    std::int32_t primitiveType = kTriangleListPrimitiveType;

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
   * Address: 0x00809120 (FUN_00809120, Moho::LowFidelityTerrain::DrawNormals)
   *
   * What it does:
   * The low-fidelity terrain normal/decal render pass (see header).
   */
  bool LowFidelityTerrain::DrawNormals(
    MeshRenderer* const renderer,
    const float lod,
    boost::weak_ptr<gpg::gal::TextureD3D9> /*terrainNormalTexture*/,
    TerrainShadowContext* const shadowContext)
  {
    if (!ren_Terrain) {
      return false;
    }

    auto& shaderVars = GetTerrainShaderVars();
    CD3DDevice* const device = D3D_GetDevice();

    LoadShaderVars();
    DrawLowFidelityTerrainBatch(reinterpret_cast<const LowFidelityTriangleBatchRuntime&>(*this));
    LoadTerrainLighting(shadowContext);

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

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

      if (rangeStart + static_cast<std::int32_t>(rangeCount) < kSkirtMaxIndexCount && rangeCount != 0U) {
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

        (void)device->DrawTriangleList(&vertexView, &indexView, &primitiveType);
      }
    }

    DrawDecalPass(renderer, lod, WldTerrainDecalType_GlowMask, "TDecalGlowMask");
    DrawDecalPass(renderer, lod, WldTerrainDecalType_Albedo, "TDecals");
    DrawDecalPass(renderer, lod, WldTerrainDecalType_WaterAlbedo, "TDecalsWaterAlbedo");
    DrawGlowingDecals(renderer, lod);
    DrawSplatComposite();

    return true;
  }
} // namespace moho
