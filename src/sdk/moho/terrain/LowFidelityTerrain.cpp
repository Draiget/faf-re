#include "moho/terrain/LowFidelityTerrain.h"
#include "gpg/core/utils/Logging.h"   // TEMPORARY PROBE (do not commit)

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>

#include <boost/detail/sp_counted_base.hpp>

#include "Wm3Vector3.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StatItem.h"
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
#include "moho/sim/STIMap.h"
#include "moho/terrain/MediumFidelityTerrain.h"
#include "moho/terrain/HighFidelityTerrain.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/terrain/water/WaterFactory.h"
#include "moho/render/d3d/CD3DRenderTarget.h"

namespace
{
  constexpr std::int32_t kSkirtMaxIndexCount = 199998;
  constexpr std::int32_t kTriangleListPrimitiveType = 4;
  constexpr float kMinDecalAlpha = 0.0039215689f; // 1/255
  constexpr std::int32_t kMaxSplatsPerFrame = 250;

  /**
   * x87 "frndint" (round-to-nearest) + correction is the binary's idiom for
   * floor-toward-negative-infinity float-to-int conversion, used repeatedly
   * in the decal-rect-query bounds below. std::floor + truncating cast is
   * the identical IEEE-754 result for every finite input.
   */
  [[nodiscard]] std::int32_t FloorToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

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
  /// seed is the game tick, which IDA mistypes as a MeshRenderer* because it
  /// arrives in a register (see WRenViewport::RenderCompositeTerrain @0x007F827E).
  void BindLowFidelityDecalTexture(
    moho::ShaderVar& target,
    moho::CWldTerrainDecal& decal,
    const int slot,
    const float lod,
    const std::int32_t gameTick)
  {
    const boost::shared_ptr<moho::ID3DTextureSheet> texture =
      decal.GetTexture(slot, lod, gameTick);
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
  extern bool ren_GenerateMesh;
  extern bool ren_IgnoreDecalLOD;
  extern int ren_DecalFidelity;
  extern bool ren_NormalDecals;
  extern bool ren_Splats;
  extern float ren_DecalFadeFraction;

  boost::shared_ptr<RD3DTextureResource> sTerrainGridTexture;
  WaterSurface* sTerrainWaterSurface = nullptr;
  CD3DTextureBatcher* texture_batcher = nullptr;

  /**
   * Part of 0x00809E80 (the device-teardown sweep).
   *
   * Binary order at 0x0080A050..0x0080A0E0: batcher (0x010C0AB8) deleted, water
   * surface (0x010BF730) through its scalar deleting destructor, then the grid
   * texture (0x010BF70C / count 0x010BF710) dropped. This lane owns one shared
   * texture where the other two fidelities own three.
   */
  void ReleaseLowFidelityTerrainSharedResources() noexcept
  {
    DeleteOwned(texture_batcher);
    DeleteOwned(sTerrainWaterSurface);
    sTerrainGridTexture.reset();
  }

  /**
   * Address: 0x00809E80 (FUN_00809E80, sub_809E80)
   *
   * IDA signature:
   * void sub_809E80();
   *
   * What it does:
   * Drops every process-wide terrain resource when the D3D device goes away,
   * high fidelity first, then medium, then low - the order the binary walks
   * them in. Each group is a named helper in its own translation unit because
   * the statics it releases are private there; the binary has them all inlined
   * into this one function.
   */
  void REN_ReleaseTerrainSharedResources() noexcept
  {
    ReleaseHighFidelityTerrainSharedResources();
    ReleaseMediumFidelityTerrainSharedResources();
    ReleaseLowFidelityTerrainSharedResources();
  }

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
   * Address: 0x00808F90 (FUN_00808F90, Moho::LowFidelityTerrain::DrawTerrainDepth)
   *
   * IDA signature:
   * void __thiscall sub_808F90(_DWORD **this, int camera);
   *
   * What it does:
   * Depth-only terrain pass. Gated on `ren_Terrain` like every other draw in
   * this class, it selects the `terrain` effect's `TTerrainDepth` technique,
   * binds the camera view/projection matrices and the tesselator's height
   * scale, then issues the one prebuilt low-fidelity batch.
   *
   * Each shader-var write is guarded by `Exists()`, as in the binary - the
   * technique does not necessarily declare all three.
   */
  void LowFidelityTerrain::DrawTerrainDepth(const GeomCamera3& camera)
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

    DrawLowFidelityTerrainBatch(reinterpret_cast<const LowFidelityTriangleBatchRuntime&>(*this));
  }

  /**
   * Address: 0x00809050 (FUN_00809050, Moho::LowFidelityTerrain::CondDrawTerrainTechnique)
   * Primary vtable slot 7 (??_7LowFidelityTerrain@Moho@@6B@ @0x00E41A94, +0x1C).
   *
   * IDA signature:
   * void __userpurge sub_809050(int this@<ecx>, int@<edi>, int@<esi>,
   *     float, int params);
   *
   * What it does:
   * Draws one terrain pass under a caller-chosen technique. Gated on
   * `ren_Terrain` like the rest of the class: selects the `terrain` effect and
   * the technique named by the params block, binds that pass's view/projection
   * matrices and the tesselator height scale, then issues the one prebuilt
   * low-fidelity terrain batch.
   *
   * Unlike `DrawTerrainDepth` the technique is not a literal - it comes from
   * the params block, which is what makes this the `Cond` variant. The body is
   * the medium-fidelity override (0x00805B50) instruction for instruction,
   * differing only in the tesselator field offset (`mov ecx, [ebx+10h]` at
   * 0x008090D5 versus `[edi+2F30h]`) and in the closing draw helper
   * (`sub_807F50` with `this` in esi, versus medium's `sub_805490`).
   */
  void LowFidelityTerrain::CondDrawTerrainTechnique(const STerrainTechniqueDrawParams& params)
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

    // The height scale is read before the Exists() guard in the binary
    // (0x008090D5-0x008090DF precedes the shader-var probe), so the tesselator
    // call happens whether or not the var is bound.
    const float heightScale = mTesselator->GetHeightScale();
    if (shaderVars.heightScale.Exists()) {
      shaderVars.heightScale.SetFloat(heightScale);
    }

    DrawLowFidelityTerrainBatch(reinterpret_cast<const LowFidelityTriangleBatchRuntime&>(*this));
  }

  /**
   * Address: 0x00809B50 (FUN_00809B50, Moho::LowFidelityTerrain::DrawWaterTerrain)
   * Primary vtable slot 11 (vftable @0x00E41A94).
   *
   * IDA signature:
   * volatile signed __int32 *__thiscall sub_809B50(
   *     int this, int a2, int a3, int a4, volatile signed __int32 *a5,
   *     int a6, volatile signed __int32 *a7);
   * (`a4`+`a5` and `a6`+`a7` are the split halves of two by-value
   * boost::shared_ptr<ID3DRenderTarget> arguments.)
   *
   * What it does:
   * Hands the frame's water surface to the active WaterSurface fidelity.
   * Low fidelity adds no viewport setup of its own - it fetches the terrain's
   * water shader properties and issues the one surface pass.
   *
   * The argument mapping was taken from the .asm rather than the decompiler,
   * which normalises `[esp+24h+arg_10]` and `[esp+2Ch+arg_10]` to one name
   * across three `sub esp, 8` adjustments and so prints the tick and the frame
   * delta as if they were the shared_ptr halves. At the slot-4 call the stack
   * holds, low to high: tick, tickLerp, camera, shaderProperties, then the two
   * retained shared_ptr pairs.
   */
  void LowFidelityTerrain::DrawWaterTerrain(
    const std::int32_t tick,
    const float tickLerp,
    const boost::shared_ptr<ID3DRenderTarget> refractionTexture,
    const boost::shared_ptr<ID3DRenderTarget> reflectionTexture)
  {
    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    (void)sTerrainWaterSurface->RenderWaterSurface(
      tick,
      tickLerp,
      mCamera,
      terrainRes->GetWaterShaderProperties(),
      refractionTexture,
      reflectionTexture);
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
  void LowFidelityTerrain::DrawTerrainNormal(const std::int32_t /*gameTick*/, const float /*deltaSeconds*/)
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
   * Primary vtable slot 14 (??_7LowFidelityTerrain@Moho@@6B@ @0x00E41A94, +0x38).
   *
   * What it does:
   * Preserves the dirty-terrain pass hook as an intentional no-op for this
   * low-fidelity terrain lane - the whole body is `retn 4`. The parameter type
   * comes from the medium-fidelity override of the same slot (0x00805F10).
   */
  void LowFidelityTerrain::DrawDirtyTerrain(CD3DPrimBatcher* const /*primBatcher*/)
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

      const boost::shared_ptr<CD3DRenderTarget> shadowTexture =
        shadowContext->useSecondaryShadowTexture ? shadowContext->secondaryShadowTexture
                                                  : shadowContext->primaryShadowTexture;
      shaderVars.shadowTexture.SetRenderTargetTexture(shadowTexture);
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
    const std::int32_t gameTick, const float lod, const std::int32_t decalType, const char* const techniqueName)
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

      BindLowFidelityDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, gameTick);
      BindLowFidelityDecalTexture(shaderVars.decalSpecTexture, decal, 1, lod, gameTick);

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
  void LowFidelityTerrain::DrawGlowingDecals(const std::int32_t gameTick, const float lod)
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

      BindLowFidelityDecalTexture(shaderVars.decalAlbedoTexture, decal, 0, lod, gameTick);

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
    const std::int32_t gameTick,
    const float deltaSeconds,
    const boost::shared_ptr<ID3DRenderTarget>& /*terrainNormalTexture*/,
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

    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_GlowMask, "TDecalGlowMask");
    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_Albedo, "TDecals");
    DrawDecalPass(gameTick, deltaSeconds, WldTerrainDecalType_WaterAlbedo, "TDecalsWaterAlbedo");
    DrawGlowingDecals(gameTick, deltaSeconds);
    DrawSplatComposite();

    return true;
  }

  /**
   * Address: 0x00808640 (FUN_00808640, Moho::LowFidelityTerrain::Func3)
   *
   * What it does: see the header - per-frame render-context update. See the
   * header's own Doxygen block for the full behavioural summary; this is the
   * simplest of the three fidelity classes' overrides - no viewport-block
   * fields, no shoreline, and (unlike High/Medium) the vertex/index-sheet
   * re-upload and splat pass run every call, not gated behind the dirty
   * check (confirmed via the binary's own jump targets: both "skip
   * tessellation" paths land directly at the unconditional tail).
   */
  void LowFidelityTerrain::UpdateRenderContext(
    const std::int32_t gameTick,
    const float deltaSeconds,
    GeomCamera3* const camera,
    const std::int32_t* const /*viewportBlock*/,
    const bool minimapPass,
    const std::int32_t /*forceRegenerate*/)
  {
    mCamera = camera;

    auto* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainResource);

    bool dirty = terrainRes->IsInEditMode();
    if (!dirty) {
      dirty = mCamera->tranform.Compare(mCachedCameraTransform);
    }

    mCachedCameraTransform = mCamera->tranform;

    bool decalsDirty = false;
    if (!minimapPass) {
      auto* const decalManager = static_cast<CDecalManager*>(terrainRes->GetDecalManager());
      decalsDirty = decalManager->HasPendingChanges();
    }

    if (ren_GenerateMesh && (dirty || decalsDirty)) {
      mTesselator->Rebuild(mCamera, terrainRes);

      auto& shaderVars = GetTerrainShaderVars();
      if (shaderVars.heightScale.Exists()) {
        shaderVars.heightScale.SetFloat(mTesselator->GetHeightScale());
      }

      ShaderVar& terrainHeightScale = GetTerrainHeightScaleShaderVar();
      if (terrainHeightScale.Exists()) {
        terrainHeightScale.SetFloat(mTesselator->GetHeightScale());
      }
      ShaderVar& terrainTime = GetTerrainTimeShaderVar();
      if (terrainTime.Exists()) {
        terrainTime.SetFloat(static_cast<float>(gameTick) + deltaSeconds);
      }

      mSkirtStartIndex = static_cast<std::uint32_t>(mTesselator->GetSkirtIndexStart());
      mUnknown24 = static_cast<std::uint32_t>(mTesselator->GetSkirtVertexStart() - 1);
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

        for (UserEntity* const entity : visibleDecals) {
          auto* const decal = reinterpret_cast<CWldTerrainDecal*>(entity);

          if (decal->mFidelity > 0) {
            continue;
          }
          if (!ren_NormalDecals
              && (decal->mType == WldTerrainDecalType_NormalsAlpha || decal->mType == WldTerrainDecalType_Normals)) {
            continue;
          }
          if (lodAreaThreshold > (decal->mScale.z * decal->mScale.x)) {
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
              reinterpret_cast<LowFidelityDecalCommandLane&>(mPrimaryPatchData).PushBack(command);

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
              reinterpret_cast<LowFidelityDecalCommandLane&>(mPrimaryPatchData).PushBack(command);

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

      std::int32_t splatBudget = 0;
      for (UserEntity* const entity : visibleSplats) {
        auto* const splat = reinterpret_cast<CWldSplat*>(entity);

        if (splat->mFidelity > 0) {
          continue;
        }

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

        splat->UpdateBatchTexture(texture_batcher);

        auto& splatVertexLane = reinterpret_cast<LowFidelitySplatVertexLane&>(mSecondaryPatchData);
        const std::size_t countBeforeAppend = splatVertexLane.Size();
        for (const CWldSplat::SplatVertex& sourceVertex : splat->mSplatVertices) {
          splatVertexLane.PushBack(reinterpret_cast<const LowFidelitySplatVertex&>(sourceVertex));
        }

        for (std::size_t v = countBeforeAppend; v < splatVertexLane.Size(); ++v) {
          *reinterpret_cast<float*>(splatVertexLane[v].bytes + 0x14) = bakedAlpha;
        }
      }
    }

    const std::int32_t rectCacheCount = mTesselator->GetRectCacheCount();
    std::int32_t collisionIndexCount = mTesselator->GetCollisionIndexCount();
    // TEMPORARY PROBE (do not commit)
    {
      static int sRectBudget = 0;
      if (sRectBudget < 8) {
        ++sRectBudget;
        gpg::Warnf("[TERRDIAG-LOW] rectCacheCount=%d collisionIndexCount=%d", rectCacheCount, collisionIndexCount);
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
} // namespace moho
