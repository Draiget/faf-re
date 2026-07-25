#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/terrain/water/WaterSurface.h"

namespace boost::detail
{
  class sp_counted_base;
}

namespace gpg::gal
{
  class TextureD3D9;
}

namespace moho
{
  class CD3DIndexSheet;
  class CD3DTextureBatcher;
  class CD3DVertexSheet;
  class CTesselator;
  class CWldTerrainDecal;
  class MeshRenderer;
  class RD3DTextureResource;
  class StratumMaterial;
  struct GeomCamera3;
  struct SNormalMapInfo;
  struct TerrainShadowContext;

  /**
   * Low-fidelity terrain renderer and sheet-owner runtime.
   */
  class LowFidelityTerrain : public TerrainCommon
  {
  public:
    /**
     * Address: 0x00807FC0 (??0LowFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??0LowFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes low-fidelity terrain runtime ownership lanes and both inline
     * patch-index storage vectors.
     */
    LowFidelityTerrain();

    /**
     * Address: 0x00808070 (??1LowFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??1LowFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Tears down low-fidelity terrain runtime resources and restores inline
     * patch-index storage ownership.
     */
    ~LowFidelityTerrain() override;

    /**
     * Address: 0x00809D80 (FUN_00809D80, ??3LowFidelityTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs the low-fidelity terrain destructor lane and conditionally frees
     * the object storage when the delete flag requests heap release.
     */
    static LowFidelityTerrain* DeleteWithFlag(LowFidelityTerrain* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x008081A0 (FUN_008081A0, Moho::LowFidelityTerrain::Create)
     *
     * What it does:
     * Binds the terrain resource, clears shared global terrain-water assets,
     * then dispatches initialization.
     */
    bool Create(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x00808240 (FUN_00808240, Moho::LowFidelityTerrain::Init)
     *
     * What it does:
     * Rebuilds low-fidelity terrain tessellation and render-sheet ownership
     * lanes for the active terrain resource.
     */
    bool Init();

    /**
     * Address: 0x00809B30 (FUN_00809B30, Moho::LowFidelityTerrain::DrawWaterLine)
     *
     * What it does:
     * Dispatches the shared low-fidelity water alpha-mask lane for the active
     * terrain camera.
     */
    void DrawWaterLine(std::int32_t arg0, std::int32_t arg1);

    /**
     * Address: 0x00809C80 (FUN_00809C80, Moho::LowFidelityTerrain::DrawTerrainSkirt)
     *
     * What it does:
     * Issues one terrain-skirt indexed draw for the low-fidelity terrain path
     * when terrain/skirt flags are enabled and skirt index lanes are valid.
     */
    virtual void DrawTerrainSkirt();

    /**
     * Address: 0x00809B20 (FUN_00809B20, Moho::LowFidelityTerrain::DrawTerrainNormal)
     *
     * What it does:
     * Preserves the low-fidelity terrain normal pass as an intentional no-op
     * hook for this terrain fidelity lane.
     */
    virtual void DrawTerrainNormal(std::int32_t arg0, std::int32_t arg1);

    /**
     * Address: 0x00809D30 (FUN_00809D30, Moho::LowFidelityTerrain::DrawTerrain)
     *
     * What it does:
     * Releases one retained shared-control lane passed by the render caller and
     * leaves terrain draw behavior as an empty hook for this fidelity path.
     */
    virtual void DrawTerrain(
      std::int32_t arg0,
      boost::detail::sp_counted_base* retainedControl,
      std::int32_t arg1
    );

    /**
     * Address: 0x00809D70 (FUN_00809D70, Moho::LowFidelityTerrain::DrawDirtyTerrain)
     *
     * What it does:
     * Preserves the dirty-terrain pass hook as an intentional no-op for this
     * low-fidelity terrain lane.
     */
    virtual void DrawDirtyTerrain(std::int32_t arg0);

    /**
     * Address: 0x00808590 (FUN_00808590, Moho::LowFidelityTerrain::Destroy)
     *
     * What it does:
     * Releases owned tessellator/render-sheet lanes and drops retained decal
     * mask texture ownership.
     */
    void Destroy();

    /**
     * Address: 0x00809120 (FUN_00809120, Moho::LowFidelityTerrain::DrawNormals)
     * Primary vtable slot (??_7LowFidelityTerrain@Moho@@6B@).
     *
     * IDA signature:
     * int __userpurge DrawNormals@<eax>(LowFidelityTerrain *this@<ecx>,
     *     MeshRenderer *renderer@<ebx>, int, float lod, int, int*, int shadowContext);
     * (the two split integer args are the by-value
     * boost::weak_ptr<gpg::gal::TextureD3D9> terrainNormalTexture.)
     *
     * What it does:
     * Low-fidelity terrain normal/decal render pass. When terrain rendering is
     * disabled, releases the by-value weak scratch handle and returns false.
     * Otherwise loads the low-fidelity terrain shader vars, draws the prebuilt
     * terrain batch, loads terrain lighting for the shadow context, iterates each
     * normal-map tile binding the NormalMapScale/Offset + E_X/E_Y/Size_Source basis
     * vars and drawing the tesselated tile geometry, then draws the glow-mask /
     * albedo / water-albedo decal passes, the glowing decals, and the splat
     * composite. Returns true.
     */
    virtual bool DrawNormals(
      MeshRenderer* renderer,
      float lod,
      boost::weak_ptr<gpg::gal::TextureD3D9> terrainNormalTexture,
      TerrainShadowContext* shadowContext
    );

    /**
     * Address: 0x008079B0 (FUN_008079B0, Moho::LowFidelityTerrain::LoadShaderVars)
     *
     * What it does:
     * Selects the `terrain` effect + `LowFidelityTerrain` technique and binds the
     * camera view/projection matrices, tesselator height scale, terrain scale,
     * every stratum albedo texture + tile lane, and the decal-mask texture.
     */
    void LoadShaderVars();

    /**
     * Address: 0x00807D20 (FUN_00807D20, Moho::LowFidelityTerrain::LoadTerrainLighting)
     *
     * What it does:
     * Selects the `LowFidelityLighting` technique and binds lighting multiplier,
     * sun direction/ambience/color and shadow-fill color from the terrain
     * resource. Enables + binds the cast-shadow lane when a shadow context is
     * supplied; otherwise writes the shadows-disabled flag.
     */
    void LoadTerrainLighting(TerrainShadowContext* shadowContext);

    TerrainWaterResourceView* mTerrainResource = nullptr;           // +0x0C
    CTesselator* mTesselator = nullptr;                             // +0x10
    CD3DVertexSheet* mTerrainVertexSheet = nullptr;                 // +0x14
    CD3DIndexSheet* mTerrainIndexSheet = nullptr;                   // +0x18
    GeomCamera3* mCamera = nullptr;                                 // +0x1C
    std::uint32_t mSkirtStartIndex = 0u;                            // +0x20
    std::uint32_t mUnknown24 = 0u;                                  // +0x24
    std::uint32_t mSkirtEndIndex = 0u;                              // +0x28
    std::int32_t mSkirtEndVertex = 0;                               // +0x2C
    std::int32_t mSkirtBaseVertex = 0;                              // +0x30
    float mTerrainScale = 1.0F;                                     // +0x34
    float mUnknown38 = 0.0F;                                        // +0x38
    float mUnknown3C = 0.0F;                                        // +0x3C
    float mUnknown40 = 0.0F;                                        // +0x40
    float mUnknown44 = 0.0F;                                        // +0x44
    float mUnknown48 = 0.0F;                                        // +0x48
    float mUnknown4C = 0.0F;                                        // +0x4C
    gpg::core::FastVectorN<std::uint32_t, 3000> mPrimaryPatchData; // +0x50
    gpg::core::FastVectorN<std::uint32_t, 7000> mSecondaryPatchData; // +0x2F40
    CD3DVertexSheet* mDynamicVertexSheet = nullptr;                 // +0x9CB0
    CD3DIndexSheet* mDynamicIndexSheet = nullptr;                   // +0x9CB4

  private:
    /**
     * Address: 0x008094B0 (FUN_008094B0, sub_8094B0)
     *
     * What it does:
     * Draws every queued decal command whose type equals `decalType`: selects the
     * caller technique (or `TDecalOverDraw` under ren_DecalOverDraw), binds the
     * decal matrix + slot-0 albedo + slot-1 spec textures + decal alpha, and
     * submits one indexed triangle-list draw per matching command. No-op unless
     * ren_Decals.
     */
    void DrawDecalPass(MeshRenderer* renderer, float lod, std::int32_t decalType, const char* techniqueName);

    /**
     * Address: 0x00809730 (FUN_00809730, sub_809730)
     *
     * What it does:
     * Draws every glowing decal command (mType == WldTerrainDecalType_Glow) with
     * the `TDecalsGlow` technique (or `TDecalOverDraw`): binds decal matrix +
     * slot-0 albedo + decal alpha, one indexed draw per command. No-op unless
     * ren_Decals && ren_glowingDecals.
     */
    void DrawGlowingDecals(MeshRenderer* renderer, float lod);

    /**
     * Address: 0x00809930 (FUN_00809930, sub_809930)
     *
     * What it does:
     * Uploads the composited splat-vertex lane into the dynamic vertex sheet,
     * selects the `LowFidelitySplat` technique, binds the shared texture-batcher
     * composite texture into the decal-albedo lane, and submits one indexed
     * triangle-list draw over all splat quads. No-op when the splat lane is empty.
     */
    void DrawSplatComposite();
  };

  static_assert(offsetof(LowFidelityTerrain, mTerrainResource) == 0x0C, "LowFidelityTerrain::mTerrainResource offset must be 0x0C");
  static_assert(offsetof(LowFidelityTerrain, mTesselator) == 0x10, "LowFidelityTerrain::mTesselator offset must be 0x10");
  static_assert(
    offsetof(LowFidelityTerrain, mSkirtStartIndex) == 0x20,
    "LowFidelityTerrain::mSkirtStartIndex offset must be 0x20"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mSkirtEndIndex) == 0x28,
    "LowFidelityTerrain::mSkirtEndIndex offset must be 0x28"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mSkirtEndVertex) == 0x2C,
    "LowFidelityTerrain::mSkirtEndVertex offset must be 0x2C"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mSkirtBaseVertex) == 0x30,
    "LowFidelityTerrain::mSkirtBaseVertex offset must be 0x30"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mPrimaryPatchData) == 0x50,
    "LowFidelityTerrain::mPrimaryPatchData offset must be 0x50"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mSecondaryPatchData) == 0x2F40,
    "LowFidelityTerrain::mSecondaryPatchData offset must be 0x2F40"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mDynamicVertexSheet) == 0x9CB0,
    "LowFidelityTerrain::mDynamicVertexSheet offset must be 0x9CB0"
  );
  static_assert(
    offsetof(LowFidelityTerrain, mDynamicIndexSheet) == 0x9CB4,
    "LowFidelityTerrain::mDynamicIndexSheet offset must be 0x9CB4"
  );
  static_assert(sizeof(LowFidelityTerrain) == 0x9CB8, "LowFidelityTerrain size must be 0x9CB8");

  extern CD3DTextureBatcher* texture_batcher;
} // namespace moho
