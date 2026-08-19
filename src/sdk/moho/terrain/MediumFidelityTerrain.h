#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/gal/Matrix.h"
#include "legacy/containers/String.h"
#include "moho/render/camera/VTransform.h"
#include "moho/terrain/TerrainCommon.h"

namespace gpg::gal
{
  class TextureD3D9;
}

namespace moho
{
  class CD3DRenderTarget;
  class ID3DRenderTarget;
  class CWldTerrainDecal;
  class MeshRenderer;

  /**
   * One queued terrain-decal draw command, recovered from the medium-fidelity
   * decal draw helpers (0x008065E0 / 0x00806A50 / 0x00806C60). Each command
   * carries the index/vertex-sheet sub-range for one decal quad plus the decal
   * object that supplies its animated albedo/spec/normal textures. Element size
   * is exactly 24 bytes; the command lane at `+0x40` holds up to 500 inline
   * commands (`500 * 24 == 0x2EE0`, matching the inline byte window between
   * `+0x50` and `mTesselator@+0x2F30`).
   */
  struct TerrainDecalDrawCommand
  {
    std::int32_t startIndex;   // +0x00 -> CD3DIndexSheetViewRuntime::startIndex
    std::int32_t indexCount;   // +0x04 -> CD3DIndexSheetViewRuntime::indexCount
    std::int32_t baseVertex;   // +0x08 -> CD3DVertexSheetViewRuntime::baseVertex
    std::int32_t endVertex;    // +0x0C -> CD3DVertexSheetViewRuntime::endVertex
    float alpha;               // +0x10 -> DecalAlpha shader-var value
    CWldTerrainDecal* decal;   // +0x14 -> owning decal (textures + matrices)
  };
  static_assert(sizeof(TerrainDecalDrawCommand) == 0x18, "TerrainDecalDrawCommand size must be 0x18");

  /**
   * One composited terrain splat vertex, recovered from the splat draw helper
   * (0x00806860) which memcpys the whole splat lane into the overlay vertex
   * sheet and draws it with the `TSplats` technique. Element size is exactly
   * 28 bytes; the splat lane at `+0x2F40` holds up to 10000 inline vertices
   * (`10000 * 28 == 0x445C0`, matching the inline byte window between `+0x2F50`
   * and `mOverlayVertexSheet@+0x47510`). Only the raw byte payload is copied,
   * so the individual channels are kept as an opaque 28-byte record.
   */
  struct TerrainSplatVertex
  {
    std::uint8_t bytes[0x1C]; // +0x00 opaque 28-byte vertex record
  };
  static_assert(sizeof(TerrainSplatVertex) == 0x1C, "TerrainSplatVertex size must be 0x1C");

  using MediumDecalCommandLane = gpg::core::FastVectorN<TerrainDecalDrawCommand, 500>;
  using MediumSplatVertexLane = gpg::core::FastVectorN<TerrainSplatVertex, 10000>;

  class CD3DDynamicTextureSheet;
  class CD3DIndexSheet;
  class CD3DVertexSheet;
  class CTesselator;
  struct GeomCamera3;
  struct TerrainWaterResourceView;

  /**
   * Runtime shadow-render context passed into the terrain-lighting binder when
   * the terrain effect is rendered with a cast-shadow source. The layout is
   * recovered from sub_805600's shadow branch (0x00805975-0x00805A1A) and the
   * shadow-texture accessor sub_7FEE70 (0x007FEE70). Only the fields the terrain
   * lighting path touches are modeled; the object is owned by the shadow render
   * subsystem and is never constructed here.
   */
  struct TerrainShadowContext
  {
    std::uint8_t reserved00[0x0C]; // +0x00

    /// Selects between the primary/secondary retained shadow textures.
    /// Read as a byte at +0x0C by sub_7FEE70.
    bool useSecondaryShadowTexture; // +0x0C

    std::uint8_t reserved0D[0x07]; // +0x0D

    /// Terrain shadow-enabled flag, written to the effect as a 4-byte blob.
    /// Read as a byte at +0x14 by sub_805600.
    bool shadowsEnabled; // +0x14

    std::uint8_t reserved15[0x9F]; // +0x15

    /// World-to-shadow-map matrix bound into the `ShadowMatrix` shader var.
    gpg::gal::Matrix shadowMatrix; // +0xB4

    std::uint8_t reservedF4[0x1EC]; // +0xF4

    /// Retained shadow texture used when `useSecondaryShadowTexture == false`.
    boost::shared_ptr<CD3DRenderTarget> primaryShadowTexture; // +0x2E0

    std::uint8_t reserved2E8[0x08]; // +0x2E8

    /// Retained shadow texture used when `useSecondaryShadowTexture == true`.
    boost::shared_ptr<CD3DRenderTarget> secondaryShadowTexture; // +0x2F0
  };

  static_assert(
    offsetof(TerrainShadowContext, useSecondaryShadowTexture) == 0x0C,
    "TerrainShadowContext::useSecondaryShadowTexture offset must be 0x0C"
  );

  /**
   * Address: 0x007FEE70 (FUN_007FEE70, sub_7FEE70)
   *
   * What it does:
   * Returns the active retained shadow texture for a cast-shadow terrain
   * pass. Shared by every fidelity class's LoadTerrainLighting, so it lives
   * beside TerrainShadowContext rather than being copied per TU.
   */
  [[nodiscard]] boost::shared_ptr<CD3DRenderTarget> GetActiveShadowTexture(
    const TerrainShadowContext& shadowContext
  );
  static_assert(
    offsetof(TerrainShadowContext, shadowsEnabled) == 0x14,
    "TerrainShadowContext::shadowsEnabled offset must be 0x14"
  );
  static_assert(
    offsetof(TerrainShadowContext, shadowMatrix) == 0xB4,
    "TerrainShadowContext::shadowMatrix offset must be 0xB4"
  );
  static_assert(
    offsetof(TerrainShadowContext, primaryShadowTexture) == 0x2E0,
    "TerrainShadowContext::primaryShadowTexture offset must be 0x2E0"
  );
  static_assert(
    offsetof(TerrainShadowContext, secondaryShadowTexture) == 0x2F0,
    "TerrainShadowContext::secondaryShadowTexture offset must be 0x2F0"
  );

  /**
   * Medium-fidelity terrain renderer runtime.
   */
  class MediumFidelityTerrain : public TerrainCommon
  {
  public:
    /**
     * Address: 0x00803A10 (FUN_00803A10, ??0MediumFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??0MediumFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes medium-fidelity terrain ownership lanes and both inline
     * patch-index vector stores.
     */
    MediumFidelityTerrain();

    /**
     * Address: 0x00803AD0 (FUN_00803AD0, ??1MediumFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??1MediumFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Tears down medium-fidelity terrain resources, restores inline vector
     * storage ownership, and then dispatches base teardown.
     */
    ~MediumFidelityTerrain() override;

    /**
     * Address: 0x00807990 (FUN_00807990, ??3MediumFidelityTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs the medium-fidelity terrain destructor lane and conditionally frees
     * the object storage when the delete flag requests heap release.
     */
    static MediumFidelityTerrain* DeleteWithFlag(
      MediumFidelityTerrain* object,
      std::uint8_t deleteFlags
    ) noexcept;

    /**
     * Address: 0x00803C00 (FUN_00803C00, Moho::MediumFidelityTerrain::Create)
     *
     * What it does:
     * Binds the terrain resource, clears shared medium-fidelity water/texture
     * helper lanes, then dispatches initialization.
     */
    bool Create(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x00804350 (FUN_00804350)
     *
     * What it does:
     * Releases all owned tesselator/sheet lanes and clears the shared decal
     * mask ownership handle.
     */
    void Destroy();

    /**
     * Address: 0x00803CE0 (FUN_00803CE0, Moho::MediumFidelityTerrain::Init)
     *
     * What it does:
     * Rebuilds medium-fidelity terrain tessellation/sheet lanes, fills dynamic
     * quad index buffers, and lazily initializes runtime texture helpers.
     */
    bool Init();

    /**
     * Address: 0x00804DF0 (FUN_00804DF0, Moho::MediumFidelityTerrain::LoadShaderVars)
     *
     * What it does:
     * Binds terrain shader texture lanes, writes terrain scale + viewport
     * normalization constants, and forwards the optional terrain-normal texture
     * weak handle into the active terrain effect.
     */
    void LoadShaderVars(const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture);

    /**
     * Address: 0x00805600 (FUN_00805600, sub_805600)
     *
     * What it does:
     * Selects the `terrain` effect and binds all lighting shader vars from the
     * active camera (view/proj/half-angle/camera dir+pos) and terrain resource
     * (lighting multiplier, sun dir/ambience/color, specular, shadow-fill), the
     * optional cast-shadow context (shadows-enabled/shadow matrix/shadow
     * texture), and the noise / decal-mask / bi-cubic-lookup textures.
     */
    void LoadTerrainLighting(TerrainShadowContext* shadowContext);

    /**
     * Address: 0x00804440 (FUN_00804440, Moho::MediumFidelityTerrain::Func3)
     * Primary vtable slot 5 (vftable @0x00E41A94; TerrainCommon slot 5).
     *
     * What it does:
     * Per-frame render-context update. No-ops when `mTerrainResource` is null.
     * Otherwise stores the camera pointer and the 6-int viewport block
     * unconditionally, then derives a dirty flag from
     * `IWldTerrainRes::IsInEditMode()` OR'd with a transform-compare of
     * `mCamera->tranform` against the cached `mOverlayTransform`. When not a
     * minimap pass, OR `ren_ForceUpdateMinimapTerrain`, OR that dirty flag,
     * refreshes `mOverlayTransform` from the camera and (outside minimap
     * passes) ORs in the decal manager's pending-changes flag. When mesh
     * generation is enabled and something is dirty, rebuilds tessellation,
     * re-derives the four skirt-range fields plus their min-scan base vertex,
     * and (outside minimap passes, when `ren_Decals`) gathers on-screen
     * decals into `mDecalDrawCommands` - unlike the low-fidelity class, the
     * per-decal fidelity field only gates whether the LOD-area threshold
     * check applies (fidelity `0` always passes it) rather than being an
     * unconditional skip. Independently of the dirty gate, resets and
     * (outside minimap passes, when `ren_Splats`) refills the splat-vertex
     * lane, capped at 2500 splats per frame with no per-splat fidelity check.
     * Finally, unconditionally re-uploads the tesselator's current
     * rect-cache and collision-index lanes into the terrain vertex/index
     * sheets. Ignores its final (shoreline-regenerate) parameter entirely -
     * this class has no shoreline.
     */
    void UpdateRenderContext(
      std::int32_t gameTick,
      float deltaSeconds,
      GeomCamera3* camera,
      const std::int32_t* viewportBlock,
      bool minimapPass,
      std::int32_t forceRegenerate
    ) override;

    /**
     * Address: 0x00805490 (FUN_00805490, sub_805490)
     *
     * What it does:
     * Draws one terrain triangle-list pass using `mTerrainIndexSheet` and
     * `mTerrainVertexSheet` with `(start=0, base=0)` and the clamped legacy
     * index count when it is positive and divisible by 3.
     */
    void DrawTriangles();

    /**
     * Address: 0x00807660 (FUN_00807660, Moho::MediumFidelityTerrain::DrawTerrain)
     *
     * What it does:
     * Runs one full opaque terrain pass: rebinds lighting shader vars (no shadow
     * source), selects the `terrain` effect + caller technique, binds the overlay
     * texture, loads the base terrain shader vars, and submits the terrain
     * triangle list. Releases the retained overlay-texture handle on return.
     */
    virtual void DrawTerrain(
      boost::shared_ptr<CD3DDynamicTextureSheet> overlayTexture,
      const msvc8::string* techniqueName
    );

    /**
     * Address: 0x00807410 (FUN_00807410, Moho::MediumFidelityTerrain::DrawWaterLine)
     *
     * What it does:
     * Dispatches the shared medium-fidelity water alpha-mask lane for the
     * active terrain camera.
     */
    void DrawWaterLine(std::int32_t arg0, std::int32_t arg1);

    /**
     * Address: 0x00805C20 (FUN_00805C20, Moho::MediumFidelityTerrain::DrawNormals)
     * Primary vtable slot 8 (vftable @0x00E41A54; RTTI dump slot 8).
     *
     * IDA signature:
     * int __thiscall Moho::MediumFidelityTerrain::DrawNormals(
     *     MediumFidelityTerrain *this, MeshRenderer *a2, float a3,
     *     int a4, volatile signed __int32 *a5, int a6);
     * (`a4`+`a5` are the split halves of one by-value
     * `boost::weak_ptr<CD3DDynamicTextureSheet>`; `a6` is the shadow context.)
     *
     * What it does:
     * The terrain normal/decal render pass. Binds terrain lighting for the shadow
     * context, then either forwards to the debug normal-visualization path
     * (`ren_ShowNormals`) or runs the full decal/splat pass: binds the water ramp
     * and the three water-elevation constants, selects the active stratum-material
     * technique, retains the optional weak scratch handle across the base
     * shader-var load, draws the terrain triangles, then the glow-mask decals, the
     * albedo decals, the splat composite, the glowing decals, and (when
     * `ren_DecalOverDraw`) the normal-mapped decals. Returns 1 when terrain
     * rendering is enabled, 0 otherwise.
     */
    bool DrawNormals(
      std::int32_t gameTick,
      float deltaSeconds,
      const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture,
      TerrainShadowContext* shadowContext
    ) override;

    /**
     * Address: 0x00806F50 (FUN_00806F50, Moho::MediumFidelityTerrain::DrawTerrainNormal)
     * Primary vtable slot 9 (vftable @0x00E41A54; RTTI dump slot 9).
     *
     * IDA signature:
     * void __fastcall Moho::MediumFidelityTerrain::DrawTerrainNormal(
     *     MediumFidelityTerrain *this, MeshRenderer *renderer, float lod);
     *
     * What it does:
     * Debug normal-visualization pass invoked from DrawNormals under
     * `ren_ShowNormals`. Selects the `TTerrainNormals` technique via the effect's
     * `normals` string annotation, loads terrain lighting/shader vars, draws the
     * terrain triangles + normal-mapped decals, then iterates the terrain normal
     * maps binding per-tile scale/offset/extent shader vars and drawing each tile.
     *
     * NOTE: The body is a separate recovery pass. It depends on the
     * `NormalMapScale` / `NormalMapOffset` / `UtilityTextureA` terrain shader vars
     * plus three normal-basis vars whose exact HLSL registration names
     * (decompiler-labeled `E_X` / `E_Y` / `Size_Source`) are not yet verified from
     * the binary, and on `CD3DEffect::GetStringAnnotation` + the terrain-res
     * normal-map iteration slots. It is declared here so the vtable slot and the
     * DrawNormals dispatch are modeled 1:1; recover the body before linking.
     */
    void DrawTerrainNormal(std::int32_t gameTick, float deltaSeconds) override;

    /**
     * Address: 0x00805530 (FUN_00805530, Moho::MediumFidelityTerrain::DrawTerrainSkirt)
     *
     * What it does:
     * Issues one terrain-skirt triangle-list draw for the medium-fidelity
     * terrain path when skirt rendering is enabled and index-lane constraints
     * are valid.
     */
    /**
     * Address: 0x00806370 (FUN_00806370, sub_806370)
     *
     * What it does:
     * Composites the water-albedo decals over the water surface.
     */
    void DrawWaterAlbedoDecals(std::int32_t gameTick, float deltaSeconds);

    /**
     * Address: 0x00807430 (FUN_00807430, Moho::MediumFidelityTerrain::DrawWaterTerrain)
     * Primary vtable slot 11 (vftable @0x00E41A54).
     *
     * What it does:
     * Binds the water2 viewport scale/offset, issues the water surface
     * pass, then composites the water-albedo decals.
     */
    void DrawWaterTerrain(
      std::int32_t tick,
      float tickLerp,
      boost::shared_ptr<ID3DRenderTarget> refractionTexture,
      boost::shared_ptr<ID3DRenderTarget> reflectionTexture) override;

    /**
     * Address: 0x00805A90 (FUN_00805A90)
     * Primary vtable slot 6.
     *
     * What it does:
     * Depth-only terrain pass through the `TTerrainDepth` technique.
     */
    void DrawTerrainDepth(const GeomCamera3& camera) override;

    void DrawTerrainSkirt() override;

    /**
     * Draw parameters for one terrain technique pass.
     *
     * Derived from FUN_00805B50's operands, which all normalise to the same
     * stack argument: the technique name is an `msvc8::string` at +0x00 whose
     * `_Myres` the binary tests at +0x18 and whose SSO buffer it reads at
     * +0x04; the two matrices sit at +0x1C and +0x5C. Those tile exactly:
     * a 28-byte msvc8::string ends at 0x1C, and 0x1C + 0x40 == 0x5C.
     *
     * Note the offsets coincide with `GeomCamera3` (projection +0x1C, view
     * +0x5C), because a `VTransform` is also 0x1C bytes. It is not a camera:
     * +0x18 there is `pos_.z`, and the binary tests that slot as an integer
     * string length.
     */
    struct STerrainTechniqueDrawParams
    {
      msvc8::string mTechniqueName;  // +0x00
      VMatrix4 mProjection;          // +0x1C
      VMatrix4 mView;                // +0x5C
    };

    /**
     * Address: 0x00805B50 (FUN_00805B50, Moho::MediumFidelityTerrain::CondDrawTerrainTechnique)
     *
     * What it does:
     * Draws one terrain pass under a caller-chosen technique, gated on
     * `ren_Terrain`.
     */
    void CondDrawTerrainTechnique(const STerrainTechniqueDrawParams& params);

    static_assert(
      offsetof(STerrainTechniqueDrawParams, mTechniqueName) == 0x00,
      "STerrainTechniqueDrawParams::mTechniqueName offset must be 0x00"
    );
    static_assert(
      offsetof(STerrainTechniqueDrawParams, mProjection) == 0x1C,
      "STerrainTechniqueDrawParams::mProjection offset must be 0x1C"
    );
    static_assert(
      offsetof(STerrainTechniqueDrawParams, mView) == 0x5C,
      "STerrainTechniqueDrawParams::mView offset must be 0x5C"
    );

  private:
    /**
     * Address: 0x008065E0 (FUN_008065E0, sub_8065E0)
     *
     * IDA signature:
     * void __stdcall sub_8065E0(MediumFidelityTerrain *a1, MeshRenderer *a4,
     *     float a5, int argC, const char *arg10);
     *
     * What it does:
     * Draws every queued decal command whose decal type matches `decalType`.
     * Selects the caller technique (or `TDecalOverDraw` under `ren_DecalOverDraw`),
     * then for each matching command binds the decal texture matrix, the slot-0
     * albedo and slot-1 spec textures, the decal alpha, and submits one indexed
     * triangle-list draw over the terrain vertex/index sheets. No-op unless
     * `ren_Decals` is enabled.
     */
    void DrawDecalPass(std::int32_t gameTick, float lod, std::int32_t decalType, const char* techniqueName);

    /**
     * Address: 0x00806860 (FUN_00806860, sub_806860)
     *
     * IDA signature:
     * int __usercall sub_806860@<eax>(MediumFidelityTerrain *this@<esi>);
     *
     * What it does:
     * Uploads the composited splat-vertex lane into the overlay vertex sheet,
     * selects the `TSplats` technique, binds the shared texture-batcher composite
     * texture into the decal albedo lane, and submits one indexed triangle-list
     * draw covering all splat quads. No-op when the splat lane is empty.
     */
    void DrawSplatComposite();

    /**
     * Address: 0x00806A50 (FUN_00806A50, sub_806A50)
     *
     * IDA signature:
     * void __stdcall sub_806A50(MediumFidelityTerrain *a1, MeshRenderer *a4, float a5);
     *
     * What it does:
     * Draws every queued decal command of glowing type (`mType == 6`) with the
     * `TDecalsGlow` technique (or `TDecalOverDraw` under `ren_DecalOverDraw`):
     * binds the decal matrix, slot-0 albedo texture, and decal alpha, then submits
     * one indexed triangle-list draw per glowing decal. No-op unless both
     * `ren_Decals` and `ren_glowingDecals` are enabled.
     */
    void DrawGlowingDecals(std::int32_t gameTick, float lod);

    /**
     * Address: 0x00806C60 (FUN_00806C60, sub_806C60)
     *
     * IDA signature:
     * void __stdcall sub_806C60(MediumFidelityTerrain *a1, MeshRenderer *a4, float a5);
     *
     * What it does:
     * Draws the normal-mapped decal commands (`mType == 2`, stopping at the first
     * `mType == 7` sentinel). Selects `TDecalsNormals` / `TDecalsNormalsAlpha` /
     * `TDecalOverDraw` depending on `ren_DecalOverDraw` and whether the sentinel was
     * seen, binds the camera view/proj matrices, the decal + tangent matrices, the
     * decal alpha, and the slot-0 normal texture, then submits one indexed
     * triangle-list draw per matching decal. No-op unless `ren_Decals` is enabled.
     */
    void DrawNormalMappedDecals(std::int32_t gameTick, float lod);

  public:
    TerrainWaterResourceView* mTerrainResource;                        // +0x0C
    std::int32_t mViewportOriginX;                                     // +0x10
    std::int32_t mViewportOriginY;                                     // +0x14
    std::int32_t mViewportWidth;                                       // +0x18
    std::int32_t mViewportHeight;                                      // +0x1C
    std::int32_t mViewportRenderWidth;                                 // +0x20
    std::int32_t mViewportRenderHeight;                                // +0x24
    GeomCamera3* mCamera;                                              // +0x28
    std::uint32_t mSkirtStartIndex = 0u;                              // +0x2C
    std::uint32_t mUnknown30 = 0u;                                    // +0x30
    std::uint32_t mSkirtEndIndex = 0u;                                // +0x34
    std::int32_t mSkirtEndVertex = 0;                                 // +0x38
    std::int32_t mSkirtBaseVertex = 0;                                // +0x3C
    MediumDecalCommandLane mDecalDrawCommands;                         // +0x40
    CTesselator* mTesselator;                                          // +0x2F30
    CD3DVertexSheet* mTerrainVertexSheet;                              // +0x2F34
    CD3DIndexSheet* mTerrainIndexSheet;                                // +0x2F38
    std::uint32_t mPad2F3C = 0u;                                       // +0x2F3C
    MediumSplatVertexLane mSplatVertices;                              // +0x2F40
    CD3DVertexSheet* mOverlayVertexSheet;                              // +0x47510
    CD3DIndexSheet* mOverlayIndexSheet;                                // +0x47514
    VTransform mOverlayTransform;                                      // +0x47518
    std::uint32_t mUnknown47534;                                       // +0x47534
  };

  static_assert(
    offsetof(MediumDecalCommandLane, inlineVec_) == 0x10,
    "FastVectorN<TerrainDecalDrawCommand,500>::inlineVec_ offset must be 0x10"
  );

  static_assert(
    offsetof(MediumFidelityTerrain, mTerrainResource) == 0x0C,
    "MediumFidelityTerrain::mTerrainResource offset must be 0x0C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportOriginX) == 0x10,
    "MediumFidelityTerrain::mViewportOriginX offset must be 0x10"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportOriginY) == 0x14,
    "MediumFidelityTerrain::mViewportOriginY offset must be 0x14"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportWidth) == 0x18,
    "MediumFidelityTerrain::mViewportWidth offset must be 0x18"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportHeight) == 0x1C,
    "MediumFidelityTerrain::mViewportHeight offset must be 0x1C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportRenderWidth) == 0x20,
    "MediumFidelityTerrain::mViewportRenderWidth offset must be 0x20"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mViewportRenderHeight) == 0x24,
    "MediumFidelityTerrain::mViewportRenderHeight offset must be 0x24"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mDecalDrawCommands) == 0x40,
    "MediumFidelityTerrain::mDecalDrawCommands offset must be 0x40"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtStartIndex) == 0x2C,
    "MediumFidelityTerrain::mSkirtStartIndex offset must be 0x2C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtEndIndex) == 0x34,
    "MediumFidelityTerrain::mSkirtEndIndex offset must be 0x34"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtEndVertex) == 0x38,
    "MediumFidelityTerrain::mSkirtEndVertex offset must be 0x38"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtBaseVertex) == 0x3C,
    "MediumFidelityTerrain::mSkirtBaseVertex offset must be 0x3C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mDecalDrawCommands) +
        offsetof(MediumDecalCommandLane, inlineVec_) ==
      0x50,
    "MediumFidelityTerrain decal-command inline storage must start at 0x50"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mTesselator) == 0x2F30,
    "MediumFidelityTerrain::mTesselator offset must be 0x2F30"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSplatVertices) == 0x2F40,
    "MediumFidelityTerrain::mSplatVertices offset must be 0x2F40"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mOverlayVertexSheet) == 0x47510,
    "MediumFidelityTerrain::mOverlayVertexSheet offset must be 0x47510"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mOverlayTransform) == 0x47518,
    "MediumFidelityTerrain::mOverlayTransform offset must be 0x47518"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mUnknown47534) == 0x47534,
    "MediumFidelityTerrain::mUnknown47534 offset must be 0x47534"
  );
  static_assert(sizeof(MediumFidelityTerrain) == 0x47538, "MediumFidelityTerrain size must be 0x47538");

  /**
   * Releases the medium-fidelity terrain's process-wide shared resources: the
   * texture batcher, the water surface, and the noise-fill / cubic-blend /
   * grid textures.
   *
   * The binary inlines this into the device-teardown sweep at 0x00809E80; it is
   * a named helper here because those statics are private to
   * MediumFidelityTerrain.cpp. See REN_ReleaseTerrainSharedResources.
   */
  void ReleaseMediumFidelityTerrainSharedResources() noexcept;
} // namespace moho
