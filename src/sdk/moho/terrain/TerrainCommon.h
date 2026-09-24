#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"

namespace moho
{
  class RD3DTextureResource;
  class IWldTerrainRes;
  struct GeomCamera3;
  class ID3DRenderTarget;
  struct TerrainShadowContext;
  class CD3DPrimBatcher;
  class CD3DDynamicTextureSheet;
  // Slot 7's argument block. Its single owning definition lives in
  // MediumFidelityTerrain.h, which includes this header, so it can only be
  // named here by forward declaration - it is passed by const reference.
  struct STerrainTechniqueDrawParams;
  class CWldTerrainDecal;

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
    std::int32_t startIndex;   // +0x00 -> SD3DIndexRange::startIndex
    std::int32_t indexCount;   // +0x04 -> SD3DIndexRange::indexCount
    std::int32_t startVertex;  // +0x08 -> SD3DVertexRange::startVertex (min referenced vertex)
    std::int32_t endVertex;    // +0x0C -> SD3DVertexRange::endVertex
    float alpha;               // +0x10 -> DecalAlpha shader-var value
    CWldTerrainDecal* decal;   // +0x14 -> owning decal (textures + matrices)
  };
  static_assert(sizeof(TerrainDecalDrawCommand) == 0x18, "TerrainDecalDrawCommand size must be 0x18");

  /**
   * VFTABLE: 0x00E419D4
   *
   * Base class for terrain rendering. Holds the shared decal mask texture
   * loaded from `/textures/engine/decalMask.dds`.
   *
   * The binary splits this into `Moho::IRenTerrain` (the pure interface,
   * vftable 0x00E41994, all 15 slots `_purecall`) and `Moho::TerrainCommon`
   * (vftable 0x00E419D4, which overrides only slot 0). `~IRenTerrain`
   * (0x007FF8D0) is the body that releases `mDecalMask`, so the member lives
   * on the interface and `TerrainCommon` adds nothing but its own vftable;
   * the two are modelled as one class here.
   *
   * The 15 virtual slots are identical across all three fidelity classes and
   * were cross-confirmed from their vftables (Low 0x00E41A94, Medium
   * 0x00E41A54, High 0x00E41A14):
   *
   *   | Slot | Method                     | Low       | Medium    | High      |
   *   |------|----------------------------|-----------|-----------|-----------|
   *   |   0  | ~TerrainCommon             | 0x809D80  | 0x807990  | 0x803970  |
   *   |   1  | IsFidelity                 | 0x808190  | 0x803BF0  | 0x7FFB70  |
   *   |   2  | Create                     | 0x8081A0  | 0x803C00  | 0x7FFB80  |
   *   |   3  | Init                       | 0x808240  | 0x803CE0  | 0x7FFC60  |
   *   |   4  | Destroy                    | 0x808590  | 0x804350  | 0x8002E0  |
   *   |   5  | (unnamed, `Func3`)         | 0x808640  | 0x804440  | 0x8003E0  |
   *   |   6  | DrawTerrainDepth           | 0x808F90  | 0x805A90  | 0x801A50  |
   *   |   7  | CondDrawTerrainTechnique   | 0x809050  | 0x805B50  | 0x801B10  |
   *   |   8  | DrawNormals                | 0x809120  | 0x805C20  | 0x801BE0  |
   *   |   9  | DrawTerrainNormal          | 0x809B20  | 0x806F50  | 0x802F20  |
   *   |  10  | DrawWaterLine              | 0x809B30  | 0x807410  | 0x8033E0  |
   *   |  11  | DrawWaterTerrain           | 0x809B50  | 0x807430  | 0x803410  |
   *   |  12  | DrawTerrainSkirt           | 0x809C80  | 0x805530  | 0x8014F0  |
   *   |  13  | DrawTerrain                | 0x809D30  | 0x807660  | 0x803640  |
   *   |  14  | DrawDirtyTerrain           | 0x809D70  | 0x805F10  | 0x801EE0  |
   *
   * All fifteen are declared here, in that order. They have to be: the binary
   * dispatches terrain by slot index, so a slot missing from the base does not
   * merely go undeclared - it shifts every slot below it. Slots 3, 4, 7, 10 and
   * 13 were previously left on the derived classes (`Init`, `Destroy`,
   * `DrawWaterLine` as non-virtuals, `CondDrawTerrainTechnique` and
   * `DrawTerrain` as *new* virtuals), which appended two fresh slots per
   * derived class after slot 9 and moved `DrawWaterTerrain`, `DrawTerrainSkirt`
   * and `DrawDirtyTerrain` off the indices the binary's call sites use. Every
   * one of those bodies is now recovered in all three fidelity classes, so they
   * are declared in the base and overridden below.
   */
  /**
   * The three terrain fidelity levels, as `graphics_Fidelity` encodes them.
   *
   * Fixed by two independent sites in the binary: `IRenTerrain::Create`
   * (0x00809DA0) switches on these to pick which renderer to construct, and
   * each renderer's `IsFidelity` (slot 1) compares against its own value --
   * 0x00808190 against 0, 0x00803BF0 against 1, 0x007FFB70 against 2.
   */
  inline constexpr std::int32_t kLowTerrainFidelity = 0;
  inline constexpr std::int32_t kMediumTerrainFidelity = 1;
  inline constexpr std::int32_t kHighTerrainFidelity = 2;

  class TerrainCommon
  {
  public:
    /**
     * Address: 0x007FF840 (FUN_007FF840, ??0TerrainCommon@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the vtable and loads the decal mask texture from D3D resources.
     */
    TerrainCommon();

    /**
     * Address: 0x007FF8D0 (FUN_007FF8D0, ??1IRenTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases the shared decal-mask texture handle and restores the terrain
     * base vtable lane during teardown.
     */
    virtual ~TerrainCommon();

    /**
     * Primary vtable slot 1 (unnamed in the binary; `Func1` in per-class
     * recovery notes). Bodies: 0x00808190 (Low), 0x00803BF0 (Medium),
     * 0x007FFB70 (High).
     *
     * What it does:
     * Answers whether this renderer is the given fidelity level. Each of the
     * three implementations is the same four instructions against a different
     * constant -- `xor eax, eax; cmp [esp+4], N; setz al; retn 4` -- with N
     * being 0, 1 and 2 respectively.
     *
     * Those constants are the same ones `IRenTerrain::Create` (0x00809DA0)
     * switches `graphics_Fidelity` on to pick which class to construct, so
     * the level encoding is fixed by two independent sites: 0 is low, 1 is
     * medium, 2 is high.
     */
    [[nodiscard]] virtual bool IsFidelity(std::int32_t fidelity) const = 0;

    /**
     * What it does:
     * Binds one terrain-resource owner lane and initializes fidelity-specific
     * terrain runtime state.
     */
    [[nodiscard]] virtual bool Create(IWldTerrainRes* terrainResource) = 0;

    /**
     * Primary vtable slot 3. Bodies: 0x00808240 (Low), 0x00803CE0 (Medium),
     * 0x007FFC60 (High).
     *
     * What it does:
     * Builds the fidelity-specific device resources the terrain needs -
     * vertex/index sheets, effect handles and, on high fidelity, the
     * shoreline - and reports whether the renderer came up.
     */
    [[nodiscard]] virtual bool Init() = 0;

    /**
     * Primary vtable slot 4. Bodies: 0x00808590 (Low), 0x00804350 (Medium),
     * 0x008002E0 (High).
     *
     * What it does:
     * Releases everything `Init` built, in the reverse order. High fidelity
     * tears its shoreline down first (`Shoreline::Destroy` at 0x008002EB).
     */
    virtual void Destroy() = 0;

    /**
     * Primary vtable slot 5 (unnamed in the binary; `Func3` in per-class
     * recovery notes).
     *
     * What it does:
     * Per-frame render-context update: stores the camera and 6-int viewport
     * block, derives a dirty flag from edit-mode/camera-transform changes,
     * and - when dirty (or forced) and not a minimap pass - rebuilds
     * tessellation, gathers on-screen decals/splats, and re-uploads the
     * tesselator's rect-cache/collision-index lanes into the terrain
     * vertex/index sheets. Behavior differs across the three fidelity
     * classes in which fields exist (only high fidelity has a shoreline)
     * and in a handful of gating details - see each override's own
     * documentation.
     *
     * Dispatched from `WRenViewport::Render` (0x007F90D0): `mov edx,
     * [edx+14h]` / `call edx` at 0x007F93A6-0x007F93C7, immediately before
     * the slot-9 (`DrawTerrainNormal`) dispatch.
     */
    virtual void UpdateRenderContext(
      std::int32_t gameTick,
      float deltaSeconds,
      GeomCamera3* camera,
      const std::int32_t* viewportBlock,
      bool minimapPass,
      std::int32_t forceRegenerate) = 0;

    /**
     * Primary vtable slot 6.
     *
     * What it does:
     * Depth-only terrain pass, drawn into the shadow map's depth target.
     *
     * Dispatched from `Shadow::RenderShadowMap` (0x007FEEA0), which calls
     * it through this slot with the light camera before the mesh depth
     * pass - the terrain has to be in the shadow map too.
     */
    virtual void DrawTerrainDepth(const GeomCamera3& camera) = 0;

    /**
     * Primary vtable slot 7. Bodies: 0x00809050 (Low), 0x00805B50 (Medium),
     * 0x00801B10 (High) - all three are the same body to the instruction.
     *
     * What it does:
     * Draws the terrain with a technique chosen by the caller rather than a
     * literal, which is what makes it the `Cond` variant of the slot-13 pass:
     * it binds the params block's view and projection matrices plus the
     * tesselator height scale, then issues the terrain triangle list.
     */
    virtual void CondDrawTerrainTechnique(const STerrainTechniqueDrawParams& params) = 0;

    /**
     * Primary vtable slot 8.
     *
     * What it does:
     * The terrain normal/decal render pass - the one that actually draws the
     * terrain surface. Binds terrain lighting for the shadow context, then
     * either forwards to the debug normal-visualization path
     * (`ren_ShowNormals`) or runs the full decal/splat pass.
     *
     * Dispatched from `WRenViewport::RenderCompositeTerrain` (0x007F81C0):
     * `mov edx, [edx+20h]` / `call edx` at 0x007F8277, with `sCurGameTick`
     * pushed last at 0x007F827E.
     */
    virtual bool DrawNormals(
      std::int32_t gameTick,
      float deltaSeconds,
      const boost::shared_ptr<ID3DRenderTarget>& terrainNormalTexture,
      TerrainShadowContext* shadowContext) = 0;

    /**
     * Primary vtable slot 9.
     *
     * What it does:
     * Fills the off-screen terrain-normal buffer that
     * `WRenViewport::TransformTerrainNormals` samples for its `TCreateBasis`
     * pass. Low fidelity does not need the buffer and keeps this an empty hook.
     *
     * Dispatched from `WRenViewport::RenderTerrainNormals` (0x007F7F10).
     * Parameter 1 is the game tick, not a `MeshRenderer*`: the binary pushes
     * `sCurGameTick` last at 0x007F827E for the sibling slot-8 dispatch, and
     * the decal texture lookups thread it straight into
     * `CWldTerrainDecal::GetTexture`'s `int frameSeed`.
     */
    virtual void DrawTerrainNormal(std::int32_t gameTick, float deltaSeconds) = 0;

    /**
     * Primary vtable slot 10. Bodies: 0x00809B30 (Low), 0x00807410 (Medium),
     * 0x008033E0 (High).
     *
     * What it does:
     * Issues the water alpha-mask lane - the shoreline waterline band - for
     * the active terrain camera, through whichever `waterFidelity` path is
     * selected (0x008033E3 loads the global and dispatches its slot 3).
     */
    virtual void DrawWaterLine(std::int32_t gameTick, float deltaSeconds) = 0;

    /**
     * Primary vtable slot 11.
     *
     * What it does:
     * Issues the frame's water surface pass through the active WaterSurface
     * fidelity, after whatever per-fidelity viewport setup that path needs.
     *
     * Dispatched from `WRenViewport::RenderWater` (0x007F86F0). The two
     * render targets arrive as by-value shared_ptrs - refraction from
     * mPrimaryTargetLocks[mHead], reflection from mSecondaryTargetLocks[mHead].
     */
    virtual void DrawWaterTerrain(
      std::int32_t tick,
      float tickLerp,
      boost::shared_ptr<ID3DRenderTarget> refractionTexture,
      boost::shared_ptr<ID3DRenderTarget> reflectionTexture) = 0;

    /**
     * Primary vtable slot 12.
     *
     * What it does:
     * Emits the terrain skirt geometry - the vertical band that closes the
     * gap between the terrain grid edge and the world bounds - for whichever
     * fidelity path is active.
     *
     * Dispatched from `WRenViewport::RenderCompositeTerrain` (0x007F81C0),
     * which tail-jumps through this slot: `mov edx, [eax+30h]` / `jmp edx`
     * at 0x007F8285.
     */
    virtual void DrawTerrainSkirt() = 0;

    /**
     * Primary vtable slot 13. Bodies: 0x00809D30 (Low), 0x00807660 (Medium),
     * 0x00803640 (High) - all three `retn 0Ch`, i.e. 12 bytes of arguments:
     * the by-value `shared_ptr` (8) plus the technique-name pointer (4).
     *
     * What it does:
     * Runs one full opaque terrain pass: rebinds every terrain-lighting shader
     * var with no shadow source, re-selects the `terrain` effect, selects the
     * caller-provided technique, binds the overlay texture sheet, loads the
     * base terrain shader vars with no terrain-normal target, and submits the
     * terrain triangle list. The retained overlay handle is released as the
     * by-value `shared_ptr` parameter goes out of scope.
     *
     * Low fidelity draws no terrain here, so its body consists of nothing but
     * that parameter's destructor -- which is why IDA types 0x00809D30 as
     * `(int, sp_counted_base*, int)`: it only ever saw the `shared_ptr`'s two
     * raw words go by. The same 12 argument bytes are the same two parameters
     * in all three classes.
     */
    virtual void DrawTerrain(
      boost::shared_ptr<CD3DDynamicTextureSheet> overlayTexture,
      const msvc8::string* techniqueName) = 0;

    /**
     * Primary vtable slot 14.
     *
     * What it does:
     * Debug overlay, gated on the fidelity-specific "show dirty terrain"
     * toggle. Draws one height-conforming quad over every entry of the
     * terrain resource's debug dirty-rectangle list that overlaps - or is
     * fully contained by - the terrain footprint of the camera frustum.
     *
     * Dispatched from `REN_RenderViewportUI` (0x007F88D0), once per
     * registered world-view entry, immediately after the per-view UI head is
     * bound: `mov edx, [eax+38h]` / `call edx` on the entry's own terrain
     * pointer at 0x007F8917-0x007F891C. NOT a separate "UI callback" -
     * `WRenViewportWorldViewParamRuntime::terrain` genuinely holds the same
     * per-view `TerrainCommon`-derived object `WRenViewport::Render` uses for
     * every other terrain pass; slot 14 is simply the one slot this
     * particular call site dispatches.
     */
    virtual void DrawDirtyTerrain(CD3DPrimBatcher* batcher) = 0;

    boost::shared_ptr<RD3DTextureResource> mDecalMask{}; // +0x04
  };

  static_assert(offsetof(TerrainCommon, mDecalMask) == 0x04, "TerrainCommon::mDecalMask offset must be 0x04");
  static_assert(sizeof(TerrainCommon) == 0x0C, "TerrainCommon size must be 0x0C");
} // namespace moho
