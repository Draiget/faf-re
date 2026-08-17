#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  class RD3DTextureResource;
  struct TerrainWaterResourceView;
  class ID3DRenderTarget;
  struct TerrainShadowContext;

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
   * Only the slots whose body exists in every fidelity class are declared
   * here - a slot declared on the base but unimplemented in one derived class
   * would force a stub, which this project forbids. The remaining slots stay
   * on the derived classes until their bodies are recovered, at which point
   * they move up in the order above.
   */
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
     * What it does:
     * Binds one terrain-resource owner lane and initializes fidelity-specific
     * terrain runtime state.
     */
    [[nodiscard]] virtual bool Create(TerrainWaterResourceView* terrainResource) = 0;

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

    virtual void DrawTerrainSkirt() = 0;

    boost::shared_ptr<RD3DTextureResource> mDecalMask{}; // +0x04
  };

  static_assert(offsetof(TerrainCommon, mDecalMask) == 0x04, "TerrainCommon::mDecalMask offset must be 0x04");
  static_assert(sizeof(TerrainCommon) == 0x0C, "TerrainCommon size must be 0x0C");
} // namespace moho
