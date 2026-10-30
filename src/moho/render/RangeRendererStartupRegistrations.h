#pragma once

namespace moho
{
  /**
   * Console-variable state for the range-ring renderer.
   *
   * The engine exposes the whole range-ring pass through seven console
   * variables that are bound to these globals by the static-initialiser
   * registrations in `RangeRendererStartupRegistrations.cpp`. Every value is
   * byte-verified against `bin/external/ForgedAlliance.exe`: the four `bool`
   * range flags live in the zero-initialised `.bss` tail (default `false`),
   * while the two thickness coefficients and `ren_Ranges` carry real `.data`
   * initialisers.
   *
   * Reader map (from `data_refs` in the namespace callgraph index):
   * - `range_RenderSelected`      -> FUN_007EF280 (selected-ring pass)
   * - `range_RenderHighlighted`   -> FUN_007EF420 (highlighted-ring pass)
   * - `range_RenderBuild`         -> FUN_007EEA00 (`RangeRenderer::Render`)
   * - `range_Fill`                -> FUN_007EF5A0 (`func_RenderRings`)
   * - `range_InnerThicknessCoeff` -> FUN_007EF5A0 (`func_RenderRings`)
   * - `range_OuterThicknessCoeff` -> FUN_007EF5A0 (`func_RenderRings`)
   * - `ren_Ranges`                -> FUN_007F90D0 (`WRenViewport::Render`)
   */

  /** Global: 0x010A640A. Draw range rings for the current selection. */
  extern bool range_RenderSelected;

  /** Global: 0x010A640B. Draw range rings for the hovered/highlighted unit. */
  extern bool range_RenderHighlighted;

  /** Global: 0x010A6414. Draw range rings for the pending build placement. */
  extern bool range_RenderBuild;

  /** Global: 0x010A6415. Fill ring interiors instead of drawing outlines only. */
  extern bool range_Fill;

  /** Global: 0x00F57EA4. Inner ring thickness coefficient (default 1/1024). */
  extern float range_InnerThicknessCoeff;

  /** Global: 0x00F57EA8. Outer ring thickness coefficient (default 1/1024). */
  extern float range_OuterThicknessCoeff;

  /** Global: 0x00F57E4F. Master enable for the range-ring viewport pass. */
  /**
   * NOT PRESENT IN THE ORIGINAL BINARY.
   *
   * Additive extension, not a recovery: there is no console object for this in
   * the shipped image and no `Address:` can be cited for it. It exists so a UI
   * mod can ask for the engine's real ring geometry to be drawn at the cursor
   * for the current selection, which the original only ever does for a
   * building being placed (`range_RenderBuild`). Default false, so an engine
   * built without a mod touching it behaves exactly as the binary does.
   */
  extern bool range_RenderSelectedAtCursor;

  /**
   * NOT PRESENT IN THE ORIGINAL BINARY.
   *
   * Additive extension, not a recovery. Draws the selection's *reclaim* reach
   * at the cursor, which is a different radius from the build-range overlay:
   * `CUnitReclaimTask` (0x006C1C10 lane, TASKSTATE_Waiting) rejects a target
   * when
   *
   *   rawDistance - MaxFootprintExtent(self) - MaxFootprintExtent(target)
   *     > Economy.MaxBuildDistance
   *
   * and `MaxFootprintExtent` is `max(mSizeX, mSizeZ)` - the *whole* footprint,
   * not its half-extent. So measured from its own centre a unit reclaims out to
   * `MaxBuildDistance + max(mSizeX, mSizeZ)`, which for a 5x5 factory is 10
   * against an engineer's 6 even though both blueprints leave
   * `MaxBuildDistance` at the engine default of 5. That inflation is original
   * engine behaviour and is reproduced here deliberately rather than corrected.
   *
   * Default false, so an engine built without a mod touching it behaves exactly
   * as the binary does.
   */
  extern bool range_RenderReclaimAtCursor;

  /**
   * NOT PRESENT IN THE ORIGINAL BINARY.
   *
   * Additive extension, not a recovery. Draws the attack range of the unit
   * under the cursor - one ring, the widest weapon profile that unit actually
   * carries, in the military red - so a modifier key can answer "how far does
   * that thing shoot" without selecting it.
   *
   * This is not `range_RenderHighlighted`, which it neither replaces nor
   * changes. That flag drives the engine's own hovered-unit pass
   * (`sub_7EF420`), which draws *every* profile the hovered unit matches and
   * only for the focus army's own units. This one draws a single ring and does
   * not filter by army, because a player hovering something they have not
   * selected is usually asking about a threat.
   *
   * Default false, so an engine built without a mod touching it behaves exactly
   * as the binary does.
   */
  extern bool range_RenderHoveredAttack;

  /**
   * NOT PRESENT IN THE ORIGINAL BINARY.
   *
   * FAF FA-Binary-Patches #149 (range ring stencil overflow), extended to the
   * outlines: `func_RenderRings` draws fill rings and outline bands 127 at a
   * time with a stencil flush after each batch, so 128 or more overlapping
   * rings merge without ring outlines inside the merged area (#149) and
   * without gaps in the outer outline (the edge loop #149 left alone). Default
   * true; false keeps the original 1000-payload batches and single passes.
   * Render only.
   */
  extern bool range_StencilFlush;

  /**
   * NOT PRESENT IN THE ORIGINAL BINARY.
   *
   * Performance switch: `func_RenderRings` drops the ring volumes "Cast" would
   * draw with no effect on the image - those outside the camera's view of the
   * ring slab, and, with `range_StencilFlush`, the fills and outlines that only
   * reach parts of the view another single fill already holds (zoomed in on a
   * large selection, nearly all of them). Default true; false casts every
   * volume as the original does. Render only.
   */
  extern bool range_ViewCull;

  extern bool ren_Ranges;
















} // namespace moho
