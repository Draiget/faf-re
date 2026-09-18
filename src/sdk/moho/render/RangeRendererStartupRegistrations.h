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

  extern bool ren_Ranges;

  /**
   * Address: 0x00C03F50 (FUN_00C03F50, ??1TConVar_range_RenderSelected@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_RenderSelected();

  /**
   * Address: 0x00BE0AD0 (FUN_00BE0AD0, register_TConVar_range_RenderSelected)
   */
  void register_TConVar_range_RenderSelected();

  /**
   * Address: 0x00C03F80 (FUN_00C03F80, ??1TConVar_range_RenderHighlighted@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_RenderHighlighted();

  /**
   * Address: 0x00BE0B10 (FUN_00BE0B10, register_TConVar_range_RenderHighlighted)
   */
  void register_TConVar_range_RenderHighlighted();

  /**
   * Address: 0x00C03FB0 (FUN_00C03FB0, ??1TConVar_range_RenderBuild@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_RenderBuild();

  /**
   * Address: 0x00BE0B50 (FUN_00BE0B50, register_TConVar_range_RenderBuild)
   */
  void register_TConVar_range_RenderBuild();

  /**
   * Address: 0x00C03FE0 (FUN_00C03FE0, ??1TConVar_range_Fill@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_Fill();

  /**
   * Address: 0x00BE0B90 (FUN_00BE0B90, register_TConVar_range_Fill)
   */
  void register_TConVar_range_Fill();

  /**
   * Address: 0x00C04010 (FUN_00C04010, ??1TConVar_range_InnerThicknessCoeff@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_InnerThicknessCoeff();

  /**
   * Address: 0x00BE0BD0 (FUN_00BE0BD0, register_TConVar_range_InnerThicknessCoeff)
   */
  void register_TConVar_range_InnerThicknessCoeff();

  /**
   * Address: 0x00C04040 (FUN_00C04040, ??1TConVar_range_OuterThicknessCoeff@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_range_OuterThicknessCoeff();

  /**
   * Address: 0x00BE0C10 (FUN_00BE0C10, register_TConVar_range_OuterThicknessCoeff)
   */
  void register_TConVar_range_OuterThicknessCoeff();

  /**
   * Address: 0x00C046F0 (FUN_00C046F0, ??1TConVar_ren_Ranges@Moho@@QAE@@Z)
   */
  void cleanup_TConVar_ren_Ranges();

  /**
   * Address: 0x00BE1690 (FUN_00BE1690, register_TConVar_ren_Ranges)
   */
  void register_TConVar_ren_Ranges();
} // namespace moho
