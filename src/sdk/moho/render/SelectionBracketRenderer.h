#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"
#include "moho/sim/WeakEntitySet.h"

namespace moho
{
  class CD3DPrimBatcher;
  class CWldSession;
  class UserEntity;

  struct GeomCamera3;

  /**
   * One entry of the process-global "blinky box" list - a selection bracket the
   * UI flashes on and off around a unit for a bounded amount of time, published
   * from Lua through `AddBlinkyBox(entityId, onTime, offTime, totalTime)`
   * (`cfunc_AddBlinkyBoxL`, 0x007FDB70) and pushed onto the list by
   * `func_PushBlinkyBox` (0x007FD9F0).
   *
   * Offsets are the ones `func_RenUI` reads while ticking the list at
   * 0x007FD894..0x007FD8F5: the weak unit link at `+0x08`, the on/off flag at
   * `+0x10`, and the four floats at `+0x14`/`+0x18`/`+0x1C`/`+0x20`/`+0x24`.
   */
  struct BlinkyBox final : TDatListItem<BlinkyBox, void>
  {
    SSelectionWeakRefUserEntity mUnit; // +0x08
    std::uint8_t mIsOn;                // +0x10
    std::uint8_t pad_11_13[3]{};       // +0x11
    float mCurDuration;                // +0x14
    float mCurCycleTime;               // +0x18
    float mOnTime;                     // +0x1C
    float mOffTime;                    // +0x20
    float mTotalTime;                  // +0x24
  };

  static_assert(sizeof(BlinkyBox) == 0x28, "BlinkyBox size must be 0x28");
  static_assert(offsetof(BlinkyBox, mUnit) == 0x08, "BlinkyBox::mUnit offset must be 0x08");
  static_assert(offsetof(BlinkyBox, mIsOn) == 0x10, "BlinkyBox::mIsOn offset must be 0x10");
  static_assert(offsetof(BlinkyBox, mCurDuration) == 0x14, "BlinkyBox::mCurDuration offset must be 0x14");
  static_assert(offsetof(BlinkyBox, mCurCycleTime) == 0x18, "BlinkyBox::mCurCycleTime offset must be 0x18");
  static_assert(offsetof(BlinkyBox, mOnTime) == 0x1C, "BlinkyBox::mOnTime offset must be 0x1C");
  static_assert(offsetof(BlinkyBox, mOffTime) == 0x20, "BlinkyBox::mOffTime offset must be 0x20");
  static_assert(offsetof(BlinkyBox, mTotalTime) == 0x24, "BlinkyBox::mTotalTime offset must be 0x24");

  /**
   * Address: 0x00F5AC14 (`sBlinkyBoxes`)
   *
   * Sentinel node of the process-global blinky-box ring. `func_RenUI` walks it
   * from `mNext` and stops when it comes back around to the sentinel
   * (`cmp sBlinkyBoxes.mNext, offset sBlinkyBoxes` at 0x007FD681 / 0x007FD804 /
   * 0x007FD882). Defined once, in `SelectionBracketRenderer.cpp`.
   */
  extern TDatListItem<BlinkyBox, void> sBlinkyBoxes;

  /**
   * Address: 0x00F57DE5 (ren_SelectBoxes)
   *
   * Console toggle gating the whole world-view selection pass. Defined in
   * `SelectionBracketRenderer.cpp` - `func_RenUI`'s read at 0x007FD4B8 and the
   * convar registration at 0x00BE1E66 are the only two references in the
   * image.
   */
  extern bool ren_SelectBoxes;

  /**
   * Address: 0x007FC820 (FUN_007FC820, func_DrawSelectionBrackets)
   *
   * IDA signature:
   * void __usercall func_DrawSelectionBrackets(
   *   Moho::UserEntity *entity@<ecx>, Moho::CD3DPrimBatcher *batcher,
   *   Moho::GeomCamera3 *camera, float interpolationAlpha);
   * (IDA's own four-argument `__cdecl` prototype is wrong twice over: it drops
   * the `ecx` entity and folds the camera into the float. The three stack
   * dwords live at frame `+0x04`/`+0x08`/`+0x0C` - read back at 0x007FCE15,
   * 0x007FCBAE and 0x007FCC31 - and every call site cleans them itself with
   * `add esp, 0Ch`, e.g. 0x007FD58A.)
   *
   * What it does:
   * Draws the four corner brackets of one entity's selection box into
   * `batcher`. Sizes come from the entity's mesh bounding box scaled by
   * `ren_SelectionSizeFudge`, overridden per-axis by the unit blueprint's
   * `mSelectionSizeX`/`mSelectionSizeZ` (scaled by `ren_UnitSelectionScale`)
   * when those are positive; the box centre is shifted by the blueprint's
   * selection-centre offset rotated into the entity's interpolated
   * orientation, lifted by `ren_SelectionHeightFudge`, and flattened to zero
   * Y-extent. Bracket thickness is the blueprint's `mSelectionThickness` when
   * it is non-negligible and `ren_SelectBracketSize` otherwise, then clamped
   * up so the bracket never shrinks below `ren_SelectBracketMinPixelSize` on
   * screen. Emits one `DrawQuad` per ground-plane corner, each textured with
   * its own quarter of the 2x2 bracket atlas.
   */
  void DrawSelectionBrackets(
    UserEntity* entity,
    CD3DPrimBatcher* batcher,
    const GeomCamera3* camera,
    float interpolationAlpha
  );

  /**
   * Address: 0x007FD490 (FUN_007FD490, func_RenUI)
   *
   * IDA signature:
   * void __cdecl func_RenUI(
   *   Moho::CWldSession *session, Moho::GeomCamera3 *camera,
   *   Moho::CD3DPrimBatcher *batcher, float interpolationAlpha,
   *   float elapsedSeconds);
   * (**five** arguments, not IDA's four. The fifth is read as a float at
   * 0x007FD88E and 0x007FD9A1 while ticking the blinky-box list, and both
   * call sites push five dwords and clean with `add esp, 14h` - 0x007F9533 in
   * `WRenViewport::Render` and 0x007D1B71 in `Cartographic::Render`. Do not
   * "fix" this back to four.)
   *
   * What it does:
   * The world-view UI selection pass, gated on `ren_SelectBoxes`. Runs three
   * sub-passes through one prim batcher: the shared player-bracket texture
   * over every live entity in the session selection and in the
   * `sSelectionBrackets` set; the hovered unit, when it is neither already
   * blinking nor already selected, with its own per-army bracket texture; and
   * finally the blinky-box list, advancing each entry's on/off cycle by
   * `elapsedSeconds`, dropping expired or dead entries, and drawing the ones
   * currently in their "on" phase.
   */
  void RenUI(
    CWldSession* session,
    const GeomCamera3* camera,
    CD3DPrimBatcher* batcher,
    float interpolationAlpha,
    float elapsedSeconds
  );
} // namespace moho
