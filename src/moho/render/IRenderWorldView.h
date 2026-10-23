#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"

namespace moho
{
  class CameraImpl;
  class CD3DPrimBatcher;
  struct GeomCamera3; // defined as a struct in GeomCamera3.h - the class-key must match or MSVC mangles calls with V instead of U

  /**
   * VFTABLE: 0x00E4054C
   * COL:     0x00E98610
   *
   * The two draw slots, 0 and 2, take `(batcher, gameTick, tickFraction,
   * frameSeconds)`. Both floats travel as floats all the way down: the frame
   * loop (`WRenViewport::Render`, 0x007F95B3..0x007F95EA) pushes
   * `sCurGameTick`, then `sDeltaFrame` and `sWeightedFrameRate` through the
   * x87 stack, and `CUIWorldView::Render` (0x0086EE00) forwards `[ebp+10h]` and
   * `[ebp+14h]` with `fld`/`fstp` only - never as pointers.
   */
  class IRenderWorldView
  {
  public:
    /**
     * Address: 0x007F6280 (FUN_007F6280, ??0IRenderWorldView@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one world-view render interface base object.
     */
    IRenderWorldView();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * What it does:
     * Abstract world-view render callback. `tickFraction` is how far the
     * frame is into the current sim tick (the entity interpolant), and
     * `frameSeconds` the weighted frame time.
     */
    virtual void Render(CD3DPrimBatcher* batcher, int gameTick, float tickFraction, float frameSeconds) = 0;

    /**
     * Address: 0x007F6250 (FUN_007F6250, Moho::SimpleRenderWorldView::Func1)
     * Slot: 1
     *
     * What it does:
     * Default no-op for the first optional world-view hook.
     */
    virtual void Func1();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     *
     * What it does:
     * Abstract command-graph render callback, with slot 0's arguments.
     */
    virtual void RenderCommandGraph(CD3DPrimBatcher* batcher, int gameTick, float tickFraction, float frameSeconds) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     *
     * What it does:
     * Returns active camera object for this world-view lane.
     */
    [[nodiscard]] virtual CameraImpl* GetCamera() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     *
     * What it does:
     * Returns active camera-view payload for this world-view lane.
     */
    [[nodiscard]] virtual GeomCamera3* GetCameraView() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 5
     *
     * What it does:
     * Returns camera positional offset used by this world-view lane.
     */
    [[nodiscard]] virtual Wm3::Vector3f* GetCameraOffset() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 6
     *
     * What it does:
     * Returns camera target zoom for this world-view lane.
     */
    [[nodiscard]] virtual float CameraGetTargetZoom() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 7
     *
     * What it does:
     * Returns max zoom for this world-view lane.
     */
    [[nodiscard]] virtual float GetMaxZoom() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 8
     *
     * What it does:
     * Returns current camera zoom for this world-view lane.
     */
    [[nodiscard]] virtual float CameraGetZoom() = 0;

    /**
     * Address: 0x007F6260 (FUN_007F6260, Moho::IRenderWorldView::Func2)
     * Slot: 9
     *
     * What it does:
     * Default optional feature flag lane; returns false.
     */
    [[nodiscard]] virtual bool Func2();

    /**
     * Address: 0x007F6270 (FUN_007F6270, Moho::SimpleRenderWorldView::IsMiniMap)
     * Slot: 10
     *
     * What it does:
     * Default minimap indicator lane; returns false.
     */
    [[nodiscard]] virtual bool IsMiniMap();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 11
     *
     * What it does:
     * Updates orthographic/behavior toggle for this view and returns stored state.
     */
    virtual void SetOrthographic(bool enabled) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 12
     *
     * What it does:
     * Returns whether this view can apply camera shake behavior.
     */
    [[nodiscard]] virtual bool CanShake() = 0;

  protected:
    /**
     * Address: 0x007F6370 (FUN_007F6370)
     * Address: 0x007F7A60 (FUN_007F7A60)
     *
     * What it does:
     * Puts the interface vtable back (`mov [eax], 0E4054Ch; ret`). The vtable
     * has no destructor slot, so this one is not virtual; nothing deletes
     * through the interface. 0x007F7A60 is the copy
     * `WRenViewport::RenderPreviewImage` (0x007F7400) calls when its local
     * preview view goes out of scope, 0x007F6370 the one in this TU, and
     * `CUIWorldView`'s destructor inlines the same store at 0x0086EB85.
     *
     * The empty body is deliberate: a user-provided destructor is what makes
     * MSVC emit that restore, and `= default` would make it trivial.
     */
    ~IRenderWorldView() {}
  };

  static_assert(sizeof(IRenderWorldView) == 0x04, "IRenderWorldView size must be 0x04");
} // namespace moho
