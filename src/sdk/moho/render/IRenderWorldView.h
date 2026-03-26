#pragma once

#include <cstddef>
#include <cstdint>

#include "wm3/Vector3.h"

namespace moho
{
  struct RenderCameraRuntime;
  struct RenderCameraViewRuntime;

  /**
   * VFTABLE: 0x00E4054C
   * COL:     0x00E98610
   */
  class IRenderWorldView
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     *
     * What it does:
     * Abstract world-view render callback.
     */
    virtual void Render(
      std::int32_t renderParam0,
      std::int32_t renderParam1,
      std::int32_t renderParam2,
      std::int32_t renderParam3
    ) = 0;

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
     * Abstract command-graph render callback.
     */
    virtual void RenderCommandGraph(
      std::int32_t graphParam0,
      std::int32_t graphParam1,
      std::int32_t graphParam2,
      std::int32_t graphParam3
    ) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     *
     * What it does:
     * Returns active camera object for this world-view lane.
     */
    [[nodiscard]] virtual RenderCameraRuntime* GetCamera() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     *
     * What it does:
     * Returns active camera-view payload for this world-view lane.
     */
    [[nodiscard]] virtual RenderCameraViewRuntime* GetCameraView() = 0;

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
     * Address: 0x007F6260 (FUN_007F6260, Moho::CRenderWorldView::Func2)
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
    virtual bool SetOrthographic(bool enabled) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 12
     *
     * What it does:
     * Returns whether this view can apply camera shake behavior.
     */
    [[nodiscard]] virtual bool CanShake() = 0;
  };

  static_assert(sizeof(IRenderWorldView) == 0x04, "IRenderWorldView size must be 0x04");
} // namespace moho
