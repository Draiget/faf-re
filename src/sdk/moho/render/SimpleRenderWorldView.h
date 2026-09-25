#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/IRenderWorldView.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E40584
   * COL:     0x00E985C4
   */
  class SimpleRenderWorldView : public IRenderWorldView
  {
  public:
    /**
     * Address: 0x007F6290 (FUN_007F6290)
     *
     * What it does:
     * Binds the view to one camera payload, shake off. `RenderPreviewImage`
     * (0x007F7400) builds its strategic-map preview view with this, inlined
     * at 0x007F7612..0x007F761E.
     */
    explicit SimpleRenderWorldView(GeomCamera3* cameraView);

    /**
     * Address: 0x007F62A0 (FUN_007F62A0, nullsub_56)
     * Slot: 0
     *
     * What it does:
     * Default world-view render callback; intentionally no-op.
     */
    void Render(CD3DPrimBatcher* batcher, int gameTick, float tickFraction, float frameSeconds) override;

    /**
     * Address: 0x007F62B0 (FUN_007F62B0, Moho::SimpleRenderWorldView::RenderCommandGraph)
     * Slot: 2
     *
     * What it does:
     * Default command-graph render callback; intentionally no-op.
     */
    void RenderCommandGraph(CD3DPrimBatcher* batcher, int gameTick, float tickFraction, float frameSeconds) override;

    /**
     * Address: 0x007F62C0 (FUN_007F62C0, Moho::SimpleRenderWorldView::GetCamera)
     * Slot: 3
     *
     * What it does:
     * Returns null camera handle for the simple world-view lane.
     */
    [[nodiscard]] CameraImpl* GetCamera() override;

    /**
     * Address: 0x007F62D0 (FUN_007F62D0, Moho::SimpleRenderWorldView::GetCameraView)
     * Slot: 4
     *
     * What it does:
     * Returns stored camera-view payload pointer.
     */
    [[nodiscard]] GeomCamera3* GetCameraView() override;

    /**
     * Address: 0x007F62E0 (FUN_007F62E0, Moho::SimpleRenderWorldView::GetCameraOffset)
     * Slot: 5
     *
     * What it does:
     * Returns process-wide zero camera-offset vector.
     */
    [[nodiscard]] Wm3::Vector3f* GetCameraOffset() override;

    /**
     * Address: 0x007F6320 (FUN_007F6320, Moho::SimpleRenderWorldView::CameraGetTargetZoom)
     * Slot: 6
     *
     * What it does:
     * Returns default target zoom (0.0f).
     */
    [[nodiscard]] float CameraGetTargetZoom() override;

    /**
     * Address: 0x007F6330 (FUN_007F6330, Moho::SimpleRenderWorldView::GetMaxZoom)
     * Slot: 7
     *
     * What it does:
     * Returns default max zoom (0.0f).
     */
    [[nodiscard]] float GetMaxZoom() override;

    /**
     * Address: 0x007F6340 (FUN_007F6340, Moho::SimpleRenderWorldView::CameraGetZoom)
     * Slot: 8
     *
     * What it does:
     * Returns default current zoom (0.0f).
     */
    [[nodiscard]] float CameraGetZoom() override;

    /**
     * Address: 0x007F6350 (FUN_007F6350, Moho::SimpleRenderWorldView::SetOrthographic)
     * Slot: 11
     *
     * What it does:
     * Stores toggle byte and returns written state.
     */
    void SetOrthographic(bool enabled) override;

    /**
     * Address: 0x007F6360 (FUN_007F6360, Moho::SimpleRenderWorldView::CanShake)
     * Slot: 12
     *
     * What it does:
     * Returns the stored toggle byte.
     */
    [[nodiscard]] bool CanShake() override;

  public:
    bool mCanShake;           // +0x04
    GeomCamera3* mCameraView; // +0x08
  };

  static_assert(offsetof(SimpleRenderWorldView, mCanShake) == 0x04, "SimpleRenderWorldView::mCanShake offset must be 0x04");
  static_assert(offsetof(SimpleRenderWorldView, mCameraView) == 0x08, "SimpleRenderWorldView::mCameraView offset must be 0x08");
  static_assert(sizeof(SimpleRenderWorldView) == 0x0C, "SimpleRenderWorldView size must be 0x0C");
} // namespace moho
