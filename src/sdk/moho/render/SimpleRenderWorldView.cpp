#include "moho/render/SimpleRenderWorldView.h"

#include <cstdint>

namespace
{
  std::uint32_t gSimpleRenderWorldViewOffsetInit = 0;
  Wm3::Vector3f gSimpleRenderWorldViewOffset{};

  struct SimpleRenderWorldViewCtorRuntimeView
  {
    void* vtable = nullptr;                    // +0x00
    std::uint8_t canShake = 0;                 // +0x04
    std::uint8_t padding05_07[3] = {0, 0, 0};  // +0x05
    moho::RenderCameraViewRuntime* cameraView = nullptr; // +0x08
  };
  static_assert(
    offsetof(SimpleRenderWorldViewCtorRuntimeView, canShake) == 0x04,
    "SimpleRenderWorldViewCtorRuntimeView::canShake offset must be 0x04"
  );
  static_assert(
    offsetof(SimpleRenderWorldViewCtorRuntimeView, cameraView) == 0x08,
    "SimpleRenderWorldViewCtorRuntimeView::cameraView offset must be 0x08"
  );
  static_assert(sizeof(SimpleRenderWorldViewCtorRuntimeView) == 0x0C, "SimpleRenderWorldViewCtorRuntimeView size must be 0x0C");

  /**
   * Address: 0x007F6290 (FUN_007F6290)
   *
   * What it does:
   * Initializes one simple world-view runtime lane by rebinding its vtable,
   * clearing `mCanShake`, and storing the camera-view lane pointer.
   */
  [[maybe_unused]] SimpleRenderWorldViewCtorRuntimeView* InitializeSimpleRenderWorldViewRuntimeLane(
    SimpleRenderWorldViewCtorRuntimeView* const runtimeView,
    moho::RenderCameraViewRuntime* const cameraView
  ) noexcept
  {
    static std::uint8_t sSimpleRenderWorldViewVtableTag = 0;
    if (runtimeView != nullptr) {
      runtimeView->vtable = &sSimpleRenderWorldViewVtableTag;
      runtimeView->canShake = 0;
      runtimeView->cameraView = cameraView;
    }
    return runtimeView;
  }
}

namespace moho
{
  /**
   * Address: 0x007F62A0 (FUN_007F62A0, nullsub_56)
   */
  void SimpleRenderWorldView::Render(const std::int32_t, const std::int32_t, const std::int32_t, const std::int32_t)
  {}

  /**
   * Address: 0x007F62B0 (FUN_007F62B0, Moho::SimpleRenderWorldView::RenderCommandGraph)
   */
  void SimpleRenderWorldView::RenderCommandGraph(
    const std::int32_t,
    const std::int32_t,
    const std::int32_t,
    const std::int32_t
  )
  {}

  /**
   * Address: 0x007F62C0 (FUN_007F62C0, Moho::SimpleRenderWorldView::GetCamera)
   */
  RenderCameraRuntime* SimpleRenderWorldView::GetCamera()
  {
    return nullptr;
  }

  /**
   * Address: 0x007F62D0 (FUN_007F62D0, Moho::SimpleRenderWorldView::GetCameraView)
   */
  RenderCameraViewRuntime* SimpleRenderWorldView::GetCameraView()
  {
    return mCameraView;
  }

  /**
   * Address: 0x007F62E0 (FUN_007F62E0, Moho::SimpleRenderWorldView::GetCameraOffset)
   */
  Wm3::Vector3f* SimpleRenderWorldView::GetCameraOffset()
  {
    if ((gSimpleRenderWorldViewOffsetInit & 1u) == 0u) {
      gSimpleRenderWorldViewOffsetInit |= 1u;
      gSimpleRenderWorldViewOffset = Wm3::Vector3f::Zero();
    }
    return &gSimpleRenderWorldViewOffset;
  }

  /**
   * Address: 0x007F6320 (FUN_007F6320, Moho::SimpleRenderWorldView::CameraGetTargetZoom)
   */
  float SimpleRenderWorldView::CameraGetTargetZoom()
  {
    return 0.0f;
  }

  /**
   * Address: 0x007F6330 (FUN_007F6330, Moho::SimpleRenderWorldView::GetMaxZoom)
   */
  float SimpleRenderWorldView::GetMaxZoom()
  {
    return 0.0f;
  }

  /**
   * Address: 0x007F6340 (FUN_007F6340, Moho::SimpleRenderWorldView::CameraGetZoom)
   */
  float SimpleRenderWorldView::CameraGetZoom()
  {
    return 0.0f;
  }

  /**
   * Address: 0x007F6350 (FUN_007F6350, Moho::SimpleRenderWorldView::SetOrthographic)
   */
  bool SimpleRenderWorldView::SetOrthographic(const bool enabled)
  {
    mCanShake = enabled;
    return enabled;
  }

  /**
   * Address: 0x007F6360 (FUN_007F6360, Moho::SimpleRenderWorldView::CanShake)
   */
  bool SimpleRenderWorldView::CanShake()
  {
    return mCanShake;
  }
} // namespace moho
