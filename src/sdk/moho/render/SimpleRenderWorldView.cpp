#include "moho/render/SimpleRenderWorldView.h"

#include <cstdint>

namespace
{
  std::uint32_t gSimpleRenderWorldViewOffsetInit = 0;
  Wm3::Vector3f gSimpleRenderWorldViewOffset{};
}

namespace moho
{
  /**
   * Address: 0x007F6290 (FUN_007F6290)
   *
   * What it does:
   * Installs this class's vtable (0x00E40584), clears the shake toggle and
   * stores the camera payload the view reports from `GetCameraView`.
   */
  SimpleRenderWorldView::SimpleRenderWorldView(GeomCamera3* const cameraView)
    : mCanShake(false)
    , mCameraView(cameraView)
  {}

  /**
   * Address: 0x007F62A0 (FUN_007F62A0, nullsub_56)
   */
  void SimpleRenderWorldView::Render(CD3DPrimBatcher*, int, float, float)
  {}

  /**
   * Address: 0x007F62B0 (FUN_007F62B0, Moho::SimpleRenderWorldView::RenderCommandGraph)
   */
  void SimpleRenderWorldView::RenderCommandGraph(CD3DPrimBatcher*, int, float, float)
  {}

  /**
   * Address: 0x007F62C0 (FUN_007F62C0, Moho::SimpleRenderWorldView::GetCamera)
   */
  CameraImpl* SimpleRenderWorldView::GetCamera()
  {
    return nullptr;
  }

  /**
   * Address: 0x007F62D0 (FUN_007F62D0, Moho::SimpleRenderWorldView::GetCameraView)
   */
  GeomCamera3* SimpleRenderWorldView::GetCameraView()
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
  void SimpleRenderWorldView::SetOrthographic(const bool enabled)
  {
    // 0x007F6350 is `mov al,[arg]; mov [ecx+4],al; ret 4` - the AL load feeds
    // the store, so the slot returns nothing. IDA types it `bool` only because
    // AL is still live at the return.
    mCanShake = enabled;
  }

  /**
   * Address: 0x007F6360 (FUN_007F6360, Moho::SimpleRenderWorldView::CanShake)
   */
  bool SimpleRenderWorldView::CanShake()
  {
    return mCanShake;
  }
} // namespace moho
