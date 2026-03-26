#include "CD3DPrimBatcher.h"

#include <cstddef>

#include "moho/ui/CUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  /**
   * Address: 0x0084D3E0 (FUN_0084D3E0)
   *
   * What it does:
   * Builds per-head UI orthographic matrices from the input-window client size and
   * applies UI alpha multiplier from the owning CUIManager.
   */
  void CD3DPrimBatcher::SetToViewport(const int head, const CUIManager& manager)
  {
    if (head < 0) {
      return;
    }

    const std::size_t headIndex = static_cast<std::size_t>(head);
    if (headIndex >= manager.mInputWindows.Size()) {
      return;
    }

    wxWindowBase* const inputWindow = manager.mInputWindows[headIndex];
    if (inputWindow == nullptr) {
      return;
    }

    std::int32_t width = 0;
    std::int32_t height = 0;
    WX_GetClientSize(inputWindow, width, height);
    if (width <= 0 || height <= 0) {
      return;
    }

    const float widthF = static_cast<float>(width);
    const float heightF = static_cast<float>(height);

    VMatrix4 projection{};
    projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
    projection.r[1] = {0.0f, 2.0f / (-heightF), 0.0f, 0.0f};
    projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
    projection.r[3] = {
      (widthF / (-widthF)) - (1.0f / widthF),
      (heightF / heightF) + (1.0f / heightF),
      0.5f,
      1.0f,
    };

    SetProjectionMatrix(projection);
    SetViewMatrix(UI_IdentityMatrix());
    CD3DPrimBatcherRuntimeView::FromBatcher(this)->mAlphaMultiplier = manager.mUIControlsAlpha;
  }
} // namespace moho
