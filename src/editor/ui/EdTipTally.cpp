#include "editor/ui/EdTipCheck.h"

#include <algorithm>

namespace faf::editor
{
  std::vector<TipPoint> TipCheckPoints(
    const std::vector<TipRect>& rects,
    const float step
  )
  {
    std::vector<TipPoint> out;
    if (step <= 0.0f) {
      return out;
    }
    for (const TipRect& rect : rects) {
      for (float y = rect.y + step * 0.5f; y < rect.y + rect.height; y += step) {
        for (float x = rect.x + step * 0.5f; x < rect.x + rect.width; x += step) {
          out.push_back(TipPoint{rect.window, x, y});
        }
      }
    }
    return out;
  }

  void TipTally::Record(
    const std::uint32_t id,
    const std::string& window,
    const float x,
    const float y,
    const bool tooltip
  )
  {
    if (id == 0U) {
      return;
    }
    for (Control& control : mControls) {
      if (control.id == id) {
        control.tooltip = control.tooltip || tooltip;
        return;
      }
    }
    mControls.push_back(Control{id, window, x, y, tooltip});
  }

  int TipTally::WithTooltip() const noexcept
  {
    return static_cast<int>(std::count_if(mControls.begin(), mControls.end(), [](const Control& c) {
      return c.tooltip;
    }));
  }

  std::vector<TipTally::Control> TipTally::Missing() const
  {
    std::vector<Control> out;
    for (const Control& control : mControls) {
      if (!control.tooltip) {
        out.push_back(control);
      }
    }
    return out;
  }
} // namespace faf::editor
