#include "editor/ui/EdCanvasFit.h"

#include <algorithm>

namespace faf::editor
{
  EdCanvasPlace FitCanvas(
    const float minX,
    const float minY,
    const float maxX,
    const float maxY,
    const float width,
    const float height,
    const float unit,
    const float margin,
    const float floor,
    const float maxZoom,
    const float focusX,
    const float focusY
  )
  {
    EdCanvasPlace view;
    if (width <= 0.0f || height <= 0.0f || unit <= 0.0f || maxX < minX || maxY < minY) {
      return view;
    }
    const float usableW = width * (1.0f - 2.0f * margin);
    const float usableH = height * (1.0f - 2.0f * margin);
    const float w = std::max(maxX - minX, 1.0f) * unit;
    const float h = std::max(maxY - minY, 1.0f) * unit;
    float zoom = std::min({usableW / w, usableH / h, maxZoom});
    float centreX = (minX + maxX) * 0.5f;
    float centreY = (minY + maxY) * 0.5f;
    if (zoom < floor) {
      zoom = floor;
      centreX = focusX;
      centreY = focusY;
    }
    view.zoom = zoom;
    const float scale = zoom * unit;
    view.panX = width * 0.5f / scale - centreX;
    view.panY = height * 0.5f / scale - centreY;
    return view;
  }
} // namespace faf::editor
