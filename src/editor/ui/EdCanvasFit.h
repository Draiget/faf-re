#pragma once

namespace faf::editor
{
  /** Where a node canvas looks: its zoom (1: the graph at the panels' size) and the graph's offset (graph units). */
  struct EdCanvasPlace
  {
    float zoom = 1.0f;
    float panX = 0.0f;
    float panY = 0.0f;
  };

  /**
   * The place that fits a graph's bounds (graph units) into a canvas `width` x `height` pixels, where zoom 1 is
   * `unit` pixels a graph unit (the panels' scale): `margin` of the canvas left free on each side (0.1: a tenth), the
   * zoom at most `maxZoom`. When that zoom is under `floor` (nodes too small to read), the zoom is `floor` and the
   * canvas is centred on (`focusX`, `focusY`) instead: the selection, or the graph's middle. Screen = origin +
   * (graph + pan) * zoom * unit.
   */
  [[nodiscard]] EdCanvasPlace FitCanvas(
    float minX,
    float minY,
    float maxX,
    float maxY,
    float width,
    float height,
    float unit,
    float margin,
    float floor,
    float maxZoom,
    float focusX,
    float focusY
  );
} // namespace faf::editor
