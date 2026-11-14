#include "editor/tools/EdUnitIcon.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace faf::editor
{
  IconBox AlphaBox(
    const std::uint32_t* bgra,
    const int side
  )
  {
    IconBox box;
    box.x0 = side;
    box.y0 = side;
    for (int y = 0; y < side; ++y) {
      for (int x = 0; x < side; ++x) {
        if ((bgra[static_cast<std::size_t>(y) * side + x] >> 24U) != 0U) {
          box.x0 = std::min(box.x0, x);
          box.y0 = std::min(box.y0, y);
          box.x1 = std::max(box.x1, x);
          box.y1 = std::max(box.y1, y);
          box.empty = false;
        }
      }
    }
    if (box.empty) {
      box = IconBox{};
    }
    return box;
  }

  std::string IconRenderProblem(
    const std::uint32_t* bgra,
    const int side,
    const float minLight
  )
  {
    const IconBox box = AlphaBox(bgra, side);
    if (box.empty) {
      return "the model drew nothing";
    }
    if (box.x0 == 0 && box.y0 == 0 && box.x1 == side - 1 && box.y1 == side - 1) {
      return "the render is opaque edge to edge (no outline to frame)";
    }
    double light = 0.0;
    int count = 0;
    for (int i = 0; i < side * side; ++i) {
      const std::uint32_t p = bgra[i];
      if ((p >> 24U) == 0U) {
        continue;
      }
      light += (0.0722 * (p & 0xFFU) + 0.7152 * ((p >> 8U) & 0xFFU) + 0.2126 * ((p >> 16U) & 0xFFU)) / 255.0;
      ++count;
    }
    if (light / count < minLight) {
      char text[96];
      std::snprintf(text, sizeof(text), "the render is too dark (mean brightness %.2f)", light / count);
      return text;
    }
    return {};
  }

  std::vector<float> IconPixels(
    const std::uint32_t* bgra,
    const int side,
    const int out,
    const float fill
  )
  {
    const IconBox box = AlphaBox(bgra, side);
    if (box.empty || out <= 0) {
      return {};
    }
    const float cx = 0.5f * static_cast<float>(box.x0 + box.x1 + 1);
    const float cy = 0.5f * static_cast<float>(box.y0 + box.y1 + 1);
    const float longer = static_cast<float>(std::max(box.x1 - box.x0 + 1, box.y1 - box.y0 + 1));
    const float span = longer / std::clamp(fill, 0.1f, 1.0f); // render pixels the icon covers
    const float x0 = cx - 0.5f * span;
    const float y0 = cy - 0.5f * span;
    const float step = span / static_cast<float>(out);
    std::vector<float> result(static_cast<std::size_t>(out) * out * 4U, 0.0f);
    for (int oy = 0; oy < out; ++oy) {
      for (int ox = 0; ox < out; ++ox) {
        // The render pixels under this icon pixel (at least one).
        const int sx0 = static_cast<int>(std::floor(x0 + ox * step));
        const int sy0 = static_cast<int>(std::floor(y0 + oy * step));
        const int sx1 = std::max(sx0 + 1, static_cast<int>(std::floor(x0 + (ox + 1) * step)));
        const int sy1 = std::max(sy0 + 1, static_cast<int>(std::floor(y0 + (oy + 1) * step)));
        double r = 0.0;
        double g = 0.0;
        double b = 0.0;
        double a = 0.0;
        int count = 0;
        for (int sy = sy0; sy < sy1; ++sy) {
          for (int sx = sx0; sx < sx1; ++sx) {
            ++count;
            if (sx < 0 || sy < 0 || sx >= side || sy >= side) {
              continue; // outside the render: clear
            }
            const std::uint32_t p = bgra[static_cast<std::size_t>(sy) * side + sx];
            const double alpha = static_cast<double>(p >> 24U) / 255.0;
            b += alpha * static_cast<double>(p & 0xFFU) / 255.0;
            g += alpha * static_cast<double>((p >> 8U) & 0xFFU) / 255.0;
            r += alpha * static_cast<double>((p >> 16U) & 0xFFU) / 255.0;
            a += alpha;
          }
        }
        float* const o = result.data() + (static_cast<std::size_t>(oy) * out + ox) * 4U;
        if (a > 0.0) {
          o[0] = static_cast<float>(r / a);
          o[1] = static_cast<float>(g / a);
          o[2] = static_cast<float>(b / a);
          o[3] = static_cast<float>(a / count);
        }
      }
    }
    return result;
  }
} // namespace faf::editor
