#include "editor/tools/EdUnitIcon.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
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

  std::vector<std::uint32_t> KeyedIcon(
    const std::uint32_t* const onBlack,
    const std::uint32_t* const onWhite,
    const int side,
    const float wantLight
  )
  {
    const std::size_t count = static_cast<std::size_t>(std::max(side, 0)) * static_cast<std::size_t>(std::max(side, 0));
    std::vector<float> rgba(count * 4, 0.0f);
    double light = 0.0;
    double weight = 0.0;
    for (std::size_t i = 0; i < count; ++i) {
      const auto channel = [](const std::uint32_t p, const int shift) {
        return static_cast<float>((p >> shift) & 0xFFu) / 255.0f;
      };
      const float b[3] = {channel(onBlack[i], 16), channel(onBlack[i], 8), channel(onBlack[i], 0)};
      const float w[3] = {channel(onWhite[i], 16), channel(onWhite[i], 8), channel(onWhite[i], 0)};
      // How much of the background shows: the most any channel moved between the two.
      const float through = std::clamp(std::max({w[0] - b[0], w[1] - b[1], w[2] - b[2]}), 0.0f, 1.0f);
      const float alpha = 1.0f - through;
      float* const out = &rgba[i * 4];
      out[3] = alpha;
      if (alpha > 1.0f / 255.0f) {
        for (int c = 0; c < 3; ++c) {
          out[c] = std::clamp(b[c] / alpha, 0.0f, 1.0f);
        }
        light += (out[0] * 0.2126f + out[1] * 0.7152f + out[2] * 0.0722f) * alpha;
        weight += alpha;
      }
    }
    // A dark render lifted to the wanted brightness (the thumbnail pass has no sun).
    const float mean = weight > 0.0 ? static_cast<float>(light / weight) : 0.0f;
    const float gain = mean > 1e-3f && mean < wantLight ? wantLight / mean : 1.0f;
    std::vector<std::uint32_t> out(count, 0u);
    for (std::size_t i = 0; i < count; ++i) {
      const float* const p = &rgba[i * 4];
      const auto byte = [](const float v) {
        return static_cast<std::uint32_t>(std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f));
      };
      out[i] = (byte(p[3]) << 24) | (byte(p[0] * gain) << 16) | (byte(p[1] * gain) << 8) | byte(p[2] * gain);
    }
    return out;
  }

  IconMetrics CompareIcons(
    const std::uint8_t* a,
    const std::uint8_t* b,
    const int side
  )
  {
    IconMetrics m;
    if (a == nullptr || b == nullptr || side <= 0) {
      return m;
    }
    const int n = side * side;
    int inter = 0;
    int unionCount = 0;
    double colourSum = 0.0;
    int colourN = 0;
    double alphaSum = 0.0;
    double meanA[3] = {0, 0, 0};
    double meanB[3] = {0, 0, 0};
    for (int i = 0; i < n; ++i) {
      const std::uint8_t* pa = a + static_cast<std::size_t>(i) * 4;
      const std::uint8_t* pb = b + static_cast<std::size_t>(i) * 4;
      const bool ina = pa[3] >= 128;
      const bool inb = pb[3] >= 128;
      if (ina) {
        ++m.areaA;
        for (int c = 0; c < 3; ++c) {
          meanA[c] += pa[c];
        }
      }
      if (inb) {
        ++m.areaB;
        for (int c = 0; c < 3; ++c) {
          meanB[c] += pb[c];
        }
      }
      if (ina && inb) {
        ++inter;
        colourSum += (std::abs(pa[0] - pb[0]) + std::abs(pa[1] - pb[1]) + std::abs(pa[2] - pb[2])) / 3.0;
        ++colourN;
      }
      unionCount += ina || inb ? 1 : 0;
      alphaSum += std::abs(pa[3] - pb[3]);
    }
    m.iou = unionCount > 0 ? static_cast<float>(inter) / static_cast<float>(unionCount) : 0.0f;
    m.colour = colourN > 0 ? static_cast<float>(colourSum / colourN) : 255.0f;
    m.alpha = static_cast<float>(alphaSum / n);
    if (m.areaA > 0 && m.areaB > 0) {
      double tint = 0.0;
      for (int c = 0; c < 3; ++c) {
        tint += std::abs(meanA[c] / m.areaA - meanB[c] / m.areaB) / 3.0;
      }
      m.tint = static_cast<float>(tint);
    }
    constexpr int kBlock = 8;
    double coarse = 0.0;
    int cells = 0;
    for (int by = 0; by + kBlock <= side; by += kBlock) {
      for (int bx = 0; bx + kBlock <= side; bx += kBlock) {
        double sa[4] = {0, 0, 0, 0};
        double sb[4] = {0, 0, 0, 0};
        for (int y = 0; y < kBlock; ++y) {
          for (int x = 0; x < kBlock; ++x) {
            const std::size_t k = (static_cast<std::size_t>(by + y) * side + bx + x) * 4;
            const double wa = a[k + 3] / 255.0;
            const double wb = b[k + 3] / 255.0;
            for (int c = 0; c < 3; ++c) {
              sa[c] += a[k + c] * wa;
              sb[c] += b[k + c] * wb;
            }
            sa[3] += a[k + 3];
            sb[3] += b[k + 3];
          }
        }
        double d = 0.0;
        for (int c = 0; c < 4; ++c) {
          d += std::abs(sa[c] - sb[c]) / (kBlock * kBlock);
        }
        coarse += d / 4.0;
        ++cells;
      }
    }
    m.coarse = cells > 0 ? static_cast<float>(coarse / cells) : 255.0f;
    return m;
  }

  void IconToneFit::Add(
    const std::string& faction,
    const std::uint8_t* render,
    const std::uint8_t* shipped,
    const int side
  )
  {
    Sums& s = sums[faction.empty() ? std::string("default") : faction];
    for (int i = 0; i < side * side; ++i) {
      const std::uint8_t* r = render + static_cast<std::size_t>(i) * 4;
      const std::uint8_t* p = shipped + static_cast<std::size_t>(i) * 4;
      if (r[3] >= 250 && p[3] >= 250 && p[0] + p[1] + p[2] < 705) {
        ++s.n;
        for (int c = 0; c < 3; ++c) {
          s.x[c] += r[c];
          s.y[c] += p[c];
        }
      }
    }
  }

  bool IconToneFit::Gains(
    const std::string& faction,
    float (&gains)[3]
  ) const
  {
    const auto fill = [&gains](const Sums& s) {
      if (s.n <= 200) {
        return false;
      }
      for (int c = 0; c < 3; ++c) {
        gains[c] = s.x[c] > 0.0 ? static_cast<float>(s.y[c] / s.x[c]) : 1.0f;
      }
      return true;
    };
    if (const auto it = sums.find(faction); it != sums.end() && fill(it->second)) {
      return true;
    }
    Sums all;
    for (const auto& [f, s] : sums) {
      all.n += s.n;
      for (int c = 0; c < 3; ++c) {
        all.x[c] += s.x[c];
        all.y[c] += s.y[c];
      }
    }
    return fill(all);
  }

  void ApplyIconTone(
    std::vector<std::uint8_t>& rgba,
    const float (&gains)[3]
  )
  {
    for (std::size_t i = 0; i + 3 < rgba.size(); i += 4) {
      for (int c = 0; c < 3; ++c) {
        rgba[i + static_cast<std::size_t>(c)] = static_cast<std::uint8_t>(
          std::clamp(static_cast<float>(rgba[i + static_cast<std::size_t>(c)]) * gains[c], 0.0f, 255.0f)
        );
      }
    }
  }

  std::string IconFactionOf(
    const std::string& id
  )
  {
    if (id.size() < 3) {
      return {};
    }
    const std::string p = id.substr(0, 2);
    if (p == "ue" || p == "de" || p == "xe" || p == "be") {
      return "UEF";
    }
    if (p == "ua" || p == "da" || p == "xa" || p == "ba") {
      return "Aeon";
    }
    if (p == "ur" || p == "dr" || p == "xr" || p == "br") {
      return "Cybran";
    }
    if (p == "xs" || p == "ds" || p == "bs") {
      return "Seraphim";
    }
    return {};
  }

  void IconLightEdge(
    std::vector<float>& rgba,
    const int side,
    const float solid,
    const float soft,
    const float peak
  )
  {
    if ((solid <= 0.0f && soft <= 0.0f) || side <= 0 || rgba.size() < static_cast<std::size_t>(side) * side * 4) {
      return;
    }
    const int reach = static_cast<int>(std::ceil(solid + soft));
    std::vector<float> coverage(static_cast<std::size_t>(side) * side);
    for (std::size_t i = 0; i < coverage.size(); ++i) {
      coverage[i] = rgba[i * 4 + 3];
    }
    for (int y = 0; y < side; ++y) {
      for (int x = 0; x < side; ++x) {
        const std::size_t i = static_cast<std::size_t>(y) * side + x;
        const float u = coverage[i];
        float d = 99.0f;
        if (u >= 0.5f) {
          d = 0.0f;
        } else {
          for (int dy = -reach; dy <= reach; ++dy) {
            const int yy = y + dy;
            if (yy < 0 || yy >= side) {
              continue;
            }
            for (int dx = -reach; dx <= reach; ++dx) {
              const int xx = x + dx;
              if (xx >= 0 && xx < side && coverage[static_cast<std::size_t>(yy) * side + xx] >= 0.5f) {
                d = std::min(d, std::sqrt(static_cast<float>(dx * dx + dy * dy)));
              }
            }
          }
        }
        float halo = 0.0f;
        if (d <= solid) {
          halo = peak;
        } else if (soft > 0.0f && d < solid + soft) {
          halo = peak * (1.0f - (d - solid) / soft);
        }
        const float alpha = u + halo * (1.0f - u);
        float* const p = &rgba[i * 4];
        if (alpha > 0.0f) {
          const float white = halo * (1.0f - u);
          for (int c = 0; c < 3; ++c) {
            p[c] = (p[c] * u + white) / alpha;
          }
          p[3] = alpha;
        } else {
          p[0] = p[1] = p[2] = 1.0f;
          p[3] = 0.0f;
        }
      }
    }
  }

  std::vector<std::uint32_t> IconDifference(
    const std::uint8_t* made,
    const std::uint8_t* shipped,
    const int side
  )
  {
    std::vector<std::uint32_t> out(static_cast<std::size_t>(side) * side);
    for (std::size_t i = 0; i < out.size(); ++i) {
      const bool inMade = made[i * 4 + 3] >= 128;
      const bool inShipped = shipped[i * 4 + 3] >= 128;
      std::uint32_t r = 40, g = 40, b = 40;
      if (inMade && inShipped) {
        r = 60, g = 190, b = 90;
      } else if (inMade) {
        r = 220, g = 70, b = 60;
      } else if (inShipped) {
        r = 70, g = 110, b = 230;
      }
      out[i] = 0xFF000000u | (r << 16) | (g << 8) | b;
    }
    return out;
  }
} // namespace faf::editor
