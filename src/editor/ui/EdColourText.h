#pragma once

// Colours as the mockup's colour fields write them (#RRGGBB), for colours that may be brighter than white (the map's
// lighting): the hex holds the hue at its brightest component 1, a brightness the scale. No ImGui: tested on its own
// (tests/editor/ColourTextTests.cpp).

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <string>
#include <string_view>

namespace faf::editor
{
  /** The brightness a colour's hex leaves out: its brightest component when above 1, else 1. */
  [[nodiscard]] inline float ColourBrightness(
    const float (&rgb)[3]
  )
  {
    return std::max({1.0f, rgb[0], rgb[1], rgb[2]});
  }

  /** "#RRGGBB" of a colour divided by its brightness (each component 0..1, rounded). */
  [[nodiscard]] inline std::string HexOfColour(
    const float (&rgb)[3]
  )
  {
    const float scale = ColourBrightness(rgb);
    int c[3];
    for (int i = 0; i < 3; ++i) {
      c[i] = static_cast<int>(std::lround(std::clamp(rgb[i] / scale, 0.0f, 1.0f) * 255.0f));
    }
    char text[8];
    std::snprintf(text, sizeof(text), "#%02X%02X%02X", c[0], c[1], c[2]);
    return text;
  }

  /**
   * The colour a hex names ("#RRGGBB", "RRGGBB" or "#RGB", any case), times `brightness`; false (and `rgb` as it
   * was) for anything else.
   */
  [[nodiscard]] inline bool ColourOfHex(
    std::string_view text,
    const float brightness,
    float (&rgb)[3]
  )
  {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
      text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
      text.remove_suffix(1);
    }
    if (!text.empty() && text.front() == '#') {
      text.remove_prefix(1);
    }
    const auto digit = [](const char ch) {
      if (ch >= '0' && ch <= '9') {
        return ch - '0';
      }
      const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
      return lower >= 'a' && lower <= 'f' ? lower - 'a' + 10 : -1;
    };
    int c[3];
    if (text.size() == 6) {
      for (int i = 0; i < 3; ++i) {
        const int hi = digit(text[static_cast<std::size_t>(i * 2)]);
        const int lo = digit(text[static_cast<std::size_t>(i * 2 + 1)]);
        if (hi < 0 || lo < 0) {
          return false;
        }
        c[i] = hi * 16 + lo;
      }
    } else if (text.size() == 3) {
      for (int i = 0; i < 3; ++i) {
        const int d = digit(text[static_cast<std::size_t>(i)]);
        if (d < 0) {
          return false;
        }
        c[i] = d * 17;
      }
    } else {
      return false;
    }
    for (int i = 0; i < 3; ++i) {
      rgb[i] = static_cast<float>(c[i]) / 255.0f * brightness;
    }
    return true;
  }
} // namespace faf::editor
