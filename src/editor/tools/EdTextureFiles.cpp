#include "editor/tools/EdTextureFiles.h"

#include <algorithm>
#include <cmath>
#include <string>

namespace faf::editor
{
  void NormalRelief(
    std::vector<std::uint32_t>& pixels
  )
  {
    if (pixels.empty()) {
      return;
    }
    // The packing: a flat red with a varied alpha is x in alpha.
    std::uint32_t redLow = 255, redHigh = 0, alphaLow = 255, alphaHigh = 0;
    for (const std::uint32_t p : pixels) {
      const std::uint32_t r = (p >> 16) & 0xFFu;
      const std::uint32_t a = p >> 24;
      redLow = std::min(redLow, r);
      redHigh = std::max(redHigh, r);
      alphaLow = std::min(alphaLow, a);
      alphaHigh = std::max(alphaHigh, a);
    }
    const bool xInAlpha = redHigh - redLow < 16 && alphaHigh - alphaLow >= 16;
    constexpr float lx = -0.5f;
    constexpr float ly = -0.5f; // towards the top of the picture (north)
    constexpr float lz = 0.7071f;
    for (std::uint32_t& p : pixels) {
      const float x = static_cast<float>(xInAlpha ? p >> 24 : (p >> 16) & 0xFFu) / 127.5f - 1.0f;
      // Green up the picture: a normal leaning north has a high green; the picture's y runs down.
      const float y = -(static_cast<float>((p >> 8) & 0xFFu) / 127.5f - 1.0f);
      const float z = std::sqrt(std::max(0.0f, 1.0f - x * x - y * y));
      const float light = std::clamp(x * lx + y * ly + z * lz, 0.0f, 1.0f);
      const auto grey = static_cast<std::uint32_t>(std::lround(40.0f + 215.0f * light));
      p = 0xFF000000u | (grey << 16) | (grey << 8) | grey;
    }
  }

  std::filesystem::path MaskSetFile(
    const std::filesystem::path& file,
    const int layer
  )
  {
    const std::filesystem::path base = MaskSetBase(file);
    return base.parent_path() / (base.stem().string() + "_" + std::to_string(layer + 1) + base.extension().string());
  }

  std::filesystem::path MaskSetBase(
    const std::filesystem::path& file
  )
  {
    const std::string stem = file.stem().string();
    if (stem.size() >= 2 && stem[stem.size() - 2] == '_' && stem.back() >= '1' && stem.back() <= '8') {
      return file.parent_path() / (stem.substr(0, stem.size() - 2) + file.extension().string());
    }
    return file;
  }
} // namespace faf::editor
