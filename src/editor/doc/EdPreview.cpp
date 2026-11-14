#include "editor/doc/EdPreview.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    void AppendWord(
      std::vector<char>& out,
      const std::uint32_t value
    )
    {
      char bytes[4];
      std::memcpy(bytes, &value, 4);
      out.insert(out.end(), bytes, bytes + 4);
    }

    void AppendFloat(
      std::vector<char>& out,
      const float value
    )
    {
      std::uint32_t word = 0;
      std::memcpy(&word, &value, 4);
      AppendWord(out, word);
    }

    struct Rgb
    {
      float r, g, b;
    };

    Rgb Mix(
      const Rgb& a,
      const Rgb& b,
      const float t
    )
    {
      return {a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t, a.b + (b.b - a.b) * t};
    }

    std::uint32_t Pack(
      const Rgb& c
    )
    {
      const auto byte = [](const float v) {
        return static_cast<std::uint32_t>(std::clamp(std::lround(v), 0L, 255L));
      };
      return 0xFF000000u | (byte(c.r) << 16) | (byte(c.g) << 8) | byte(c.b);
    }

    /** The land's colour at `t` (0 the lowest land, 1 the highest). */
    Rgb LandColour(
      const float t
    )
    {
      static constexpr Rgb kStops[] = {
        {94.0f, 127.0f, 58.0f},   // low ground
        {128.0f, 132.0f, 74.0f},  // plains
        {140.0f, 120.0f, 88.0f},  // hills
        {150.0f, 146.0f, 138.0f}, // rock
        {236.0f, 236.0f, 236.0f}, // peaks
      };
      constexpr int kLast = static_cast<int>(sizeof(kStops) / sizeof(kStops[0])) - 1;
      const float at = std::clamp(t, 0.0f, 1.0f) * kLast;
      const int i = std::min(static_cast<int>(at), kLast - 1);
      return Mix(kStops[i], kStops[i + 1], at - static_cast<float>(i));
    }
  } // namespace

  PreviewFrame PreviewFrameOf(
    const float mapWidth,
    const float mapDepth
  )
  {
    PreviewFrame f;
    const float longer = std::max({mapWidth, mapDepth, 1.0f});
    f.scale = longer / static_cast<float>(kPreviewSide);
    f.offsetX = (static_cast<float>(kPreviewSide) - mapWidth / f.scale) * 0.5f;
    f.offsetZ = (static_cast<float>(kPreviewSide) - mapDepth / f.scale) * 0.5f;
    return f;
  }

  std::vector<std::uint32_t> PreviewPixels(
    const HeightImage& heights,
    const float mapWidth,
    const float mapDepth,
    const PreviewOptions& options
  )
  {
    constexpr int kSide = kPreviewSide;
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide, 0xFF000000u);
    if (heights.width < 2 || heights.height < 2 || mapWidth <= 0.0f || mapDepth <= 0.0f) {
      return pixels;
    }
    // The height (game units) at a world point, between samples.
    const auto heightAt = [&](float x, float z) {
      const float sx = std::clamp(x / mapWidth, 0.0f, 1.0f) * static_cast<float>(heights.width - 1);
      const float sz = std::clamp(z / mapDepth, 0.0f, 1.0f) * static_cast<float>(heights.height - 1);
      const int x0 = std::min(static_cast<int>(sx), heights.width - 2);
      const int z0 = std::min(static_cast<int>(sz), heights.height - 2);
      const float tx = sx - static_cast<float>(x0);
      const float tz = sz - static_cast<float>(z0);
      const auto w = [&](int i, int j) {
        return static_cast<float>(heights.words[static_cast<std::size_t>(j) * heights.width + i]);
      };
      const float top = w(x0, z0) * (1.0f - tx) + w(x0 + 1, z0) * tx;
      const float bottom = w(x0, z0 + 1) * (1.0f - tx) + w(x0 + 1, z0 + 1) * tx;
      return (top * (1.0f - tz) + bottom * tz) / 128.0f;
    };
    // The land's range: from the sea (or the lowest ground) to the highest.
    std::uint16_t lowWord = 65535;
    std::uint16_t highWord = 0;
    for (const std::uint16_t word : heights.words) {
      lowWord = std::min(lowWord, word);
      highWord = std::max(highWord, word);
    }
    const float low = options.water ? std::max(options.waterLevel, lowWord / 128.0f) : lowWord / 128.0f;
    const float range = std::max(1.0f, highWord / 128.0f - low);
    const PreviewFrame f = PreviewFrameOf(mapWidth, mapDepth);
    // Lit from the north-west, above.
    const float lx = -0.5f;
    const float ly = 0.75f;
    const float lz = -0.5f;
    const float ll = std::sqrt(lx * lx + ly * ly + lz * lz);
    for (int py = 0; py < kSide; ++py) {
      for (int px = 0; px < kSide; ++px) {
        const float x = (static_cast<float>(px) + 0.5f - f.offsetX) * f.scale;
        const float z = (static_cast<float>(py) + 0.5f - f.offsetZ) * f.scale;
        if (x < 0.0f || z < 0.0f || x > mapWidth || z > mapDepth) {
          continue;
        }
        const float h = heightAt(x, z);
        Rgb colour{};
        if (options.water && h < options.waterLevel) {
          const float depth = std::clamp((options.waterLevel - h) / 25.0f, 0.0f, 1.0f);
          colour = Mix({70.0f, 130.0f, 160.0f}, {20.0f, 42.0f, 92.0f}, depth);
        } else {
          // A slope's light: the surface's normal from the heights a pixel apart.
          const float step = f.scale;
          const float dx = heightAt(x + step, z) - heightAt(x - step, z);
          const float dz = heightAt(x, z + step) - heightAt(x, z - step);
          const float nx = -dx;
          const float ny = 2.0f * step;
          const float nz = -dz;
          const float nl = std::sqrt(nx * nx + ny * ny + nz * nz);
          const float light = std::clamp((nx * lx + ny * ly + nz * lz) / (nl * ll), 0.0f, 1.0f);
          const float shade = 0.45f + 0.75f * light;
          const Rgb land = LandColour((h - low) / range);
          colour = {land.r * shade, land.g * shade, land.b * shade};
        }
        pixels[static_cast<std::size_t>(py) * kSide + px] = Pack(colour);
      }
    }
    for (const PreviewDot& dot : options.dots) {
      const float cx = dot.x / f.scale + f.offsetX;
      const float cz = dot.z / f.scale + f.offsetZ;
      const int r = static_cast<int>(std::ceil(dot.radius));
      for (int dz = -r; dz <= r; ++dz) {
        for (int dx = -r; dx <= r; ++dx) {
          const int x = static_cast<int>(cx) + dx;
          const int z = static_cast<int>(cz) + dz;
          if (
            static_cast<float>(dx * dx + dz * dz) <= dot.radius * dot.radius && x >= 0 && z >= 0 && x < kSide &&
            z < kSide
          ) {
            pixels[static_cast<std::size_t>(z) * kSide + x] = dot.colour;
          }
        }
      }
    }
    return pixels;
  }

  std::vector<char> PreviewRecord(
    const float mapWidth,
    const float mapDepth,
    const std::vector<std::uint32_t>& pixels
  )
  {
    constexpr std::uint32_t kSide = kPreviewSide;
    std::vector<char> out;
    AppendWord(out, 0xBEEFFEEDu);
    AppendWord(out, 2u);
    AppendFloat(out, mapWidth);
    AppendFloat(out, mapDepth);
    out.push_back(0); // the name: empty, in UTF-16
    out.push_back(0);
    AppendWord(out, 0u); // no tag/value pairs

    // The DDS: the classic 124-byte header (caps, height, width, pixel format), 32-bit BGRA, no mips.
    std::vector<char> dds;
    dds.insert(dds.end(), {'D', 'D', 'S', ' '});
    AppendWord(dds, 124u);
    AppendWord(dds, 0x1007u);
    AppendWord(dds, kSide);
    AppendWord(dds, kSide);
    for (int i = 0; i < 2 + 1 + 11; ++i) {
      AppendWord(dds, 0u); // pitch, depth, mip count, reserved
    }
    AppendWord(dds, 32u);
    AppendWord(dds, 0x41u); // RGB with alpha
    AppendWord(dds, 0u);
    AppendWord(dds, 32u);
    AppendWord(dds, 0x00FF0000u);
    AppendWord(dds, 0x0000FF00u);
    AppendWord(dds, 0x000000FFu);
    AppendWord(dds, 0xFF000000u);
    AppendWord(dds, 0x1000u); // a texture
    for (int i = 0; i < 4; ++i) {
      AppendWord(dds, 0u);
    }
    std::vector<std::uint32_t> body = pixels;
    body.resize(static_cast<std::size_t>(kSide) * kSide, 0xFF000000u);
    const auto* const bytes = reinterpret_cast<const char*>(body.data());
    dds.insert(dds.end(), bytes, bytes + body.size() * 4);

    AppendWord(out, static_cast<std::uint32_t>(dds.size()));
    out.insert(out.end(), dds.begin(), dds.end());
    return out;
  }
} // namespace faf::editor
