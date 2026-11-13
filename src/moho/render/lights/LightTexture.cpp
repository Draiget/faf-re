#include "moho/render/lights/LightTexture.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace moho::lights
{
  namespace
  {
    constexpr float kTintWhiteReduction =
      0.75f; // how much of the white of a texture average is taken out for the light colour
    constexpr std::uint32_t kDdsMagic = 0x20534444u; // "DDS "
    constexpr std::uint32_t kFourccDxt1 = 0x31545844u;
    constexpr std::uint32_t kFourccDxt3 = 0x33545844u;
    constexpr std::uint32_t kFourccDxt5 = 0x35545844u;
    constexpr std::uint32_t kPfFourcc = 0x4;
    constexpr std::uint32_t kPfRgb = 0x40;
    constexpr std::uint32_t kPfAlphaPixels = 0x1;
    constexpr std::uint32_t kCaps2Cubemap = 0x200;
    constexpr std::uint32_t kCaps2Volume = 0x200000;

    std::uint32_t Rd32(
      const std::uint8_t* p
    )
    {
      return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }

    std::uint16_t Rd16(
      const std::uint8_t* p
    )
    {
      return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    }

    void Rgb565(
      const std::uint16_t c,
      std::uint8_t (&rgb)[3]
    )
    {
      rgb[0] = static_cast<std::uint8_t>(((c >> 11) & 31) * 255 / 31);
      rgb[1] = static_cast<std::uint8_t>(((c >> 5) & 63) * 255 / 63);
      rgb[2] = static_cast<std::uint8_t>((c & 31) * 255 / 31);
    }

    // The 16 colour texels of a DXT colour block; `oneBitAlpha` (DXT1) makes the transparent colour index alpha 0.
    void DecodeColourBlock(
      const std::uint8_t* b,
      const bool oneBitAlpha,
      std::uint8_t (&px)[16][4]
    )
    {
      const std::uint16_t c0 = Rd16(b);
      const std::uint16_t c1 = Rd16(b + 2);
      std::uint8_t pal[4][4];
      Rgb565(c0, reinterpret_cast<std::uint8_t (&)[3]>(pal[0]));
      Rgb565(c1, reinterpret_cast<std::uint8_t (&)[3]>(pal[1]));
      pal[0][3] = pal[1][3] = pal[2][3] = pal[3][3] = 255;
      if (c0 > c1 || !oneBitAlpha) {
        for (int i = 0; i < 3; ++i) {
          pal[2][i] = static_cast<std::uint8_t>((2 * pal[0][i] + pal[1][i]) / 3);
          pal[3][i] = static_cast<std::uint8_t>((pal[0][i] + 2 * pal[1][i]) / 3);
        }
      } else {
        for (int i = 0; i < 3; ++i) {
          pal[2][i] = static_cast<std::uint8_t>((pal[0][i] + pal[1][i]) / 2);
          pal[3][i] = 0;
        }
        pal[3][3] = 0;
      }
      const std::uint32_t bits = Rd32(b + 4);
      for (int i = 0; i < 16; ++i) {
        const std::uint32_t idx = (bits >> (2 * i)) & 3;
        std::memcpy(px[i], pal[idx], 4);
      }
    }

    void DecodeDxt(
      const std::uint8_t* src,
      const std::uint32_t fourcc,
      const std::uint32_t w,
      const std::uint32_t h,
      Rgba8Image& out
    )
    {
      out.width = w;
      out.height = h;
      out.rgba.assign(static_cast<std::size_t>(w) * h * 4, 0);
      const std::uint32_t bw = (w + 3) / 4;
      const std::uint32_t bh = (h + 3) / 4;
      const std::size_t blockBytes = fourcc == kFourccDxt1 ? 8 : 16;
      for (std::uint32_t by = 0; by < bh; ++by) {
        for (std::uint32_t bx = 0; bx < bw; ++bx) {
          const std::uint8_t* blk = src + (static_cast<std::size_t>(by) * bw + bx) * blockBytes;
          std::uint8_t px[16][4];
          if (fourcc == kFourccDxt1) {
            DecodeColourBlock(blk, true, px);
          } else {
            DecodeColourBlock(blk + 8, false, px);
            if (fourcc == kFourccDxt3) {
              for (int i = 0; i < 16; ++i) {
                const std::uint8_t nibble = (blk[i / 2] >> (4 * (i & 1))) & 15;
                px[i][3] = static_cast<std::uint8_t>(nibble * 17);
              }
            } else {
              const std::uint8_t a0 = blk[0];
              const std::uint8_t a1 = blk[1];
              std::uint8_t al[8];
              al[0] = a0;
              al[1] = a1;
              if (a0 > a1) {
                for (int i = 1; i < 7; ++i) {
                  al[1 + i] = static_cast<std::uint8_t>(((7 - i) * a0 + i * a1) / 7);
                }
              } else {
                for (int i = 1; i < 5; ++i) {
                  al[1 + i] = static_cast<std::uint8_t>(((5 - i) * a0 + i * a1) / 5);
                }
                al[6] = 0;
                al[7] = 255;
              }
              std::uint64_t bits = 0;
              for (int i = 0; i < 6; ++i) {
                bits |= static_cast<std::uint64_t>(blk[2 + i]) << (8 * i);
              }
              for (int i = 0; i < 16; ++i) {
                px[i][3] = al[(bits >> (3 * i)) & 7];
              }
            }
          }
          for (std::uint32_t y = 0; y < 4; ++y) {
            for (std::uint32_t x = 0; x < 4; ++x) {
              const std::uint32_t X = bx * 4 + x;
              const std::uint32_t Y = by * 4 + y;
              if (X < w && Y < h) {
                std::memcpy(&out.rgba[(static_cast<std::size_t>(Y) * w + X) * 4], px[y * 4 + x], 4);
              }
            }
          }
        }
      }
    }

    // Shifts and widths of a bit mask (an uncompressed DDS pixel format channel).
    struct Channel
    {
      std::uint32_t mask = 0;
      int shift = 0;
      int bits = 0;
    };

    Channel MakeChannel(
      const std::uint32_t mask
    )
    {
      Channel c;
      c.mask = mask;
      if (mask == 0) {
        return c;
      }
      while (((mask >> c.shift) & 1u) == 0) {
        ++c.shift;
      }
      while (c.shift + c.bits < 32 && ((mask >> (c.shift + c.bits)) & 1u) != 0) {
        ++c.bits;
      }
      return c;
    }

    std::uint8_t Extract(
      const std::uint32_t pixel,
      const Channel& c,
      const std::uint8_t fallback
    )
    {
      if (c.mask == 0 || c.bits == 0) {
        return fallback;
      }
      const std::uint32_t v = (pixel & c.mask) >> c.shift;
      const std::uint32_t maxV = (c.bits >= 32) ? 0xFFFFFFFFu : ((1u << c.bits) - 1u);
      return static_cast<std::uint8_t>((static_cast<std::uint64_t>(v) * 255u) / maxV);
    }

    std::size_t DxtLevelBytes(
      const std::uint32_t fourcc,
      const std::uint32_t w,
      const std::uint32_t h
    )
    {
      return static_cast<std::size_t>((w + 3) / 4) * ((h + 3) / 4) * (fourcc == kFourccDxt1 ? 8 : 16);
    }
  } // namespace

  bool DecodeDds(
    const std::uint8_t* const data,
    const std::size_t size,
    const std::uint32_t maxDim,
    Rgba8Image& out
  )
  {
    out = Rgba8Image{};
    if (data == nullptr || size < 128 || Rd32(data) != kDdsMagic || Rd32(data + 4) != 124) {
      return false;
    }
    const std::uint32_t height = Rd32(data + 12);
    const std::uint32_t width = Rd32(data + 16);
    const std::uint32_t mips = std::max<std::uint32_t>(1, Rd32(data + 28));
    const std::uint32_t pfFlags = Rd32(data + 80);
    const std::uint32_t fourcc = Rd32(data + 84);
    const std::uint32_t bpp = Rd32(data + 88);
    const std::uint32_t caps2 = Rd32(data + 112);
    if (width == 0 || height == 0 || width > 16384 || height > 16384 || (caps2 & (kCaps2Cubemap | kCaps2Volume)) != 0) {
      return false;
    }

    const bool compressed =
      (pfFlags & kPfFourcc) != 0 && (fourcc == kFourccDxt1 || fourcc == kFourccDxt3 || fourcc == kFourccDxt5);
    const bool uncompressed = (pfFlags & kPfRgb) != 0 && (bpp == 16 || bpp == 24 || bpp == 32);
    if (!compressed && !uncompressed) {
      return false;
    }

    // walk the mip chain to the first level that fits
    std::size_t offset = 128;
    std::uint32_t w = width;
    std::uint32_t h = height;
    std::uint32_t level = 0;
    for (;; ++level) {
      const std::size_t bytes = compressed ? DxtLevelBytes(fourcc, w, h) : static_cast<std::size_t>(w) * h * (bpp / 8);
      const bool fits = std::max(w, h) <= maxDim || level + 1 >= mips;
      if (offset + bytes > size) {
        return false; // truncated
      }
      if (fits) {
        const std::uint8_t* src = data + offset;
        if (compressed) {
          DecodeDxt(src, fourcc, w, h, out);
          return true;
        }
        const Channel r = MakeChannel(Rd32(data + 92));
        const Channel g = MakeChannel(Rd32(data + 96));
        const Channel b = MakeChannel(Rd32(data + 100));
        const Channel a = MakeChannel((pfFlags & kPfAlphaPixels) != 0 ? Rd32(data + 104) : 0u);
        out.width = w;
        out.height = h;
        out.rgba.assign(static_cast<std::size_t>(w) * h * 4, 0);
        const std::uint32_t bytesPerPixel = bpp / 8;
        for (std::size_t i = 0; i < static_cast<std::size_t>(w) * h; ++i) {
          std::uint32_t px = 0;
          for (std::uint32_t k = 0; k < bytesPerPixel; ++k) {
            px |= static_cast<std::uint32_t>(src[i * bytesPerPixel + k]) << (8 * k);
          }
          out.rgba[i * 4 + 0] = Extract(px, r, 0);
          out.rgba[i * 4 + 1] = Extract(px, g, 0);
          out.rgba[i * 4 + 2] = Extract(px, b, 0);
          out.rgba[i * 4 + 3] = Extract(px, a, 255);
        }
        return true;
      }
      offset += bytes;
      w = std::max<std::uint32_t>(1, w / 2);
      h = std::max<std::uint32_t>(1, h / 2);
    }
  }

  TextureColour Summarise(
    const Rgba8Image& image
  )
  {
    TextureColour out;
    const std::size_t count = static_cast<std::size_t>(image.width) * image.height;
    if (count == 0 || image.rgba.size() < count * 4) {
      return out;
    }
    double sumLum = 0.0;
    double sumAlpha = 0.0;
    double sumWeighted[3] = {0.0, 0.0, 0.0};
    double sumWeight = 0.0;
    double sumPlain[3] = {0.0, 0.0, 0.0};
    double sumPlainWeight = 0.0;
    float peak = 0.0f;
    for (std::size_t i = 0; i < count; ++i) {
      const float r = image.rgba[i * 4 + 0] / 255.0f;
      const float g = image.rgba[i * 4 + 1] / 255.0f;
      const float b = image.rgba[i * 4 + 2] / 255.0f;
      const float a = image.rgba[i * 4 + 3] / 255.0f;
      const float lum = 0.2126f * r + 0.7152f * g + 0.0722f * b;
      const float glow = a * lum; // what an additive blend with the alpha as the factor puts on screen
      sumLum += glow;
      sumAlpha += a;
      peak = std::max(peak, glow);
      // the hue is carried by the bright texels: weight by the glow
      sumPlain[0] += a * r;
      sumPlain[1] += a * g;
      sumPlain[2] += a * b;
      sumPlainWeight += a;
      sumWeighted[0] += glow * r;
      sumWeighted[1] += glow * g;
      sumWeighted[2] += glow * b;
      sumWeight += glow;
    }
    out.brightness = static_cast<float>(sumLum / static_cast<double>(count));
    out.alpha = static_cast<float>(sumAlpha / static_cast<double>(count));
    out.peak = peak;
    if (sumWeight > 1.0e-6) {
      float m = 0.0f;
      for (int c = 0; c < 3; ++c) {
        out.hue[c] = static_cast<float>(sumWeighted[c] / sumWeight);
        m = std::max(m, out.hue[c]);
      }
      if (m > 1.0e-6f) {
        for (float& c : out.hue) {
          c /= m;
        }
      }
    } else {
      out.hue[0] = out.hue[1] = out.hue[2] = 1.0f;
    }
    if (sumPlainWeight > 1.0e-6) {
      for (int c = 0; c < 3; ++c) {
        out.average[c] = static_cast<float>(sumPlain[c] / sumPlainWeight);
      }
    } else {
      out.average[0] = out.average[1] = out.average[2] = 1.0f;
    }
    // The colour the texture glows in is where it is bright: the glow-weighted hue (brightest channel 1). The earlier
    // version took 75 % of the white out of the alpha-weighted average, which turns a slightly bluish white (0.90
    // 0.93 1.00) into a clear blue (0.69 0.78 1.00): every light of a bluish-white sprite got a blue cast and the
    // ramp's own colour (red, orange, purple) was muted by it.
    for (int c = 0; c < 3; ++c) {
      out.tint[c] = out.hue[c];
    }
    // the tint is a colour, not a brightness (how much of the quad glows is `brightness` / `peak`): its brightest
    // channel is 1
    const float tintTop = std::max(out.tint[0], std::max(out.tint[1], out.tint[2]));
    if (tintTop > 1.0e-6f) {
      for (float& c : out.tint) {
        c /= tintTop;
      }
    } else {
      out.tint[0] = out.tint[1] = out.tint[2] = 1.0f;
    }
    out.valid = true;
    return out;
  }

  void ReduceWhite(
    float (&rgb)[3],
    const float amount
  )
  {
    float lo = std::min(rgb[0], std::min(rgb[1], rgb[2]));
    float hi = std::max(rgb[0], std::max(rgb[1], rgb[2]));
    if (!(hi > 1.0e-6f)) {
      rgb[0] = rgb[1] = rgb[2] = 1.0f;
      return;
    }
    const float k = amount < 0.0f ? 0.0f : (amount > 1.0f ? 1.0f : amount);
    float reduced[3] = {rgb[0] - k * lo, rgb[1] - k * lo, rgb[2] - k * lo};
    const float top = std::max(reduced[0], std::max(reduced[1], reduced[2]));
    if (!(top > 1.0e-6f)) {
      return; // nothing left but white: it stays
    }
    const float scale = hi / top; // the brightest channel keeps its value
    for (int c = 0; c < 3; ++c) {
      rgb[c] = reduced[c] * scale;
    }
    (void)lo;
  }

  void SampleRamp(
    const Rgba8Image& ramp,
    const float u,
    const float v,
    float (&rgba)[4]
  )
  {
    rgba[0] = rgba[1] = rgba[2] = rgba[3] = 0.0f;
    if (
      ramp.width == 0 || ramp.height == 0 || ramp.rgba.size() < static_cast<std::size_t>(ramp.width) * ramp.height * 4
    ) {
      return;
    }
    const float uu = std::isfinite(u) ? std::min(1.0f, std::max(0.0f, u)) : 0.0f;
    const float vv = std::isfinite(v) ? std::min(1.0f, std::max(0.0f, v)) : 0.0f;
    const std::uint32_t row =
      std::min<std::uint32_t>(ramp.height - 1, static_cast<std::uint32_t>(vv * static_cast<float>(ramp.height)));
    const float x = uu * static_cast<float>(ramp.width - 1);
    const std::uint32_t x0 = static_cast<std::uint32_t>(x);
    const std::uint32_t x1 = std::min(ramp.width - 1, x0 + 1);
    const float f = x - static_cast<float>(x0);
    const std::uint8_t* p0 = &ramp.rgba[(static_cast<std::size_t>(row) * ramp.width + x0) * 4];
    const std::uint8_t* p1 = &ramp.rgba[(static_cast<std::size_t>(row) * ramp.width + x1) * 4];
    for (int c = 0; c < 4; ++c) {
      rgba[c] = (p0[c] + (p1[c] - p0[c]) * f) / 255.0f;
    }
  }
} // namespace moho::lights
