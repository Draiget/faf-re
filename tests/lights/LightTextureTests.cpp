// Host test of the CPU texture reader (src/moho/render/lights/LightTexture): synthetic DDS files in every supported
// layout, the mip choice, the colour summary the lights take their hue from, and the ramp sampling. Called from main()
// in LightCollectorTests.cpp.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "moho/render/lights/LightTexture.h"

namespace
{
  using namespace moho::lights;

  int gTexFailures = 0;
  int gTexChecks = 0;

#define TCHECK(cond)                                                                                                   \
  do {                                                                                                                 \
    ++gTexChecks;                                                                                                      \
    if (!(cond)) {                                                                                                     \
      ++gTexFailures;                                                                                                  \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  bool Near(
    const float a,
    const float b,
    const float eps = 0.02f
  )
  {
    return std::fabs(a - b) <= eps;
  }

  void Put32(
    std::vector<std::uint8_t>& v,
    const std::size_t at,
    const std::uint32_t value
  )
  {
    for (int i = 0; i < 4; ++i) {
      v[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value >> (8 * i));
    }
  }

  // A DDS header (128 bytes) for a surface of the given format.
  std::vector<std::uint8_t> Header(
    const std::uint32_t w,
    const std::uint32_t h,
    const std::uint32_t mips,
    const std::uint32_t fourcc,
    const std::uint32_t bpp = 0,
    const std::uint32_t rMask = 0,
    const std::uint32_t gMask = 0,
    const std::uint32_t bMask = 0,
    const std::uint32_t aMask = 0
  )
  {
    std::vector<std::uint8_t> v(128, 0);
    Put32(v, 0, 0x20534444u);
    Put32(v, 4, 124);
    Put32(v, 12, h);
    Put32(v, 16, w);
    Put32(v, 28, mips);
    Put32(v, 76, 32);
    if (fourcc != 0) {
      Put32(v, 80, 0x4);
      Put32(v, 84, fourcc);
    } else {
      Put32(v, 80, 0x40 | (aMask != 0 ? 0x1u : 0u));
      Put32(v, 88, bpp);
      Put32(v, 92, rMask);
      Put32(v, 96, gMask);
      Put32(v, 100, bMask);
      Put32(v, 104, aMask);
    }
    return v;
  }

  constexpr std::uint32_t kDxt1 = 0x31545844u;
  constexpr std::uint32_t kDxt3 = 0x33545844u;
  constexpr std::uint32_t kDxt5 = 0x35545844u;

  void AppendBlock(
    std::vector<std::uint8_t>& v,
    const std::uint16_t c0,
    const std::uint16_t c1,
    const std::uint32_t indices
  )
  {
    v.push_back(static_cast<std::uint8_t>(c0));
    v.push_back(static_cast<std::uint8_t>(c0 >> 8));
    v.push_back(static_cast<std::uint8_t>(c1));
    v.push_back(static_cast<std::uint8_t>(c1 >> 8));
    for (int i = 0; i < 4; ++i) {
      v.push_back(static_cast<std::uint8_t>(indices >> (8 * i)));
    }
  }

  void TestDxt1()
  {
    std::vector<std::uint8_t> dds = Header(4, 4, 1, kDxt1);
    AppendBlock(dds, 0xF800, 0x0000, 0); // every texel is colour 0: pure red
    Rgba8Image img;
    TCHECK(DecodeDds(dds.data(), dds.size(), 256, img));
    TCHECK(img.width == 4 && img.height == 4 && img.rgba.size() == 64);
    TCHECK(img.rgba[0] == 255 && img.rgba[1] == 0 && img.rgba[2] == 0 && img.rgba[3] == 255);

    const TextureColour c = Summarise(img);
    TCHECK(c.valid);
    TCHECK(Near(c.hue[0], 1.0f) && Near(c.hue[1], 0.0f) && Near(c.hue[2], 0.0f));
    TCHECK(Near(c.brightness, 0.2126f) && Near(c.peak, 0.2126f) && Near(c.alpha, 1.0f));

    // 1-bit alpha: c0 <= c1 puts a transparent colour at index 3
    std::vector<std::uint8_t> dds2 = Header(4, 4, 1, kDxt1);
    AppendBlock(dds2, 0x0000, 0xFFFF, 0xFFFFFFFFu); // all texels index 3 -> transparent black
    TCHECK(DecodeDds(dds2.data(), dds2.size(), 256, img));
    TCHECK(img.rgba[3] == 0);
    TCHECK(Near(Summarise(img).alpha, 0.0f));
  }

  void TestDxt3AndDxt5()
  {
    // DXT5: alpha 255 .. 0 palette with every index 0 -> alpha 255; colours: pure blue
    std::vector<std::uint8_t> dds = Header(4, 4, 1, kDxt5);
    dds.insert(dds.end(), {255, 0, 0, 0, 0, 0, 0, 0}); // alpha block: a0 = 255, a1 = 0, indices 0
    AppendBlock(dds, 0x001F, 0x0000, 0);
    Rgba8Image img;
    TCHECK(DecodeDds(dds.data(), dds.size(), 256, img));
    TCHECK(img.rgba[0] == 0 && img.rgba[1] == 0 && img.rgba[2] == 255 && img.rgba[3] == 255);
    const TextureColour c = Summarise(img);
    TCHECK(Near(c.hue[2], 1.0f) && Near(c.hue[0], 0.0f));
    TCHECK(Near(c.peak, 0.0722f));

    // DXT5 alpha code 1 is a1: a0 = 255, a1 = 0, every index 1 -> alpha 0
    std::vector<std::uint8_t> half = Header(4, 4, 1, kDxt5);
    half.insert(half.end(), {255, 0, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24});
    AppendBlock(half, 0xFFFF, 0xFFFF, 0);
    TCHECK(DecodeDds(half.data(), half.size(), 256, img));
    TCHECK(img.rgba[3] == 0);

    // DXT3: explicit 4-bit alpha, every texel 0xF -> 255
    std::vector<std::uint8_t> d3 = Header(4, 4, 1, kDxt3);
    d3.insert(d3.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    AppendBlock(d3, 0x07E0, 0x0000, 0); // green
    TCHECK(DecodeDds(d3.data(), d3.size(), 256, img));
    TCHECK(img.rgba[0] == 0 && img.rgba[1] == 255 && img.rgba[3] == 255);
  }

  void TestUncompressed()
  {
    // A8R8G8B8 2x2: (r,g,b,a) = (255,128,0,255), (0,0,0,0), ...
    std::vector<std::uint8_t> dds = Header(2, 2, 1, 0, 32, 0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0xFF000000u);
    const std::uint32_t px[4] = {0xFFFF8000u, 0x00000000u, 0xFF0000FFu, 0x80FFFFFFu};
    for (const std::uint32_t p : px) {
      for (int i = 0; i < 4; ++i) {
        dds.push_back(static_cast<std::uint8_t>(p >> (8 * i)));
      }
    }
    Rgba8Image img;
    TCHECK(DecodeDds(dds.data(), dds.size(), 256, img));
    TCHECK(img.width == 2 && img.height == 2);
    TCHECK(img.rgba[0] == 255 && img.rgba[1] == 128 && img.rgba[2] == 0 && img.rgba[3] == 255);
    TCHECK(img.rgba[4 + 3] == 0);
    TCHECK(img.rgba[8 + 0] == 0 && img.rgba[8 + 2] == 255);
    TCHECK(img.rgba[12 + 3] == 128);

    // X8R8G8B8 (no alpha mask): alpha reads as opaque
    std::vector<std::uint8_t> x = Header(1, 1, 1, 0, 32, 0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0);
    x.insert(x.end(), {0x10, 0x20, 0x30, 0x00}); // B G R X
    TCHECK(DecodeDds(x.data(), x.size(), 256, img));
    TCHECK(img.rgba[0] == 0x30 && img.rgba[1] == 0x20 && img.rgba[2] == 0x10 && img.rgba[3] == 255);

    // R5G6B5 16 bit
    std::vector<std::uint8_t> r5 = Header(1, 1, 1, 0, 16, 0xF800u, 0x07E0u, 0x001Fu, 0);
    r5.insert(r5.end(), {0x00, 0xF8}); // 0xF800 little endian = red
    TCHECK(DecodeDds(r5.data(), r5.size(), 256, img));
    TCHECK(img.rgba[0] == 255 && img.rgba[1] == 0 && img.rgba[2] == 0);
  }

  void TestMipChoice()
  {
    // an 8x8 DXT1 with a 4x4 and a 2x2 level (and a 1x1): maxDim 4 takes the 4x4, maxDim 1 the last
    std::vector<std::uint8_t> dds = Header(8, 8, 4, kDxt1);
    for (int i = 0; i < 4; ++i) {
      AppendBlock(dds, 0xF800, 0x0000, 0); // 8x8: four blocks, red
    }
    AppendBlock(dds, 0x07E0, 0x0000, 0); // 4x4: one block, green
    AppendBlock(dds, 0x001F, 0x0000, 0); // 2x2: one block, blue
    AppendBlock(dds, 0xFFFF, 0xFFFF, 0); // 1x1: one block, white
    Rgba8Image img;
    TCHECK(DecodeDds(dds.data(), dds.size(), 256, img) && img.width == 8 && img.rgba[0] == 255 && img.rgba[1] == 0);
    TCHECK(DecodeDds(dds.data(), dds.size(), 4, img) && img.width == 4 && img.rgba[1] == 255 && img.rgba[0] == 0);
    TCHECK(DecodeDds(dds.data(), dds.size(), 2, img) && img.width == 2 && img.rgba[2] == 255);
    TCHECK(DecodeDds(dds.data(), dds.size(), 1, img) && img.width == 1 && img.rgba[0] == 255 && img.rgba[1] == 255);
    TCHECK(DecodeDds(dds.data(), dds.size(), 0, img) && img.width == 1); // nothing fits: the smallest
  }

  void TestRefusals()
  {
    Rgba8Image img;
    TCHECK(!DecodeDds(nullptr, 0, 256, img) && img.rgba.empty());
    const std::uint8_t tiny[16] = {};
    TCHECK(!DecodeDds(tiny, sizeof(tiny), 256, img));

    std::vector<std::uint8_t> dds = Header(4, 4, 1, kDxt1);
    AppendBlock(dds, 0xF800, 0, 0);
    // truncated at every length
    for (std::size_t n = 0; n < dds.size(); ++n) {
      TCHECK(!DecodeDds(dds.data(), n, 256, img));
    }
    TCHECK(DecodeDds(dds.data(), dds.size(), 256, img));

    // bad magic, bad header size, absurd dimensions, cube map, volume, unknown format
    std::vector<std::uint8_t> bad = dds;
    Put32(bad, 0, 0x12345678u);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 4, 100);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 16, 0);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 16, 1000000);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 112, 0x200);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 112, 0x200000);
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 84, 0x30315844u); // DX10
    TCHECK(!DecodeDds(bad.data(), bad.size(), 256, img));
    bad = dds;
    Put32(bad, 28, 9); // claims more mips than the data holds: the first fitting level is still found
    TCHECK(DecodeDds(bad.data(), bad.size(), 256, img));
  }

  void TestSummary()
  {
    // an empty or short image is not valid
    TCHECK(!Summarise(Rgba8Image{}).valid);
    Rgba8Image shortImg;
    shortImg.width = 4;
    shortImg.height = 4;
    shortImg.rgba.assign(8, 255);
    TCHECK(!Summarise(shortImg).valid);

    // black: valid, no glow, hue falls back to white
    Rgba8Image black;
    black.width = 2;
    black.height = 2;
    black.rgba.assign(16, 0);
    for (std::size_t i = 3; i < 16; i += 4) {
      black.rgba[i] = 255;
    }
    const TextureColour b = Summarise(black);
    TCHECK(b.valid && b.peak == 0.0f && b.brightness == 0.0f && Near(b.hue[0], 1.0f) && Near(b.hue[1], 1.0f));

    // a bright orange dot on a dim blue background: the hue is the dot
    Rgba8Image img;
    img.width = 4;
    img.height = 4;
    img.rgba.assign(64, 0);
    for (std::size_t i = 0; i < 16; ++i) {
      img.rgba[i * 4 + 2] = 40; // dim blue
      img.rgba[i * 4 + 3] = 255;
    }
    img.rgba[5 * 4 + 0] = 255;
    img.rgba[5 * 4 + 1] = 140;
    img.rgba[5 * 4 + 2] = 0;
    const TextureColour c = Summarise(img);
    TCHECK(c.hue[0] > 0.95f && c.hue[1] > 0.4f && c.hue[2] < 0.3f);
    TCHECK(c.peak > 0.5f && c.brightness < c.peak);

    // transparent texels do not count: the same dot with alpha 0 elsewhere
    for (std::size_t i = 0; i < 16; ++i) {
      if (i != 5) {
        img.rgba[i * 4 + 3] = 0;
      }
    }
    const TextureColour d = Summarise(img);
    TCHECK(Near(d.alpha, 1.0f / 16.0f, 0.01f) && d.hue[0] > 0.99f);
  }

  void TestReduceWhite()
  {
    // white stays white, a pure colour stays, a pale colour gets its colour back with the brightest channel kept
    float white[3] = {0.8f, 0.8f, 0.8f};
    ReduceWhite(white, 0.75f);
    TCHECK(Near(white[0], 0.8f) && Near(white[1], 0.8f) && Near(white[2], 0.8f));
    float red[3] = {1.0f, 0.0f, 0.0f};
    ReduceWhite(red, 1.0f);
    TCHECK(Near(red[0], 1.0f) && Near(red[1], 0.0f) && Near(red[2], 0.0f));
    float pale[3] = {1.0f, 0.8f, 0.6f};
    ReduceWhite(pale, 1.0f);
    TCHECK(Near(pale[0], 1.0f) && Near(pale[1], 0.5f) && Near(pale[2], 0.0f)); // (0.4, 0.2, 0) scaled to max 1
    float half[3] = {1.0f, 0.8f, 0.6f};
    ReduceWhite(half, 0.5f);
    TCHECK(
      Near(half[0], 1.0f) && half[1] > 0.6f && half[1] < 0.8f && half[2] < 0.6f
    ); // between the pale colour and the pure one
    float none[3] = {0.0f, 0.0f, 0.0f};
    ReduceWhite(none, 0.75f);
    TCHECK(Near(none[0], 1.0f) && Near(none[1], 1.0f) && Near(none[2], 1.0f)); // nothing: white, not NaN
    float zero[3] = {1.0f, 0.5f, 0.25f};
    ReduceWhite(zero, 0.0f);
    TCHECK(Near(zero[1], 0.5f) && Near(zero[2], 0.25f));

    // the average colour of a texture with a white core and an orange halo: the tint is orange, the hue (brightness
    // weighted) is paler
    Rgba8Image img;
    img.width = 2;
    img.height = 2;
    img.rgba = {255, 255, 255, 255, 255, 140, 40, 255, 255, 140, 40, 255, 255, 140, 40, 255};
    const TextureColour c = Summarise(img);
    TCHECK(c.valid);
    TCHECK(c.tint[0] > c.tint[1] && c.tint[1] > c.tint[2]);
    // the tint is the glow-weighted hue: no white taken out (taking 75 % out turned a slightly bluish white into a
    // clear blue)
    TCHECK(Near(c.tint[0], c.hue[0]) && Near(c.tint[1], c.hue[1]) && Near(c.tint[2], c.hue[2]));
    TCHECK(Near(c.average[0], 1.0f));
    TCHECK(Near(c.tint[0], 1.0f)); // normalised: brightest channel 1
    // a dark texture (a spark: black with one bright texel) has the same tint as a bright one
    Rgba8Image dark;
    dark.width = 2;
    dark.height = 2;
    dark.rgba = {10, 5, 1, 255, 10, 5, 1, 255, 10, 5, 1, 255, 10, 5, 1, 255};
    const TextureColour dc = Summarise(dark);
    TCHECK(Near(dc.tint[0], 1.0f) && dc.tint[1] < 1.0f && dc.tint[2] < dc.tint[1]);

    // a bluish white stays nearly white (it used to become a clear blue)
    Rgba8Image bluish;
    bluish.width = 2;
    bluish.height = 2;
    bluish.rgba = {230, 237, 255, 255, 230, 237, 255, 255, 230, 237, 255, 255, 230, 237, 255, 255};
    const TextureColour bc = Summarise(bluish);
    TCHECK(bc.tint[0] > 0.85f && bc.tint[1] > 0.9f && Near(bc.tint[2], 1.0f));
  }

  void TestRamp()
  {
    // a ramp 4 wide, 2 rows: row 0 goes black -> white, row 1 is constant red; alpha 255 -> 0 on row 0
    Rgba8Image ramp;
    ramp.width = 4;
    ramp.height = 2;
    ramp.rgba.assign(32, 0);
    for (int x = 0; x < 4; ++x) {
      const std::uint8_t v = static_cast<std::uint8_t>(x * 85);
      ramp.rgba[static_cast<std::size_t>(x) * 4 + 0] = v;
      ramp.rgba[static_cast<std::size_t>(x) * 4 + 1] = v;
      ramp.rgba[static_cast<std::size_t>(x) * 4 + 2] = v;
      ramp.rgba[static_cast<std::size_t>(x) * 4 + 3] = static_cast<std::uint8_t>(255 - x * 85);
      ramp.rgba[(4 + static_cast<std::size_t>(x)) * 4 + 0] = 255;
      ramp.rgba[(4 + static_cast<std::size_t>(x)) * 4 + 3] = 255;
    }
    float c[4];
    SampleRamp(ramp, 0.0f, 0.0f, c);
    TCHECK(Near(c[0], 0.0f) && Near(c[3], 1.0f));
    SampleRamp(ramp, 1.0f, 0.0f, c);
    TCHECK(Near(c[0], 1.0f) && Near(c[3], 0.0f));
    SampleRamp(ramp, 0.5f, 0.0f, c); // between columns 1 and 2
    TCHECK(Near(c[0], 0.5f, 0.02f) && Near(c[3], 0.5f, 0.02f));
    SampleRamp(ramp, 0.5f, 0.9f, c); // row 1: constant red
    TCHECK(Near(c[0], 1.0f) && Near(c[1], 0.0f) && Near(c[3], 1.0f));
    SampleRamp(ramp, -3.0f, 5.0f, c); // clamped
    TCHECK(Near(c[0], 1.0f) && Near(c[3], 1.0f));
    SampleRamp(ramp, std::nanf(""), std::nanf(""), c);
    TCHECK(Near(c[0], 0.0f) && Near(c[3], 1.0f)); // NaN reads as 0
    SampleRamp(Rgba8Image{}, 0.5f, 0.5f, c);
    TCHECK(c[0] == 0.0f && c[3] == 0.0f);
  }
} // namespace

int RunTextureTests(
  int& checks
)
{
  TestDxt1();
  TestDxt3AndDxt5();
  TestUncompressed();
  TestMipChoice();
  TestRefusals();
  TestSummary();
  TestReduceWhite();
  TestRamp();
  checks += gTexChecks;
  return gTexFailures;
}
