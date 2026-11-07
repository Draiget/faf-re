// Engine addition: ImageCodec::WriteDds and the reload DeviceVulkan::UpdateSurface and
// DeviceD3D12::UpdateSurface do with its output, against whichever d3dx11_43.dll this process
// loads: Microsoft's on Windows, Wine's under Wine. Wine needs version 11.0 or newer, the first
// whose D3DX11CreateTextureFromMemory isn't a stub.

#include <algorithm>
#include <gtest/gtest.h>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

using gpg::gal::imaging::DecodeOptions;
using gpg::gal::imaging::FileFormat;
using gpg::gal::imaging::Image;
using gpg::gal::imaging::ImageCodec;

namespace
{
  void Check(const bool condition, const char* const what, const char* const detail = "")
  {
    EXPECT_TRUE(condition) << what << (detail[0] != '\0' ? " - " : "") << detail;
    std::printf("%s: %s%s%s\n", condition ? "PASS" : "FAIL", what, detail[0] != '\0' ? " - " : "", detail);
  }

  struct NamedFormat
  {
    DXGI_FORMAT format;
    const char* name;
  };

  // The formats dxgi::TextureFormatToDxgi creates, and the one D3DX11 decodes 32-bit files to.
  constexpr NamedFormat kFormats[] = {
    {DXGI_FORMAT_B8G8R8A8_UNORM, "B8G8R8A8"},
    {DXGI_FORMAT_R8G8B8A8_UNORM, "R8G8B8A8"},
    {DXGI_FORMAT_B8G8R8X8_UNORM, "B8G8R8X8"},
    {DXGI_FORMAT_B5G6R5_UNORM, "B5G6R5"},
    {DXGI_FORMAT_A8_UNORM, "A8"},
    {DXGI_FORMAT_R8_UNORM, "R8"},
    {DXGI_FORMAT_R8G8_UNORM, "R8G8"},
    {DXGI_FORMAT_BC1_UNORM, "BC1"},
    {DXGI_FORMAT_BC2_UNORM, "BC2"},
    {DXGI_FORMAT_BC3_UNORM, "BC3"},
    {DXGI_FORMAT_R16_FLOAT, "R16F"},
    {DXGI_FORMAT_R16G16_FLOAT, "R16G16F"},
    {DXGI_FORMAT_R16G16B16A16_FLOAT, "R16G16B16A16F"},
    {DXGI_FORMAT_R32_FLOAT, "R32F"},
    {DXGI_FORMAT_R32G32_FLOAT, "R32G32F"},
    {DXGI_FORMAT_R32G32B32A32_FLOAT, "R32G32B32A32F"},
  };

  /** Fills the image with varied bytes that survive a format round trip: no NaN, X8 opaque. */
  void FillPattern(Image& image)
  {
    std::uint32_t state = 0x12345678U;
    const auto next = [&state] {
      state ^= state << 13U;
      state ^= state >> 17U;
      state ^= state << 5U;
      return state;
    };
    const auto put = [&image](const std::size_t at, const auto value) { std::memcpy(image.bytes.data() + at, &value, sizeof(value)); };
    switch (image.format) {
    case DXGI_FORMAT_R16_FLOAT:
    case DXGI_FORMAT_R16G16_FLOAT:
    case DXGI_FORMAT_R16G16B16A16_FLOAT:
      for (std::size_t at = 0U; at + 2U <= image.bytes.size(); at += 2U) {
        put(at, static_cast<std::uint16_t>(0x3C00U | (next() & 0x3FFU))); // 1.0 to 2.0
      }
      break;
    case DXGI_FORMAT_R32_FLOAT:
    case DXGI_FORMAT_R32G32_FLOAT:
    case DXGI_FORMAT_R32G32B32A32_FLOAT:
      for (std::size_t at = 0U; at + 4U <= image.bytes.size(); at += 4U) {
        put(at, static_cast<float>(next() & 0xFFFFU) / 65536.0f);
      }
      break;
    case DXGI_FORMAT_B8G8R8X8_UNORM:
      for (std::size_t at = 0U; at + 4U <= image.bytes.size(); at += 4U) {
        put(at, next() | 0xFF000000U);
      }
      break;
    default:
      for (std::uint8_t& byte : image.bytes) {
        byte = static_cast<std::uint8_t>(next());
      }
      break;
    }
  }

  [[nodiscard]] Image MakeImage(const DXGI_FORMAT format, const std::uint32_t width, const std::uint32_t height, const std::uint32_t mips, const bool cube = false)
  {
    Image image;
    image.Allocate(format, width, height, mips, cube ? 6U : 1U);
    image.cube = cube;
    FillPattern(image);
    return image;
  }

  /** The reload UpdateSurface does: the destination's format, size and level count. */
  [[nodiscard]] HRESULT Reload(ImageCodec& codec, const std::vector<std::uint8_t>& file, const DXGI_FORMAT format, const std::uint32_t width, const std::uint32_t height, const std::uint32_t mips, Image& out)
  {
    DecodeOptions options;
    options.format = format;
    options.width = width;
    options.height = height;
    options.mipLevels = mips;
    return codec.Decode(file.data(), file.size(), options, out);
  }

  /** Levels under 4x4 of a block format are left out: D3DX11's round trip changes their bytes. */
  [[nodiscard]] bool SameLevels(const Image& a, const Image& b)
  {
    if (a.format != b.format || a.width != b.width || a.height != b.height || a.mipLevels != b.mipLevels || a.subresources.size() != b.subresources.size()) {
      std::printf(
        "  shape: format %d, then %d; %ux%u, then %ux%u; %u levels, then %u\n", static_cast<int>(a.format), static_cast<int>(b.format), a.width, a.height, b.width, b.height, a.mipLevels, b.mipLevels
      );
      return false;
    }
    const bool blocks = gpg::gal::dxgi::IsBlockCompressed(a.format);
    // X8's fourth byte means nothing: Vulkan samples it as one, and D3DX11 zeroes it from some files.
    const std::uint32_t unusedByteStride = a.format == DXGI_FORMAT_B8G8R8X8_UNORM ? 4U : 0U;
    for (std::size_t index = 0U; index < a.subresources.size(); ++index) {
      const Image::Subresource& level = a.subresources[index];
      if (blocks && (level.width < 4U || level.height < 4U)) {
        continue;
      }
      for (std::uint32_t at = 0U; at < level.slicePitch; ++at) {
        if (unusedByteStride != 0U && at % unusedByteStride == unusedByteStride - 1U) {
          continue;
        }
        if (a.bytes[level.offset + at] != b.bytes[b.subresources[index].offset + at]) {
          std::printf("  subresource %zu byte %u: %02X, then %02X\n", index, at, a.bytes[level.offset + at], b.bytes[b.subresources[index].offset + at]);
          return false;
        }
      }
    }
    return true;
  }

  /** True when this D3DX11 can't load the format even from a file it wrote itself. */
  [[nodiscard]] bool D3dxRefusesFormat(ImageCodec& codec, const Image& source)
  {
    std::vector<std::uint8_t> encoded;
    std::vector<std::uint8_t> own;
    Image reloaded;
    return SUCCEEDED(codec.Encode(source, FileFormat::Dds, encoded)) && SUCCEEDED(ImageCodec::WriteDds(source, own)) && encoded != own &&
      FAILED(Reload(codec, encoded, source.format, source.width, source.height, source.mipLevels, reloaded));
  }

  void TestEveryFormatRoundTrips(ImageCodec& codec)
  {
    for (const NamedFormat& entry : kFormats) {
      const Image source = MakeImage(entry.format, 16U, 16U, 5U);
      std::vector<std::uint8_t> file;
      const HRESULT written = ImageCodec::WriteDds(source, file);
      Image reloaded;
      const HRESULT read = SUCCEEDED(written) ? Reload(codec, file, entry.format, 16U, 16U, 5U, reloaded) : written;
      if (SUCCEEDED(written) && FAILED(read) && D3dxRefusesFormat(codec, source)) {
        std::printf("SKIP: %s - this D3DX11 can't load it from its own file either\n", entry.name);
        continue;
      }
      char detail[96]{};
      std::snprintf(detail, sizeof(detail), "write 0x%08lX, read 0x%08lX", static_cast<unsigned long>(written), static_cast<unsigned long>(read));
      Check(SUCCEEDED(read) && SameLevels(source, reloaded), entry.name, detail);
    }
  }

  // The stratum masks: a file D3DX11 loaded as R8G8B8A8 going into a B8G8R8A8 engine texture.
  void TestSwizzleKeepsChannels(ImageCodec& codec)
  {
    const Image source = MakeImage(DXGI_FORMAT_R8G8B8A8_UNORM, 32U, 16U, 1U);
    std::vector<std::uint8_t> file;
    Image reloaded;
    const HRESULT result = SUCCEEDED(ImageCodec::WriteDds(source, file)) ? Reload(codec, file, DXGI_FORMAT_B8G8R8A8_UNORM, 32U, 16U, 1U, reloaded) : E_FAIL;
    bool same = SUCCEEDED(result) && reloaded.format == DXGI_FORMAT_B8G8R8A8_UNORM && reloaded.bytes.size() == source.bytes.size();
    for (std::size_t at = 0U; same && at + 4U <= source.bytes.size(); at += 4U) {
      same = reloaded.bytes[at] == source.bytes[at + 2U] && reloaded.bytes[at + 1U] == source.bytes[at + 1U] &&
        reloaded.bytes[at + 2U] == source.bytes[at] && reloaded.bytes[at + 3U] == source.bytes[at + 3U];
    }
    Check(same, "R8G8B8A8 reloaded as B8G8R8A8 keeps its channels");
  }

  // A format D3DX11 may refuse to load as itself still has to be a readable file: one solid colour
  // comes back as that colour in 8 bits per channel.
  void TestB5G6R5FileIsReadable(ImageCodec& codec)
  {
    Image source;
    source.Allocate(DXGI_FORMAT_B5G6R5_UNORM, 8U, 8U, 1U, 1U);
    constexpr std::uint16_t kPixel = (21U << 11U) | (42U << 5U) | 10U; // about two thirds red and green, one third blue
    for (std::size_t at = 0U; at + 2U <= source.bytes.size(); at += 2U) {
      std::memcpy(source.bytes.data() + at, &kPixel, sizeof(kPixel));
    }
    std::vector<std::uint8_t> file;
    Image reloaded;
    const HRESULT result = SUCCEEDED(ImageCodec::WriteDds(source, file)) ? Reload(codec, file, DXGI_FORMAT_B8G8R8A8_UNORM, 8U, 8U, 1U, reloaded) : E_FAIL;
    bool same = SUCCEEDED(result) && reloaded.format == DXGI_FORMAT_B8G8R8A8_UNORM;
    for (std::size_t at = 0U; same && at + 4U <= reloaded.bytes.size(); at += 4U) {
      same = std::abs(reloaded.bytes[at] - 82) <= 2 && std::abs(reloaded.bytes[at + 1U] - 170) <= 2 && std::abs(reloaded.bytes[at + 2U] - 173) <= 2 && reloaded.bytes[at + 3U] == 255U;
    }
    char detail[64]{};
    std::snprintf(detail, sizeof(detail), "read 0x%08lX", static_cast<unsigned long>(result));
    Check(same, "a B5G6R5 file reads back as its colour in B8G8R8A8", detail);
  }

  // A mask of another size: one solid colour stays that colour through the resize.
  void TestResizeKeepsColour(ImageCodec& codec)
  {
    Image source;
    source.Allocate(DXGI_FORMAT_R8G8B8A8_UNORM, 64U, 64U, 1U, 1U);
    constexpr std::uint8_t kColour[4] = {10U, 200U, 90U, 255U};
    for (std::size_t at = 0U; at + 4U <= source.bytes.size(); at += 4U) {
      std::memcpy(source.bytes.data() + at, kColour, sizeof(kColour));
    }
    std::vector<std::uint8_t> file;
    Image reloaded;
    const HRESULT result = SUCCEEDED(ImageCodec::WriteDds(source, file)) ? Reload(codec, file, DXGI_FORMAT_B8G8R8A8_UNORM, 32U, 32U, 1U, reloaded) : E_FAIL;
    bool same = SUCCEEDED(result) && reloaded.width == 32U && reloaded.height == 32U && reloaded.format == DXGI_FORMAT_B8G8R8A8_UNORM;
    for (std::size_t at = 0U; same && at + 4U <= reloaded.bytes.size(); at += 4U) {
      same = std::abs(reloaded.bytes[at] - kColour[2]) <= 1 && std::abs(reloaded.bytes[at + 1U] - kColour[1]) <= 1 &&
        std::abs(reloaded.bytes[at + 2U] - kColour[0]) <= 1 && std::abs(reloaded.bytes[at + 3U] - kColour[3]) <= 1;
    }
    Check(same, "a resized solid colour stays that colour");
  }

  // The water map: the engine's texture is BC3 (gal format 12), the file's may not be.
  void TestReloadInBlockFormat(ImageCodec& codec)
  {
    const Image source = MakeImage(DXGI_FORMAT_R8G8B8A8_UNORM, 64U, 64U, 1U);
    std::vector<std::uint8_t> file;
    Image reloaded;
    const HRESULT result = SUCCEEDED(ImageCodec::WriteDds(source, file)) ? Reload(codec, file, DXGI_FORMAT_BC3_UNORM, 32U, 32U, 1U, reloaded) : E_FAIL;
    char detail[64]{};
    std::snprintf(detail, sizeof(detail), "read 0x%08lX", static_cast<unsigned long>(result));
    Check(SUCCEEDED(result) && reloaded.format == DXGI_FORMAT_BC3_UNORM && reloaded.width == 32U && reloaded.height == 32U, "R8G8B8A8 reloaded as smaller BC3", detail);
  }

  void TestCube(ImageCodec& codec)
  {
    const Image source = MakeImage(DXGI_FORMAT_BC3_UNORM, 16U, 16U, 5U, true);
    std::vector<std::uint8_t> file;
    Image reloaded;
    const HRESULT result = SUCCEEDED(ImageCodec::WriteDds(source, file)) ? Reload(codec, file, DXGI_FORMAT_BC3_UNORM, 16U, 16U, 5U, reloaded) : E_FAIL;
    char detail[64]{};
    std::snprintf(detail, sizeof(detail), "read 0x%08lX", static_cast<unsigned long>(result));
    Check(SUCCEEDED(result) && reloaded.cube && reloaded.arraySize == 6U && SameLevels(source, reloaded), "a BC3 cube keeps its six faces", detail);
  }

  // The original applies texture-quality skip only to 2D. Run both decode
  // routes; RGB cubes always use D3DX, while full-chain BC cubes can load direct.
  void TestQualityKeepsCubeTopMip(ImageCodec& codec)
  {
    const bool oldDirect = gpg::gal::imaging::gDdsDirectLoad;
    for (const bool direct : {false, true}) {
      gpg::gal::imaging::gDdsDirectLoad = direct;
      for (const DXGI_FORMAT format : {DXGI_FORMAT_BC3_UNORM, DXGI_FORMAT_B8G8R8A8_UNORM}) {
        for (const bool cube : {false, true}) {
          const Image source = MakeImage(format, 64U, 64U, 7U, cube);
          std::vector<std::uint8_t> file;
          const HRESULT written = ImageCodec::WriteDds(source, file);
          Image baseline;
          const HRESULT baselineRead = SUCCEEDED(written) ?
            codec.Decode(file.data(), file.size(), DecodeOptions{}, baseline) : written;
          const bool baselineShape = SUCCEEDED(baselineRead) && baseline.width == 64U && baseline.height == 64U &&
            baseline.mipLevels == 7U && baseline.arraySize == (cube ? 6U : 1U) && baseline.cube == cube;
          Check(baselineShape, "zero-skip baseline has the source dimensions");
          if (!baselineShape) {
            continue;
          }
          for (const std::uint32_t skip : {0U, 1U, 2U}) {
            DecodeOptions options;
            options.skipMipLevels = skip;
            Image reloaded;
            const HRESULT read =
              SUCCEEDED(written) ? codec.Decode(file.data(), file.size(), options, reloaded) : written;
            const std::uint32_t firstMip = cube ? 0U : skip;
            Image expected;
            expected.Allocate(baseline.format, 64U >> firstMip, 64U >> firstMip, 7U - firstMip, cube ? 6U : 1U);
            expected.cube = cube;
            for (std::uint32_t face = 0U; face < expected.arraySize; ++face) {
              for (std::uint32_t mip = 0U; mip < expected.mipLevels; ++mip) {
                const Image::Subresource& from = baseline.subresources[face * baseline.mipLevels + firstMip + mip];
                const Image::Subresource& to = expected.subresources[face * expected.mipLevels + mip];
                std::memcpy(expected.bytes.data() + to.offset, baseline.bytes.data() + from.offset, to.slicePitch);
              }
            }
            char detail[96]{};
            std::snprintf(
              detail,
              sizeof(detail),
              "format %d, cube %u, direct %u, skip %u",
              static_cast<int>(format),
              cube ? 1U : 0U,
              direct ? 1U : 0U,
              skip
            );
            Check(
              SUCCEEDED(read) && reloaded.cube == cube && SameLevels(expected, reloaded),
              "texture quality skips only 2D mips",
              detail
            );
          }
        }
      }
    }
    gpg::gal::imaging::gDdsDirectLoad = oldDirect;
  }

  // A synthetic uncompressed DDS volume: WriteDds deliberately does not encode volumes.
  void TestQualityKeepsVolumeTopMip(ImageCodec& codec)
  {
    std::vector<std::uint8_t> file(128U, 0U);
    const auto word = [&file](const std::size_t offset, const std::uint32_t value) {
      std::memcpy(file.data() + offset, &value, sizeof(value));
    };
    word(0U, 0x20534444U);
    word(4U, 124U);
    word(8U, 0x82100FU); // CAPS, HEIGHT, WIDTH, PITCH, PIXELFORMAT, MIPMAPCOUNT, DEPTH
    word(12U, 8U);
    word(16U, 8U);
    word(20U, 32U);
    word(24U, 8U);
    word(28U, 4U);
    word(76U, 32U);
    word(80U, 0x41U);
    word(88U, 32U);
    word(92U, 0x00FF0000U);
    word(96U, 0x0000FF00U);
    word(100U, 0x000000FFU);
    word(104U, 0xFF000000U);
    word(108U, 0x401008U); // COMPLEX, TEXTURE, MIPMAP
    word(112U, 0x200000U); // VOLUME
    for (std::uint32_t mip = 0U; mip < 4U; ++mip) {
      const std::uint32_t side = 8U >> mip;
      file.insert(file.end(), side * side * side * 4U, static_cast<std::uint8_t>(32U + mip));
    }
    for (const std::uint32_t skip : {0U, 1U, 2U}) {
      DecodeOptions options;
      options.skipMipLevels = skip;
      Image reloaded;
      const HRESULT read = codec.Decode(file.data(), file.size(), options, reloaded);
      bool same = SUCCEEDED(read) && reloaded.volume && !reloaded.cube && reloaded.width == 8U &&
        reloaded.height == 8U && reloaded.depth == 8U && reloaded.mipLevels == 4U && reloaded.subresources.size() == 4U;
      std::size_t expectedOffset = 0U;
      for (std::uint32_t mip = 0U; same && mip < 4U; ++mip) {
        const std::uint32_t side = 8U >> mip;
        const Image::Subresource& level = reloaded.subresources[mip];
        const std::size_t levelBytes = static_cast<std::size_t>(side) * side * side * 4U;
        same = level.width == side && level.height == side && level.depth == side &&
          level.rowPitch == side * 4U && level.rowCount == side && level.slicePitch == side * side * 4U &&
          level.offset == expectedOffset && expectedOffset + levelBytes <= reloaded.bytes.size();
        for (std::size_t at = expectedOffset; same && at < expectedOffset + levelBytes; ++at) {
          same = reloaded.bytes[at] == static_cast<std::uint8_t>(32U + mip);
        }
        expectedOffset += levelBytes;
      }
      same = same && expectedOffset == reloaded.bytes.size();
      Check(same, "texture quality leaves volume dimensions and mip bytes unchanged");
    }
  }

  // The original's D3DX9 load, measured on d3dx9_35: a 2D DDS with more than one level drops
  // min(skip, levels - 1) top levels and keeps the rest byte for byte; a one-level DDS and a PNG
  // load whole. The levels D3DX builds past a short chain are kept the same way.
  void TestQualitySkipFollowsD3dx9(ImageCodec& codec)
  {
    const bool oldDirect = gpg::gal::imaging::gDdsDirectLoad;
    for (const bool direct : {false, true}) {
      gpg::gal::imaging::gDdsDirectLoad = direct;
      for (const DXGI_FORMAT format : {DXGI_FORMAT_BC3_UNORM, DXGI_FORMAT_B8G8R8A8_UNORM}) {
        for (const std::uint32_t levels : {1U, 2U, 3U, 7U}) {
          std::vector<std::uint8_t> file;
          const HRESULT written = ImageCodec::WriteDds(MakeImage(format, 64U, 64U, levels), file);
          Image baseline;
          const HRESULT baselineRead = SUCCEEDED(written) ? codec.Decode(file.data(), file.size(), DecodeOptions{}, baseline) : written;
          if (!SUCCEEDED(baselineRead)) {
            Check(false, "quality baseline loads");
            continue;
          }
          for (const std::uint32_t skip : {1U, 2U}) {
            const std::uint32_t dropped = levels > 1U ? std::min(skip, levels - 1U) : 0U;
            Image expected;
            expected.Allocate(baseline.format, 64U >> dropped, 64U >> dropped, baseline.mipLevels - dropped, 1U);
            for (std::uint32_t mip = 0U; mip < expected.mipLevels; ++mip) {
              const Image::Subresource& from = baseline.subresources[mip + dropped];
              std::memcpy(expected.bytes.data() + expected.subresources[mip].offset, baseline.bytes.data() + from.offset, from.slicePitch);
            }
            DecodeOptions options;
            options.skipMipLevels = skip;
            Image reloaded;
            const HRESULT read = codec.Decode(file.data(), file.size(), options, reloaded);
            char detail[96]{};
            std::snprintf(detail, sizeof(detail), "format %d, %u levels, direct %u, skip %u", static_cast<int>(format), levels, direct ? 1U : 0U, skip);
            Check(SUCCEEDED(read) && SameLevels(expected, reloaded), "texture quality drops levels as D3DX9 does", detail);
          }
        }
      }
    }
    gpg::gal::imaging::gDdsDirectLoad = oldDirect;

    std::vector<std::uint8_t> png;
    const Image source = MakeImage(DXGI_FORMAT_R8G8B8A8_UNORM, 64U, 64U, 1U);
    if (SUCCEEDED(codec.Encode(source, FileFormat::Png, png))) {
      Image whole;
      Image reloaded;
      DecodeOptions options;
      options.skipMipLevels = 1U;
      const bool loaded = SUCCEEDED(codec.Decode(png.data(), png.size(), DecodeOptions{}, whole)) &&
        SUCCEEDED(codec.Decode(png.data(), png.size(), options, reloaded));
      Check(loaded && SameLevels(whole, reloaded), "texture quality leaves a PNG whole");
    } else {
      Check(false, "PNG encodes");
    }
  }

  /** Encode, which is D3DX11's writer where it has one: the same texels come back either way. */
  void TestEncodeMatchesWriteDds(ImageCodec& codec)
  {
    for (const NamedFormat& entry : kFormats) {
      const Image source = MakeImage(entry.format, 16U, 16U, 5U);
      std::vector<std::uint8_t> encoded;
      std::vector<std::uint8_t> own;
      const HRESULT result = codec.Encode(source, FileFormat::Dds, encoded);
      (void)ImageCodec::WriteDds(source, own);
      Image fromEncoded;
      Image fromOwn;
      const HRESULT readEncoded = FAILED(result) ? result : Reload(codec, encoded, entry.format, 16U, 16U, 5U, fromEncoded);
      const HRESULT readOwn = Reload(codec, own, entry.format, 16U, 16U, 5U, fromOwn);
      const bool read = SUCCEEDED(readEncoded) && SUCCEEDED(readOwn);
      if (FAILED(readEncoded) && FAILED(readOwn) && SUCCEEDED(result) && encoded != own) {
        std::printf("SKIP: %s - this D3DX11 can't load it from its own file either\n", entry.name);
        continue;
      }
      char detail[128]{};
      std::snprintf(detail, sizeof(detail), "encode 0x%08lX, read 0x%08lX and 0x%08lX, %s", static_cast<unsigned long>(result), static_cast<unsigned long>(readEncoded), static_cast<unsigned long>(readOwn), encoded == own ? "same file as WriteDds" : "D3DX11's file");
      Check(read && SameLevels(fromEncoded, fromOwn), entry.name, detail);
    }
  }

  void TestRefusesWhatItCannotWrite()
  {
    Image volume = MakeImage(DXGI_FORMAT_R8G8B8A8_UNORM, 4U, 4U, 1U);
    volume.volume = true;
    std::vector<std::uint8_t> file;
    Check(ImageCodec::WriteDds(volume, file) == E_INVALIDARG, "a volume is refused");
    Image missing = MakeImage(DXGI_FORMAT_R8G8B8A8_UNORM, 4U, 4U, 1U);
    missing.subresources.clear();
    Check(ImageCodec::WriteDds(missing, file) == E_INVALIDARG, "an image without its levels is refused");
  }
} // namespace

class Existing_ImageCodec : public ::testing::Test
{
protected:
  void SetUp() override
  {
    codec = ImageCodec::Instance();
    if (codec == nullptr) {
      GTEST_SKIP() << "no d3dx11_43.dll or no WARP device";
    }
    gpg::gal::imaging::gDdsDirectLoad = false;
    gpg::gal::imaging::gTextureDecodeCache = false;
  }

  ImageCodec* codec{nullptr};
};

TEST_F(Existing_ImageCodec, RefusesWhatItCannotWrite)
{
  TestRefusesWhatItCannotWrite();
}

TEST_F(Existing_ImageCodec, EveryFormatRoundTrips)
{
  TestEveryFormatRoundTrips(*codec);
}

TEST_F(Existing_ImageCodec, B5G6R5FileIsReadable)
{
  TestB5G6R5FileIsReadable(*codec);
}

TEST_F(Existing_ImageCodec, SwizzleKeepsChannels)
{
  TestSwizzleKeepsChannels(*codec);
}

TEST_F(Existing_ImageCodec, ResizeKeepsColour)
{
  TestResizeKeepsColour(*codec);
}

TEST_F(Existing_ImageCodec, ReloadInBlockFormat)
{
  TestReloadInBlockFormat(*codec);
}

TEST_F(Existing_ImageCodec, Cube)
{
  TestCube(*codec);
}

TEST_F(Existing_ImageCodec, QualityKeepsCubeTopMip)
{
  TestQualityKeepsCubeTopMip(*codec);
}

TEST_F(Existing_ImageCodec, QualityKeepsVolumeTopMip)
{
  TestQualityKeepsVolumeTopMip(*codec);
}

TEST_F(Existing_ImageCodec, QualitySkipFollowsD3dx9)
{
  TestQualitySkipFollowsD3dx9(*codec);
}

TEST_F(Existing_ImageCodec, EncodeMatchesWriteDds)
{
  TestEncodeMatchesWriteDds(*codec);
}
