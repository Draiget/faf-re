#include "editor/graph/EdTextureBake.h"

#include "DirectXTex.h"
#include "gpg/gal/backends/common/ImageCodec.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    /** The image as RGBA floats, then each smaller level the 2 x 2 average of the one above. */
    std::vector<TexImage> MipChain(const TexImage& image)
    {
      std::vector<TexImage> levels(1);
      TexImage& top = levels.front();
      top.Reset(image.size, 4);
      for (int y = 0; y < image.size; ++y) {
        for (int x = 0; x < image.size; ++x) {
          const float* s = image.Pixel(x, y);
          float* d = top.Pixel(x, y);
          if (image.channels == 4) {
            std::copy(s, s + 4, d);
          } else {
            d[0] = d[1] = d[2] = s[0];
            d[3] = 1.0f;
          }
        }
      }
      while (levels.back().size > 1) {
        const TexImage& above = levels.back();
        TexImage next;
        next.Reset(std::max(1, above.size / 2), 4);
        for (int y = 0; y < next.size; ++y) {
          for (int x = 0; x < next.size; ++x) {
            float* d = next.Pixel(x, y);
            for (int c = 0; c < 4; ++c) {
              const int x0 = std::min(x * 2, above.size - 1);
              const int y0 = std::min(y * 2, above.size - 1);
              const int x1 = (x * 2 + 1) % above.size;
              const int y1 = (y * 2 + 1) % above.size;
              d[c] = (above.Pixel(x0, y0)[c] + above.Pixel(x1, y0)[c] + above.Pixel(x0, y1)[c] + above.Pixel(x1, y1)[c]) * 0.25f;
            }
          }
        }
        levels.push_back(std::move(next));
      }
      return levels;
    }

    std::uint8_t Byte(const float v)
    {
      return static_cast<std::uint8_t>(std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f));
    }
  } // namespace

  bool EncodeDds(const TexImage& image, const DdsKind kind, std::vector<std::uint8_t>& out, std::string& error)
  {
    if (image.size <= 0 || (image.channels != 1 && image.channels != 4)) {
      error = "empty image";
      return false;
    }
    const std::vector<TexImage> levels = MipChain(image);
    const DXGI_FORMAT format = kind == DdsKind::Bgra ? DXGI_FORMAT_B8G8R8A8_UNORM : kind == DdsKind::Bc1 ? DXGI_FORMAT_BC1_UNORM : DXGI_FORMAT_BC3_UNORM;
    gpg::gal::imaging::Image dds;
    dds.Allocate(format, static_cast<std::uint32_t>(image.size), static_cast<std::uint32_t>(image.size), static_cast<std::uint32_t>(levels.size()), 1U);
    if (dds.subresources.size() != levels.size()) {
      error = "the DDS layout has no room for the mip levels";
      return false;
    }
    for (std::size_t mip = 0; mip < levels.size(); ++mip) {
      const TexImage& level = levels[mip];
      const auto& sub = dds.subresources[mip];
      // The level as 8-bit pixels: BGRA for the uncompressed file, RGBA for the encoder.
      std::vector<std::uint8_t> pixels(static_cast<std::size_t>(level.size) * level.size * 4U);
      for (int y = 0; y < level.size; ++y) {
        for (int x = 0; x < level.size; ++x) {
          const float* p = level.Pixel(x, y);
          std::uint8_t* d = pixels.data() + (static_cast<std::size_t>(y) * level.size + x) * 4U;
          d[0] = Byte(kind == DdsKind::Bgra ? p[2] : p[0]);
          d[1] = Byte(p[1]);
          d[2] = Byte(kind == DdsKind::Bgra ? p[0] : p[2]);
          d[3] = Byte(p[3]);
        }
      }
      const std::size_t rowBytes = static_cast<std::size_t>(level.size) * 4U;
      if (kind == DdsKind::Bgra) {
        for (int y = 0; y < level.size; ++y) {
          std::memcpy(dds.bytes.data() + sub.offset + static_cast<std::size_t>(y) * sub.rowPitch, pixels.data() + y * rowBytes,
                      std::min<std::size_t>(rowBytes, sub.rowPitch));
        }
        continue;
      }
      DirectX::Image source{};
      source.width = static_cast<std::size_t>(level.size);
      source.height = static_cast<std::size_t>(level.size);
      source.format = DXGI_FORMAT_R8G8B8A8_UNORM;
      source.rowPitch = rowBytes;
      source.slicePitch = rowBytes * static_cast<std::size_t>(level.size);
      source.pixels = pixels.data();
      DirectX::ScratchImage compressed;
      const HRESULT hr = DirectX::Compress(source, format, DirectX::TEX_COMPRESS_DEFAULT, DirectX::TEX_THRESHOLD_DEFAULT, compressed);
      const DirectX::Image* result = SUCCEEDED(hr) ? compressed.GetImage(0, 0, 0) : nullptr;
      if (result == nullptr) {
        error = "compressing mip level " + std::to_string(mip) + " failed";
        return false;
      }
      // Row of 4 x 4 blocks by row.
      for (std::uint32_t row = 0; row < sub.rowCount; ++row) {
        std::memcpy(dds.bytes.data() + sub.offset + static_cast<std::size_t>(row) * sub.rowPitch, result->pixels + row * result->rowPitch,
                    std::min<std::size_t>(result->rowPitch, sub.rowPitch));
      }
    }
    if (FAILED(gpg::gal::imaging::ImageCodec::WriteDds(dds, out))) {
      error = "writing the DDS failed";
      return false;
    }
    return true;
  }
} // namespace faf::editor
