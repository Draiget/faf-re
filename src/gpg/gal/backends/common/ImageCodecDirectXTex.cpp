// FAF addition, not in the shipped binary: ImageCodec's decoder when d3dx11_43.dll is missing
// (issue #318). See ImageCodec.h.

#include "ImageCodecDirectXTex.h"

#include <algorithm>
#include <cstring>

#include <objbase.h>

#include "DirectXTex.h"

#include "gpg/gal/backends/dxgi/DxgiFormats.h"

namespace gpg::gal::imaging
{
  namespace
  {
    [[nodiscard]] bool IsDds(const void* const data, const std::size_t bytes) noexcept
    {
      return bytes >= 4U && std::memcmp(data, "DDS ", 4U) == 0;
    }

    /** WIC needs COM on the calling thread; the loader threads may not have it. */
    class ComScope
    {
    public:
      ComScope() noexcept : mResult(::CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
      ~ComScope()
      {
        if (SUCCEEDED(mResult)) {
          ::CoUninitialize();
        }
      }
      ComScope(const ComScope&) = delete;
      ComScope& operator=(const ComScope&) = delete;

    private:
      HRESULT mResult;
    };

    // Luminance expands to grey RGBA as D3DX11 does (a plain R8 would read as red).
    constexpr DirectX::DDS_FLAGS kDdsFlags = DirectX::DDS_FLAGS_EXPAND_LUMINANCE;

    HRESULT LoadFile(const void* const data, const std::size_t bytes, DirectX::ScratchImage& outImage)
    {
      const auto* const source = static_cast<const std::uint8_t*>(data);
      if (IsDds(data, bytes)) {
        return DirectX::LoadFromDDSMemory(source, bytes, kDdsFlags, nullptr, outImage);
      }
      // PNG, BMP, JPG. D3DX11 refuses TGA files, and so does WIC.
      const ComScope com;
      return DirectX::LoadFromWICMemory(source, bytes, DirectX::WIC_FLAGS_NONE, nullptr, outImage);
    }

    [[nodiscard]] std::uint32_t FullChain(const std::size_t width, const std::size_t height) noexcept
    {
      std::uint32_t levels = 1U;
      for (std::size_t side = std::max(width, height); side > 1U; side >>= 1U) {
        ++levels;
      }
      return levels;
    }

    /** The format D3DX11 decodes a file into: block-compressed and A8 files keep theirs, the rest is RGBA8. */
    [[nodiscard]] DXGI_FORMAT DefaultFormat(const DXGI_FORMAT fileFormat) noexcept
    {
      if (DirectX::IsCompressed(fileFormat) || fileFormat == DXGI_FORMAT_A8_UNORM || fileFormat == DXGI_FORMAT_R8G8B8A8_UNORM) {
        return fileFormat;
      }
      return DXGI_FORMAT_R8G8B8A8_UNORM;
    }

    void CopyLevelInto(const DirectX::Image& from, const DirectX::Image& to)
    {
      const std::size_t rowBytes = std::min(from.rowPitch, to.rowPitch);
      const std::size_t rows = std::min(from.slicePitch / std::max<std::size_t>(from.rowPitch, 1U), to.slicePitch / std::max<std::size_t>(to.rowPitch, 1U));
      for (std::size_t row = 0U; row < rows; ++row) {
        std::memcpy(to.pixels + row * to.rowPitch, from.pixels + row * from.rowPitch, rowBytes);
      }
    }

    /**
     * One level in `format` at width x height: stretched (D3DX11's default filter) or placed at the
     * top left with transparent black around it (ResizeFilter::None) when the size differs.
     */
    HRESULT ToFormat(const DirectX::Image& from, const DXGI_FORMAT format, const std::size_t width, const std::size_t height,
                     const ResizeFilter filter, DirectX::ScratchImage& outLevel)
    {
      if (from.format == format && from.width == width && from.height == height) {
        return outLevel.InitializeFromImage(from);
      }
      DirectX::ScratchImage work;
      constexpr DXGI_FORMAT kWorkFormat = DXGI_FORMAT_R32G32B32A32_FLOAT;
      HRESULT result = S_OK;
      if (from.format == kWorkFormat) {
        result = work.InitializeFromImage(from);
      } else if (DirectX::IsCompressed(from.format)) {
        result = DirectX::Decompress(from, kWorkFormat, work);
      } else {
        result = DirectX::Convert(from, kWorkFormat, DirectX::TEX_FILTER_DEFAULT, DirectX::TEX_THRESHOLD_DEFAULT, work);
      }
      if (FAILED(result)) {
        return result;
      }
      if (from.width != width || from.height != height) {
        DirectX::ScratchImage sized;
        if (filter == ResizeFilter::None) {
          result = sized.Initialize2D(kWorkFormat, width, height, 1U, 1U);
          if (SUCCEEDED(result)) {
            std::memset(sized.GetPixels(), 0, sized.GetPixelsSize());
            const DirectX::Image& source = *work.GetImage(0U, 0U, 0U);
            const DirectX::Rect area(0U, 0U, std::min(source.width, width), std::min(source.height, height));
            result = DirectX::CopyRectangle(source, area, *sized.GetImage(0U, 0U, 0U), DirectX::TEX_FILTER_DEFAULT, 0U, 0U);
          }
        } else {
          result = DirectX::Resize(*work.GetImage(0U, 0U, 0U), width, height, DirectX::TEX_FILTER_TRIANGLE, sized);
        }
        if (FAILED(result)) {
          return result;
        }
        work = std::move(sized);
      }
      const DirectX::Image& level = *work.GetImage(0U, 0U, 0U);
      if (format == kWorkFormat) {
        outLevel = std::move(work);
        return S_OK;
      }
      return DirectX::IsCompressed(format)
        ? DirectX::Compress(level, format, DirectX::TEX_COMPRESS_DEFAULT, DirectX::TEX_THRESHOLD_DEFAULT, outLevel)
        : DirectX::Convert(level, format, DirectX::TEX_FILTER_DEFAULT, DirectX::TEX_THRESHOLD_DEFAULT, outLevel);
    }

    /**
     * The file's levels in the shape D3DX11 gives them. D3DX11 keeps the size, keeps a full mip
     * chain and builds one for a file with fewer levels: the file's levels come over (byte for
     * byte when the format stays), and the rest is built from the smallest of them, here
     * filtered and encoded with DirectXTex: within about 32-45 dB of D3DX11's (issue #318).
     */
    HRESULT Shape(DirectX::ScratchImage& file, const DecodeOptions& options, DirectX::ScratchImage& outImage)
    {
      const DirectX::TexMetadata meta = file.GetMetadata();
      const DXGI_FORMAT format = options.format != DXGI_FORMAT_UNKNOWN ? options.format : DefaultFormat(meta.format);
      std::size_t width = options.width != 0U ? options.width : meta.width;
      std::size_t height = options.height != 0U ? options.height : meta.height;
      const bool compressed = DirectX::IsCompressed(format);
      if (compressed) {
        // Whole blocks: an 18x18 image going to BC3 is stretched over 20x20, or with
        // ResizeFilter::None placed in its top left.
        width = (width + 3U) & ~std::size_t{3U};
        height = (height + 3U) & ~std::size_t{3U};
      }
      std::uint32_t levels = options.mipLevels;
      if (levels == 0U) {
        levels = meta.mipLevels == FullChain(meta.width, meta.height) ? static_cast<std::uint32_t>(meta.mipLevels) : FullChain(width, height);
      }
      levels = std::min(levels, FullChain(width, height));

      const bool sameSize = width == meta.width && height == meta.height;
      if (meta.dimension == DirectX::TEX_DIMENSION_TEXTURE3D) {
        if (meta.format != format || !sameSize || meta.mipLevels != levels) {
          return E_NOTIMPL; // no volume texture in the game needs converting
        }
        outImage = std::move(file);
        return S_OK;
      }
      // The file's levels that carry over (all of them at the same size, else only the top,
      // resized), then the rest built from the last of those, as D3DX11 does for a file with
      // part of a chain.
      const std::size_t kept = sameSize ? std::min<std::size_t>(meta.mipLevels, levels) : 1U;
      DirectX::TexMetadata outMeta = meta;
      outMeta.format = format;
      outMeta.width = width;
      outMeta.height = height;
      outMeta.mipLevels = levels;
      HRESULT result = outImage.Initialize(outMeta);
      if (FAILED(result)) {
        return result;
      }
      const auto place = [&outImage](const DirectX::Image& from, const std::size_t mip, const std::size_t slice) {
        const DirectX::Image* const to = outImage.GetImage(mip, slice, 0U);
        CopyLevelInto(from, *to);
      };

      for (std::size_t slice = 0U; slice < meta.arraySize; ++slice) {
        for (std::size_t mip = 0U; mip < kept; ++mip) {
          const DirectX::Image& from = *file.GetImage(mip, slice, 0U);
          if (meta.format == format && sameSize) {
            place(from, mip, slice);
            continue;
          }
          DirectX::ScratchImage level;
          result = ToFormat(from, format, std::max<std::size_t>(1U, width >> mip), std::max<std::size_t>(1U, height >> mip), options.filter, level);
          if (FAILED(result)) {
            return result;
          }
          place(*level.GetImage(0U, 0U, 0U), mip, slice);
        }
        if (kept >= levels) {
          continue;
        }
        // A float copy of the last kept level: the 8-bit route goes through WIC's scaler, which was
        // 20-30 dB off on DXT3/DXT5 files with alpha.
        DirectX::ScratchImage base;
        result = ToFormat(*file.GetImage(kept - 1U, slice, 0U), DXGI_FORMAT_R32G32B32A32_FLOAT, std::max<std::size_t>(1U, width >> (kept - 1U)),
                          std::max<std::size_t>(1U, height >> (kept - 1U)), options.filter, base);
        DirectX::ScratchImage chain;
        if (SUCCEEDED(result)) {
          // The filter closer to D3DX11's on the game's files (tmp numbers in issue #318, mean PSNR
          // of the built levels): box for BC1/BC2 and cubes (DXT3 37.9 dB against 32.4 with
          // linear, DXT5 cubes 47.7 against 42.8), linear for BC3 2D textures (40.4 against 39.8,
          // worst file 32.9 against 22.9) and uncompressed ones (60.8 against 41.9). DirectXTex's
          // box filter takes power-of-two sizes only.
          const DirectX::Image& top = *base.GetImage(0U, 0U, 0U);
          const bool powerOfTwo = (top.width & (top.width - 1U)) == 0U && (top.height & (top.height - 1U)) == 0U;
          const bool box = powerOfTwo && compressed && (format != DXGI_FORMAT_BC3_UNORM || meta.IsCubemap());
          result = DirectX::GenerateMipMaps(top, box ? DirectX::TEX_FILTER_BOX : DirectX::TEX_FILTER_LINEAR, levels - kept + 1U, chain);
        }
        for (std::size_t mip = kept; SUCCEEDED(result) && mip < levels; ++mip) {
          DirectX::ScratchImage level;
          const DirectX::Image& built = *chain.GetImage(mip - kept + 1U, 0U, 0U);
          result = ToFormat(built, format, built.width, built.height, options.filter, level);
          if (SUCCEEDED(result)) {
            place(*level.GetImage(0U, 0U, 0U), mip, slice);
          }
        }
        if (FAILED(result)) {
          return result;
        }
      }
      return S_OK;
    }

    void CopyLevel(const DirectX::Image& from, std::uint8_t* const to, const std::uint32_t rowPitch, const std::uint32_t rowCount)
    {
      const std::size_t rowBytes = std::min<std::size_t>(rowPitch, from.rowPitch);
      for (std::uint32_t row = 0U; row < rowCount; ++row) {
        std::memcpy(to + static_cast<std::size_t>(row) * rowPitch, from.pixels + row * from.rowPitch, rowBytes);
      }
    }
  } // namespace

  HRESULT DecodeWithDirectXTex(const void* const data, const std::size_t bytes, const DecodeOptions& options, Image& outImage)
  {
    DirectX::ScratchImage file;
    HRESULT result = LoadFile(data, bytes, file);
    if (FAILED(result)) {
      return result;
    }
    DirectX::ScratchImage shaped;
    result = Shape(file, options, shaped);
    if (FAILED(result)) {
      return result;
    }
    const DirectX::TexMetadata& meta = shaped.GetMetadata();
    const auto format = meta.format;
    const auto width = static_cast<std::uint32_t>(meta.width);
    const auto height = static_cast<std::uint32_t>(meta.height);
    const auto levels = static_cast<std::uint32_t>(meta.mipLevels);

    if (meta.dimension == DirectX::TEX_DIMENSION_TEXTURE3D) {
      outImage = Image{};
      outImage.format = format;
      outImage.width = width;
      outImage.height = height;
      outImage.depth = static_cast<std::uint32_t>(meta.depth);
      outImage.mipLevels = levels;
      outImage.volume = true;
      std::size_t offset = 0U;
      for (std::uint32_t mip = 0U; mip < levels; ++mip) {
        Image::Subresource subresource;
        subresource.offset = offset;
        subresource.width = std::max(1U, width >> mip);
        subresource.height = std::max(1U, height >> mip);
        subresource.depth = std::max(1U, outImage.depth >> mip);
        const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(format, subresource.width, subresource.height);
        subresource.rowPitch = layout.rowPitch;
        subresource.rowCount = layout.rowCount;
        subresource.slicePitch = layout.ByteSize();
        offset += static_cast<std::size_t>(subresource.slicePitch) * subresource.depth;
        outImage.subresources.push_back(subresource);
      }
      outImage.bytes.assign(offset, 0U);
      for (std::uint32_t mip = 0U; mip < levels; ++mip) {
        const Image::Subresource& subresource = outImage.subresources[mip];
        for (std::uint32_t slice = 0U; slice < subresource.depth; ++slice) {
          CopyLevel(*shaped.GetImage(mip, 0U, slice), outImage.bytes.data() + subresource.offset + slice * subresource.slicePitch,
                    subresource.rowPitch, subresource.rowCount);
        }
      }
      return S_OK;
    }

    // The quality skip as DecodeWithD3dx does it: whole top levels dropped, none on a cube, and a
    // block-compressed top level stays a whole number of blocks.
    const bool cube = meta.IsCubemap() && meta.arraySize == 6U;
    std::uint32_t skip = meta.IsCubemap() ? 0U : std::min(options.skipMipLevels, levels - 1U);
    while (skip != 0U && dxgi::IsBlockCompressed(format) && (((width >> skip) % 4U) != 0U || ((height >> skip) % 4U) != 0U)) {
      --skip;
    }
    outImage.Allocate(format, width >> skip, height >> skip, levels - skip, static_cast<std::uint32_t>(meta.arraySize));
    outImage.cube = cube;
    outImage.volume = false;
    for (std::uint32_t index = 0U; index < outImage.subresources.size(); ++index) {
      const Image::Subresource& subresource = outImage.subresources[index];
      const DirectX::Image& level = *shaped.GetImage(index % outImage.mipLevels + skip, index / outImage.mipLevels, 0U);
      CopyLevel(level, outImage.bytes.data() + subresource.offset, subresource.rowPitch, subresource.rowCount);
    }
    return S_OK;
  }

  HRESULT GetImageSizeWithDirectXTex(const void* const data, const std::size_t bytes, std::uint32_t& outWidth, std::uint32_t& outHeight)
  {
    DirectX::TexMetadata meta{};
    const auto* const source = static_cast<const std::uint8_t*>(data);
    HRESULT result = S_OK;
    if (IsDds(data, bytes)) {
      result = DirectX::GetMetadataFromDDSMemory(source, bytes, kDdsFlags, meta);
    } else {
      const ComScope com;
      result = DirectX::GetMetadataFromWICMemory(source, bytes, DirectX::WIC_FLAGS_NONE, meta);
    }
    if (SUCCEEDED(result)) {
      outWidth = static_cast<std::uint32_t>(meta.width);
      outHeight = static_cast<std::uint32_t>(meta.height);
    }
    return result;
  }

  HRESULT EncodeWithDirectXTex(const Image& image, const FileFormat format, std::vector<std::uint8_t>& outBytes)
  {
    if (format == FileFormat::Dds) {
      return ImageCodec::WriteDds(image, outBytes);
    }
    if (image.subresources.empty()) {
      return E_INVALIDARG;
    }
    const Image::Subresource& top = image.subresources.front();
    DirectX::Image level{};
    level.width = top.width;
    level.height = top.height;
    level.format = image.format;
    level.rowPitch = top.rowPitch;
    level.slicePitch = top.slicePitch;
    level.pixels = const_cast<std::uint8_t*>(image.bytes.data() + top.offset);
    DirectX::ScratchImage plain;
    if (DirectX::IsCompressed(image.format)) {
      const HRESULT result = DirectX::Decompress(level, DXGI_FORMAT_R8G8B8A8_UNORM, plain);
      if (FAILED(result)) {
        return result;
      }
      level = *plain.GetImage(0U, 0U, 0U);
    }
    DirectX::WICCodecs codec = DirectX::WIC_CODEC_PNG;
    if (format == FileFormat::Bmp) {
      codec = DirectX::WIC_CODEC_BMP;
    } else if (format == FileFormat::Jpg) {
      codec = DirectX::WIC_CODEC_JPEG;
    }
    const ComScope com;
    DirectX::Blob blob;
    const HRESULT result = DirectX::SaveToWICMemory(level, DirectX::WIC_FLAGS_NONE, DirectX::GetWICCodec(codec), blob);
    if (FAILED(result)) {
      return result;
    }
    const auto* const begin = blob.GetConstBufferPointer();
    outBytes.assign(begin, begin + blob.GetBufferSize());
    return S_OK;
  }
} // namespace gpg::gal::imaging
