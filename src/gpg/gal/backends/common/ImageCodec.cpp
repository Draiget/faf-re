// FAF addition, not in the shipped binary: see ImageCodec.h.

#include "ImageCodec.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

#include <d3d11.h>
#include <wrl/client.h>
// D3DX11 (DirectX SDK, June 2010): only the declarations come from the
// header; the exports are linked at run time from d3dx11_43.dll.
#include <d3dx11tex.h>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"
#include "gpg/gal/effects/EffectRuntime.h"

namespace gpg::gal::imaging
{
  using Microsoft::WRL::ComPtr;

  struct ImageCodec::State
  {
    HMODULE module = nullptr;
    decltype(&::D3DX11GetImageInfoFromMemory) getImageInfo = nullptr;
    decltype(&::D3DX11CreateTextureFromMemory) createTexture = nullptr;
    decltype(&::D3DX11SaveTextureToMemory) saveToMemory = nullptr;
    decltype(&::D3DX11SaveTextureToFileA) saveToFile = nullptr;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;

    ~State()
    {
      context.Reset();
      device.Reset();
      if (module != nullptr) {
        ::FreeLibrary(module);
      }
    }
  };

  void Image::Allocate(
    const DXGI_FORMAT imageFormat,
    const std::uint32_t imageWidth,
    const std::uint32_t imageHeight,
    const std::uint32_t levels,
    const std::uint32_t slices
  )
  {
    format = imageFormat;
    width = std::max(imageWidth, 1U);
    height = std::max(imageHeight, 1U);
    depth = 1U;
    mipLevels = std::max(levels, 1U);
    arraySize = std::max(slices, 1U);
    subresources.clear();
    std::size_t offset = 0U;
    for (std::uint32_t slice = 0U; slice < arraySize; ++slice) {
      for (std::uint32_t mip = 0U; mip < mipLevels; ++mip) {
        Subresource subresource;
        subresource.offset = offset;
        subresource.width = std::max(1U, width >> mip);
        subresource.height = std::max(1U, height >> mip);
        const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(format, subresource.width, subresource.height);
        subresource.rowPitch = layout.rowPitch;
        subresource.rowCount = layout.rowCount;
        subresource.slicePitch = layout.ByteSize();
        offset += subresource.slicePitch;
        subresources.push_back(subresource);
      }
    }
    bytes.assign(offset, 0U);
  }

  ImageCodec* ImageCodec::Instance()
  {
    static ImageCodec* const codec = [] {
      auto* const created = new ImageCodec();
      if (!created->Load()) {
        delete created;
        return static_cast<ImageCodec*>(nullptr);
      }
      return created;
    }();
    return codec;
  }

  ImageCodec::~ImageCodec() = default;

  bool ImageCodec::Load()
  {
    auto state = std::make_unique<State>();
    state->module = ::LoadLibraryA("d3dx11_43.dll");
    if (state->module == nullptr) {
      gpg::Warnf("imaging: d3dx11_43.dll is not installed (DirectX End-User Runtime, June 2010)");
      return false;
    }
    state->getImageInfo =
      reinterpret_cast<decltype(&::D3DX11GetImageInfoFromMemory)>(::GetProcAddress(state->module, "D3DX11GetImageInfoFromMemory"));
    state->createTexture =
      reinterpret_cast<decltype(&::D3DX11CreateTextureFromMemory)>(::GetProcAddress(state->module, "D3DX11CreateTextureFromMemory"));
    state->saveToMemory =
      reinterpret_cast<decltype(&::D3DX11SaveTextureToMemory)>(::GetProcAddress(state->module, "D3DX11SaveTextureToMemory"));
    state->saveToFile = reinterpret_cast<decltype(&::D3DX11SaveTextureToFileA)>(::GetProcAddress(state->module, "D3DX11SaveTextureToFileA"));
    if (state->getImageInfo == nullptr || state->createTexture == nullptr || state->saveToMemory == nullptr || state->saveToFile == nullptr) {
      gpg::Warnf("imaging: d3dx11_43.dll lacks the texture exports");
      return false;
    }
    const HRESULT result = ::D3D11CreateDevice(
      nullptr, D3D_DRIVER_TYPE_WARP, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0U, D3D11_SDK_VERSION, &state->device,
      nullptr, &state->context
    );
    if (FAILED(result)) {
      gpg::Warnf("imaging: no WARP device for texture decoding (HRESULT 0x%08lX)", static_cast<unsigned long>(result));
      return false;
    }
    mState = std::move(state);
    return true;
  }

  bool gDdsDirectLoad = true;
  bool gTextureDecodeCache = true;

  namespace
  {
    constexpr std::uint32_t FourCc(const char a, const char b, const char c, const char d) noexcept
    {
      return static_cast<std::uint32_t>(static_cast<std::uint8_t>(a)) | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(b)) << 8U) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(c)) << 16U) | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(d)) << 24U);
    }

    [[nodiscard]] std::uint32_t ReadU32(const std::uint8_t* const at) noexcept
    {
      std::uint32_t value = 0U;
      std::memcpy(&value, at, sizeof(value));
      return value;
    }

    /**
     * The DDS fast path (see gDdsDirectLoad): a plain DXT1/3/5 file, 2D or a full cube, whose
     * (skipped-to) top level is a multiple of 4 on both sides, read into `outImage`. Anything
     * else - another format, a DX10 header, a volume, a short file, a size or format override -
     * returns false and goes through D3DX11.
     */
    [[nodiscard]] bool TryReadBlockCompressedDds(
      const std::uint8_t* const data, const std::size_t bytes, const DecodeOptions& options, Image& outImage
    )
    {
      constexpr std::size_t kHeaderBytes = 4U + 124U;
      if (options.format != DXGI_FORMAT_UNKNOWN || options.width != 0U || options.height != 0U || options.mipLevels != 0U) {
        return false;
      }
      if (bytes < kHeaderBytes || ReadU32(data) != FourCc('D', 'D', 'S', ' ') || ReadU32(data + 4) != 124U) {
        return false;
      }
      constexpr std::uint32_t kMipMapCountFlag = 0x20000U;
      constexpr std::uint32_t kFourCcFlag = 0x4U;
      constexpr std::uint32_t kCubemap = 0x200U;
      constexpr std::uint32_t kAllFaces = 0xFC00U;
      constexpr std::uint32_t kVolume = 0x200000U;
      const std::uint32_t flags = ReadU32(data + 8);
      const std::uint32_t height = ReadU32(data + 12);
      const std::uint32_t width = ReadU32(data + 16);
      const std::uint32_t mipCount = (flags & kMipMapCountFlag) != 0U ? std::max(ReadU32(data + 28), 1U) : 1U;
      const std::uint32_t pixelFlags = ReadU32(data + 80);
      const std::uint32_t fourCc = ReadU32(data + 84);
      const std::uint32_t caps2 = ReadU32(data + 112);
      if ((pixelFlags & kFourCcFlag) == 0U || (caps2 & kVolume) != 0U || width == 0U || height == 0U || mipCount > 16U) {
        return false;
      }
      DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
      if (fourCc == FourCc('D', 'X', 'T', '1')) {
        format = DXGI_FORMAT_BC1_UNORM;
      } else if (fourCc == FourCc('D', 'X', 'T', '3')) {
        format = DXGI_FORMAT_BC2_UNORM;
      } else if (fourCc == FourCc('D', 'X', 'T', '5')) {
        format = DXGI_FORMAT_BC3_UNORM;
      } else {
        return false;
      }
      const bool cube = (caps2 & kCubemap) != 0U;
      if (cube && (caps2 & kAllFaces) != kAllFaces) {
        return false;
      }
      // D3DX builds the levels a file lacks (a 512x512 file with one level comes back with
      // ten); only a full chain is read directly.
      std::uint32_t fullChain = 1U;
      for (std::uint32_t side = std::max(width, height); side > 1U; side >>= 1U) {
        ++fullChain;
      }
      if (mipCount != fullChain) {
        return false;
      }
      const std::uint32_t faces = cube ? 6U : 1U;

      // D3DX's FirstMipLevel; the caller retries from level 0 when D3DX refuses the skip.
      std::uint32_t skip = options.skipMipLevels;
      if (skip >= mipCount) {
        skip = 0U;
      }
      const std::uint32_t topWidth = std::max(1U, width >> skip);
      const std::uint32_t topHeight = std::max(1U, height >> skip);
      // Power-of-two sides only: D3DX11 changes the data of a level whose side drops below a
      // multiple of 4 while still above 4 (the 128x6 level of a 256x12 texture).
      const auto powerOfTwo = [](const std::uint32_t side) { return (side & (side - 1U)) == 0U; };
      if (!powerOfTwo(width) || !powerOfTwo(height) || (topWidth % 4U) != 0U || (topHeight % 4U) != 0U) {
        return false;
      }

      // Every face's full chain in the file, to know where each level starts.
      std::vector<std::size_t> levelBytes(mipCount);
      std::size_t faceBytes = 0U;
      for (std::uint32_t mip = 0U; mip < mipCount; ++mip) {
        levelBytes[mip] = dxgi::ComputeLevelLayout(format, std::max(1U, width >> mip), std::max(1U, height >> mip)).ByteSize();
        faceBytes += levelBytes[mip];
      }
      if (bytes - kHeaderBytes < faceBytes * faces) {
        return false;
      }

      outImage.Allocate(format, topWidth, topHeight, mipCount - skip, faces);
      outImage.cube = cube;
      outImage.volume = false;
      for (std::uint32_t face = 0U; face < faces; ++face) {
        std::size_t source = kHeaderBytes + face * faceBytes;
        for (std::uint32_t mip = 0U; mip < mipCount; ++mip) {
          if (mip >= skip) {
            const Image::Subresource& target = outImage.subresources[face * outImage.mipLevels + (mip - skip)];
            std::memcpy(outImage.bytes.data() + target.offset, data + source, target.slicePitch);
          }
          source += levelBytes[mip];
        }
      }
      return true;
    }

    // ---- decode cache (gTextureDecodeCache) -----------------------------------------
    constexpr char kDecodeCacheMagic[8] = {'F', 'A', 'F', 'I', 'M', 'G', '1', '\0'};
    constexpr std::uint64_t kDecodeCacheMinMicroseconds = 8000U;

    struct DecodeCacheHeader
    {
      char magic[8];
      std::uint64_t key;
      std::uint32_t format, width, height, depth, mipLevels, arraySize, cube, volume, subresourceCount;
      std::uint64_t byteCount;
    };

    [[nodiscard]] std::uint64_t DecodeCacheKey(const void* const data, const std::size_t bytes, const DecodeOptions& options)
    {
      effects::Fnv1a64 hash;
      hash.Add("faf image decode cache 1");
      // The file stores Image::Subresource as is, whose offset is pointer-sized: x86 and x64
      // builds share the directory and keep separate entries.
      const std::uint32_t pointerBytes = sizeof(void*);
      hash.Add(&pointerBytes, sizeof(pointerBytes));
      hash.Add(data, bytes);
      hash.Add(&options, sizeof(options));
      return hash.Value();
    }

    [[nodiscard]] std::string DecodeCachePath(const std::uint64_t key)
    {
      const std::string& directory = effects::ShaderCacheDirectory();
      if (directory.empty()) {
        return {};
      }
      static const bool created = [&directory] {
        const std::string textures = directory + "textures";
        return ::CreateDirectoryA(textures.c_str(), nullptr) != FALSE || ::GetLastError() == ERROR_ALREADY_EXISTS;
      }();
      if (!created) {
        return {};
      }
      char name[48]{};
      std::snprintf(name, sizeof(name), "textures\\%016llx.img", static_cast<unsigned long long>(key));
      return directory + name;
    }

    [[nodiscard]] bool ReadDecodeCache(const std::string& path, const std::uint64_t key, Image& outImage)
    {
      HANDLE const file = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return false;
      }
      DecodeCacheHeader header{};
      DWORD read = 0U;
      bool ok = ::ReadFile(file, &header, sizeof(header), &read, nullptr) && read == sizeof(header) &&
        std::memcmp(header.magic, kDecodeCacheMagic, sizeof(kDecodeCacheMagic)) == 0 && header.key == key &&
        header.subresourceCount != 0U && header.subresourceCount <= 6U * 16U && header.byteCount < (256ULL << 20U);
      if (ok) {
        outImage.format = static_cast<DXGI_FORMAT>(header.format);
        outImage.width = header.width;
        outImage.height = header.height;
        outImage.depth = header.depth;
        outImage.mipLevels = header.mipLevels;
        outImage.arraySize = header.arraySize;
        outImage.cube = header.cube != 0U;
        outImage.volume = header.volume != 0U;
        outImage.subresources.resize(header.subresourceCount);
        const DWORD subresourceBytes = static_cast<DWORD>(header.subresourceCount * sizeof(Image::Subresource));
        outImage.bytes.resize(static_cast<std::size_t>(header.byteCount));
        ok = ::ReadFile(file, outImage.subresources.data(), subresourceBytes, &read, nullptr) && read == subresourceBytes &&
          ::ReadFile(file, outImage.bytes.data(), static_cast<DWORD>(outImage.bytes.size()), &read, nullptr) &&
          read == outImage.bytes.size();
      }
      ::CloseHandle(file);
      if (!ok) {
        outImage = Image{};
      }
      return ok;
    }

    void WriteDecodeCache(const std::string& path, const std::uint64_t key, const Image& image)
    {
      DecodeCacheHeader header{};
      std::memcpy(header.magic, kDecodeCacheMagic, sizeof(kDecodeCacheMagic));
      header.key = key;
      header.format = static_cast<std::uint32_t>(image.format);
      header.width = image.width;
      header.height = image.height;
      header.depth = image.depth;
      header.mipLevels = image.mipLevels;
      header.arraySize = image.arraySize;
      header.cube = image.cube ? 1U : 0U;
      header.volume = image.volume ? 1U : 0U;
      header.subresourceCount = static_cast<std::uint32_t>(image.subresources.size());
      header.byteCount = image.bytes.size();
      char suffix[32]{};
      std::snprintf(suffix, sizeof(suffix), ".%lu.tmp", static_cast<unsigned long>(::GetCurrentThreadId()));
      const std::string temporary = path + suffix;
      HANDLE const file = ::CreateFileA(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      const DWORD subresourceBytes = static_cast<DWORD>(image.subresources.size() * sizeof(Image::Subresource));
      DWORD written = 0U;
      const bool ok = ::WriteFile(file, &header, sizeof(header), &written, nullptr) && written == sizeof(header) &&
        ::WriteFile(file, image.subresources.data(), subresourceBytes, &written, nullptr) && written == subresourceBytes &&
        ::WriteFile(file, image.bytes.data(), static_cast<DWORD>(image.bytes.size()), &written, nullptr) &&
        written == image.bytes.size();
      ::CloseHandle(file);
      if (!ok || !::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ::DeleteFileA(temporary.c_str());
      }
    }

    [[nodiscard]] bool VerifyRequested()
    {
      static const bool verify = [] {
        char value[8]{};
        std::size_t length = 0U;
        return ::getenv_s(&length, value, sizeof(value), "FAF_IMAGECODEC_VERIFY") == 0 && length != 0U && value[0] == '1';
      }();
      return verify;
    }
  } // namespace

  HRESULT ImageCodec::Decode(const void* const data, const std::size_t bytes, const DecodeOptions& options, Image& outImage)
  {
    if (gDdsDirectLoad && TryReadBlockCompressedDds(static_cast<const std::uint8_t*>(data), bytes, options, outImage)) {
      if (VerifyRequested()) {
        Image reference;
        const HRESULT result = DecodeWithD3dx(data, bytes, options, reference);
        bool same = SUCCEEDED(result) && reference.format == outImage.format && reference.width == outImage.width &&
          reference.height == outImage.height && reference.mipLevels == outImage.mipLevels &&
          reference.arraySize == outImage.arraySize && reference.cube == outImage.cube &&
          reference.bytes.size() == outImage.bytes.size();
        // Levels under 4x4 (one block): D3DX11's round trip through the WARP device changes a few
        // of their bytes, the direct load keeps the file's. Counted, not treated as a difference.
        static std::uint32_t sTinyLevelDifferences = 0U;
        for (std::uint32_t index = 0U; same && index < outImage.subresources.size(); ++index) {
          const Image::Subresource& level = outImage.subresources[index];
          const bool equal = std::memcmp(outImage.bytes.data() + level.offset, reference.bytes.data() + level.offset, level.slicePitch) == 0;
          if (!equal && (level.width < 4U || level.height < 4U)) {
            if (sTinyLevelDifferences++ == 0U) {
              gpg::Logf("imaging: DDS direct load: levels under 4x4 differ from D3DX11 (the file's bytes are kept); counted, not logged again");
            }
          } else if (!equal) {
            same = false;
          }
        }
        if (!same) {
          std::size_t firstDiff = 0U;
          const std::size_t common = std::min(reference.bytes.size(), outImage.bytes.size());
          while (firstDiff < common && reference.bytes[firstDiff] == outImage.bytes[firstDiff]) {
            ++firstDiff;
          }
          std::size_t diffCount = 0U;
          for (std::size_t index = firstDiff; index < common; ++index) {
            diffCount += reference.bytes[index] != outImage.bytes[index] ? 1U : 0U;
          }
          std::uint32_t diffSubresource = 0U;
          for (std::uint32_t index = 0U; index < outImage.subresources.size(); ++index) {
            if (outImage.subresources[index].offset <= firstDiff) {
              diffSubresource = index;
            }
          }
          gpg::Warnf(
            "imaging: DDS direct load differs from D3DX11 (format %d/%d, %ux%u/%ux%u, mips %u/%u, slices %u/%u, %zu/%zu bytes, "
            "first difference at byte %zu (subresource %u), %zu bytes differ)",
            static_cast<int>(outImage.format), static_cast<int>(reference.format), outImage.width, outImage.height,
            reference.width, reference.height, outImage.mipLevels, reference.mipLevels, outImage.arraySize,
            reference.arraySize, outImage.bytes.size(), reference.bytes.size(), firstDiff, diffSubresource, diffCount
          );
          outImage = std::move(reference);
          return result;
        }
      }
      return S_OK;
    }

    if (!gTextureDecodeCache) {
      return DecodeWithD3dx(data, bytes, options, outImage);
    }
    const std::uint64_t key = DecodeCacheKey(data, bytes, options);
    const std::string path = DecodeCachePath(key);
    if (!path.empty() && ReadDecodeCache(path, key, outImage)) {
      return S_OK;
    }
    LARGE_INTEGER start{}, end{}, frequency{};
    ::QueryPerformanceCounter(&start);
    const HRESULT result = DecodeWithD3dx(data, bytes, options, outImage);
    ::QueryPerformanceCounter(&end);
    ::QueryPerformanceFrequency(&frequency);
    const auto microseconds = static_cast<std::uint64_t>(1000000.0 * static_cast<double>(end.QuadPart - start.QuadPart) / static_cast<double>(frequency.QuadPart));
    if (SUCCEEDED(result) && !path.empty() && microseconds >= kDecodeCacheMinMicroseconds) {
      // Written on a background thread from a copy, so the frame does not wait for the disk.
      auto copy = std::make_shared<Image>(outImage);
      std::thread([path, key, copy] { WriteDecodeCache(path, key, *copy); }).detach();
    }
    return result;
  }

  HRESULT ImageCodec::DecodeWithD3dx(const void* const data, const std::size_t bytes, const DecodeOptions& options, Image& outImage)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    State& state = *mState;

    D3DX11_IMAGE_INFO info{};
    HRESULT result = state.getImageInfo(data, bytes, nullptr, &info, nullptr);
    if (FAILED(result)) {
      return result;
    }

    const auto load = [&](const std::uint32_t firstMip, ComPtr<ID3D11Resource>& resource) {
      D3DX11_IMAGE_LOAD_INFO loadInfo; // every field D3DX11_DEFAULT / FROM_FILE
      if (options.width != 0U) {
        loadInfo.Width = options.width;
      }
      if (options.height != 0U) {
        loadInfo.Height = options.height;
      }
      if (options.mipLevels != 0U) {
        loadInfo.MipLevels = options.mipLevels;
      }
      if (options.format != DXGI_FORMAT_UNKNOWN) {
        loadInfo.Format = options.format;
      }
      if (firstMip != 0U) {
        loadInfo.FirstMipLevel = firstMip;
      }
      loadInfo.Usage = D3D11_USAGE_STAGING;
      loadInfo.BindFlags = 0U;
      loadInfo.CpuAccessFlags = D3D11_CPU_ACCESS_READ;
      loadInfo.MiscFlags = 0U; // a staging resource carries no cube flag; the faces come as six slices
      return state.createTexture(state.device.Get(), data, bytes, &loadInfo, nullptr, &resource, nullptr);
    };

    ComPtr<ID3D11Resource> resource;
    result = E_FAIL;
    if (options.skipMipLevels != 0U) {
      result = load(options.skipMipLevels, resource);
    }
    if (FAILED(result)) {
      resource.Reset();
      result = load(0U, resource);
    }
    if (FAILED(result)) {
      return result;
    }

    ComPtr<ID3D11Texture2D> texture2D;
    ComPtr<ID3D11Texture3D> texture3D;
    if (SUCCEEDED(resource.As(&texture2D))) {
      D3D11_TEXTURE2D_DESC desc{};
      texture2D->GetDesc(&desc);
      outImage.Allocate(desc.Format, desc.Width, desc.Height, desc.MipLevels, desc.ArraySize);
      outImage.cube = (info.MiscFlags & D3D11_RESOURCE_MISC_TEXTURECUBE) != 0U && desc.ArraySize == 6U;
      outImage.volume = false;
      for (std::uint32_t index = 0U; index < outImage.subresources.size(); ++index) {
        const Image::Subresource& subresource = outImage.subresources[index];
        D3D11_MAPPED_SUBRESOURCE mapped{};
        result = state.context->Map(texture2D.Get(), index, D3D11_MAP_READ, 0U, &mapped);
        if (FAILED(result)) {
          return result;
        }
        for (std::uint32_t row = 0U; row < subresource.rowCount; ++row) {
          std::memcpy(outImage.bytes.data() + subresource.offset + static_cast<std::size_t>(row) * subresource.rowPitch,
                      static_cast<const std::uint8_t*>(mapped.pData) + static_cast<std::size_t>(row) * mapped.RowPitch,
                      subresource.rowPitch);
        }
        state.context->Unmap(texture2D.Get(), index);
      }
      return S_OK;
    }

    if (SUCCEEDED(resource.As(&texture3D))) {
      D3D11_TEXTURE3D_DESC desc{};
      texture3D->GetDesc(&desc);
      outImage.format = desc.Format;
      outImage.width = desc.Width;
      outImage.height = desc.Height;
      outImage.depth = desc.Depth;
      outImage.mipLevels = desc.MipLevels;
      outImage.arraySize = 1U;
      outImage.cube = false;
      outImage.volume = true;
      outImage.subresources.clear();
      std::size_t offset = 0U;
      for (std::uint32_t mip = 0U; mip < desc.MipLevels; ++mip) {
        Image::Subresource subresource;
        subresource.offset = offset;
        subresource.width = std::max(1U, desc.Width >> mip);
        subresource.height = std::max(1U, desc.Height >> mip);
        subresource.depth = std::max(1U, desc.Depth >> mip);
        const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(desc.Format, subresource.width, subresource.height);
        subresource.rowPitch = layout.rowPitch;
        subresource.rowCount = layout.rowCount;
        subresource.slicePitch = layout.ByteSize();
        offset += static_cast<std::size_t>(subresource.slicePitch) * subresource.depth;
        outImage.subresources.push_back(subresource);
      }
      outImage.bytes.assign(offset, 0U);
      for (std::uint32_t mip = 0U; mip < desc.MipLevels; ++mip) {
        const Image::Subresource& subresource = outImage.subresources[mip];
        D3D11_MAPPED_SUBRESOURCE mapped{};
        result = state.context->Map(texture3D.Get(), mip, D3D11_MAP_READ, 0U, &mapped);
        if (FAILED(result)) {
          return result;
        }
        for (std::uint32_t slice = 0U; slice < subresource.depth; ++slice) {
          for (std::uint32_t row = 0U; row < subresource.rowCount; ++row) {
            std::memcpy(
              outImage.bytes.data() + subresource.offset + static_cast<std::size_t>(slice) * subresource.slicePitch +
                static_cast<std::size_t>(row) * subresource.rowPitch,
              static_cast<const std::uint8_t*>(mapped.pData) + static_cast<std::size_t>(slice) * mapped.DepthPitch +
                static_cast<std::size_t>(row) * mapped.RowPitch,
              subresource.rowPitch
            );
          }
        }
        state.context->Unmap(texture3D.Get(), mip);
      }
      return S_OK;
    }
    return E_NOINTERFACE;
  }

  namespace
  {
    HRESULT CreateEncodable(ID3D11Device* const device, const Image& image, ComPtr<ID3D11Texture2D>& outTexture)
    {
      D3D11_TEXTURE2D_DESC desc{};
      desc.Width = image.width;
      desc.Height = image.height;
      desc.MipLevels = image.mipLevels;
      desc.ArraySize = image.cube ? 6U : 1U;
      desc.Format = image.format;
      desc.SampleDesc.Count = 1U;
      desc.Usage = D3D11_USAGE_DEFAULT;
      desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
      desc.MiscFlags = image.cube ? D3D11_RESOURCE_MISC_TEXTURECUBE : 0U;
      std::vector<D3D11_SUBRESOURCE_DATA> initial;
      for (std::uint32_t index = 0U; index < desc.MipLevels * desc.ArraySize && index < image.subresources.size(); ++index) {
        const Image::Subresource& subresource = image.subresources[index];
        D3D11_SUBRESOURCE_DATA data{};
        data.pSysMem = image.bytes.data() + subresource.offset;
        data.SysMemPitch = subresource.rowPitch;
        data.SysMemSlicePitch = subresource.slicePitch;
        initial.push_back(data);
      }
      if (initial.size() != static_cast<std::size_t>(desc.MipLevels) * desc.ArraySize) {
        return E_INVALIDARG;
      }
      return device->CreateTexture2D(&desc, initial.data(), &outTexture);
    }
  } // namespace

  HRESULT ImageCodec::Encode(const Image& image, const FileFormat format, std::vector<std::uint8_t>& outBytes)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    ComPtr<ID3D11Texture2D> texture;
    HRESULT result = CreateEncodable(mState->device.Get(), image, texture);
    if (FAILED(result)) {
      return result;
    }
    ComPtr<ID3D10Blob> blob;
    result = mState->saveToMemory(
      mState->context.Get(), texture.Get(), static_cast<D3DX11_IMAGE_FILE_FORMAT>(format), &blob, 0U
    );
    if (FAILED(result)) {
      return result;
    }
    const auto* const begin = static_cast<const std::uint8_t*>(blob->GetBufferPointer());
    outBytes.assign(begin, begin + blob->GetBufferSize());
    return S_OK;
  }

  HRESULT ImageCodec::EncodeToFile(const Image& image, const FileFormat format, const char* const path)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    ComPtr<ID3D11Texture2D> texture;
    const HRESULT result = CreateEncodable(mState->device.Get(), image, texture);
    if (FAILED(result)) {
      return result;
    }
    return mState->saveToFile(mState->context.Get(), texture.Get(), static_cast<D3DX11_IMAGE_FILE_FORMAT>(format), path);
  }

  FileFormat ImageCodec::FromGalFormat(const int galFormat) noexcept
  {
    // The D3D10 table (0x00D430A0): BMP, JPG, PNG, PNG, DDS.
    constexpr FileFormat kFormats[5] = {FileFormat::Bmp, FileFormat::Jpg, FileFormat::Png, FileFormat::Png, FileFormat::Dds};
    return (galFormat >= 0 && galFormat < 5) ? kFormats[galFormat] : FileFormat::Bmp;
  }
} // namespace gpg::gal::imaging
