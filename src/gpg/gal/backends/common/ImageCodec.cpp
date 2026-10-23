// FAF addition, not in the shipped binary: see ImageCodec.h.

#include "ImageCodec.h"

#include <algorithm>
#include <cstring>

#include <d3d11.h>
#include <wrl/client.h>
// D3DX11 (DirectX SDK, June 2010): only the declarations come from the
// header; the exports are linked at run time from d3dx11_43.dll.
#include <d3dx11tex.h>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

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

  HRESULT ImageCodec::Decode(const void* const data, const std::size_t bytes, const DecodeOptions& options, Image& outImage)
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
