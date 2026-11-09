#include "editor/tools/EdHeightFile.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wincodec.h>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    }

    [[nodiscard]] bool IsRaw(const std::filesystem::path& file)
    {
      const std::string extension = Lower(file.extension().string());
      return extension == ".raw" || extension == ".r16";
    }

    [[nodiscard]] std::string HResultText(const HRESULT result)
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "0x%08lX", static_cast<unsigned long>(result));
      return text;
    }

    /** COM on this thread for the imaging component, undone when it was this call that started it. */
    class ComScope
    {
    public:
      ComScope()
        : mStarted(SUCCEEDED(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)))
      {}
      ~ComScope()
      {
        if (mStarted) {
          ::CoUninitialize();
        }
      }
      ComScope(const ComScope&) = delete;
      ComScope& operator=(const ComScope&) = delete;

    private:
      bool mStarted;
    };

    template <typename T>
    struct ComPtr
    {
      T* p = nullptr;
      ~ComPtr()
      {
        if (p != nullptr) {
          p->Release();
        }
      }
      T** operator&() { return &p; }
      T* operator->() const { return p; }
    };

    bool ReadRaw(const std::filesystem::path& file, const int expectWidth, const int expectHeight, HeightImage& out, std::string& error)
    {
      std::ifstream in(file, std::ios::binary | std::ios::ate);
      if (!in) {
        error = "can't open " + file.string();
        return false;
      }
      const auto bytes = static_cast<std::size_t>(in.tellg());
      const std::size_t count = bytes / 2;
      int width = 0;
      int height = 0;
      if (expectWidth > 0 && expectHeight > 0 && count == static_cast<std::size_t>(expectWidth) * static_cast<std::size_t>(expectHeight)) {
        width = expectWidth;
        height = expectHeight;
      } else {
        const auto side = static_cast<int>(std::lround(std::sqrt(static_cast<double>(count))));
        if (bytes % 2 != 0 || static_cast<std::size_t>(side) * static_cast<std::size_t>(side) != count || side < 2) {
          error = file.filename().string() + " is " + std::to_string(bytes) + " bytes: not a square of 16-bit heights, nor the map's size";
          return false;
        }
        width = side;
        height = side;
      }
      out.width = width;
      out.height = height;
      out.words.resize(count);
      in.seekg(0);
      std::vector<unsigned char> raw(bytes);
      in.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(bytes));
      if (!in) {
        error = "can't read " + file.string();
        return false;
      }
      for (std::size_t i = 0; i < count; ++i) {
        out.words[i] = static_cast<std::uint16_t>(raw[i * 2] | (raw[i * 2 + 1] << 8));
      }
      return true;
    }

    bool ReadImage(const std::filesystem::path& file, HeightImage& out, std::string& error)
    {
      const ComScope com;
      ComPtr<IWICImagingFactory> factory;
      HRESULT hr = ::CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory.p));
      ComPtr<IWICBitmapDecoder> decoder;
      if (SUCCEEDED(hr)) {
        hr = factory->CreateDecoderFromFilename(file.wstring().c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder);
      }
      ComPtr<IWICBitmapFrameDecode> frame;
      if (SUCCEEDED(hr)) {
        hr = decoder->GetFrame(0, &frame);
      }
      ComPtr<IWICFormatConverter> converter;
      if (SUCCEEDED(hr)) {
        hr = factory->CreateFormatConverter(&converter);
      }
      if (SUCCEEDED(hr)) {
        hr = converter->Initialize(frame.p, GUID_WICPixelFormat16bppGray, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom);
      }
      UINT width = 0;
      UINT height = 0;
      if (SUCCEEDED(hr)) {
        hr = converter->GetSize(&width, &height);
      }
      if (FAILED(hr) || width < 2 || height < 2) {
        error = "can't read " + file.filename().string() + " as an image (" + HResultText(hr) + ")";
        return false;
      }
      out.width = static_cast<int>(width);
      out.height = static_cast<int>(height);
      out.words.resize(static_cast<std::size_t>(width) * height);
      hr = converter->CopyPixels(nullptr, width * 2, static_cast<UINT>(out.words.size() * 2), reinterpret_cast<BYTE*>(out.words.data()));
      if (FAILED(hr)) {
        error = "can't read the pixels of " + file.filename().string() + " (" + HResultText(hr) + ")";
        return false;
      }
      return true;
    }

    bool WritePng(const std::filesystem::path& file, const HeightImage& image, std::string& error)
    {
      const ComScope com;
      ComPtr<IWICImagingFactory> factory;
      HRESULT hr = ::CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory.p));
      ComPtr<IWICStream> stream;
      if (SUCCEEDED(hr)) {
        hr = factory->CreateStream(&stream);
      }
      if (SUCCEEDED(hr)) {
        hr = stream->InitializeFromFilename(file.wstring().c_str(), GENERIC_WRITE);
      }
      ComPtr<IWICBitmapEncoder> encoder;
      if (SUCCEEDED(hr)) {
        hr = factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder);
      }
      if (SUCCEEDED(hr)) {
        hr = encoder->Initialize(stream.p, WICBitmapEncoderNoCache);
      }
      ComPtr<IWICBitmapFrameEncode> frame;
      if (SUCCEEDED(hr)) {
        hr = encoder->CreateNewFrame(&frame, nullptr);
      }
      if (SUCCEEDED(hr)) {
        hr = frame->Initialize(nullptr);
      }
      if (SUCCEEDED(hr)) {
        hr = frame->SetSize(static_cast<UINT>(image.width), static_cast<UINT>(image.height));
      }
      WICPixelFormatGUID format = GUID_WICPixelFormat16bppGray;
      if (SUCCEEDED(hr)) {
        hr = frame->SetPixelFormat(&format);
      }
      if (SUCCEEDED(hr) && format != GUID_WICPixelFormat16bppGray) {
        hr = E_FAIL;
      }
      if (SUCCEEDED(hr)) {
        hr = frame->WritePixels(static_cast<UINT>(image.height), static_cast<UINT>(image.width) * 2, static_cast<UINT>(image.words.size() * 2),
                                reinterpret_cast<BYTE*>(const_cast<std::uint16_t*>(image.words.data())));
      }
      if (SUCCEEDED(hr)) {
        hr = frame->Commit();
      }
      if (SUCCEEDED(hr)) {
        hr = encoder->Commit();
      }
      if (FAILED(hr)) {
        error = "can't write " + file.string() + " (" + HResultText(hr) + ")";
        return false;
      }
      return true;
    }
  } // namespace

  bool ReadHeightImage(const std::filesystem::path& file, const int expectWidth, const int expectHeight, HeightImage& out, std::string& error)
  {
    out = {};
    return IsRaw(file) ? ReadRaw(file, expectWidth, expectHeight, out, error) : ReadImage(file, out, error);
  }

  bool WriteHeightImage(const std::filesystem::path& file, const HeightImage& image, std::string& error)
  {
    if (image.width < 1 || image.height < 1 || image.words.size() != static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height)) {
      error = "no heights to write";
      return false;
    }
    if (IsRaw(file)) {
      std::vector<unsigned char> raw(image.words.size() * 2);
      for (std::size_t i = 0; i < image.words.size(); ++i) {
        raw[i * 2] = static_cast<unsigned char>(image.words[i] & 0xFFu);
        raw[i * 2 + 1] = static_cast<unsigned char>(image.words[i] >> 8);
      }
      std::ofstream out(file, std::ios::binary);
      out.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
      if (!out) {
        error = "can't write " + file.string();
        return false;
      }
      return true;
    }
    if (Lower(file.extension().string()) != ".png") {
      error = "heights are written as .png, .raw or .r16";
      return false;
    }
    return WritePng(file, image, error);
  }

  HeightImage ResampleHeights(const HeightImage& image, const int width, const int height)
  {
    if (image.width == width && image.height == height) {
      return image;
    }
    HeightImage out;
    out.width = width;
    out.height = height;
    out.words.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height));
    const double stepX = width > 1 ? static_cast<double>(image.width - 1) / (width - 1) : 0.0;
    const double stepZ = height > 1 ? static_cast<double>(image.height - 1) / (height - 1) : 0.0;
    const auto at = [&](const int x, const int z) {
      return static_cast<double>(image.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(image.width) + static_cast<std::size_t>(x)]);
    };
    for (int z = 0; z < height; ++z) {
      const double pz = z * stepZ;
      const int z0 = std::min(image.height - 1, static_cast<int>(pz));
      const int z1 = std::min(image.height - 1, z0 + 1);
      const double fz = pz - z0;
      for (int x = 0; x < width; ++x) {
        const double px = x * stepX;
        const int x0 = std::min(image.width - 1, static_cast<int>(px));
        const int x1 = std::min(image.width - 1, x0 + 1);
        const double fx = px - x0;
        const double value = (at(x0, z0) * (1.0 - fx) + at(x1, z0) * fx) * (1.0 - fz) + (at(x0, z1) * (1.0 - fx) + at(x1, z1) * fx) * fz;
        out.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] =
          static_cast<std::uint16_t>(std::lround(std::clamp(value, 0.0, 65535.0)));
      }
    }
    return out;
  }

  void ScaleHeights(HeightImage& image, const float scale)
  {
    if (scale == 1.0f) {
      return;
    }
    for (std::uint16_t& word : image.words) {
      word = static_cast<std::uint16_t>(std::lround(std::clamp(static_cast<double>(word) * scale, 0.0, 65535.0)));
    }
  }
} // namespace faf::editor
