#include "editor/tools/EdHeightFile.h"

#include <cstring>
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
    [[nodiscard]] std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    [[nodiscard]] bool IsRaw(
      const std::filesystem::path& file
    )
    {
      const std::string extension = Lower(file.extension().string());
      return extension == ".raw" || extension == ".r16";
    }

    [[nodiscard]] std::string HResultText(
      const HRESULT result
    )
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
      T** operator&()
      {
        return &p;
      }
      T* operator->() const
      {
        return p;
      }
    };

    /** `.r32`: 32-bit little-endian floats, square or of the expected size (Gaea's and World Machine's float export).
     */
    std::expected<HeightImage, std::string> ReadFloats(
      const std::filesystem::path& file,
      const int expectWidth,
      const int expectHeight
    )
    {
      std::ifstream in(file, std::ios::binary | std::ios::ate);
      if (!in) {
        return std::unexpected("can't open " + file.string());
      }
      const auto bytes = static_cast<std::size_t>(in.tellg());
      const std::size_t count = bytes / 4;
      int width = 0;
      int height = 0;
      if (
        expectWidth > 0 && expectHeight > 0 &&
        count == static_cast<std::size_t>(expectWidth) * static_cast<std::size_t>(expectHeight)
      ) {
        width = expectWidth;
        height = expectHeight;
      } else {
        const auto side = static_cast<int>(std::lround(std::sqrt(static_cast<double>(count))));
        if (bytes % 4 != 0 || static_cast<std::size_t>(side) * static_cast<std::size_t>(side) != count || side < 2) {
          return std::unexpected(
            file.filename().string() + " is " + std::to_string(bytes) +
            " bytes: not a square of 32-bit heights, nor the map's size"
          );
        }
        width = side;
        height = side;
      }
      std::vector<float> floats(count);
      in.seekg(0);
      in.read(reinterpret_cast<char*>(floats.data()), static_cast<std::streamsize>(count * 4));
      if (!in) {
        return std::unexpected("can't read " + file.string());
      }
      // 0..1 is the tools' normalised range; anything above 1 is read as game units (128 words a unit).
      bool normalised = true;
      for (const float value : floats) {
        normalised = normalised && value <= 1.0001f;
      }
      HeightImage out;
      out.width = width;
      out.height = height;
      out.words.resize(count);
      for (std::size_t i = 0; i < count; ++i) {
        const double word = normalised ? floats[i] * 65535.0 : floats[i] * 128.0;
        out.words[i] =
          static_cast<std::uint16_t>(std::lround(std::clamp(std::isfinite(word) ? word : 0.0, 0.0, 65535.0)));
      }
      return out;
    }

    std::expected<HeightImage, std::string> ReadRaw(
      const std::filesystem::path& file,
      const int expectWidth,
      const int expectHeight
    )
    {
      std::ifstream in(file, std::ios::binary | std::ios::ate);
      if (!in) {
        return std::unexpected("can't open " + file.string());
      }
      const auto bytes = static_cast<std::size_t>(in.tellg());
      const std::size_t count = bytes / 2;
      int width = 0;
      int height = 0;
      if (
        expectWidth > 0 && expectHeight > 0 &&
        count == static_cast<std::size_t>(expectWidth) * static_cast<std::size_t>(expectHeight)
      ) {
        width = expectWidth;
        height = expectHeight;
      } else {
        const auto side = static_cast<int>(std::lround(std::sqrt(static_cast<double>(count))));
        if (bytes % 2 != 0 || static_cast<std::size_t>(side) * static_cast<std::size_t>(side) != count || side < 2) {
          return std::unexpected(
            file.filename().string() + " is " + std::to_string(bytes) +
            " bytes: not a square of 16-bit heights, nor the map's size"
          );
        }
        width = side;
        height = side;
      }
      HeightImage out;
      out.width = width;
      out.height = height;
      out.words.resize(count);
      in.seekg(0);
      std::vector<unsigned char> raw(bytes);
      in.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(bytes));
      if (!in) {
        return std::unexpected("can't read " + file.string());
      }
      for (std::size_t i = 0; i < count; ++i) {
        out.words[i] = static_cast<std::uint16_t>(raw[i * 2] | (raw[i * 2 + 1] << 8));
      }
      return out;
    }

    std::expected<HeightImage, std::string> ReadImage(
      const std::filesystem::path& file
    )
    {
      const ComScope com;
      ComPtr<IWICImagingFactory> factory;
      HRESULT hr = ::CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory.p));
      ComPtr<IWICBitmapDecoder> decoder;
      if (SUCCEEDED(hr)) {
        hr = factory->CreateDecoderFromFilename(
          file.wstring().c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder
        );
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
        hr = converter->Initialize(
          frame.p, GUID_WICPixelFormat16bppGray, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom
        );
      }
      UINT width = 0;
      UINT height = 0;
      if (SUCCEEDED(hr)) {
        hr = converter->GetSize(&width, &height);
      }
      if (FAILED(hr) || width < 2 || height < 2) {
        return std::unexpected("can't read " + file.filename().string() + " as an image (" + HResultText(hr) + ")");
      }
      HeightImage out;
      out.width = static_cast<int>(width);
      out.height = static_cast<int>(height);
      out.words.resize(static_cast<std::size_t>(width) * height);
      hr = converter->CopyPixels(
        nullptr, width * 2, static_cast<UINT>(out.words.size() * 2), reinterpret_cast<BYTE*>(out.words.data())
      );
      if (FAILED(hr)) {
        return std::unexpected("can't read the pixels of " + file.filename().string() + " (" + HResultText(hr) + ")");
      }
      return out;
    }

    std::expected<void, std::string> WritePng(
      const std::filesystem::path& file,
      const HeightImage& image,
      const bool eightBit = false
    )
    {
      const std::string extension = Lower(file.extension().string());
      const bool tiff = extension == ".tif" || extension == ".tiff";
      std::vector<std::uint8_t> bytes;
      if (eightBit) {
        bytes.resize(image.words.size());
        for (std::size_t i = 0; i < image.words.size(); ++i) {
          bytes[i] = static_cast<std::uint8_t>(image.words[i] >> 8);
        }
      }
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
        hr = factory->CreateEncoder(tiff ? GUID_ContainerFormatTiff : GUID_ContainerFormatPng, nullptr, &encoder);
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
      const WICPixelFormatGUID wanted = eightBit ? GUID_WICPixelFormat8bppGray : GUID_WICPixelFormat16bppGray;
      WICPixelFormatGUID format = wanted;
      if (SUCCEEDED(hr)) {
        hr = frame->SetPixelFormat(&format);
      }
      if (SUCCEEDED(hr) && format != wanted) {
        hr = E_FAIL;
      }
      if (SUCCEEDED(hr)) {
        hr = eightBit ? frame->WritePixels(
                          static_cast<UINT>(image.height),
                          static_cast<UINT>(image.width),
                          static_cast<UINT>(bytes.size()),
                          reinterpret_cast<BYTE*>(bytes.data())
                        )
                      : frame->WritePixels(
                          static_cast<UINT>(image.height),
                          static_cast<UINT>(image.width) * 2,
                          static_cast<UINT>(image.words.size() * 2),
                          reinterpret_cast<BYTE*>(const_cast<std::uint16_t*>(image.words.data()))
                        );
      }
      if (SUCCEEDED(hr)) {
        hr = frame->Commit();
      }
      if (SUCCEEDED(hr)) {
        hr = encoder->Commit();
      }
      if (FAILED(hr)) {
        return std::unexpected("can't write " + file.string() + " (" + HResultText(hr) + ")");
      }
      return {};
    }
  } // namespace

  std::expected<void, std::string> WriteColourPng(
    const std::filesystem::path& file,
    const int width,
    const int height,
    const std::vector<std::uint32_t>& bgra
  )
  {
    if (width <= 0 || height <= 0 || bgra.size() != static_cast<std::size_t>(width) * height) {
      return std::unexpected("no picture to write");
    }
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
      hr = frame->SetSize(static_cast<UINT>(width), static_cast<UINT>(height));
    }
    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    if (SUCCEEDED(hr)) {
      hr = frame->SetPixelFormat(&format);
    }
    if (SUCCEEDED(hr) && format != GUID_WICPixelFormat32bppBGRA) {
      hr = E_FAIL;
    }
    if (SUCCEEDED(hr)) {
      hr = frame->WritePixels(
        static_cast<UINT>(height),
        static_cast<UINT>(width) * 4,
        static_cast<UINT>(bgra.size() * 4),
        reinterpret_cast<BYTE*>(const_cast<std::uint32_t*>(bgra.data()))
      );
    }
    if (SUCCEEDED(hr)) {
      hr = frame->Commit();
    }
    if (SUCCEEDED(hr)) {
      hr = encoder->Commit();
    }
    if (FAILED(hr)) {
      return std::unexpected("can't write " + file.string() + " (" + HResultText(hr) + ")");
    }
    return {};
  }

  std::expected<HeightImage, std::string> ReadHeightImage(
    const std::filesystem::path& file,
    const int expectWidth,
    const int expectHeight
  )
  {
    if (Lower(file.extension().string()) == ".r32") {
      return ReadFloats(file, expectWidth, expectHeight);
    }
    return IsRaw(file) ? ReadRaw(file, expectWidth, expectHeight) : ReadImage(file);
  }

  std::expected<void, std::string> WriteHeightImage(
    const std::filesystem::path& file,
    const HeightImage& image,
    const bool eightBit
  )
  {
    if (
      image.width < 1 || image.height < 1 ||
      image.words.size() != static_cast<std::size_t>(image.width) * static_cast<std::size_t>(image.height)
    ) {
      return std::unexpected("no heights to write");
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
        return std::unexpected("can't write " + file.string());
      }
      return {};
    }
    const std::string extension = Lower(file.extension().string());
    if (extension == ".r32") {
      std::vector<float> floats(image.words.size());
      for (std::size_t i = 0; i < image.words.size(); ++i) {
        floats[i] = static_cast<float>(image.words[i]) / 65535.0f;
      }
      std::ofstream out(file, std::ios::binary);
      out.write(reinterpret_cast<const char*>(floats.data()), static_cast<std::streamsize>(floats.size() * 4));
      if (!out) {
        return std::unexpected("can't write " + file.string());
      }
      return {};
    }
    if (extension != ".png" && extension != ".tif" && extension != ".tiff") {
      return std::unexpected("heights are written as .png, .tif, .raw, .r16 or .r32");
    }
    return WritePng(file, image, eightBit);
  }

  std::expected<void, std::string> WriteFloatImage(
    const std::filesystem::path& file,
    const int width,
    const int height,
    const std::vector<float>& values
  )
  {
    if (
      width < 1 || height < 1 || values.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height)
    ) {
      return std::unexpected("no values to write");
    }
    const std::string extension = Lower(file.extension().string());
    if (extension == ".r32") {
      std::ofstream out(file, std::ios::binary);
      out.write(reinterpret_cast<const char*>(values.data()), static_cast<std::streamsize>(values.size() * 4));
      if (!out) {
        return std::unexpected("can't write " + file.string());
      }
      return {};
    }
    if (extension != ".tif" && extension != ".tiff") {
      return std::unexpected("32-bit floats are written as .tif or .r32");
    }
    // A baseline TIFF written by hand (the Windows TIFF encoder offers no float grey): little-endian, one uncompressed
    // strip of 32-bit floats (SampleFormat 3), grey with black at zero.
    std::vector<std::uint8_t> out;
    const auto put16 = [&](const std::uint32_t v) {
      out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
      out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    };
    const auto put32 = [&](const std::uint32_t v) {
      put16(v & 0xFFFFu);
      put16(v >> 16);
    };
    const std::uint32_t bytes = static_cast<std::uint32_t>(values.size() * 4);
    const std::uint32_t dataAt = 8;
    const std::uint32_t ifdAt = dataAt + bytes + (bytes & 1u);
    out.insert(out.end(), {'I', 'I', 42, 0});
    put32(ifdAt);
    const std::size_t data = out.size();
    out.resize(data + bytes);
    std::memcpy(out.data() + data, values.data(), bytes);
    if ((bytes & 1u) != 0u) {
      out.push_back(0);
    }
    struct Tag
    {
      std::uint16_t id;
      std::uint16_t type; // 3 SHORT, 4 LONG
      std::uint32_t value;
    };
    const Tag tags[] = {
      {256, 4, static_cast<std::uint32_t>(width)},  // ImageWidth
      {257, 4, static_cast<std::uint32_t>(height)}, // ImageLength
      {258, 3, 32},                                 // BitsPerSample
      {259, 3, 1},                                  // Compression: none
      {262, 3, 1},                                  // PhotometricInterpretation: black is zero
      {273, 4, dataAt},                             // StripOffsets
      {277, 3, 1},                                  // SamplesPerPixel
      {278, 4, static_cast<std::uint32_t>(height)}, // RowsPerStrip
      {279, 4, bytes},                              // StripByteCounts
      {284, 3, 1},                                  // PlanarConfiguration: chunky
      {339, 3, 3},                                  // SampleFormat: IEEE float
    };
    put16(static_cast<std::uint32_t>(std::size(tags)));
    for (const Tag& tag : tags) {
      put16(tag.id);
      put16(tag.type);
      put32(1);
      if (tag.type == 3) {
        put16(tag.value);
        put16(0);
      } else {
        put32(tag.value);
      }
    }
    put32(0); // no next IFD
    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!stream) {
      return std::unexpected("can't write " + file.string());
    }
    return {};
  }

  const char* ResampleFilterName(
    const ResampleFilter filter
  ) noexcept
  {
    switch (filter) {
    case ResampleFilter::Nearest:
      return "Nearest";
    case ResampleFilter::Bicubic:
      return "Bicubic";
    case ResampleFilter::Lanczos3:
      return "Lanczos 3";
    default:
      return "Bilinear";
    }
  }

  HeightImage ResampleHeights(
    const HeightImage& image,
    const int width,
    const int height,
    const ResampleFilter filter
  )
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
      return static_cast<double>(
        image.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(image.width) + static_cast<std::size_t>(x)]
      );
    };
    if (filter != ResampleFilter::Bilinear) {
      // Separable kernels over the source samples (clamped at the edges); shrinking widens the kernel by the step so
      // it low-passes instead of skipping samples (FAF Studio's resampler does the same).
      const int taps = filter == ResampleFilter::Nearest ? 0 : filter == ResampleFilter::Bicubic ? 2 : 3;
      const auto kernel = [filter](const double t) {
        const double a = std::fabs(t);
        if (filter == ResampleFilter::Bicubic) {
          constexpr double b = -0.5; // Catmull-Rom
          return a <= 1.0 ? (b + 2.0) * a * a * a - (b + 3.0) * a * a + 1.0
            : a < 2.0     ? b * a * a * a - 5.0 * b * a * a + 8.0 * b * a - 4.0 * b
                          : 0.0;
        }
        if (a < 1.0e-9) {
          return 1.0;
        }
        if (a >= 3.0) {
          return 0.0;
        }
        constexpr double pi = 3.14159265358979323846;
        return 3.0 * std::sin(pi * a) * std::sin(pi * a / 3.0) / (pi * pi * a * a);
      };
      const double scaleX = std::max(1.0, stepX);
      const double scaleZ = std::max(1.0, stepZ);
      for (int z = 0; z < height; ++z) {
        const double pz = z * stepZ;
        for (int x = 0; x < width; ++x) {
          const double px = x * stepX;
          double value = 0.0;
          if (taps == 0) {
            value = at(
              std::clamp(static_cast<int>(std::lround(px)), 0, image.width - 1),
              std::clamp(static_cast<int>(std::lround(pz)), 0, image.height - 1)
            );
          } else {
            double sum = 0.0;
            double total = 0.0;
            const int reachX = static_cast<int>(std::ceil(taps * scaleX));
            const int reachZ = static_cast<int>(std::ceil(taps * scaleZ));
            const int bx = static_cast<int>(std::floor(px));
            const int bz = static_cast<int>(std::floor(pz));
            for (int sz = bz - reachZ + 1; sz <= bz + reachZ; ++sz) {
              const double wz = kernel((pz - sz) / scaleZ);
              if (wz == 0.0) {
                continue;
              }
              for (int sx = bx - reachX + 1; sx <= bx + reachX; ++sx) {
                const double weight = wz * kernel((px - sx) / scaleX);
                if (weight == 0.0) {
                  continue;
                }
                sum += weight * at(std::clamp(sx, 0, image.width - 1), std::clamp(sz, 0, image.height - 1));
                total += weight;
              }
            }
            value = total != 0.0 ? sum / total : 0.0;
          }
          out.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] =
            static_cast<std::uint16_t>(std::lround(std::clamp(value, 0.0, 65535.0)));
        }
      }
      return out;
    }
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
        const double value =
          (at(x0, z0) * (1.0 - fx) + at(x1, z0) * fx) * (1.0 - fz) + (at(x0, z1) * (1.0 - fx) + at(x1, z1) * fx) * fz;
        out.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] =
          static_cast<std::uint16_t>(std::lround(std::clamp(value, 0.0, 65535.0)));
      }
    }
    return out;
  }

  void ScaleHeights(
    HeightImage& image,
    const float scale
  )
  {
    if (scale == 1.0f) {
      return;
    }
    for (std::uint16_t& word : image.words) {
      word = static_cast<std::uint16_t>(std::lround(std::clamp(static_cast<double>(word) * scale, 0.0, 65535.0)));
    }
  }

  std::expected<HeightImage, std::string> ReadHeightImageWith(
    const std::filesystem::path& file,
    const int expectWidth,
    const int expectHeight,
    const HeightReadOptions& options
  )
  {
    const std::string extension = Lower(file.extension().string());
    const bool rawFile = extension == ".raw" || extension == ".r16" || extension == ".r32";
    const bool plainRaw = options.rawBits == (extension == ".r32" ? 32 : 16) &&
      options.rawFloat == (extension == ".r32") && !options.bigEndian && options.rawWidth <= 0;
    if (rawFile && !plainRaw) {
      // A raw file laid out as asked: samples of rawBits, whole or float, in either byte order.
      std::ifstream in(file, std::ios::binary | std::ios::ate);
      if (!in) {
        return std::unexpected("can't open " + file.string());
      }
      const auto bytes = static_cast<std::size_t>(in.tellg());
      in.seekg(0);
      std::vector<std::uint8_t> data(bytes);
      in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(bytes));
      const int size = std::max(1, options.rawBits / 8);
      const std::size_t count = bytes / static_cast<std::size_t>(size);
      int width = options.rawWidth;
      int height = options.rawHeight > 0 ? options.rawHeight : options.rawWidth;
      if (width <= 0) {
        if (
          expectWidth > 0 && count == static_cast<std::size_t>(expectWidth) * static_cast<std::size_t>(expectHeight)
        ) {
          width = expectWidth;
          height = expectHeight;
        } else {
          width = height = static_cast<int>(std::lround(std::sqrt(static_cast<double>(count))));
        }
      }
      if (width < 2 || height < 2 || static_cast<std::size_t>(width) * static_cast<std::size_t>(height) > count) {
        return std::unexpected(
          file.filename().string() + " holds " + std::to_string(count) + " samples, not " + std::to_string(width) +
          " x " + std::to_string(height)
        );
      }
      HeightImage out;
      out.width = width;
      out.height = height;
      out.words.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height));
      for (std::size_t i = 0; i < out.words.size(); ++i) {
        std::uint32_t v = 0;
        for (int b = 0; b < size; ++b) {
          const std::uint32_t byte = data[i * static_cast<std::size_t>(size) + static_cast<std::size_t>(b)];
          v |= options.bigEndian ? byte << (8 * (size - 1 - b)) : byte << (8 * b);
        }
        double word = 0.0;
        if (options.rawFloat && size == 4) {
          float f = 0.0f;
          std::memcpy(&f, &v, 4);
          word = std::clamp(static_cast<double>(f), 0.0, 1.0) * 65535.0;
        } else {
          word = static_cast<double>(v) / static_cast<double>((std::uint64_t{1} << (8 * size)) - 1) * 65535.0;
        }
        out.words[i] = static_cast<std::uint16_t>(std::clamp(std::lround(word), 0L, 65535L));
      }
      return out;
    }
    if (options.channel <= 0 || rawFile) {
      return ReadHeightImage(file, expectWidth, expectHeight);
    }
    // One channel of a colour picture (a splat's red, a mask in the alpha).
    const ComScope com;
    ComPtr<IWICImagingFactory> factory;
    HRESULT hr = ::CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory.p));
    ComPtr<IWICBitmapDecoder> decoder;
    if (SUCCEEDED(hr)) {
      hr = factory->CreateDecoderFromFilename(
        file.wstring().c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder
      );
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
      hr = converter->Initialize(
        frame.p, GUID_WICPixelFormat64bppRGBA, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom
      );
    }
    UINT width = 0;
    UINT height = 0;
    if (SUCCEEDED(hr)) {
      hr = converter->GetSize(&width, &height);
    }
    if (FAILED(hr) || width < 2 || height < 2) {
      return std::unexpected("can't read " + file.filename().string() + " as a colour image (" + HResultText(hr) + ")");
    }
    std::vector<std::uint16_t> rgba(static_cast<std::size_t>(width) * height * 4);
    hr = converter->CopyPixels(
      nullptr, width * 8, static_cast<UINT>(rgba.size() * 2), reinterpret_cast<BYTE*>(rgba.data())
    );
    if (FAILED(hr)) {
      return std::unexpected("can't read the pixels of " + file.filename().string() + " (" + HResultText(hr) + ")");
    }
    HeightImage out;
    out.width = static_cast<int>(width);
    out.height = static_cast<int>(height);
    out.words.resize(static_cast<std::size_t>(width) * height);
    const int c = std::clamp(options.channel, 1, 4) - 1;
    for (std::size_t i = 0; i < out.words.size(); ++i) {
      out.words[i] = rgba[i * 4 + static_cast<std::size_t>(c)];
    }
    return out;
  }
} // namespace faf::editor
