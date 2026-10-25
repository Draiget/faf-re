#pragma once

// FAF addition, not in the shipped binary.
//
// Texture file decoding and encoding for the backends whose API has no D3DX
// (Direct3D 12, Vulkan). It runs the same D3DX11 code the Direct3D 11 backend
// loads textures with (d3dx11_43.dll), on a private WARP Direct3D 11 device,
// and hands back the decoded levels in CPU memory - so every backend sees
// identical texels for the same file.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <dxgiformat.h>
#include <windows.h>

namespace gpg::gal::imaging
{
  /** A decoded image: every subresource, tightly packed. */
  struct Image
  {
    struct Subresource
    {
      std::size_t offset = 0;     // into `bytes`
      std::uint32_t width = 0;
      std::uint32_t height = 0;
      std::uint32_t depth = 1;
      std::uint32_t rowPitch = 0; // bytes per row (per row of 4x4 blocks when block compressed)
      std::uint32_t rowCount = 0;
      std::uint32_t slicePitch = 0;
    };

    DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t depth = 1;     // volume textures
    std::uint32_t mipLevels = 1;
    std::uint32_t arraySize = 1; // 6 for a cube
    bool cube = false;
    bool volume = false;
    std::vector<Subresource> subresources; // array slice major: [slice * mipLevels + mip]
    std::vector<std::uint8_t> bytes;

    /** Lays out empty storage for the given shape. */
    void Allocate(DXGI_FORMAT imageFormat, std::uint32_t imageWidth, std::uint32_t imageHeight, std::uint32_t levels, std::uint32_t slices);
  };

  struct DecodeOptions
  {
    std::uint32_t skipMipLevels = 0;           // D3DX "first mip level"
    DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;  // UNKNOWN: as the file
    std::uint32_t width = 0;                   // 0: as the file
    std::uint32_t height = 0;
    std::uint32_t mipLevels = 0;               // 0: as the file
  };

  /** D3DX11_IMAGE_FILE_FORMAT values. */
  enum class FileFormat : int
  {
    Bmp = 0,
    Jpg = 1,
    Png = 3,
    Dds = 4,
  };

  /**
   * Engine addition: DDS files holding BC1/BC2/BC3 (DXT1/3/5) data with a full mip chain, 2D
   * or cube, are read straight into the image instead of through D3DX11 on the WARP device,
   * which took 25-45 ms for each 1024x1024 unit texture and serialised every load behind one
   * lock. The result has the same format, shape and bytes, except in the levels under 4x4,
   * where D3DX11's round trip changes a few bytes and this keeps the file's
   * (`FAF_IMAGECODEC_VERIFY=1` decodes both ways and logs any other difference). Console
   * variable `ren_DdsDirectLoad`; 0 sends every file through D3DX11.
   */
  extern bool gDdsDirectLoad;

  /**
   * Engine addition: a texture D3DX11 took more than 8 ms to decode (mostly the original
   * game's textures without mip levels, whose chain D3DX11 builds and BC-compresses again on
   * the CPU, 30-40 ms each) is kept in the shader cache directory under a hash of the file's
   * bytes and the decode options, and the next session reads it back instead. The cached
   * image is D3DX11's own output, so the texels are the same. Console variable
   * `ren_TextureDecodeCache`; 0 decodes every time.
   */
  extern bool gTextureDecodeCache;

  class ImageCodec
  {
  public:
    /** The process-wide codec; nullptr when d3dx11_43.dll or a WARP device is not available. */
    [[nodiscard]] static ImageCodec* Instance();

    ~ImageCodec();
    ImageCodec(const ImageCodec&) = delete;
    ImageCodec& operator=(const ImageCodec&) = delete;

    /** Decodes a texture file (DDS, PNG, BMP, JPG, TGA ...). */
    HRESULT Decode(const void* data, std::size_t bytes, const DecodeOptions& options, Image& outImage);

    /** Encodes `image` (its first array slice) as an image file. */
    HRESULT Encode(const Image& image, FileFormat format, std::vector<std::uint8_t>& outBytes);
    HRESULT EncodeToFile(const Image& image, FileFormat format, const char* path);

    /** gal image file format (BMP, JPG, PNG, PNG, DDS) -> FileFormat. */
    [[nodiscard]] static FileFormat FromGalFormat(int galFormat) noexcept;

  private:
    ImageCodec() = default;
    [[nodiscard]] bool Load();
    HRESULT DecodeWithD3dx(const void* data, std::size_t bytes, const DecodeOptions& options, Image& outImage);

    struct State;
    std::unique_ptr<State> mState;
    std::mutex mMutex;
  };
} // namespace gpg::gal::imaging
