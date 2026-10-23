#pragma once

// FAF addition, not in the shipped binary: the gal <-> DXGI format tables
// shared by the Direct3D 11 and Direct3D 12 backends (Vulkan maps from DXGI).

#include <cstdint>

#include <dxgiformat.h>

namespace gpg::gal::dxgi
{
  /**
   * gal texture format -> DXGI. Unlike the D3D10 table this maps the D3D9
   * 32-bit formats onto the BGRA DXGI formats Direct3D 11 supports, so data
   * the engine writes in D3D9 byte order (A8R8G8B8 = B,G,R,A) uploads as is.
   */
  [[nodiscard]] DXGI_FORMAT TextureFormatToDxgi(std::uint32_t galFormat) noexcept;

  /** DXGI -> gal texture format; 20 (the D3D10 table's "unsupported") when there is none. */
  [[nodiscard]] std::uint32_t DxgiToTextureFormat(DXGI_FORMAT format) noexcept;

  /** gal render-target format -> DXGI (the D3D10 table, BGRA where D3D9 was ARGB). */
  [[nodiscard]] DXGI_FORMAT RenderTargetFormatToDxgi(std::uint32_t galFormat) noexcept;

  /** DXGI -> gal render-target format; 8 when there is none (as the D3D10 table). */
  [[nodiscard]] std::uint32_t DxgiToRenderTargetFormat(DXGI_FORMAT format) noexcept;

  /** The three formats one depth target needs. */
  struct DepthFormats
  {
    DXGI_FORMAT texture = DXGI_FORMAT_UNKNOWN; // typeless when the target is sampled
    DXGI_FORMAT depthView = DXGI_FORMAT_UNKNOWN;
    DXGI_FORMAT shaderView = DXGI_FORMAT_UNKNOWN;
  };

  /** gal depth-stencil format -> DXGI; `sampled` asks for a typeless texture. */
  [[nodiscard]] DepthFormats DepthStencilFormatToDxgi(std::uint32_t galFormat, bool sampled) noexcept;

  /** Bytes per texel, or per 4x4 block for block-compressed formats; 0 if unknown. */
  [[nodiscard]] std::uint32_t FormatElementBytes(DXGI_FORMAT format) noexcept;

  /** True for the BC formats (4x4 blocks). */
  [[nodiscard]] bool IsBlockCompressed(DXGI_FORMAT format) noexcept;

  /** Row pitch and row count of one mip level of a `width` x `height` image. */
  struct LevelLayout
  {
    std::uint32_t rowPitch = 0;
    std::uint32_t rowCount = 0;
    [[nodiscard]] std::uint32_t ByteSize() const noexcept { return rowPitch * rowCount; }
  };

  [[nodiscard]] LevelLayout ComputeLevelLayout(DXGI_FORMAT format, std::uint32_t width, std::uint32_t height) noexcept;
} // namespace gpg::gal::dxgi
