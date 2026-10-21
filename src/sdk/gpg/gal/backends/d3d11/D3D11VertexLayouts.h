#pragma once

// FAF addition, not in the shipped binary.

#include <cstdint>
#include <span>

#include <d3d11.h>

namespace gpg::gal::d3d11
{
  /** Number of gal vertex formats (`VertexFormatD3D10.cpp` accepts 0..23). */
  inline constexpr std::uint32_t kVertexFormatCount = 24U;

  /**
   * The input-layout elements of gal vertex format `format`, numbered as the
   * engine and the D3D9 backend number them: the D3D10 backend's tables
   * (0x00F311F8 / 0x00D44940 in the shipped binary) for 0..16 - in D3D10's
   * element forms, which the D3D10-dialect shaders expect - and D3D9's
   * declarations for 17..22, where the D3D10 table runs one code short.
   * Format 23 has no layout; an out-of-range format throws.
   */
  [[nodiscard]] std::span<const D3D11_INPUT_ELEMENT_DESC> VertexLayoutElements(std::uint32_t format);
} // namespace gpg::gal::d3d11
