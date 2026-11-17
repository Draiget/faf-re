#pragma once

// FAF addition, not in the shipped binary: BC1, BC2 and BC3 (the game's DXT1, DXT3 and DXT5) decoded on the
// CPU, for a Vulkan device without BC textures (DeviceVulkan::CreateTexture), as phones' GPUs mostly are.
//
// The decode is Direct3D's (the Direct3D 11 functional specification, BC1 to BC3) as WARP, Direct3D's software
// rasterizer, does it, texel for texel (tests/image_codec/BlockCompressionWarpTests.cpp): the endpoints expand
// from 5 and 6 bits by repeating their top bits, the colours between are weighted in 256ths (171 and 85) and
// truncated, a BC1 block's half is the truncated mean, and the alphas between are the exact means rounded to
// the nearest. DirectXTex's Decompress, which the codec has, interpolates in floats and rounds, which puts
// channels 1 or 2 apart from that, and is slower, which a device without BC textures pays for every texture a
// map loads. Encoding, which only readbacks need, is DirectXTex's (EncodeBc123WithDirectXTex).

#include <cstddef>
#include <cstdint>

#include <dxgiformat.h>

namespace gpg::gal::imaging
{
  /** BC1, BC2 or BC3 in any of its typeless, UNORM and sRGB forms. */
  [[nodiscard]] bool IsBc123(DXGI_FORMAT format) noexcept;

  /**
   * Decodes a level of `width` x `height` texels in `format` (IsBc123), stored as whole 4x4 blocks with
   * `rowPitch` bytes per row of blocks, into `rgba`: R8G8B8A8, `width` * 4 bytes per row. Texels of partial
   * blocks beyond the level are not written.
   */
  void DecodeBc123(
    DXGI_FORMAT format,
    const void* blocks,
    std::size_t rowPitch,
    std::uint32_t width,
    std::uint32_t height,
    std::uint8_t* rgba
  ) noexcept;
} // namespace gpg::gal::imaging
