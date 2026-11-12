#pragma once

#include "editor/graph/EdTextureGraph.h"

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** How a texture graph's image is written. */
  enum class DdsKind : std::uint8_t
  {
    Bgra, // uncompressed 32-bit: the live preview (no encoding time)
    Bc1,  // DXT1: opaque images (normal maps)
    Bc3,  // DXT5: with alpha (a stratum's albedo, its alpha the shader's)
  };

  /**
   * An image as a DDS file with a full mip chain (each level the box average of the one above, wrapping, as the image
   * tiles), with the classic header the game's Direct3D 9 decoder reads (ImageCodec::WriteDds). Grey images are
   * written as grey RGB. False with `error` when the encoder fails.
   */
  bool EncodeDds(const TexImage& image, DdsKind kind, std::vector<std::uint8_t>& out, std::string& error);

  /**
   * The size in bytes of the file EncodeDds writes for a `size` x `size` image: the 128-byte header and every mip
   * level down to 1 x 1 (blocks of 4 x 4: 8 bytes for BC1, 16 for BC3, at least one block a level; 4 bytes a pixel
   * for BGRA). 1024 px: 1,398,256 bytes as BC3, 699,192 as BC1.
   */
  [[nodiscard]] inline std::uint64_t DdsFileSize(
    const int size,
    const DdsKind kind
  )
  {
    std::uint64_t bytes = 128;
    for (int level = size; level >= 1; level /= 2) {
      const std::uint64_t side = static_cast<std::uint64_t>(level);
      if (kind == DdsKind::Bgra) {
        bytes += side * side * 4U;
      } else {
        const std::uint64_t blocks = (side + 3U) / 4U;
        bytes += blocks * blocks * (kind == DdsKind::Bc1 ? 8U : 16U);
      }
    }
    return bytes;
  }
} // namespace faf::editor
