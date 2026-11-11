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
} // namespace faf::editor
