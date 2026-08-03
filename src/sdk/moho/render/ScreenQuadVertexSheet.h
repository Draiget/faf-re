#pragma once

#include <cstdint>

namespace moho
{
  class ID3DVertexSheet;

  /**
   * One vertex of a screen-space quad: a pre-transformed position followed by
   * a texture coordinate.
   */
  struct ScreenQuadVertex
  {
    float x;
    float y;
    float z;
    float w;
    float u;
    float v;
  };

  static_assert(sizeof(ScreenQuadVertex) == 0x18, "ScreenQuadVertex size must be 0x18");

  // Vertex-format token and stream usage/frequency the screen quads are built
  // with, identical in Shadow::Init (0x007FE3E0) and Silhouette::Init
  // (0x008145A0).
  inline constexpr int kScreenQuadVertexFormatToken = 7;
  inline constexpr std::uint32_t kScreenQuadStreamUsage = 0U;
  inline constexpr int kScreenQuadVertexCount = 4;

  /**
   * Fills a freshly created four-vertex sheet with the unit screen quad,
   * scaling positions by `scaleX`/`scaleY` and texture coordinates by
   * `scaleU`/`scaleV`.
   *
   * Both callers in the binary open-code the same sequence - lock stream 0 for
   * four vertices, copy a constant unit quad from `.rdata`, multiply the lanes
   * in place, unlock. The two constants (0x00DFE8D8 for the shadow map,
   * 0x00DFE808 for the silhouette) are byte-identical, so one copy serves both
   * here. Shadow passes 1.0f for the texture scales, which is the identity the
   * binary gets by simply not emitting those multiplies.
   */
  void FillScreenQuadVertexSheet(
    ID3DVertexSheet& vertexSheet,
    float scaleX,
    float scaleY,
    float scaleU,
    float scaleV
  );
} // namespace moho
