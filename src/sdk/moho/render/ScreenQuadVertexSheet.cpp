#include "moho/render/ScreenQuadVertexSheet.h"

#include <cstring>

#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"

namespace
{
  /**
   * The unit quad both screen-quad builders start from, read out of the
   * shipped image's `.rdata` rather than transcribed from the decompiler:
   * 0x00DFE8D8 (shadow) and 0x00DFE808 (silhouette) hold identical bytes.
   */
  constexpr moho::ScreenQuadVertex kUnitScreenQuad[moho::kScreenQuadVertexCount] = {
    {0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f},
    {0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f},
    {1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 1.0f},
    {1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 0.0f},
  };
} // namespace

namespace moho
{
  void FillScreenQuadVertexSheet(
    ID3DVertexSheet& vertexSheet,
    const float scaleX,
    const float scaleY,
    const float scaleU,
    const float scaleV
  )
  {
    ID3DVertexStream* const vertexStream = vertexSheet.GetVertStream(0U);
    auto* const vertices =
      static_cast<ScreenQuadVertex*>(vertexStream->Lock(0, kScreenQuadVertexCount, false, false));

    std::memcpy(vertices, kUnitScreenQuad, sizeof(kUnitScreenQuad));

    for (int index = 0; index < kScreenQuadVertexCount; ++index) {
      ScreenQuadVertex& vertex = vertices[index];
      vertex.x *= scaleX;
      vertex.y *= scaleY;
      vertex.u *= scaleU;
      vertex.v *= scaleV;
    }

    vertexStream->Unlock();
  }
} // namespace moho
