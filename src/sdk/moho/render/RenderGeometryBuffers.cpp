#include "moho/render/RenderGeometryBuffers.h"

namespace moho
{
  void RenderGeometryBuffers::Reset() noexcept
  {
    mIndexBuffer.reset();
    mVertexBuffer.reset();
    mVertexFormat.reset();
  }
} // namespace moho
