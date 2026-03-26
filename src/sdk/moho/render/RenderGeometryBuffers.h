#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"

namespace moho
{
  /**
   * Common render-geometry resource triple shared by multiple viewport renderers.
   */
  struct RenderGeometryBuffers
  {
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mVertexFormat; // +0x00
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mVertexBuffer; // +0x08
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mIndexBuffer;    // +0x10

    void Reset() noexcept;
  };

  static_assert(
    offsetof(RenderGeometryBuffers, mVertexFormat) == 0x00, "RenderGeometryBuffers::mVertexFormat offset must be 0x00"
  );
  static_assert(
    offsetof(RenderGeometryBuffers, mVertexBuffer) == 0x08, "RenderGeometryBuffers::mVertexBuffer offset must be 0x08"
  );
  static_assert(
    offsetof(RenderGeometryBuffers, mIndexBuffer) == 0x10, "RenderGeometryBuffers::mIndexBuffer offset must be 0x10"
  );
  static_assert(sizeof(RenderGeometryBuffers) == 0x18, "RenderGeometryBuffers size must be 0x18");
} // namespace moho
