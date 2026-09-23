#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/VertexBuffer.hpp"
#include "gpg/gal/VertexFormat.hpp"

namespace moho
{
  /**
   * Common render-geometry resource triple shared by multiple viewport renderers.
   */
  struct RenderGeometryBuffers
  {
    boost::shared_ptr<gpg::gal::VertexFormat> mVertexFormat; // +0x00
    boost::shared_ptr<gpg::gal::VertexBuffer> mVertexBuffer; // +0x08
    boost::shared_ptr<gpg::gal::IndexBuffer> mIndexBuffer;    // +0x10

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
