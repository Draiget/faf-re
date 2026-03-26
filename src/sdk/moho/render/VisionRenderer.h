#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "moho/render/CRenFrame.h"
#include "moho/render/RenderGeometryBuffers.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E422E8
   * COL:     0x00E98CE8
   */
  class VisionRenderer
  {
  public:
    /**
     * Address: 0x0081BF10 (FUN_0081BF10, Moho::VisionRenderer::VisionRenderer)
     *
     * What it does:
     * Initializes vision-render frame-pass state and geometry ownership lanes.
     */
    VisionRenderer();

    /**
     * Address: 0x0081BF70 (FUN_0081BF70, Moho::VisionRenderer::dtr)
     * Address: 0x0081BF90 (FUN_0081BF90, Moho::VisionRenderer::~VisionRenderer)
     *
     * What it does:
     * Releases vision-render geometry resources and tears down frame-pass state.
     */
    virtual ~VisionRenderer();

    /**
     * Address: 0x0081C0C0 (FUN_0081C0C0, Moho::VisionRenderer::Init)
     *
     * What it does:
     * Rebuilds vertex/index geometry used by fog-of-war vision rendering.
     */
    void Init();

    /**
     * Address: 0x0081C550 (FUN_0081C550, sub_81C550)
     *
     * What it does:
     * Clears and releases vision-render dynamic resources.
     */
    void ResetRenderResources() noexcept;

  public:
    std::uint32_t mIndexCount = 0;                                  // +0x04
    std::uint32_t mVertexCount = 0;                                 // +0x08
    RenderGeometryBuffers mGeometry;                                // +0x0C
    std::uint32_t mUnknown24 = 0;                                   // +0x24
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mVertexBuffer2;   // +0x28
    CRenFrame mFrame;                                               // +0x30
  };

  static_assert(offsetof(VisionRenderer, mIndexCount) == 0x04, "VisionRenderer::mIndexCount offset must be 0x04");
  static_assert(offsetof(VisionRenderer, mVertexCount) == 0x08, "VisionRenderer::mVertexCount offset must be 0x08");
  static_assert(offsetof(VisionRenderer, mGeometry) == 0x0C, "VisionRenderer::mGeometry offset must be 0x0C");
  static_assert(offsetof(VisionRenderer, mUnknown24) == 0x24, "VisionRenderer::mUnknown24 offset must be 0x24");
  static_assert(offsetof(VisionRenderer, mVertexBuffer2) == 0x28, "VisionRenderer::mVertexBuffer2 offset must be 0x28");
  static_assert(offsetof(VisionRenderer, mFrame) == 0x30, "VisionRenderer::mFrame offset must be 0x30");
  static_assert(sizeof(VisionRenderer) == 0x78, "VisionRenderer size must be 0x78");
} // namespace moho
