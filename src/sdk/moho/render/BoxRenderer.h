#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/RenderGeometryBuffers.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3EECC
   * COL:     0x00E977F4
   */
  class BoxRenderer
  {
  public:
    /**
     * Address: 0x007D04C0 (FUN_007D04C0, Moho::BoxRenderer::dtr)
     * Address: 0x007D04E0 (FUN_007D04E0, Moho::BoxRenderer::~BoxRenderer)
     *
     * What it does:
     * Releases box-render geometry resources and destroys shared ownership lanes.
     */
    virtual ~BoxRenderer();

    /**
     * Address: 0x007D0820 (FUN_007D0820, sub_7D0820)
     *
     * What it does:
     * Clears and releases vertex-format, vertex-buffer, and index-buffer ownership.
     */
    void ResetRenderResources() noexcept;

    void InitializeGeometryResources();

  public:
    RenderGeometryBuffers mGeometry; // +0x04
  };

  static_assert(offsetof(BoxRenderer, mGeometry) == 0x04, "BoxRenderer::mGeometry offset must be 0x04");
  static_assert(sizeof(BoxRenderer) == 0x1C, "BoxRenderer size must be 0x1C");
} // namespace moho
