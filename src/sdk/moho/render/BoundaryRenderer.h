#pragma once

#include <cstddef>

#include "moho/render/BoxRenderer.h"
#include "moho/render/CRenFrame.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3EE8C
   * COL:     0x00E977AC
   */
  class BoundaryRenderer
  {
  public:
    /**
     * Address: 0x007D00A0 (FUN_007D00A0, Moho::BoundaryRenderer::BoundaryRenderer)
     *
     * What it does:
     * Initializes the boundary renderer body resources and frame-pass state.
     */
    BoundaryRenderer();

    /**
     * Address: 0x007D0100 (FUN_007D0100, Moho::BoundaryRenderer::dtr)
     * Address: 0x007D0120 (FUN_007D0120, Moho::BoundaryRenderer::~BoundaryRenderer)
     *
     * What it does:
     * Tears down boundary frame-pass state and body geometry resources.
     */
    virtual ~BoundaryRenderer();

    /**
     * Address: 0x007D05D0 (FUN_007D05D0, Moho::BoundaryRenderer::Init)
     *
     * BoxRenderer *
     *
     * What it does:
     * Rebuilds boundary box geometry resources for the provided body subobject.
     */
    static void Init(BoxRenderer* boundaryRendererBody);

    void Init();

  public:
    BoxRenderer mBoundaryRendererBody; // +0x04
    CRenFrame mFrame;                  // +0x20
  };

  static_assert(
    offsetof(BoundaryRenderer, mBoundaryRendererBody) == 0x04,
    "BoundaryRenderer::mBoundaryRendererBody offset must be 0x04"
  );
  static_assert(offsetof(BoundaryRenderer, mFrame) == 0x20, "BoundaryRenderer::mFrame offset must be 0x20");
  static_assert(sizeof(BoundaryRenderer) == 0x68, "BoundaryRenderer size must be 0x68");
} // namespace moho
