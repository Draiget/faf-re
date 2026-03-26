#include "moho/render/BoundaryRenderer.h"

namespace moho
{
  /**
   * Address: 0x007D00A0 (FUN_007D00A0, Moho::BoundaryRenderer::BoundaryRenderer)
   */
  BoundaryRenderer::BoundaryRenderer()
    : mBoundaryRendererBody()
    , mFrame()
  {}

  /**
   * Address: 0x007D0100 (FUN_007D0100, Moho::BoundaryRenderer::dtr)
   * Address: 0x007D0120 (FUN_007D0120, Moho::BoundaryRenderer::~BoundaryRenderer)
   */
  BoundaryRenderer::~BoundaryRenderer() = default;

  /**
   * Address: 0x007D05D0 (FUN_007D05D0, Moho::BoundaryRenderer::Init)
   */
  void BoundaryRenderer::Init(BoxRenderer* const boundaryRendererBody)
  {
    if (!boundaryRendererBody) {
      return;
    }

    boundaryRendererBody->InitializeGeometryResources();
  }

  void BoundaryRenderer::Init()
  {
    Init(&mBoundaryRendererBody);
  }
} // namespace moho
