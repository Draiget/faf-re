#pragma once

#include <cstddef>

#include "moho/render/BoxRenderer.h"
#include "moho/render/CRenFrame.h"

namespace moho
{
  class CWldSession;
  struct GeomCamera3;

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

  /**
   * Address: 0x007D01C0 (FUN_007D01C0, func_RenBoundary)
   *
   * IDA signature:
   * void __thiscall func_RenBoundary(void *this, Moho::BoundaryRenderer *a4, int a3, int _AC);
   *
   * The shipped body is `retn 0Ch` (0x007D044E) with three stack arguments and
   * the head index in `ecx` - it is a free function that link-time code
   * generation gave a register-passed leading argument, not a member. Argument
   * roles decoded from the shipped body: `ecx` feeds
   * `DeviceContext::GetHead` at 0x007D01EE, the first stack argument is
   * dereferenced at `+0x20` for `CRenFrame` (0x007D040A) and at `+0x04` for the
   * `BoxRenderer` subobject (0x007D0359), the second reaches `STIMap` through
   * `+0x1C -> +0x04 -> +0x04` (0x007D0201..0x007D0207), and the third is
   * forwarded untouched as the camera argument of both `CastBoundaryVolume`
   * calls (0x007D0358 / 0x007D03B0).
   *
   * What it does:
   * Draws the playable-area boundary wall for one head. Skips entirely when the
   * playable rect already matches the terrain's own world bounds; otherwise
   * clears the stencil, casts the full-map volume clockwise and the playable
   * volume counter-clockwise into it, and composites the result through the
   * renderer's `"Boundary"` frame pass.
   */
  void RenderPlayableBoundary(
    unsigned int headIndex,
    BoundaryRenderer& boundary,
    CWldSession& session,
    const GeomCamera3& camera
  );
} // namespace moho
