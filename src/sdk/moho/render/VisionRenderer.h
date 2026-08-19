#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "moho/render/CRenFrame.h"
#include "moho/render/RenderGeometryBuffers.h"

namespace gpg::gal
{
  class EffectD3D9;
}

namespace moho
{
  class CWldSession;
  struct GeomCamera3;

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
    /**
     * Write cursor, in whole `Wm3::Circle2f` instances, into the dynamic
     * per-instance vertex buffer below. `Init` sizes that buffer to 12288
     * circles and `LockVisionInstanceRange` (0x0081CCB0) sub-allocates from it
     * with `D3DLOCK_NOOVERWRITE`, wrapping back to 0 with `D3DLOCK_DISCARD`.
     */
    std::uint32_t mInstanceRingCursor = 0;                          // +0x24
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mVertexBuffer2;   // +0x28
    CRenFrame mFrame;                                               // +0x30
  };

  static_assert(offsetof(VisionRenderer, mIndexCount) == 0x04, "VisionRenderer::mIndexCount offset must be 0x04");
  static_assert(offsetof(VisionRenderer, mVertexCount) == 0x08, "VisionRenderer::mVertexCount offset must be 0x08");
  static_assert(offsetof(VisionRenderer, mGeometry) == 0x0C, "VisionRenderer::mGeometry offset must be 0x0C");
  static_assert(
    offsetof(VisionRenderer, mInstanceRingCursor) == 0x24, "VisionRenderer::mInstanceRingCursor offset must be 0x24"
  );
  static_assert(offsetof(VisionRenderer, mVertexBuffer2) == 0x28, "VisionRenderer::mVertexBuffer2 offset must be 0x28");
  static_assert(offsetof(VisionRenderer, mFrame) == 0x30, "VisionRenderer::mFrame offset must be 0x30");
  static_assert(sizeof(VisionRenderer) == 0x78, "VisionRenderer size must be 0x78");

  /**
   * Address: 0x007D0460 (FUN_007D0460, func_GetVisionEffect)
   *
   * IDA signature:
   * boost::shared_ptr_EffectD3D9 *__usercall func_GetVisionEffect@<eax>(
   *         boost::shared_ptr_EffectD3D9 *a1@<esi>);
   *
   * What it does:
   * Resolves the `"vision"` D3D effect from the device resources and returns its
   * base GAL effect handle. Shared by both consumers of that effect: the
   * playable-boundary volume cast (`CastBoundaryVolume`, 0x007D0914) and the
   * fog-of-war overlay (`RenderFogOfWar`, 0x0081C6A9), which live in two
   * different translation units - hence the external linkage.
   */
  [[nodiscard]] boost::shared_ptr<gpg::gal::EffectD3D9> AcquireVisionBaseEffect();

  /**
   * Address: 0x0081C660 (FUN_0081C660, func_ren_FogOfWar)
   *
   * IDA signature:
   * HWND *__userpurge func_ren_FogOfWar@<eax>(Moho::CWldSession *a1@<ecx>,
   *         Moho::VisionRenderer *a2, unsigned int idx, Moho::GeomCamera3 *cam,
   *         float amt, int a6);
   *
   * IDA invents a return value and a sixth argument; the shipped body is
   * `retn 10h` (0x0081CCA7) with four stack arguments and the session in `ecx`,
   * and every value IDA reads back as `result` is a dead register from the
   * inlined `boost::shared_ptr` teardown chain at 0x0081CB73..0x0081CC8D.
   *
   * What it does:
   * Draws one frame of the fog-of-war overlay: collects every visible vision
   * circle inside the camera's terrain footprint (`VisionDB::TryAdd`), publishes
   * the count to the `Vision_Total` engine stat, clears the stencil, then
   * instance-draws the vision cylinder geometry in 12288-circle batches through
   * the `"CastVision"` technique and composites the result with the renderer's
   * `"Vision"` frame pass.
   */
  void RenderFogOfWar(
    CWldSession& session,
    VisionRenderer& renderer,
    unsigned int headIndex,
    const GeomCamera3& camera,
    float interpolant
  );
} // namespace moho
