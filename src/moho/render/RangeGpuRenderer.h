#pragma once

// Engine addition, not in the shipped binary.
//
// `ren_GpuRanges`: range.fx's "Cast" pass as one instanced draw per ring batch
// from a structured buffer (RangeGpuShader.h), with the technique's own
// depth/stencil state. `func_RenderRings` keeps its batches and frame passes; a
// batch is drawn here instead of locking `RangeRenderer::mDynamicVertexBuffer`
// and running the effect technique.

#include <cstdint>
#include <span>

#include "boost/shared_ptr.h"
#include "moho/misc/RangeExtractor.h"
#include "moho/render/GpuArrayStream.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
  class VertexBuffer;
} // namespace gpg::gal

namespace moho
{
  class RangeRenderer;
  struct GeomCamera3;

  extern int ren_GpuRanges;

  class RangeGpuRenderer
  {
  public:
    [[nodiscard]] static RangeGpuRenderer& Get();

    /** `ren_GpuRanges` is on and the backend can draw this path (built on first use). */
    [[nodiscard]] bool IsActive();

    /**
     * Uploads every payload one `func_RenderRings` call casts, fill and edge
     * ones in one array, and the ring template if it changed. False when this
     * path cannot draw them.
     */
    [[nodiscard]] bool Upload(RangeRenderer& renderer, std::span<const SRangeExtractionPayload> payloads);

    /** Stencils payloads [first, first + count) of the last `Upload` as "Cast" does. */
    void Cast(const RangeRenderer& renderer, const GeomCamera3& camera, std::uint32_t first, std::uint32_t count);

  private:
    RangeGpuRenderer() = default;

    [[nodiscard]] bool RefreshCylinder(RangeRenderer& renderer);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
    boost::shared_ptr<gpg::gal::GpuBuffer> mCylinder;
    const gpg::gal::VertexBuffer* mCylinderSource = nullptr;
    gpg::gal::GpuBuffer* mPayloadBuffer = nullptr;
    GpuArrayStream mPayloadStream{"RangePayloads", sizeof(SRangeExtractionPayload)};
  };
} // namespace moho
